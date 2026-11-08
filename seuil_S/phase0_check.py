#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""phase0_check.py -- PHASE 0 (aveugle aux temps) : les cellules de la campagne S sont-elles realisables et de la taille prevue ?

N'AFFICHE AUCUNE DUREE. Pour chaque cellule du plan de phase 0 (RTT 0, 1 bloc) il rapporte :
  - le taux de connexions reussies ;
  - les octets recus par le client (Rx) compares au vol predit (TLS : +-10 o exigees ; QUIC : ecart relatif, a titre d'etalonnage) ;
  - pour QUIC (pcap) : octets du premier vol client (B_c) et tailles modales des datagrammes ;
  - la valeur a injecter dans predict_freeze.py (--quic-dgram) si elle differe de la valeur par defaut.
Usage : python3 phase0_check.py --root captures_S_phase0 --pred freeze_S_draft
"""
from __future__ import annotations
import argparse, collections, glob, json, os, sys
import numpy as np
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import analyse_seuil as A
import fw_segments as W


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", nargs="+", required=True)
    ap.add_argument("--pred", default="freeze_S")
    a = ap.parse_args()
    pred = pd.read_csv(os.path.join(a.pred, "predictions_frozen.csv"))
    const = json.load(open(os.path.join(a.pred, "constants_frozen.json")))
    df = A.walk(a.root)
    if df.empty:
        sys.exit("aucune donnee")
    df["family"] = [A.fam_of(r.proto, r.kem, r.mtu, const["FAMILIES"]) for r in df.itertuples()]
    rows = []
    for (fam, sig, pad), g in df.groupby(["family", "sig", "pad"]):
        x = pred[(pred.family == fam) & (pred.sig == sig) & (pred.chain_target == pad) & (pred.kind.isin(["pad", "base", "bridge"]))]
        if x.empty:
            continue
        x = x.iloc[0]
        rows.append(dict(family=fam, sig=sig, pad=pad, n=len(g), ok_rate=float(g.app_ms.notna().mean()), rx_median=float(g.rx.median()),
                         flight_pred=float(x.flight_a), rx_minus_pred=float(g.rx.median() - x.flight_a),
                         rel=float((g.rx.median() - x.flight_a) / x.flight_a)))
    o = pd.DataFrame(rows)
    pd.set_option("display.width", 200, "display.max_rows", 300)
    print("=== PHASE 0 : realisabilite et tailles (aucune duree affichee) ===")
    print(o.to_string(index=False, float_format=lambda v: "%.3f" % v))
    tls = o[o.family.str.startswith("TLS")]
    print("\nTLS : cellules avec |Rx - vol predit| <= 10 o : %d / %d" % (int((tls.rx_minus_pred.abs() <= 10).sum()), len(tls)))
    print("Cellules avec taux de reussite < 100 %% : %s" % list(o[o.ok_rate < 1.0][["family", "sig", "pad"]].itertuples(index=False, name=None)))
    fl = W.collect(a.root, pred)
    if fl.empty:
        print("\n(aucun block.pcap exploitable : verifier pcap_perconn/*/*/block.pcap et conn_windows.csv)")
        return
    print("\nPCAP : %d flux (%d fichiers)" % (len(fl), fl.file.nunique()))
    t = fl[fl.proto == "tls"]
    if len(t):
        g = t.groupby(["mtu", "kem", "sig", "pad"]).agg(n=("execution", "size"), segs_first=("segs_first", "median"), bytes_first=("bytes_first", "median"),
                                                        rounds=("rounds_obs", "median"), seg_sizes=("seg_sizes", lambda v: v.iloc[0]))
        print("\nTLS (pcap) : 1re ronde (rien d'autre n'est lu) :")
        print(g.reset_index().to_string(index=False))
    q = fl[fl.proto == "quic"]
    if len(q):
        g = q.groupby(["kem", "sig", "pad"]).agg(n=("execution", "size"), bc=("bc", "median"), n_cli=("n_client_dgrams", "median"),
                                                 burst1_bytes=("burst1_bytes", "median"), burst1_dgrams=("burst1_dgrams", "median"),
                                                 burst2_bytes=("burst2_bytes", "median"), ratio=("ratio", "median"))
        print("\nQUIC (pcap) :")
        print(g.reset_index().to_string(index=False, float_format=lambda v: "%.2f" % v))
        cli = collections.Counter(int(x) for v in q.client_dgram_sizes.dropna() for x in str(v).split(",") if x)
        srv = collections.Counter(int(x) for v in q.burst1_sizes.dropna() for x in str(v).split(",") if x)
        print("\nQUIC : tailles de datagrammes client = %s ; serveur (ronde 1) = %s" % (cli.most_common(3), srv.most_common(4)))
        qd = srv.most_common(1)[0][0] if srv else None
        cell = q.groupby(["kem", "sig", "pad"]).agg(bc=("bc", "median"), b1=("burst1_bytes", "median"), ratio=("ratio", "median")).reset_index()
        bc_kem = cell.groupby("kem").bc.median()
        args = []
        if qd:
            args.append("--quic-dgram %d" % qd)
        for kem, v in bc_kem.items():
            args.append("--bc %s=%d" % (kem, int(round(v))))
        capped = cell[(cell.ratio >= 2.9) & (cell.ratio <= 3.0)]
        if len(capped):
            cap_obs = float(capped.b1.max())
            sub = [int(round(3 * bc_kem[k] - cap_obs)) for k in capped.kem.unique()]
            print("\nQUIC : plafond de la salve 1 observe = %d o (cellules plafonnees : %d) ; 3 x B_c - plafond = %s" % (cap_obs, len(capped), sorted(set(sub))))
            args.append("--amp-sub %d" % max(0, sub[0]))
            unc = cell[(cell.b1 < cap_obs - 1) & (cell["pad"] > 0)]
        else:
            cap_obs = None
            unc = cell[cell["pad"] > 0]
        res = []
        for r in unc.itertuples():
            fam = A.fam_of("quic", r.kem, 1500, const["FAMILIES"])
            x = pred[(pred.family == fam) & (pred.sig == r.sig) & (pred.chain_target == getattr(r, "pad")) & (pred.kind.isin(["pad"]))]
            if len(x):
                res.append(float(r.b1 - x.flight_a.iloc[0]))
        if res:
            print("QUIC : ecarts (salve 1 - vol predit) des cellules remplies non plafonnees : %s ; mediane %.1f" % ([round(v, 1) for v in res], float(np.median(res))))
            args.append("--q-offset %.0f" % round(float(np.median(res))))
        print("\n=> ARGUMENTS A DONNER A predict_freeze.py (en plus de --tools et --out) :  " + " ".join(args))
        print("   (valeur par defaut de --quic-dgram : %d ; ces valeurs sont des ECARTS par rapport au gel utilise ici : %s)" % (const["QUIC_DGRAM"], args))

if __name__ == "__main__":
    main()
