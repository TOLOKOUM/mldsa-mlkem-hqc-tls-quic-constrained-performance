#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""make_plan_S2.py -- plans de la campagne S2 (interventions sur la capacite du premier tour), a partir des PREDICTIONS GELEES d'UNE famille.
(copie de make_plan_S.py : une seule difference, la variable INIT_CWND=<segments> ajoutee aux cellules TLS dont la famille porte une fenetre initiale intervenue ;
Lancer UNE execution par famille, avec CAPTURES_ROOT et --state-dir PROPRES a la famille : le label des repertoires ne porte pas INIT_CWND.)

Format identique a make_plans_ext.sh (lu tel quel par run_campaign_ext.sh) :
    cell_id,protocol,auth,kem_family,profile,loss,delay,total_runs,only_pairs,extra_env     (delay = delai UNIDIRECTIONNEL, ms)
Sorties (dans --out) :
    plan_S2.csv        mesure : toutes les cellules x RTT {50, 150} + cellules de base (avec pont ML-DSA) ; 10 connexions / paire / bloc
    plan_S2_pcap.csv   mecanisme : cellules __pcap a 50 ms (5 flux / bloc) -- a lancer dans le meme CAPTURES_ROOT, hors analyse de k
    plan_S2_all.csv    concatenation (a donner a run_campaign_ext.sh --plan)
    plan_S2_phase0.csv phase 0 (tailles uniquement) : RTT 0, 1 bloc ; voir PREREGISTRATION_S.md
Usage : python3 make_plan_S.py --pred freeze_S --out plans_S [--n-blocks 20] [--tools /chemin/tools]
"""
from __future__ import annotations
import argparse, json, os, sys
import pandas as pd

HDR = "cell_id,protocol,auth,kem_family,profile,loss,delay,total_runs,only_pairs,extra_env"


def prof(rtt):
    return ("none", 0) if rtt == 0 else ("delay-only", rtt // 2)


def env(*parts):
    return ";".join(p for p in parts if p)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pred", default="freeze_S")
    ap.add_argument("--out", default="plans_S")
    ap.add_argument("--n-blocks", type=int, default=20)
    ap.add_argument("--per-block", type=int, default=10, help="connexions mesurees par paire et par bloc")
    ap.add_argument("--pcap-per-block", type=int, default=5)
    ap.add_argument("--tools", default=None, help="si fourni : controle d'unicite des etiquettes avec pq_common.plan_label (pq_common.py est cherche dans ce dossier, son parent et le dossier courant)")
    ap.add_argument("--micro-batches", type=int, default=1, help="1 (defaut) = une visite par cellule et par bloc ; M>1 = entrelacement en M tours (MICRO_BATCHES=M), M fois plus de visites")
    ap.add_argument("--visit-overhead-s", type=float, default=40.0, help="surcout fixe par visite (s), mesure en v2, pour l'estimation de duree")
    ap.add_argument("--conn-s", type=float, default=1.0, help="cout moyen par connexion (s), pour l'estimation de duree")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    pred = pd.read_csv(os.path.join(a.pred, "predictions_frozen.csv"))
    const = json.load(open(os.path.join(a.pred, "constants_frozen.json")))
    fams, rtts = const["FAMILIES"], const["RTTS"]
    N = a.n_blocks
    runs, pruns = N * a.per_block, N * a.pcap_per_block
    mt, pt, p0 = [], [], []
    mb = "MICRO_BATCHES=%d" % a.micro_batches if a.micro_batches > 1 else ""
    for fam, f in fams.items():
        proto, kem, sig, bridge = f["proto"], f["kem"], f["sig"], f["bridge"]
        mtu = "MTU=%d" % f["mtu"] if f["mtu"] != 1500 else ""
        if f.get("iw"):
            mtu = env(mtu, "INIT_CWND=%d" % f["iw"])      # fenetre initiale TCP du serveur (voir launcher_initcwnd.patch)
        pairs_base = "%s|%s;%s|%s" % (sig, kem, bridge, kem)
        pair = "%s|%s" % (sig, kem)
        sizes = sorted(f["sizes"])
        for rtt in rtts:
            p, d = prof(rtt)
            mt.append("S2_%s_rtt%d_base,%s,single,both,%s,0,%d,%d,%s,%s" % (fam, rtt, proto, p, d, runs, pairs_base, env(mtu, mb)))
            for X in sizes:
                mt.append("S2_%s_rtt%d_pad%d,%s,single,both,%s,0,%d,%d,%s,%s" % (fam, rtt, X, proto, p, d, runs, pair, env("CERT_PAD_TARGET_DER=%d" % X, mtu, mb)))
        p, d = prof(50)
        pt.append("S2_%s_pcap_base,%s,single,both,%s,0,%d,%d,%s,%s" % (fam, proto, p, d, pruns, pairs_base, env(mtu, "PER_CONN_PCAP=1")))
        for X in sorted(f["pcap"]):
            pt.append("S2_%s_pcap_pad%d,%s,single,both,%s,0,%d,%d,%s,%s" % (fam, X, proto, p, d, pruns, pair, env("CERT_PAD_TARGET_DER=%d" % X, mtu, "PER_CONN_PCAP=1")))
        # phase 0 : extremes + deux tailles proches des seuils, avec pcap ; 1 bloc de 10 connexions par paire.
        # TLS : RTT 50 ms (le detecteur de rondes de fw_segments exige un ecart > 0,4 RTT : a RTT 0 toute la rafale est vue comme une seule ronde) ; QUIC : RTT 0 comme en campagne S.
        p, d = prof(50) if proto == "tls" else prof(0)
        p0.append("P0S2_%s_base,%s,single,both,%s,0,%d,10,%s,%s" % (fam, proto, p, d, pairs_base, env(mtu, "PER_CONN_PCAP=1")))
        for X in sorted(set([sizes[0], sizes[len(sizes) // 2], sizes[-1]] + list(f["pcap"])[:2])):
            p0.append("P0S2_%s_pad%d,%s,single,both,%s,0,%d,10,%s,%s" % (fam, X, proto, p, d, pair, env("CERT_PAD_TARGET_DER=%d" % X, mtu, "PER_CONN_PCAP=1")))
    for name, rows in (("plan_S2.csv", mt), ("plan_S2_pcap.csv", pt), ("plan_S2_all.csv", mt + pt), ("plan_S2_phase0.csv", p0)):
        with open(os.path.join(a.out, name), "w") as fh:
            fh.write(HDR + "\n" + "\n".join(rows) + "\n")
        print("%-18s %3d cellules" % (name, len(rows)))
    # controles
    ids = [r.split(",")[0] for r in mt + pt + p0]
    assert len(ids) == len(set(ids)), "cell_id dupliques"
    if a.tools:
        for d in (os.getcwd(), os.path.dirname(os.path.abspath(a.tools)), a.tools):
            sys.path.insert(0, d)
        from pq_common import plan_label
        seen = {}
        for r in mt + pt:
            c = r.split(",")
            row = dict(profile=c[4], loss=c[5], delay=str(c[6]), extra_env=c[9])
            key = (c[1], plan_label(row), c[8])
            assert key not in seen, ("etiquette dupliquee", c[0], seen[key])
            seen[key] = c[0]
        print("etiquettes uniques : %d" % len(seen))
    nconn = sum(int(r.split(",")[7]) * (r.split(",")[8].count(";") + 1) for r in mt)
    print("connexions mesurees (hors echauffement) : %d" % nconn)
    # estimation de duree (ordre de grandeur, calibre sur la v2 : ~40 s de surcout fixe par visite)
    M = max(1, a.micro_batches)
    for name, rows in (("mesure + pcap (plan_S_all)", mt + pt), ("phase 0", p0)):
        visits = len(rows) * (M if name.startswith("mesure") else 1)
        conns = 0
        for r in rows:
            c = r.split(",")
            conns += (int(c[7]) // (M if name.startswith("mesure") else 1) // 1 + 5) * (c[8].count(";") + 1) * (M if name.startswith("mesure") else 1)
        # par bloc
        nb = N if name.startswith("mesure") else 1
        per_block = (visits * a.visit_overhead_s + conns / nb * a.conn_s) / 3600.0 if nb else 0
        print("ESTIMATION %-28s : %4d visites par bloc, ~%.2f h par bloc, ~%.1f h au total (%d bloc(s))" % (name, visits, per_block, per_block * nb, nb))


if __name__ == "__main__":
    main()
