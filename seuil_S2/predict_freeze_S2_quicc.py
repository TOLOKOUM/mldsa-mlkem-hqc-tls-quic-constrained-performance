#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""predict_freeze_S2_quicc.py -- COPIE de predict_freeze_S2.py (inchange pour TLS) avec une option de plus pour QUIC_C : --first-dgram-extra E.
E = octets d'un premier datagramme serveur (1 260 o) compte dans les octets recus mais hors du budget d'amplification (phase 0 QUIC_C a RTT 50 ms : salve 1 plafonnee a 12 212 o = 1 260 + 3 x 3 660 - 28). Defaut E = 0 : modele identique.

PREDICTIONS FIGEES de la campagne S2 (interventions sur la capacite du premier tour).

La campagne S a fait varier la taille F du vol serveur et teste OU l'escalier monte. La campagne S2 fait varier la CAPACITE du premier tour
(l'autre membre de l'inegalite F > C) et teste si le palier se deplace comme predit :
  TLS_IW4 / TLS_IW20 : fenetre initiale TCP du serveur (route `initcwnd` = 4 ou 20 segments au lieu de 10)
  QUIC_C             : premier vol client B_c, via un partage de cle client plus gros (HQC-128 au lieu de ML-KEM : 3 datagrammes Initial attendus au lieu de 2)
Une famille par execution (un dossier de gel par famille). Aucune duree n'est lue : le script n'utilise que le modele deja fige de la campagne S
(seuil_S/predict_freeze.py, tools/07_threshold_model.py, tools/11_modele_ecritures_tls.py) et les constantes de phase 0.

Regles comparees (colonnes rule_a / rule_b de predictions_frozen.csv ; k = nombre d'allers-retours ajoutes par rapport a la chaine de base) :
  TLS  : a = « ecritures (BIO) avec la fenetre initiale intervenue (IW segments) » ; b = « intervention sans effet » (meme regle, IW = 10 comme en campagne S)
  QUIC : a = « anti-amplification avec le B_c mesure en phase 0 » ; b = « B_c sans effet » (B_c = 2 440 o comme en campagne S) ;
         la regle « fenetre seule » (cwnd) n'est pas un rival de b mais est consignee dans thresholds_frozen.csv pour l'encadrement des seuils (E6).
Usage :
  python3 predict_freeze_S2.py --family TLS_IW20 --tools tools --out freeze_S2_iw20
  python3 predict_freeze_S2.py --family QUIC_C   --tools tools --out freeze_S2_quicc --bc hqc128=3660   (valeur de phase 0 ; defaut : modele)
Les arguments de calage de phase 0 de la campagne S (--quic-dgram 1220 --amp-sub 28 --q-offset 42) sont fixes par defaut ici.
"""
from __future__ import annotations
import argparse, hashlib, json, math, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "seuil_S"))
import predict_freeze as pf   # noqa: E402  (modele fige de la campagne S)

S2_FAMILIES = {
    "TLS_IW4":  dict(proto="tls", sig="secp384r1", kem="x448_mlkem768", mtu=1500, bridge="mldsa65", iw=4,
                     intervention="initcwnd=4 (route du serveur)"),
    "TLS_IW20": dict(proto="tls", sig="secp384r1", kem="x448_mlkem768", mtu=1500, bridge="mldsa65", iw=20,
                     intervention="initcwnd=20 (route du serveur)"),
    "QUIC_C":   dict(proto="quic", sig="ed25519", kem="hqc128", mtu=1500, bridge="mldsa44", iw=None,
                     intervention="partage de cle client HQC-128 (B_c attendu : 3 datagrammes)"),
}
S_BC = 2440                      # B_c mesure en campagne S pour x448_mlkem768 et x25519_mlkem512 (2 datagrammes de 1 220 o)
MAX_CHAIN = {"TLS_IW4": 20000, "TLS_IW20": 46000, "QUIC_C": 12000}   # <= tailles validees en phase 0 de la campagne S (TLS 46 000 o, QUIC 35 500 o) ; QUIC : pas de second palier (mal localise en campagne S)


class ModelS2(pf.Model):
    first_extra = 0     # octets du premier datagramme serveur hors budget (--first-dgram-extra)

    def _quic(self, kem, sig, chain, rule):
        d = super()._quic(kem, sig, chain, rule)
        if self.first_extra:
            d = dict(d)
            d["rounds"] = self.p3.rounds_needed(d["F"] - self.first_extra, d["burst"], self.p3.QUIC_IW)
        return d

    def tls_bio_iw(self, kem, sig, chain, mss, iw):
        recs = self.records(kem, sig, chain)
        w = self.m11.bio_writes(recs)
        seg, q = self.m11.tcp_first_window(w, mss, iw)
        s_eff = len(seg) + (math.ceil(q / mss) if q else 0)
        r = self.p3.rounds_needed(s_eff, iw, iw)
        return dict(F=sum(recs), segs=s_eff, rounds=r, fw_seg=len(seg), fw_bytes=sum(seg), writes="+".join(map(str, w)))

    def rule_rounds(self, fam, rule, chain, sig=None):
        f = pf.FAMILIES[fam]
        sig = sig or f["sig"]
        if f["proto"] == "tls":
            mss = f["mtu"] - 52
            iw = f["iw"] if rule == "bio_iw" else 10
            return self.tls_bio_iw(f["kem"], sig, chain, mss, iw)
        if rule == "amp":
            return self._quic(f["kem"], sig, chain, "amp")
        if rule == "amp_bc":                                      # B_c sans effet : valeur de la campagne S
            keep = dict(self.bc_override); self.bc_override[f["kem"]] = S_BC
            try:
                return self._quic(f["kem"], sig, chain, "amp")
            finally:
                self.bc_override = keep
        if rule == "cwnd":
            return self._quic(f["kem"], sig, chain, "cwnd")
        raise ValueError(rule)


def r50(x):
    return int(round(x / 50.0) * 50)


def thr(M, fam, rule, step):
    base = pf.BASE_CHAIN[pf.FAMILIES[fam]["sig"]]
    b0 = M.rule_rounds(fam, rule, base)["rounds"]
    for c in range(base, 120001):
        if M.rule_rounds(fam, rule, c)["rounds"] - b0 >= step:
            return c
    return None


def choose_sizes(M, fam, ra, rb, extra_rules=()):
    f = pf.FAMILIES[fam]
    need = pf.MARGIN_MIN[f["proto"]]
    cap = MAX_CHAIN[fam]
    bounds = []
    for rule in (ra, rb) + tuple(extra_rules):
        for step in (1, 2, 3):
            t = thr(M, fam, rule, step)
            if t is not None and t <= cap + 4000:
                bounds.append(t)
    bounds = sorted(set(bounds))
    cand = [0.5 * bounds[0]]
    for t in bounds:
        cand += [t - 350, t + 250]
    for lo, hi in zip(bounds, bounds[1:]):
        gap = hi - lo
        n = 4 if gap > 3000 else 2 if gap > 1500 else 1          # sous-divisions des intervalles ou les regles se separent
        cand += [lo + gap * i / n for i in range(1, n)]
    cand.append(cap)
    sizes = []
    for x in sorted(set(r50(c) for c in cand)):
        x = min(x, cap)
        for _ in range(8):             # decale par pas de 50 o jusqu'a respecter les marges de CHAQUE regle
            if all(pf.margin(M, fam, r, x) >= need for r in (ra, rb) + tuple(extra_rules)):
                break
            x += 50
        if x <= cap and x not in sizes and x > pf.BASE_CHAIN[f["sig"]]:
            sizes.append(x)
    return sorted(sizes)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--family", required=True, choices=sorted(S2_FAMILIES))
    ap.add_argument("--tools", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--quic-dgram", type=int, default=1220)
    ap.add_argument("--amp-sub", type=int, default=28)
    ap.add_argument("--q-offset", type=float, default=42.0)
    ap.add_argument("--first-dgram-extra", type=int, default=0)
    ap.add_argument("--bc", action="append", help="KEM=octets (phase 0), ex. hqc128=3660 ; defaut : formule ceil((CH_BASE+part)/CH_CAP) x datagramme")
    ap.add_argument("--max-chain", type=int, default=None)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    fam, f = a.family, dict(S2_FAMILIES[a.family])
    if a.max_chain:
        MAX_CHAIN[fam] = a.max_chain
    M = ModelS2(os.path.abspath(a.tools))
    M.p3.QUIC_DGRAM = a.quic_dgram
    M.p3.QUIC_IW = 10 * a.quic_dgram
    M.q_offset, M.amp_sub = a.q_offset, a.amp_sub
    M.first_extra = a.first_dgram_extra
    M.bc_override = {"x25519_mlkem512": S_BC, "x448_mlkem768": S_BC}      # valeurs mesurees en campagne S
    for kv in a.bc or []:
        k, v = kv.split("="); M.bc_override[k] = int(v)
    if f["proto"] == "quic" and f["kem"] not in M.bc_override:
        cs, _ = M.p3.kem_shares(f["kem"])
        M.bc_override[f["kem"]] = math.ceil((M.p3.CH_BASE + cs) / M.p3.CH_CAP) * M.p3.QUIC_DGRAM
    pf.FAMILIES.clear(); pf.FAMILIES[fam] = f
    ra, rb = ("bio_iw", "bio_iw10") if f["proto"] == "tls" else ("amp", "amp_bc")
    pf.RULES[f["proto"]] = (ra, rb)
    extra = ("cwnd",) if f["proto"] == "quic" else ()
    f["sizes"] = choose_sizes(M, fam, ra, rb, extra)
    # sous-ensemble pcap : les cellules discriminantes les plus proches de chaque seuil (<= 7)
    pcap = []
    for t in sorted(set(thr(M, fam, r, s) for r in (ra, rb) for s in (1, 2) if thr(M, fam, r, s))):
        pcap += [x for x in f["sizes"] if abs(x - t) <= 600]
    f["pcap"] = sorted(set(pcap))[:8]
    f["thresholds_model"] = {r: [thr(M, fam, r, s) for s in (1, 2)] for r in (ra, rb) + extra}
    pf.FAMILIES[fam] = f
    rows = pf.build(M)
    import pandas as pd
    df = pd.DataFrame(rows)
    bad = [(r.family, r.chain_target, r.margin_a, r.margin_b) for _, r in df[df.kind == "pad"].iterrows()
           if r.margin_a < pf.MARGIN_MIN[r.proto] or r.margin_b < pf.MARGIN_MIN[r.proto]]
    assert not bad, "marges insuffisantes : %s" % bad
    df["iw"] = f["iw"] if f["iw"] else ""
    df.to_csv(os.path.join(a.out, "predictions_frozen.csv"), index=False)
    th = []
    for rule in (ra, rb) + extra:
        for step in (1, 2):
            t = thr(M, fam, rule, step)
            if t is not None:
                F = M.rule_rounds(fam, rule, t)["F"]
                th.append(dict(family=fam, rule=rule, step=step, chain_threshold=t, flight_threshold=round(F, 1), nonmonotone_points=0))
    pd.DataFrame(th).to_csv(os.path.join(a.out, "thresholds_frozen.csv"), index=False)

    def sha(p):
        h = hashlib.sha256(); h.update(open(p, "rb").read()); return h.hexdigest()
    const = dict(MSS_1500=1448, TCP_IW_SEGMENTS_INTERVENTION=f["iw"], BIO_BUFFER=M.m11.BUF, TLS_A=M.p3.A_TLS, SH_FIX=M.p3.SH_FIX,
                 QUIC_DGRAM=M.p3.QUIC_DGRAM, QUIC_W0=M.p3.QUIC_IW, RHO_QUIC=M.p3.RHO_QUIC, CH_BASE=M.p3.CH_BASE, CH_CAP=M.p3.CH_CAP,
                 KEM_SHARE=M.p3.KEM_SHARE, SIG_BYTES=M.p3.SIG_BYTES, CHAIN_DEFAULT=M.p3.CHAIN_DEFAULT, BASE_CHAIN=pf.BASE_CHAIN,
                 FAMILIES={fam: f}, RTTS=pf.RTTS, TOL_K=pf.TOL_K, MARGIN_MIN=pf.MARGIN_MIN, S_BC_NULL=S_BC, BC_USED=M.bc_override,
                 phase0_overrides=dict(quic_dgram=a.quic_dgram, q_offset=a.q_offset, amp_sub=a.amp_sub, bc=a.bc, first_dgram_extra=a.first_dgram_extra),
                 source_sha256={n: sha(os.path.join(a.tools, n)) for n in ("07_threshold_model.py", "11_modele_ecritures_tls.py", "pq_common.py")
                                if os.path.exists(os.path.join(a.tools, n))},
                 predict_freeze_S_sha256=sha(pf.__file__), this_script_sha256=sha(os.path.abspath(__file__)))
    json.dump(const, open(os.path.join(a.out, "constants_frozen.json"), "w"), indent=1, sort_keys=True)
    with open(os.path.join(a.out, "SHA256SUMS_frozen.txt"), "w") as fh:
        for n in ("predictions_frozen.csv", "thresholds_frozen.csv", "constants_frozen.json"):
            fh.write("%s  %s\n" % (sha(os.path.join(a.out, n)), n))
    pd.set_option("display.width", 250, "display.max_rows", 500)
    print("=== %s : %s ===" % (fam, f["intervention"]))
    print("regles : a = %s ; b = %s ; seuils du modele (chaine, octets DER) : %s" % (ra, rb, f["thresholds_model"]))
    cols = ["kind", "sig", "chain_target", "flight_a", "k_a", "k_b", "disc", "tier", "margin_a", "margin_b", "pcap_cell"]
    print(df[cols].to_string(index=False))
    nd = int(((df.kind == "pad") & (df.disc == 1) & (df.tier == "primary")).sum())
    print("\ncellules remplies : %d ; discriminantes primaires : %d ; pcap : %d" % ((df.kind == "pad").sum(), nd, int(df.pcap_cell.sum())))


if __name__ == "__main__":
    main()
