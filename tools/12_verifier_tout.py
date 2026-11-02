#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""12_verifier_tout.py -- test de non-regression : relit les sorties des phases 3 a 5b et verifie chaque affirmation chiffree de l'etude.

Chaque controle affiche PASS / FAIL avec la valeur lue. Aucune donnee brute n'est lue : seulement les CSV produits par 07, 09, 10 et 11.
Les bornes sont celles que l'on est pret a defendre dans l'article (pas des valeurs ajustees pour passer).

Usage : python3 tools/12_verifier_tout.py --root analysis_v2
        (attend analysis_v2/phase3, phase4, phase5 ; phase5b est cherche dans phase5 puis phase5b)
"""
from __future__ import annotations
import argparse, os, sys
import numpy as np
import pandas as pd

RES = []


def check(nom, ok, valeur):
    RES.append(bool(ok))
    print("  [%s] %-92s %s" % ("PASS" if ok else "FAIL", nom, valeur))


def rd(root, *cands):
    for c in cands:
        p = os.path.join(root, c)
        if os.path.exists(p):
            return pd.read_csv(p)
    print("  [SKIP] fichier introuvable : %s" % " ou ".join(cands))
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default="analysis_v2")
    a = ap.parse_args()
    R = a.root

    print("\n== 1. Mesure sans perte (07, fx) ==")
    t = rd(R, "phase3/p3_tau_lossless.csv")
    if t is not None:
        g = lambda p, k: t[(t.proto == p) & (t.kem == k)].iloc[0]
        x = g("quic", "x448_mlkem768")
        check("QUIC ML-KEM-768 : pente de D(RTT) dans [0,99 ; 1,01]", 0.99 <= x.slope <= 1.01, "%.4f [%.4f ; %.4f]" % (x.slope, x.slope_lo, x.slope_hi))
        x = g("tls", "x448_mlkem768")
        check("TLS ML-KEM-768 : pente de D(RTT) ~ 0 (|pente| < 0,01)", abs(x.slope) < 0.01, "%.4f" % x.slope)
        for p in ("quic", "tls"):
            x = g(p, "hqc192")
            check("%s HQC-192 : pente dans [0,95 ; 1,06]" % p.upper(), 0.95 <= x.slope <= 1.06, "%.3f" % x.slope)
        x = g("tls", "hqc192")
        check("TLS HQC-192 : decalage tau dans [37 ; 41] ms", 37 <= x.tau_ms <= 41, "%.1f ms" % x.tau_ms)

    print("\n== 2. Ressources (09) ==")
    c = rd(R, "phase4/p4_res_kem_contrasts.csv")
    if c is not None:
        s = c[(c.proto == "tls") & (c.level == "L3") & (c.contraste == "HQC pur - ML-KEM pur") & (c.metrique == "srv_cpu_ms")].iloc[0]
        check("TLS L3 : surcout CPU serveur de HQC pur dans [36 ; 41] ms", 36 <= s.effet <= 41, "%.1f ms" % s.effet)
        s = c[(c.proto == "tls") & (c.level == "L3") & (c.contraste == "HQC pur - ML-KEM pur") & (c.metrique == "cli_cpu_ms")].iloc[0]
        check("TLS L3 : surcout CPU client de HQC pur dans [48 ; 56] ms", 48 <= s.effet <= 56, "%.1f ms" % s.effet)

    print("\n== 3. Cellules naturelles sans perte (10, section 1) ==")
    n = rd(R, "phase5/p5_natural_lossless.csv")
    if n is not None:
        h = n[~n.in_sample]
        check("12 cellules hors echantillon", len(h) == 12, len(h))
        check("toutes conformes (|k_obs - k_pred| <= 0,25)", (h.verdict == "conforme").all(), dict(h.verdict.value_counts()))
        i = h[h.informative]
        check("4 cellules informatives, toutes conformes", len(i) == 4 and (i.verdict == "conforme").all(), "%d" % len(i))
        x = h[(h.groupe == "CHAINE A 2 NIVEAUX") & (h.proto == "tls") & (h.kem == "x448_mlkem768")].iloc[0]
        check("TLS chaine 2 niveaux x448_mlkem768 : bascule k ~ 1 (IC dans [0,9 ; 1,05])", 0.9 <= x.k_obs_median_lo and x.k_obs_median_hi <= 1.05, "%.3f [%.3f ; %.3f]" % (x.k_obs_median, x.k_obs_median_lo, x.k_obs_median_hi))
        x = h[(h.kind == "size") & (h.proto == "quic")]
        check("QUIC ECDSA rempli : k ~ 1 (IC dans [0,95 ; 1,1])", ((x.k_obs_median_lo >= 0.95) & (x.k_obs_median_hi <= 1.1)).all(), list(np.round(x.k_obs_median, 3)))
        x = h[(h.kind == "size") & (h.proto == "tls")]
        check("TLS ECDSA rempli : k ~ 0 (|k| < 0,03)", (x.k_obs_median.abs() < 0.03).all(), list(np.round(x.k_obs_median, 3)))
        check("pas de penalite hors handshake : |k(hs) - k(app)| < 0,02", (n.k_obs_hs_median - n.k_obs_median).abs().max() < 0.02, "%.4f" % (n.k_obs_hs_median - n.k_obs_median).abs().max())

    print("\n== 4. Recouvrement du calcul client HQC (10, section 2) ==")
    p = rd(R, "phase5/p5_tau_profiles.csv")
    if p is not None:
        tl = p[p.proto == "tls"]
        check("TLS : T constant entre RTT 125 et 167 (ecart max < 1 ms)", (tl.T_125 - tl.T_167).abs().max() < 1.0, "%.2f ms" % (tl.T_125 - tl.T_167).abs().max())
        tm = (tl.T_125 + tl.T_167) / 2
        check("TLS : T egal au surcout CPU serveur de HQC (ecart max < 1,5 ms)", (tm - tl.srv_cpu_excess_ms).abs().max() < 1.5, "%.2f ms" % (tm - tl.srv_cpu_excess_ms).abs().max())
        q1 = p[(p.proto == "quic") & (p.level == "L1")]
        check("QUIC L1 (borne par l'anti-amplification) : T ~ 0 (|T| < 5 ms)", (q1[["T_125", "T_167"]].abs().max().max()) < 5, "%.1f ms" % q1[["T_125", "T_167"]].abs().max().max())

    print("\n== 5. Reponse a la perte (10, section 3, QUIC) ==")
    d = rd(R, "phase5/p5_loss_dose.csv")
    if d is not None:
        q = d[(d.proto == "quic") & (d.chaine == "chaine 2 - chaine 1")]
        check("QUIC : pente(chaine 2) - pente(chaine 1) > 0, IC95 % exclut 0 (4 lignes)", len(q) == 4 and (q.lo > 0).all(), list(np.round(q.pente_ms_par_pct, 2)))

    print("\n== 6. Vols reconstitues (10, section 4) ==")
    t4 = rd(R, "phase5/p5_timeline_check.csv")
    if t4 is not None:
        q = t4[(t4.proto == "quic") & (t4.tours_pred == 2)]
        check("QUIC : 1er vol = 3 x octets client - 28 o a deux tailles de datagramme", (q.b1_minus_3x == -28).all() and q.client_bytes.nunique() == 2, sorted(q.client_bytes.unique()))
        check("QUIC : volume modelise a +-0,1 % de b1+b2 (lignes independantes du calage)", ((q.flight_pred - q.flight_obs).abs() / q.flight_obs < 0.001).all(), list(np.round(100 * (q.flight_pred - q.flight_obs) / q.flight_obs, 3)))
        tl = t4[t4.proto == "tls"]
        check("TLS : octets du 1er vol modelises a +-1 o (6 cellules)", ((tl.b1_obs - tl.flight_pred).abs() <= 1).all(), "%d cellules" % len(tl))

    print("\n== 7. Mecanisme d'ecritures TLS (11) ==")
    v = rd(R, "phase5/p5b_segments_validation.csv", "phase5b/p5b_segments_validation.csv")
    if v is not None:
        check("sequences de segments reproduites (6 / 6 a 3 o pres)", v.identique.all() and len(v) == 6, "%d / %d" % (v.identique.sum(), len(v)))
        check("dont >= 4 exactes", v.exacte.sum() >= 4, int(v.exacte.sum()))
    k = rd(R, "phase5/p5b_k_pred_ecritures.csv", "phase5b/p5b_k_pred_ecritures.csv")
    if k is not None:
        check("21 paires TLS", len(k) == 21, len(k))
        check("modele BIO : 0 paire infirmee", (k.verdict_bio == "infirme").sum() == 0, dict(k.verdict_bio.value_counts()))
        check("modele BIO : >= 18 conformes", (k.verdict_bio == "conforme").sum() >= 18, int((k.verdict_bio == "conforme").sum()))
        check("modele BIO + T (HQC-192) : 21 conformes", (k.verdict_bio_tau == "conforme").sum() == 21, int((k.verdict_bio_tau == "conforme").sum()))
        x = k[(k.level == "L5") & (k.kem == "mlkem1024")].iloc[0]
        check("L5 ML-KEM-1024 : 11 segments (> 10) donc k = 1, observe ~ 1", x.segments_mldsa == 11 and x.k_ecritures_bio == 1 and x.k_obs_125 > 0.9, "segments %d, k obs %.2f" % (x.segments_mldsa, x.k_obs_125))
        check("le modele 'octets seuls' echoue sur ces 2 paires (controle de pouvoir discriminant)", (k[k.level == "L5"].query("kem in ['mlkem1024','p521_mlkem1024']").verdict_octets == "infirme").all(), "")

    ok = sum(RES)
    print("\n== BILAN : %d / %d controles PASS ==" % (ok, len(RES)))
    sys.exit(0 if ok == len(RES) else 1)


if __name__ == "__main__":
    main()
