#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""analyse_S3_contrast.py -- contraste entre bras de S3 (traitement QUIC_PAD1 contre temoin QUIC_PAD0), a lancer APRES analyse_S2.py sur chaque bras.
Entrees : S2_cells.csv de chaque bras (sorties de analyse_S2.py) + dossiers de gel des deux bras.
Pour chaque cellule (sig, chain_target, kind) : delta = khat(traitement) - khat(temoin) ; attendu = k_a(traitement gele) - k_a(temoin gele).
Intervalle : normal, a partir des largeurs des intervalles bootstrap par blocs de chaque bras (runs independants) : se = (hi-lo)/3.92 ; se_delta = sqrt(se1^2 + se0^2).
Cellule conforme : intervalle a 95 % entierement dans [attendu - 0,25 ; attendu + 0,25].
  P3 (primaire)    : cellules pad primaires dont l'attendu est non nul : fraction conforme >= 0,80
  P3c (controle)   : cellules pad primaires dont l'attendu est nul : fraction conforme (rapportee)
  S1 (secondaire)  : cellules du traitement situees entre le seuil 1 de la regle a et le seuil 1 de la regle « fenetre seule » (cwnd) : khat dans [1 - 0,25 ; 1 + 0,25] (la fenetre seule predit 0)
  pont ML-DSA-65   : rapporte (attendu = k_a traitement - k_a temoin)
"""
import argparse, csv, math, os, sys

TOL = 0.25

def rd(path):
    return list(csv.DictReader(open(path, encoding="utf-8")))

def key(r):
    return (r["sig"], int(float(r["chain_target"])), r["kind"])

def f(x):
    try:
        return float(x)
    except Exception:
        return float("nan")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cells1", required=True, help="S2_cells.csv du traitement (QUIC_PAD1)")
    ap.add_argument("--cells0", required=True, help="S2_cells.csv du temoin (QUIC_PAD0)")
    ap.add_argument("--pred1", required=True, help="dossier de gel du traitement")
    ap.add_argument("--pred0", required=True, help="dossier de gel du temoin")
    ap.add_argument("--out", default="S3_contrast.csv")
    a = ap.parse_args()
    c1 = {key(r): r for r in rd(a.cells1) if r["kind"] in ("pad", "bridge")}
    c0 = {key(r): r for r in rd(a.cells0) if r["kind"] in ("pad", "bridge")}
    p1 = {key(r): r for r in rd(os.path.join(a.pred1, "predictions_frozen.csv")) if r["kind"] in ("pad", "bridge")}
    p0 = {key(r): r for r in rd(os.path.join(a.pred0, "predictions_frozen.csv")) if r["kind"] in ("pad", "bridge")}
    th = {(r["rule"], int(r["step"])): float(r["chain_threshold"]) for r in rd(os.path.join(a.pred1, "thresholds_frozen.csv"))}
    t_amp, t_cwnd = th[("amp", 1)], th[("cwnd", 1)]
    rows = []
    for k in sorted(set(c1) & set(c0) & set(p1) & set(p0), key=lambda x: (x[2] != "pad", x[1])):
        r1, r0 = c1[k], c0[k]
        d = f(r1["khat"]) - f(r0["khat"])
        se1, se0 = (f(r1["ci_hi"]) - f(r1["ci_lo"])) / 3.92, (f(r0["ci_hi"]) - f(r0["ci_lo"])) / 3.92
        se = math.sqrt(se1 ** 2 + se0 ** 2)
        lo, hi = d - 1.96 * se, d + 1.96 * se
        exp = float(p1[k]["k_a"]) - float(p0[k]["k_a"])
        ok = (lo >= exp - TOL) and (hi <= exp + TOL)
        s1 = (k[2] == "pad") and (t_amp <= k[1] < t_cwnd)
        k1 = f(r1["khat"]); ci1 = (f(r1["ci_lo"]), f(r1["ci_hi"]))
        s1ok = s1 and ci1[0] >= 1 - TOL and ci1[1] <= 1 + TOL
        rows.append(dict(sig=k[0], chain_target=k[1], kind=k[2], tier=p1[k].get("tier", ""), khat_traitement=round(k1, 4), khat_temoin=round(f(r0["khat"]), 4),
                         delta=round(d, 4), ci_lo=round(lo, 4), ci_hi=round(hi, 4), attendu=exp, conforme=int(ok), secondaire_S1=int(s1), S1_conforme=int(s1ok)))
    with open(a.out, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
    prim = [r for r in rows if r["kind"] == "pad" and r["tier"] == "primary"]
    disc = [r for r in prim if r["attendu"] != 0]
    ctl = [r for r in prim if r["attendu"] == 0]
    print("%-10s %6s %-6s %9s %9s %8s %18s %8s %s" % ("sig", "chaine", "kind", "k_trait", "k_temoin", "delta", "IC95", "attendu", "conforme"))
    for r in rows:
        print("%-10s %6d %-6s %9.3f %9.3f %+8.3f [%+7.3f;%+7.3f] %+8.0f %s%s" % (r["sig"], r["chain_target"], r["kind"], r["khat_traitement"], r["khat_temoin"], r["delta"], r["ci_lo"], r["ci_hi"], r["attendu"],
              "OUI" if r["conforme"] else "non", "  (S1)" if r["secondaire_S1"] else ""))
    fr = sum(r["conforme"] for r in disc) / len(disc) if disc else float("nan")
    print("\nP3  (primaire) cellules a delta attendu non nul : %d/%d conformes = %.2f ; decision : %s" % (sum(r["conforme"] for r in disc), len(disc), fr, "CONFIRMEE" if fr >= 0.80 else "NON CONFIRMEE"))
    print("P3c (controle) cellules a delta attendu nul     : %d/%d conformes" % (sum(r["conforme"] for r in ctl), len(ctl)))
    s1 = [r for r in rows if r["secondaire_S1"]]
    print("S1  (secondaire, contre « fenetre seule » ; cellules entre %.0f et %.0f o) : %d/%d conformes a k = 1" % (t_amp, t_cwnd, sum(r["S1_conforme"] for r in s1), len(s1)))
    br = [r for r in rows if r["kind"] == "bridge"]
    for r in br:
        print("pont %s : delta %+.3f [%+.3f ; %+.3f] attendu %+.0f -> %s" % (r["sig"], r["delta"], r["ci_lo"], r["ci_hi"], r["attendu"], "conforme" if r["conforme"] else "non conforme"))

if __name__ == "__main__":
    main()
