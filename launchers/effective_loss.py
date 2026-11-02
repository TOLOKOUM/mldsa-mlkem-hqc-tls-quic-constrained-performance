#!/usr/bin/env python3
"""Perte effective par cellule (compteurs qdisc). Usage: effective_loss.py <racine_captures>"""
import glob, csv, math, re, sys, collections
root = sys.argv[1] if len(sys.argv) > 1 else "captures_pilot"
agg = collections.defaultdict(lambda: [0, 0, 0])
for f in glob.glob(f"{root}/*/single/*/qdisc_stats_*.csv"):
    parts = f.split("/"); proto, cell = parts[-4], parts[-2]
    for r in csv.DictReader(l for l in open(f) if not l.startswith("#")):
        if r["role"] != "server_egress": continue
        k = (proto, cell)
        agg[k][0] += int(r["pkts_after"]) - int(r["pkts_before"])
        agg[k][1] += int(r["dropped_after"]) - int(r["dropped_before"])
        agg[k][2] += 1
def nominal(c):
    m = re.search(r"loss(\d+)", c) or re.search(r"ge-\w+-(\d+)", c)
    return float(m.group(1)) if m else 0.0
def wilson(d, n, z=1.96):
    p = d / n; den = 1 + z*z/n; c = (p + z*z/(2*n)) / den
    h = z*math.sqrt(p*(1-p)/n + z*z/(4*n*n)) / den
    return 100*(c-h), 100*(c+h)
print(f"{'proto':5} {'cellule':34} {'paires':>6} {'envoyes':>8} {'perdus':>6} {'nom%':>5} {'eff%':>6}  IC95%            z(iid)")
for (proto, cell), (p, d, n) in sorted(agg.items()):
    tot = p + d
    if tot == 0: continue
    nom = nominal(cell); lo, hi = wilson(d, tot)
    z = (d - tot*nom/100) / math.sqrt(tot*(nom/100)*(1-nom/100)) if 0 < nom < 100 and "ge-" not in cell else float("nan")
    print(f"{proto:5} {cell:34} {n:6d} {tot:8d} {d:6d} {nom:5.1f} {100*d/tot:6.2f}  [{lo:.2f}, {hi:.2f}]  {z:+.1f}")
print("(z n'a de sens que pour les cellules iid ; GE : pertes groupees, IC trop etroits)")
