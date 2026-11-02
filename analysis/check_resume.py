#!/usr/bin/env python3
"""check_resume.py <racine_captures> -- la reprise de session est-elle EFFECTIVE ? (lecture seule, utilisable pendant la campagne)
Trois preuves independantes, par protocole et par cellule :
  1. le client declare "Resumed: 1" pour les connexions prevues en reprise, "Resumed: 0" pour les completes ;
  2. les octets recus s'effondrent en reprise (plus de Certificate ni de CertificateVerify) ;
  3. le message Certificate est ABSENT des connexions reprises (TLS : cert_plain = 0).
Usage : python3 analysis/check_resume.py captures_v3"""
import importlib.util, os, sys
import numpy as np, pandas as pd
here = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("an13", os.path.join(here, "13_analyse_extensions.py"))
an = importlib.util.module_from_spec(spec); spec.loader.exec_module(an)
root = sys.argv[1] if len(sys.argv) > 1 else "captures_v3"
cdf, _ = an.walk(root)
pd.set_option("display.width", 220)
if cdf.empty or "res" not in cdf: print("aucune donnee"); sys.exit(1)
d = cdf[(cdf.res == 1) & cdf.app_ms.notna() & cdf.mode_planned.isin(["full", "resumed"])].copy()
if d.empty: print("aucune connexion de reprise lue (cellules *__res* absentes ?)"); sys.exit(1)
d["lab"] = d.label.str.replace(r"^(delayonly_|simple_|none)", "", regex=True)
print("Connexions lues :", len(d), "| blocs :", sorted(int(b) for b in d.block.unique()))
print("\n=== 1. Reprise declaree par le client vs mode prevu ===")
g = d.groupby(["proto", "mode_planned"]).agg(n=("resumed", "size"), repris=("resumed", lambda s: int((s == 1).sum()))).reset_index()
g["part_reprise"] = (g.repris / g.n).round(4)
print(g.to_string(index=False))
bad_full = int(((d.mode_planned == "full") & (d.resumed == 1)).sum()); bad_res = int(((d.mode_planned == "resumed") & (d.resumed != 1)).sum())
print("Attendu : complet -> 0 reprise ; repris -> ~100 %%.  Anomalies : %d complete(s) qui ont repris, %d reprise(s) manquee(s)." % (bad_full, bad_res))
print("\n=== 2. Octets recus (mediane) : complet vs repris, par cellule et paire ===")
t = d.groupby(["proto", "lab", "sig", "kem", "mode_planned"]).rx.median().unstack("mode_planned")
t["repris/complet"] = (t["resumed"] / t["full"]).round(3)
t = t.rename(columns={"full": "rx_complet", "resumed": "rx_repris"}).reset_index()
t["kem"] = t.kem.str.replace("x448_mlkem768", "mlkem768")
print(t.to_string(index=False))
m = t[t.sig == "mldsa65"].groupby("proto")["repris/complet"].median()
print("\nML-DSA-65, mediane du rapport repris/complet :", {k: round(float(v), 3) for k, v in m.items()}, " (attendu <= 0.25 TLS, <= 0.30 QUIC)")
tl = d[(d.proto == "tls") & (d.mode_planned == "resumed")]
if len(tl):
    print("\n=== 3. TLS : message Certificate dans les connexions reprises ===")
    print("Certificate present (cert_plain>0 ou cert_comp>0) dans %d / %d connexions reprises (attendu 0)" %
          (int(((tl.cert_plain.fillna(0) > 0) | (tl.cert_comp.fillna(0) > 0)).sum()), len(tl)))
