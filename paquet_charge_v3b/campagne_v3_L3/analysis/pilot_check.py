#!/usr/bin/env python3
"""pilot_check.py <racine_captures> -- controle DESCRIPTIF d'un pilote d'un bloc (pas d'inference : 1 bloc ne permet pas le bootstrap).
Imprime un resume compact a coller dans le chat : connexions (reprise / compression) puis charge (debit, saturation).
Usage : python3 analysis/pilot_check.py captures_v3_pilot"""
import importlib.util, os, sys
import numpy as np, pandas as pd

here = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("an13", os.path.join(here, "13_analyse_extensions.py"))
an = importlib.util.module_from_spec(spec); spec.loader.exec_module(an)

root = sys.argv[1] if len(sys.argv) > 1 else "captures_v3_pilot"
cdf, ldf = an.walk(root)
pd.set_option("display.width", 250); pd.set_option("display.max_rows", 500); pd.set_option("display.max_columns", 50)

print("=== CONNEXIONS (une ligne = proto / cellule / paire / mode) ===")
if len(cdf):
    d = cdf.copy()
    d["mode_obs"] = np.where(d.resumed == 1, "repris", "complet")
    d["lab"] = d.label.str.replace(r"^(delayonly_|none__)", "", regex=True)
    g = d.groupby(["proto", "lab", "sig", "kem", "mode_obs"]).agg(
        n=("rx", "size"), ok=("app_ms", lambda s: int(s.notna().sum())), rx=("rx", "median"), tx=("tx", "median"),
        app_ms=("app_ms", "median"), hs_ms=("hs_ms", "median"), c25=("cert_type", lambda s: int((s == 25).sum())),
        cert_len=("cert_comp", "median"), plain_len=("cert_plain", "median"), tick=("ticket", "sum"), zrtt=("zrtt", "sum")).reset_index()
    g["kem"] = g.kem.str.replace("x448_mlkem768", "mlkem768")
    print(g.round(1).to_string(index=False))
    sent = d[d.sentinel != ""]
    if len(sent):
        print("\n=== SENTINELLES (mediane app_ms par visite) ===")
        print(sent.groupby(["proto", "sig", "sentinel"]).app_ms.median().round(2).unstack().to_string())
else:
    print("(aucune connexion lue)")

print("\n=== CHARGE (une ligne = paire / niveau de concurrence) ===")
if len(ldf):
    l = ldf.copy()
    l["kem"] = l.kem.str.replace("x448_mlkem768", "mlkem768")
    cols = ["proto", "tls_server", "sig", "kem", "conc", "n", "n_ok", "X", "fail", "app_med", "util_srv", "util_cli", "S_ms", "Scli_ms"]
    print(l[cols].sort_values(["proto", "sig", "kem", "conc"]).round(3).to_string(index=False))
    print("\nNiveaux ou le client depasse 85 %% de ses coeurs : %d / %d" % (int(l.cli_bound.sum()), len(l)))
else:
    print("(aucun niveau de charge lu -- verifier les journaux *load* et les traces CPU)")
