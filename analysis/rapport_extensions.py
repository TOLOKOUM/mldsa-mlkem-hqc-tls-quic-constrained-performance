#!/usr/bin/env python3
"""rapport_extensions.py <dossier_analysis_v3> -- rapport lisible des trois bras (reprise, compression, charge).
Lit les p6_*.csv produits par 13_analyse_extensions.py. Aucune inference nouvelle : mise en forme et lecture guidee."""
import os, sys
import pandas as pd

D = sys.argv[1] if len(sys.argv) > 1 else "analysis_v3"
pd.set_option("display.width", 220); pd.set_option("display.max_rows", 300); pd.set_option("display.max_columns", 40)

def rd(name):
    p = os.path.join(D, name)
    return pd.read_csv(p) if os.path.exists(p) else None

def titre(t): print("\n" + "=" * 100 + "\n" + t + "\n" + "=" * 100)

def kem_court(s): return s.astype(str).str.replace("x448_mlkem768", "mlkem768")

pr = rd("p6_predictions.csv")
titre("0. VERDICTS DES PREDICTIONS PRE-ENREGISTREES (PASS = IC95 % dans la bande ; FAIL = hors bande ; INCONCLUSIF = chevauche)")
if pr is None: print("p6_predictions.csv absent")
else:
    print(pr.groupby(["arm", "verdict"]).size().unstack(fill_value=0).to_string())
    for v in ["FAIL", "INCONCLUSIF"]:
        x = pr[pr.verdict == v]
        if len(x):
            print(f"\n--- {v} ({len(x)}) : a rapporter tel quel dans l'article ---")
            for _, r in x.iterrows():
                print(f"  {r['id']:<34} est={r['estimate']:.3g} IC[{r['ic_lo']:.3g} ; {r['ic_hi']:.3g}] bande[{r['band_lo']:.3g} ; {r['band_hi']:.3g}]  {str(r['description'])[:90]}")

titre("1. REPRISE DE SESSION")
cxf = os.path.join(D, "p6_connexions.csv.gz")
if os.path.exists(cxf):
    z = pd.read_csv(cxf, usecols=["proto", "label", "mode_planned", "resumed", "res", "block"], low_memory=False)
    z = z[z.res == 1].copy()
    z["lab"] = z.label.str.replace(r"^(delayonly_|simple_|none)", "", regex=True).str.replace("__res.*$", "", regex=True)
    pl = z[z.mode_planned == "resumed"]
    if len(pl):
        g = pl.groupby(["proto", "lab"]).agg(prevues=("resumed", "size"), reprises=("resumed", lambda s: int((s == 1).sum()))).reset_index()
        g["taux"] = (g.reprises / g.prevues).round(4); g["manquees"] = g.prevues - g.reprises
        print("Reprise EFFECTIVE (le client declare 'Resumed: 1') parmi les connexions PREVUES en reprise, par protocole et cellule :")
        print(g.to_string(index=False))
        tot = pl.groupby("proto").agg(prevues=("resumed", "size"), reprises=("resumed", lambda s: int((s == 1).sum())))
        tot["taux"] = (tot.reprises / tot.prevues).round(4)
        print("\nGlobal :"); print(tot.to_string())
        fl = z[z.mode_planned == "full"]
        print("\nConnexions 'completes' qui ont repris par erreur (attendu 0) :", int((fl.resumed == 1).sum()), "sur", len(fl))
        if (g.manquees > 0).any():
            print("Reprises manquees par bloc (dispersion) :"); print(pl[pl.resumed != 1].groupby("block").size().rename("n").to_string())
o = rd("p6_resume_octets.csv")
if o is not None:
    print("\nOctets recus (mediane) : complet vs repris (rapport < 0,25 TLS / < 0,30 QUIC attendu pour ML-DSA-65 + ML-KEM-768) :")
    print(o.round(3).to_string(index=False))
c = rd("p6_resume_contrastes.csv")
if c is not None:
    print("\nContrastes (IC95 % bootstrap sur les blocs) :")
    c = c.copy(); c["kem"] = kem_court(c.kem)
    c = c[c.metric == "app_ms"] if "metric" in c else c
    print(c.drop(columns=[k for k in ["metric"] if k in c]).round(2).to_string(index=False))

titre("2. COMPRESSION DE CERTIFICAT (TLS ; QUIC non evaluable : OpenSSL de MsQuic sans bibliotheques de compression)")
co = rd("p6_comp_octets.csv")
if co is not None:
    co = co.copy(); co["kem"] = kem_court(co.kem)
    print("Part de messages Certificate compresses (type 25) et taille, par groupe / signature / algorithme (TLS) :")
    t = co[co.proto == "tls"] if "proto" in co else co
    t = t.assign(c25=(t.cert_type == 25).astype(float))
    print(t.groupby(["groupe", "sig", "comp"]).agg(n=("n", "sum"), part_type25=("c25", "mean"), cert_comprime_o=("cert_comp", "median"),
                                                    cert_clair_o=("cert_plain", "median")).round(2).to_string())
cc = rd("p6_comp_contrastes.csv")
if cc is not None:
    cc = cc.copy(); cc["kem"] = kem_court(cc.kem)
    cc = cc[cc.proto == "tls"] if "proto" in cc else cc
    cc["val"] = cc.apply(lambda r: "%.1f%s" % (r.estimate, "*" if (r.lo > 0 or r.hi < 0) else ""), axis=1)
    w = cc.pivot_table(index=["groupe", "sig", "kem", "alg"], columns="quantite", values="val", aggfunc="first")
    print("\nEffet de la compression par rapport a 'none' (mediane inter-blocs ; * = IC95 % exclut 0) :")
    print("  gain octets recus ; dT app (ms) a RTT 0 et RTT 50 ; pente dT(RTT) = -delta k (ctl16000 attendu ~ -1, ML-DSA et ctl8700 ~ 0)")
    print(w.to_string())

titre("3. CHARGE CONCURRENTE (niveau 3, RTT 0, sans perte)")
lr = rd("p6_load_resume.csv")
if lr is None: print("Aucune donnee de charge (p6_load_resume.csv absent) : bras non lance ou non lu.")
else:
    lr = lr.copy(); lr["kem"] = kem_court(lr.kem)
    print("Courbe debit X (connexions/s) et latence par niveau de concurrence c (medianes inter-blocs ; util = CPU / coeur) :")
    cols = ["proto", "tls_server", "rtt", "sig", "kem", "conc", "X", "app_med", "util_srv", "util_cli", "fail", "S_ms", "n_blocs"]
    print(lr[[k for k in cols if k in lr]].round(3).to_string(index=False))
    sat = lr.sort_values("conc").groupby(["proto", "tls_server", "rtt", "sig", "kem"]).tail(1)
    print("\nNiveau maximal de concurrence (saturation) :")
    print(sat[[k for k in cols if k in sat]].round(3).to_string(index=False))
    print("\nLecture : si util_cli >= 0,85 au c maximal, le GENERATEUR sature avant le serveur (L0 FAIL) : ne pas interpreter ces niveaux.")
lm = rd("p6_load_modele.csv")
if lm is not None and len(lm):
    print("\nModele de file fermee X = c / (R + Z) : ecart observe/predit (%), a la saturation et a c = 1 :")
    lm = lm.copy(); lm["kem"] = kem_court(lm.kem)
    print(lm.groupby(["proto", "srv", "sig", "kem"]).agg(ecart_X_med=("X_err_pct", lambda s: s.abs().median()), ecart_R_med=("R_err_pct", lambda s: s.abs().median())).round(2).to_string())
lc = rd("p6_load_contrastes.csv")
if lc is not None and len(lc):
    print("\nContrastes de charge (IC95 % bootstrap sur les blocs) :")
    lc = lc.copy(); lc["kem"] = kem_court(lc.kem)
    print(lc.round(3).to_string(index=False))

titre("4. COUVERTURE DES DONNEES")
cx = os.path.join(D, "p6_connexions.csv.gz")
if os.path.exists(cx):
    z = pd.read_csv(cx, usecols=lambda c: c in {"proto", "label", "block", "app_ms"})
    print("Blocs lus et nombre de connexions par protocole :")
    print(z.groupby("proto").agg(connexions=("block", "size"), blocs=("block", "nunique"), bloc_min=("block", "min"), bloc_max=("block", "max")).to_string())
else:
    print("p6_connexions.csv.gz absent")
print("\nFin du rapport.")
