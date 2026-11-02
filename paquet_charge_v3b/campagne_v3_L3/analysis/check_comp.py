#!/usr/bin/env python3
"""check_comp.py <racine_captures_comp> -- la compression de certificat est-elle EFFECTIVE ? (lecture seule)
Preuves : (1) part de messages Certificate de type 25 (RFC 8879) par cellule ; (2) taille du message compresse vs en clair ;
(3) octets recus et temps app-ready : bras compresse - bras 'none', pour les memes cellules.
Attendu (TLS) : 'none' -> 0 % de type 25 ; temoins ECDSA remplis (ctl8700, ctl16000) -> ~100 % ; chaines ML-DSA -> 0 % (incompressibles).
QUIC : aucune cellule de compression (OpenSSL de MsQuic compile sans zlib/brotli/zstd), ce qui est une limite declaree.
Usage : python3 analysis/check_comp.py captures_v3_comp"""
import importlib.util, os, sys
import numpy as np, pandas as pd
here = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("an13", os.path.join(here, "13_analyse_extensions.py"))
an = importlib.util.module_from_spec(spec); spec.loader.exec_module(an)
root = sys.argv[1] if len(sys.argv) > 1 else "captures_v3_comp"
cdf, _ = an.walk(root)
pd.set_option("display.width", 230); pd.set_option("display.max_rows", 400)
if cdf.empty: print("aucune donnee"); sys.exit(1)
d = cdf[(cdf.comp != "") & cdf.app_ms.notna() & (cdf.mode_planned != "warmup")].copy()
if d.empty: print("aucune cellule de compression lue"); sys.exit(1)
d["groupe"] = np.where(d["pad"] > 0, "ctl" + d["pad"].astype(int).astype(str), "chain" + d.chain.astype(int).astype(str))
d["kem"] = d.kem.str.replace("x448_mlkem768", "mlkem768")
d["c25"] = (d.cert_type == 25).astype(float)
print("Connexions lues :", len(d), "| blocs :", sorted(int(b) for b in d.block.unique()), "| protocoles :", sorted(d.proto.unique()))
print("Cellules QUIC de compression :", int((d.proto == "quic").sum()), "(attendu 0 : non evaluable avec cette pile)")
d = d[d.proto == "tls"]
print("\n=== 1-2. Part de Certificate compresses (type 25) et tailles, par groupe / signature / algorithme ===")
a = d.groupby(["groupe", "sig", "comp"]).agg(n=("c25", "size"), part_type25=("c25", "mean"), cert_comprime_o=("cert_comp", "median"), cert_clair_o=("cert_plain", "median")).reset_index()
a["part_type25"] = a.part_type25.round(3)
print(a.to_string(index=False))
none25 = float(d[d.comp == "none"].c25.mean()); ctl = d[(d.groupe.str.startswith("ctl")) & d.comp.isin(["zlib", "brotli", "zstd"])]
print("\nManipulation : 'none' -> %.1f %% de type 25 (attendu 0) ; temoins ECDSA remplis compresses -> %.1f %% (attendu >= 98)" % (100 * none25, 100 * float(ctl.c25.mean()) if len(ctl) else float("nan")))
ml = d[(d.sig == "mldsa65") & d.comp.isin(["zlib", "brotli", "zstd"])]
print("ML-DSA-65 compresse malgre tout : %.1f %% (attendu ~0 : donnees quasi aleatoires)" % (100 * float(ml.c25.mean()) if len(ml) else float("nan")))
print("\n=== 3. Effet par rapport au bras 'none' (memes groupe / signature / KEM / RTT ; medianes) ===")
m = d.groupby(["groupe", "sig", "kem", "rtt", "comp"]).agg(rx=("rx", "median"), app=("app_ms", "median")).reset_index()
base = m[m.comp == "none"].rename(columns={"rx": "rx0", "app": "app0"}).drop(columns="comp")
x = m[m.comp != "none"].merge(base, on=["groupe", "sig", "kem", "rtt"])
x["gain_octets"] = (x.rx0 - x.rx).round(0); x["dApp_ms"] = (x.app - x.app0).round(1)
print(x[["groupe", "sig", "kem", "rtt", "comp", "rx0", "rx", "gain_octets", "app0", "app", "dApp_ms"]].round(1).to_string(index=False))
print("\nLecture attendue (TLS, ML-KEM-768) : ctl16000 -> gain ~14-15 ko et dApp ~ -RTT (k : 1 -> 0) ; ctl8700 -> gain ~8 ko mais dApp ~ 0 (vol deja < IW10) ;"
      "\nchaines ML-DSA -> gain ~0 et dApp ~ 0 (la compression ne resout pas la penalite ML-DSA). Les medianes d'un ou deux blocs sont indicatives.")
