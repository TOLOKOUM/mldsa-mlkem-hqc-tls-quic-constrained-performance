#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""09_ressources.py -- PHASE 4 : cout en ressources (CPU, memoire, paquets) de ML-DSA, ML-KEM, HQC, TLS 1.3 et QUIC.

Donnees : colonnes cli_cpu_us / srv_cpu_us (CPU par poignee de main), cli_mem_b / srv_mem_b (pic memoire), cli_d_pkts / srv_d_pkts (paquets).
ATTENTION A L'UNITE : ces compteurs sont mesures par VISITE (25 connexions dans la famille main) puis recopies sur chaque
connexion (constants a l'interieur d'une visite pour 99,7 % des visites). L'unite reelle est donc la visite : on prend une valeur par
visite, les paquets sont divises par le nombre de connexions de la visite, puis on agrege par mediane de bloc ; l'inference se fait
entre les 20 blocs (jamais entre connexions).

Condition de reference : RTT 0, sans perte, famille 'main', hors exclusions dures, connexions reussies.
Contrastes apparies par bloc ; IC95 % bootstrap sur les blocs. Aucun test d'hypothese n'est annonce : ce sont des tailles d'effet.

Sorties : p4_res_kem_abs.csv, p4_res_sig_effect.csv, p4_res_kem_contrasts.csv, p4_res_report.txt
Usage : python3 tools/09_ressources.py --in analysis_v2 --out analysis_v2/phase4
"""
from __future__ import annotations
import argparse, importlib.util, os, sys, warnings
import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
REP: list[str] = []
B = 10000

METRICS = {"cli_cpu_ms": ("cli_cpu_us", 1e3), "srv_cpu_ms": ("srv_cpu_us", 1e3),
           "cli_mem_MiB": ("cli_mem_b", 1048576.0), "srv_mem_MiB": ("srv_mem_b", 1048576.0),
           "cli_pkts": ("cli_d_pkts", 1.0), "srv_pkts": ("srv_d_pkts", 1.0)}
CPU = ["cli_cpu_ms", "srv_cpu_ms"]
MEM = ["cli_mem_MiB", "srv_mem_MiB"]
PKT = ["cli_pkts", "srv_pkts"]


def log(msg=""):
    print(msg, flush=True)
    REP.append(str(msg))


def load_p4():
    spec = importlib.util.spec_from_file_location("p4_confirmatory", os.path.join(HERE, "04_confirmatory.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def boot(x, seed=3):
    x = np.asarray(x, float)
    x = x[np.isfinite(x)]
    n = len(x)
    if n < 2:
        return (float(x.mean()) if n else np.nan), np.nan, np.nan
    m = x[np.random.default_rng(seed).integers(0, n, (B, n))].mean(axis=1)
    lo, hi = np.quantile(m, [0.025, 0.975])
    return float(x.mean()), float(lo), float(hi)


def block_table(c):
    b = c[(c.family == "main") & (c.process == "none") & (c.fail == 0) & (~c.hard_excluded) & (c.rtt == 0) & (c.loss_nom == 0)].copy()
    for k, (src, div) in METRICS.items():
        b[k] = b[src] / div
    keys = ["proto", "auth", "level", "kem", "sig", "sig_class", "block"]
    # 1) une valeur par visite (les compteurs sont constants dans une visite), 2) mediane par bloc
    agg = {k: (k, "median") for k in METRICS}
    agg["n_conn"] = ("fail", "size")
    v = b.groupby(keys + ["visit_seq"]).agg(**agg).reset_index()
    for k in PKT:                       # compteur d'interface par visite -> paquets par connexion
        v[k] = v[k] / v["n_conn"]
    return v.groupby(keys)[list(METRICS)].median().reset_index()


def fmt(m, lo, hi, d=2):
    return ("%+." + str(d) + "f [%+." + str(d) + "f ; %+." + str(d) + "f]") % (m, lo, hi)


# ---------------------------------------------------------------------------------------------- valeurs absolues par KEM
def kem_abs(bt):
    s = bt[(bt.auth == "single") & (bt.sig_class == "classical")]
    rows = []
    for (proto, level, kem), g in s.groupby(["proto", "level", "kem"]):
        r = dict(proto=proto, level=level, kem=kem, n_blocks=g.block.nunique())
        for met in METRICS:
            m, lo, hi = boot(g[met].values, seed=5)
            r[met], r[met + "_lo"], r[met + "_hi"] = m, lo, hi
        rows.append(r)
    t = pd.DataFrame(rows)
    t.to_csv(os.path.join(OUT, "p4_res_kem_abs.csv"), index=False)
    return t


# ---------------------------------------------------------------------------------------------- effet de la signature
def sig_effect(bt):
    rows = []
    for (proto, auth, level), g in bt.groupby(["proto", "auth", "level"]):
        cl = g[g.sig_class == "classical"].set_index(["kem", "block"])
        ml = g[g.sig_class == "pqc"].set_index(["kem", "block"])
        for met in METRICS:
            diff = (ml[met] - cl[met]).dropna()
            per = diff.groupby(level="block").mean()
            ref = cl[met].groupby(level="block").mean().mean()
            m, lo, hi = boot(per.values, seed=7)
            rows.append(dict(proto=proto, auth=auth, level=level, metrique=met, effet=m, lo=lo, hi=hi, ref_classique=ref,
                             pct=100 * m / ref if ref else np.nan, n_blocks=len(per)))
    t = pd.DataFrame(rows)
    t.to_csv(os.path.join(OUT, "p4_res_sig_effect.csv"), index=False)
    return t


# ---------------------------------------------------------------------------------------------- contrastes entre KEM
def kem_contrast_list():
    L = {"L1": dict(ecdh=["x25519", "P-256"], ml="mlkem512", hq="hqc128", hyb_ml=["x25519_mlkem512", "p256_mlkem512"], hyb_hq=["x25519_hqc128", "p256_hqc128"]),
         "L3": dict(ecdh=["x448", "P-384"], ml="mlkem768", hq="hqc192", hyb_ml=["x448_mlkem768", "p384_mlkem768"], hyb_hq=["x448_hqc192", "p384_hqc192"]),
         "L5": dict(ecdh=["P-521"], ml="mlkem1024", hq="hqc256", hyb_ml=["p521_mlkem1024"], hyb_hq=["p521_hqc256"])}
    out = []
    for lv, d in L.items():
        for e in d["ecdh"]:
            out.append((lv, "ML-KEM pur - %s" % e, d["ml"], e))
        out.append((lv, "HQC pur - ML-KEM pur", d["hq"], d["ml"]))
        for h in d["hyb_ml"]:
            out.append((lv, "%s - ML-KEM pur" % h, h, d["ml"]))
        for h in d["hyb_hq"]:
            out.append((lv, "%s - HQC pur" % h, h, d["hq"]))
    return out


def kem_contrasts(bt):
    s = bt[(bt.auth == "single") & (bt.sig_class == "classical")]
    rows = []
    for proto in ("tls", "quic"):
        g = s[s.proto == proto].set_index(["level", "kem", "block"])
        for lv, name, a, b in kem_contrast_list():
            try:
                ga, gb = g.loc[(lv, a)], g.loc[(lv, b)]
            except KeyError:
                continue
            for met in METRICS:
                per = (ga[met] - gb[met]).dropna()
                m, lo, hi = boot(per.values, seed=9)
                ref = gb[met].mean()
                rows.append(dict(proto=proto, level=lv, contraste=name, metrique=met, effet=m, lo=lo, hi=hi, ref=ref, pct=100 * m / ref if ref else np.nan,
                                 n_blocks=len(per)))
    t = pd.DataFrame(rows)
    t.to_csv(os.path.join(OUT, "p4_res_kem_contrasts.csv"), index=False)
    return t


def report(kabs, sg, kc):
    log("\n=== A. COUT CPU PAR POIGNEE DE MAIN, SIGNATURE CLASSIQUE, RTT 0 (mediane de blocs ; ms) ===")
    log("  %-5s %-3s %-16s %12s %12s" % ("proto", "niv", "KEM", "CPU client", "CPU serveur"))
    for _, r in kabs.sort_values(["proto", "level", "kem"]).iterrows():
        log("  %-5s %-3s %-16s %12.1f %12.1f" % (r.proto, r.level, r.kem, r.cli_cpu_ms, r.srv_cpu_ms))
    log("\n=== B. EFFET DE LA SIGNATURE (ML-DSA - classique), moyenne des KEM, IC95 % entre blocs ===")
    for proto in ("tls", "quic"):
        for auth in ("single", "mutual"):
            s = sg[(sg.proto == proto) & (sg.auth == auth)]
            if s.empty:
                continue
            log("  [%s, auth %s]" % (proto.upper(), auth))
            for lv in ("L1", "L3", "L5"):
                x = s[s.level == lv].set_index("metrique")
                log("   %s : CPU client %s ms | CPU serveur %s ms | paquets serveur/connexion %s | memoire client %s MiB"
                    % (lv, fmt(x.loc["cli_cpu_ms", "effet"], x.loc["cli_cpu_ms", "lo"], x.loc["cli_cpu_ms", "hi"], 1),
                       fmt(x.loc["srv_cpu_ms", "effet"], x.loc["srv_cpu_ms", "lo"], x.loc["srv_cpu_ms", "hi"], 1),
                       fmt(x.loc["srv_pkts", "effet"], x.loc["srv_pkts", "lo"], x.loc["srv_pkts", "hi"], 0),
                       fmt(x.loc["cli_mem_MiB", "effet"], x.loc["cli_mem_MiB", "lo"], x.loc["cli_mem_MiB", "hi"], 2)))
    log("\n=== C. CONTRASTES ENTRE KEM (signature classique, auth simple, RTT 0) : CPU et memoire ===")
    for proto in ("tls", "quic"):
        log("  [%s]" % proto.upper())
        s = kc[kc.proto == proto]
        for lv in ("L1", "L3", "L5"):
            for name in s[s.level == lv].contraste.drop_duplicates():
                x = s[(s.level == lv) & (s.contraste == name)].set_index("metrique")
                log("   %s %-34s CPU cli %s (%+.0f %%) | CPU srv %s (%+.0f %%) | mem cli %s MiB"
                    % (lv, name, fmt(x.loc["cli_cpu_ms", "effet"], x.loc["cli_cpu_ms", "lo"], x.loc["cli_cpu_ms", "hi"], 1), x.loc["cli_cpu_ms", "pct"],
                       fmt(x.loc["srv_cpu_ms", "effet"], x.loc["srv_cpu_ms", "lo"], x.loc["srv_cpu_ms", "hi"], 1), x.loc["srv_cpu_ms", "pct"],
                       fmt(x.loc["cli_mem_MiB", "effet"], x.loc["cli_mem_MiB", "lo"], x.loc["cli_mem_MiB", "hi"], 2)))
    # rapports HQC / ML-KEM
    log("\n=== D. RAPPORT DE CPU HQC / ML-KEM (memes niveaux, signature classique) ===")
    for proto in ("tls", "quic"):
        for lv, hq, ml in (("L1", "hqc128", "mlkem512"), ("L3", "hqc192", "mlkem768"), ("L5", "hqc256", "mlkem1024")):
            a = kabs[(kabs.proto == proto) & (kabs.level == lv)].set_index("kem")
            if hq in a.index and ml in a.index:
                log("   %s %s %-7s / %-9s : client x%.2f, serveur x%.2f" % (proto.upper(), lv, hq, ml, a.loc[hq, "cli_cpu_ms"] / a.loc[ml, "cli_cpu_ms"],
                                                                         a.loc[hq, "srv_cpu_ms"] / a.loc[ml, "srv_cpu_ms"]))
    log("\n  Memoire : resolution = pages de 4 Kio ; ecarts-types intra-bloc de l'ordre de 0,25 a 0,4 Mio. Les ecarts hybride - KEM pur (jusqu'a ~0,5 Mio)")
    log("  sont probablement un effet de chargement de bibliotheques/fournisseur, pas un cout intrinseque de l'algorithme : a ne pas interpreter sans mesure dediee.")


def main():
    global OUT
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="indir", default="analysis_v2")
    ap.add_argument("--out", default="analysis_v2/phase4")
    a = ap.parse_args()
    OUT = a.out
    os.makedirs(OUT, exist_ok=True)
    p4 = load_p4()
    c = p4.load(a.indir)
    bt = block_table(c)
    log("PHASE 4 -- ressources. %d cellules-blocs (proto x auth x niveau x KEM x signature x bloc), unite d'inference = bloc." % len(bt))
    kabs = kem_abs(bt)
    sg = sig_effect(bt)
    kc = kem_contrasts(bt)
    report(kabs, sg, kc)
    with open(os.path.join(OUT, "p4_res_report.txt"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(REP))
    log("\nTermine -> %s" % OUT)


OUT = "."
if __name__ == "__main__":
    main()
