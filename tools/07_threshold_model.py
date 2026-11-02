#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""07_threshold_model.py -- PHASE 3 : modele de seuil du vol serveur, teste sur les 21 paires (hors echantillon).

Question : le cout de ML-DSA est-il, comme le montre le vol reconstitue des pcap (x448_mlkem768, RTT 50), un nombre ENTIER
d'allers-retours supplementaires, determine par l'octet-comptage du vol serveur face a la limite du transport ?
  * TLS/TCP : fenetre de congestion initiale = 10 segments (MSS 1448), doublement par aller-retour (slow start).
  * QUIC    : limite d'anti-amplification = 3 x octets de l'Initial client (RFC 9000 s.8.1) puis fenetre initiale.
Le modele n'a AUCUN parametre ajuste sur les temps : constantes fixees a partir (i) des tailles normalisees (KEM, signatures),
(ii) des tailles de chaines du manifeste, (iii) du calage sur les pcap x448_mlkem768 (octets de vol 10215 TLS, 8804+1790 QUIC).

Sorties (--out) : p3_k_pred_vs_obs.csv, p3_model_variants.csv, p3_quic_sensitivity.csv, p3_tau_lossless.csv,
                  p3_packets_validation.csv, p3_mutual_cpu.csv, p3_hqc_compute.csv, p3_report.txt, fig6_*.png/pdf, fig7_*.png/pdf

HONNETETE SUR LE PROCESSUS : le modele « octets seuls » a ete ecrit AVANT de regarder k observe ; la variante « deux ecritures »
(ServerHello ecrit a part, puis le reste) a ete ajoutee APRES avoir vu que L5 + ML-KEM-1024 franchit le seuil TLS. Les deux sont
rapportees cote a cote (p3_model_variants.csv). Rien n'est ajuste sur les k observes.

Usage : python3 tools/07_threshold_model.py --in analysis_v2 --out analysis_v2/phase3 [--manifest analysis_v2/manifests.csv]
"""
from __future__ import annotations
import argparse, importlib.util, math, os, sys, warnings
import numpy as np
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
warnings.filterwarnings("ignore")

# ---------------------------------------------------------------------------------------------- constantes du modele
# (octets du partage de cle client, octets du partage de cle serveur) ; hybrides = concatenation.
KEM_SHARE = {"P-256": (65, 65), "P-384": (97, 97), "P-521": (133, 133), "x25519": (32, 32), "x448": (56, 56),
             "mlkem512": (800, 768), "mlkem768": (1184, 1088), "mlkem1024": (1568, 1568),
             "hqc128": (2249, 4497), "hqc192": (4522, 9042), "hqc256": (7245, 14469)}      # HQC : tailles round 4 (+-1,5 % vs spec 2025)
ALIAS = {"p256": "P-256", "p384": "P-384", "p521": "P-521"}
SIG_BYTES = {"ed25519": 64, "secp384r1": 103, "secp521r1": 138, "mldsa44": 2420, "mldsa65": 3309, "mldsa87": 4627}
CHAIN_DEFAULT = {"ed25519": 304, "secp384r1": 430, "secp521r1": 504, "mldsa44": 3965, "mldsa65": 5494, "mldsa87": 7452}
CLASSICAL_OF = {"L1": "ed25519", "L3": "secp384r1", "L5": "secp521r1"}
MLDSA_OF = {"L1": "mldsa44", "L3": "mldsa65", "L5": "mldsa87"}
# Calage sur pcap x448_mlkem768 : 1945 (classique) et 10215 (ML-DSA-65) octets de vol TLS = 267 + part_serveur(1144) + chaine + signature.
SH_FIX = 100                 # ServerHello hors partage de cle (octets)
A_TLS = 267                  # constante du vol TLS (ServerHello fixe + EE + en-tetes + Finished), calee sur pcap
RHO_QUIC = 1.037             # surcout QUIC (en-tetes, tag AEAD) : 10594 / 10215 sur pcap
TCP_MSS, TCP_IW = 1448, 10
QUIC_DGRAM = 1252            # charge UDP d'un datagramme client (MTU initial 1280)
QUIC_IW = 12520              # RFC 9002 : min(10 x 1252, max(14720, 2 x 1252))
CH_BASE, CH_CAP = 300, 1200  # ClientHello hors partage de cle ; octets utiles par datagramme Initial
B_BOOT = 10000


def log(msg=""):
    print(msg, flush=True)
    REP.append(str(msg))


REP: list[str] = []


def load_p4():
    spec = importlib.util.spec_from_file_location("p4_confirmatory", os.path.join(HERE, "04_confirmatory.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------------------------- modele d'octets
def kem_shares(kem: str):
    cs = ss = 0
    for t in kem.split("_"):
        t = ALIAS.get(t.lower(), ALIAS.get(t, t))
        if t not in KEM_SHARE:
            t = {"p-256": "P-256", "p-384": "P-384", "p-521": "P-521"}.get(t.lower(), t)
        a, b = KEM_SHARE[t]
        cs += a
        ss += b
    return cs, ss


def rounds_needed(units, first_cap, growth_unit):
    """Nombre d'aller-retours pour emettre `units` : capacite cumulee cap_r = first_cap + growth_unit*(2**r - 2) (slow start)."""
    r, cap = 1, first_cap
    while units > cap and r < 12:
        r += 1
        cap = first_cap + growth_unit * (2 ** r - 2)
    return r


def tls_rounds(kem, sig, chain, variant="writes"):
    _, ss = kem_shares(kem)
    sh = ss + SH_FIX
    rest = (A_TLS - SH_FIX) + chain[sig] + SIG_BYTES[sig]
    if variant == "bytes":
        segs = math.ceil((sh + rest) / TCP_MSS)
    else:  # ServerHello ecrit a part (un tampon), puis le reste de l'ecriture chiffree
        segs = math.ceil(sh / TCP_MSS) + math.ceil(rest / TCP_MSS)
    return rounds_needed(segs, TCP_IW, TCP_IW), segs, sh + rest


def quic_rounds(kem, sig, chain, ch_base=CH_BASE, ch_cap=CH_CAP):
    cs, ss = kem_shares(kem)
    n_dg = math.ceil((ch_base + cs) / ch_cap)
    c_bytes = n_dg * QUIC_DGRAM
    b1 = min(3 * c_bytes, QUIC_IW)
    s = RHO_QUIC * (SH_FIX + ss + (A_TLS - SH_FIX) + chain[sig] + SIG_BYTES[sig])
    return rounds_needed(s, b1, QUIC_IW), s, b1, c_bytes


def chain_sizes(manifest_path):
    ch = dict(CHAIN_DEFAULT)
    if manifest_path and os.path.exists(manifest_path):
        try:
            m = pd.read_csv(manifest_path, low_memory=False)
            need = ["sig", "chain_depth", "cert_pad_bytes", "pad_bytes", "pad_target_der", "server_chain_sent"]
            miss = [k for k in need if k not in m.columns]
            if miss:
                log("  (manifeste sans les colonnes %s -> tailles de chaine par defaut = valeurs des manifestes de reference ; relancer 01_ingest.py si besoin)" % miss)
                return ch
            m = m[(m.chain_depth == 1) & (m.cert_pad_bytes == 0) & (m.pad_bytes == 0) & (m.pad_target_der == 0)]
            for sg, v in m.groupby("sig")["server_chain_sent"].median().items():
                if sg in ch and np.isfinite(v):
                    ch[sg] = int(round(v))
        except Exception as e:  # le manifeste est facultatif
            log("  (manifeste illisible, tailles par defaut) : %s" % e)
    return ch


# ---------------------------------------------------------------------------------------------- statistiques
def boot_mean(x, B=B_BOOT, seed=7):
    x = np.asarray(x, float)
    x = x[np.isfinite(x)]
    n = len(x)
    if n < 2:
        return (float(x.mean()) if n else np.nan), np.nan, np.nan
    idx = np.random.default_rng(seed).integers(0, n, (B, n))
    m = x[idx].mean(axis=1)
    lo, hi = np.quantile(m, [0.025, 0.975])
    return float(x.mean()), float(lo), float(hi)


def per_block(d, col, stat):
    keys = ["proto", "auth", "family", "level", "kem", "sig", "sig_class", "rtt", "block"]
    g = d.groupby(keys)[col]
    t = (g.mean() if stat == "mean" else g.median()).rename("m").reset_index()
    t["rtt"] = t.rtt.round(2)
    return t


def contrast(t):
    cl = t[t.sig_class == "classical"].rename(columns={"m": "m_cl"}).drop(columns=["sig", "sig_class"])
    ml = t[t.sig_class == "pqc"].rename(columns={"m": "m_ml"}).drop(columns=["sig", "sig_class"])
    k = ["proto", "auth", "family", "level", "kem", "rtt", "block"]
    e = cl.merge(ml, on=k, how="inner")
    e["D"] = e.m_ml - e.m_cl
    return e


def observed_k_main(d, col, stat):
    """Pour chaque (proto, auth, niveau, KEM) : k = [D(rtt) - D(0)] / rtt, par bloc, aux deux profils avec perte."""
    e = contrast(per_block(d[d.family == "main"], col, stat))
    p = e.pivot_table(index=["proto", "auth", "level", "kem", "block"], columns="rtt", values="D").reset_index()
    rtts = sorted(c for c in p.columns if isinstance(c, (int, float, np.floating)) and c > 0)
    rows = []
    for (proto, auth, level, kem), g in p.groupby(["proto", "auth", "level", "kem"]):
        r = dict(proto=proto, auth=auth, level=level, kem=kem, D0=float(g[0.0].mean()))
        ks = []
        for i, rt in enumerate(rtts):
            kb = ((g[rt] - g[0.0]) / rt).values
            m, lo, hi = boot_mean(kb, seed=11 + i)
            r["k%d" % round(rt)] = m
            r["k%d_lo" % round(rt)] = lo
            r["k%d_hi" % round(rt)] = hi
            ks.append(kb)
        m, lo, hi = boot_mean(np.mean(ks, axis=0), seed=21)
        r["k_pool"], r["k_pool_lo"], r["k_pool_hi"] = m, lo, hi
        rows.append(r)
    return pd.DataFrame(rows), rtts


# ---------------------------------------------------------------------------------------------- 1. prediction vs observation
def label_match(kp, ks):
    dev = max(abs(k - kp) for k in ks)
    return "conforme" if dev <= 0.25 else ("partiel" if dev <= 0.75 else "infirme")


def predict_table(chain, variant, ch_base=CH_BASE, ch_cap=CH_CAP):
    rows = []
    for lv in ("L1", "L3", "L5"):
        for proto in ("quic", "tls"):
            cl, ml = CLASSICAL_OF[lv], MLDSA_OF[lv]
            kems = KEMS[lv]
            for kem in kems:
                if proto == "tls":
                    rc, sc, bc = tls_rounds(kem, cl, chain, variant)
                    rm, sm, bm = tls_rounds(kem, ml, chain, variant)
                    rows.append(dict(proto=proto, level=lv, kem=kem, R_cl=rc, R_ml=rm, k_pred=rm - rc,
                                     units_cl=sc, units_ml=sm, bytes_cl=bc, bytes_ml=bm, first_cap=TCP_IW, client_bytes=np.nan))
                else:
                    rc, sc, b1, cb = quic_rounds(kem, cl, chain, ch_base, ch_cap)
                    rm, sm, _, _ = quic_rounds(kem, ml, chain, ch_base, ch_cap)
                    rows.append(dict(proto=proto, level=lv, kem=kem, R_cl=rc, R_ml=rm, k_pred=rm - rc,
                                     units_cl=sc, units_ml=sm, bytes_cl=sc, bytes_ml=sm, first_cap=b1, client_bytes=cb))
    return pd.DataFrame(rows)


KEMS = {"L1": ["P-256", "x25519", "p256_mlkem512", "x25519_mlkem512", "mlkem512", "hqc128", "p256_hqc128", "x25519_hqc128"],
        "L3": ["P-384", "x448", "p384_mlkem768", "x448_mlkem768", "mlkem768", "hqc192", "p384_hqc192", "x448_hqc192"],
        "L5": ["P-521", "p521_mlkem1024", "mlkem1024", "hqc256", "p521_hqc256"]}


def compare(d, chain, tau=None):
    log("\n=== 2. PREDICTION (octets seuls, constantes fixees) CONTRE OBSERVATION : nombre d'allers-retours supplementaires k ===")
    obs_app, rtts = observed_k_main(d, "app_ms", "mean")
    obs_hs, _ = observed_k_main(d, "hs_ms", "mean")
    obs_med, _ = observed_k_main(d, "app_ms", "median")
    keep = ["proto", "auth", "level", "kem", "k_pool"] + ["k%d" % round(r) for r in rtts]
    o = obs_app.merge(obs_hs[keep].add_suffix("_hs").rename(columns={"proto_hs": "proto", "auth_hs": "auth", "level_hs": "level", "kem_hs": "kem"}),
                      on=["proto", "auth", "level", "kem"], how="left")
    o = o.merge(obs_med[keep].add_suffix("_med").rename(columns={"proto_med": "proto", "auth_med": "auth", "level_med": "level", "kem_med": "kem"}),
                on=["proto", "auth", "level", "kem"], how="left")
    o = o[o.auth == "single"]
    variants = {}
    for vname in ("bytes", "writes"):
        p = predict_table(chain, vname)
        t = o.merge(p, on=["proto", "level", "kem"], how="left")
        ks = ["k%d" % round(r) for r in rtts]
        t["verdict"] = [label_match(kp, [r[k] for k in ks]) for kp, (_, r) in zip(t.k_pred, t.iterrows())]
        variants[vname] = t
    best = variants["writes"].copy()
    ksm = ["k%d_med" % round(r) for r in rtts]
    best["verdict_median"] = [label_match(kp, [r[k] for k in ksm]) for kp, (_, r) in zip(best.k_pred, best.iterrows())]
    best["verdict_bytes_only"] = variants["bytes"].verdict.values
    best["k_pred_bytes_only"] = variants["bytes"].k_pred.values
    best["evidence"] = np.where(best.proto == "tls", "SECONDAIRE_tls_perte_groupee", "ROBUSTE")
    best["family"] = np.where(best.kem.str.contains("hqc"), "hqc", "autre")
    for i, rt in enumerate(rtts):
        best["k_pred_tau%d" % round(rt)] = np.nan
    if tau is not None:
        for proto in ("quic", "tls"):
            t = tau[(tau.proto == proto) & (tau.kem == "hqc192")]
            if len(t) and t.slope.iloc[0] > 0.4:
                msk = (best.proto == proto) & best.kem.str.contains("hqc192")
                for rt in rtts:
                    best.loc[msk, "k_pred_tau%d" % round(rt)] = 1.0 - float(t.tau_ms.iloc[0]) / rt
    best.to_csv(os.path.join(OUT, "p3_k_pred_vs_obs.csv"), index=False)

    rows = []
    for vname, t in variants.items():
        for proto in ("quic", "tls"):
            s = t[t.proto == proto]
            for fam, ss in (("tous", s), ("hors_HQC", s[~s.kem.str.contains("hqc")]), ("HQC", s[s.kem.str.contains("hqc")])):
                rows.append(dict(variante=vname, proto=proto, famille=fam, n=len(ss), conforme=int((ss.verdict == "conforme").sum()),
                                 partiel=int((ss.verdict == "partiel").sum()), infirme=int((ss.verdict == "infirme").sum())))
    pd.DataFrame(rows).to_csv(os.path.join(OUT, "p3_model_variants.csv"), index=False)
    for vname in ("bytes", "writes"):
        log("-- variante '%s' (profils moderate=%.0f ms, degraded=%.0f ms) --" % (vname, rtts[0], rtts[1]))
        for proto in ("quic", "tls"):
            s = variants[vname]
            s = s[s.proto == proto]
            h = s[~s.kem.str.contains("hqc")]
            log("   %s : hors HQC %d/%d conformes ; HQC %d conformes, %d partiels, %d infirmes (sur %d)"
                % (proto.upper(), (h.verdict == "conforme").sum(), len(h), (s[s.kem.str.contains("hqc")].verdict == "conforme").sum(),
                   (s[s.kem.str.contains("hqc")].verdict == "partiel").sum(), (s[s.kem.str.contains("hqc")].verdict == "infirme").sum(),
                   s.kem.str.contains("hqc").sum()))
    for proto in ("quic", "tls"):
        s = best[best.proto == proto].sort_values(["level", "kem"])
        log("\n   [%s] paire (niveau KEM) : k_pred | k_obs(app) @%.0f / @%.0f | k_hs | verdict" % (proto.upper(), rtts[0], rtts[1]))
        for _, r in s.iterrows():
            log("   %s %-16s pred=%d | %.2f [%.2f;%.2f] / %.2f [%.2f;%.2f] | hs %.2f / %.2f | %s%s"
                % (r.level, r.kem, r.k_pred, r["k%d" % round(rtts[0])], r["k%d_lo" % round(rtts[0])], r["k%d_hi" % round(rtts[0])],
                   r["k%d" % round(rtts[1])], r["k%d_lo" % round(rtts[1])], r["k%d_hi" % round(rtts[1])],
                   r["k%d_hs" % round(rtts[0])], r["k%d_hs" % round(rtts[1])], r.verdict,
                   "" if r.verdict == r.verdict_bytes_only else "  (octets seuls : %s)" % r.verdict_bytes_only))
    log("\n   Estimateur MEDIAN par bloc (robuste a l'exposition aux pertes, k = nombre d'aller-retours de la connexion typique) :")
    for proto in ("quic", "tls"):
        s = best[best.proto == proto]
        log("   %s : conformes %d, partiels %d, infirmes %d (sur %d) ; hors HQC conformes %d/%d"
            % (proto.upper(), (s.verdict_median == "conforme").sum(), (s.verdict_median == "partiel").sum(), (s.verdict_median == "infirme").sum(),
               len(s), (s[~s.kem.str.contains("hqc")].verdict_median == "conforme").sum(), (~s.kem.str.contains("hqc")).sum()))
        for _, r in s[s.kem.str.contains("hqc256")].iterrows():
            log("      %s %s : k median = %.2f / %.2f (pred %d)" % (r.level, r.kem, r["k%d_med" % round(rtts[0])], r["k%d_med" % round(rtts[1])], r.k_pred))
    if tau is not None:
        log("\n   HQC-192 : k predit par tau mesure SANS perte (k = 1 - tau/RTT), confronte aux profils avec perte :")
        for _, r in best[best.kem.str.contains("hqc192")].sort_values(["proto", "kem"]).iterrows():
            if np.isfinite(r["k_pred_tau%d" % round(rtts[0])]):
                log("      %s %-12s predit %.2f / %.2f | observe %.2f [%.2f;%.2f] / %.2f [%.2f;%.2f]"
                    % (r.proto.upper(), r.kem, r["k_pred_tau%d" % round(rtts[0])], r["k_pred_tau%d" % round(rtts[1])],
                       r["k%d" % round(rtts[0])], r["k%d_lo" % round(rtts[0])], r["k%d_hi" % round(rtts[0])],
                       r["k%d" % round(rtts[1])], r["k%d_lo" % round(rtts[1])], r["k%d_hi" % round(rtts[1])]))
    dev = (best["k_pool"] - best["k_pool_hs"]).abs().max()
    log("\n   Ecart max |k(app_ms) - k(hs_ms)| sur toutes les paires : %.3f (la penalite est entierement dans le handshake)" % dev)
    return best, rtts


# ---------------------------------------------------------------------------------------------- 2. sensibilite des constantes QUIC
def quic_sensitivity(best, chain):
    log("\n=== 3. SENSIBILITE : les verdicts QUIC dependent-ils des constantes (ClientHello de base, octets utiles par datagramme) ? ===")
    q = best[(best.proto == "quic") & (best.auth == "single")]
    rows = []
    for cb in (200, 300, 400, 500):
        for cc in (1000, 1100, 1200, 1300):
            p = predict_table(chain, "writes", cb, cc)
            p = p[p.proto == "quic"][["level", "kem", "k_pred"]].rename(columns={"k_pred": "kp"})
            t = q.merge(p, on=["level", "kem"])
            ks = [c for c in q.columns if c.startswith("k") and c[1:].isdigit()]
            v = [label_match(kp, [r[k] for k in ks]) for kp, (_, r) in zip(t.kp, t.iterrows())]
            rows.append(dict(ch_base=cb, ch_cap=cc, conforme=v.count("conforme"), partiel=v.count("partiel"), infirme=v.count("infirme"), n=len(v)))
    s = pd.DataFrame(rows)
    s.to_csv(os.path.join(OUT, "p3_quic_sensitivity.csv"), index=False)
    log("   %d combinaisons de constantes : conformes entre %d et %d sur %d ; infirmes entre %d et %d"
        % (len(s), s.conforme.min(), s.conforme.max(), s.n.iloc[0], s.infirme.min(), s.infirme.max()))


# ---------------------------------------------------------------------------------------------- 3. tau sans perte
def tau_lossless(d):
    log("\n=== 1. CELLULES SANS PERTE (famille fx, ROBUSTE) : D(RTT) = a + b*RTT sur RTT in {50,100,150} ; tau = D(0) - a ===")
    f = d[(d.family == "fx") & (d.process == "none") & (d.loss_nom == 0)]
    if f.empty:
        log("   (aucune cellule fx sans perte)")
        return None
    e = contrast(per_block(f, "app_ms", "mean"))
    rows = []
    for (proto, kem), g in e.groupby(["proto", "kem"]):
        p = g.pivot_table(index="block", columns="rtt", values="D")
        rts = [r for r in p.columns if r > 0]
        if len(rts) < 3 or 0.0 not in p.columns:
            continue
        x = np.array(rts, float)
        sl, ic = [], []
        for _, r in p.iterrows():
            b, a = np.polyfit(x, r[rts].values.astype(float), 1)
            sl.append(b)
            ic.append(a)
        sl, ic = np.array(sl), np.array(ic)
        tau = p[0.0].values - ic
        ms, ls, hs = boot_mean(sl, seed=31)
        mt, lt, ht = boot_mean(tau, seed=32)
        rows.append(dict(proto=proto, kem=kem, slope=ms, slope_lo=ls, slope_hi=hs, tau_ms=mt, tau_lo=lt, tau_hi=ht,
                         D0=float(p[0.0].mean()), n_blocks=len(p)))
        log("   %s %-14s pente %.3f [%.3f;%.3f]   tau = %.1f [%.1f;%.1f] ms %s" % (proto.upper(), kem, ms, ls, hs, mt, lt, ht,
            "" if ms > 0.4 else "(pente ~0 : pas d'aller-retour supplementaire, tau sans objet)"))
    r = pd.DataFrame(rows)
    r.to_csv(os.path.join(OUT, "p3_tau_lossless.csv"), index=False)
    return r


# ---------------------------------------------------------------------------------------------- 4. validation par compteurs de paquets
def packets_validation(c, chain):
    log("\n=== 4. VALIDATION INDEPENDANTE DE L'OCTET-COMPTAGE : paquets serveur par visite (compteurs d'interface) contre octets du vol modelise ===")
    m = c[(c.family == "main") & (c.process == "none") & (c.auth == "single") & (c.fail == 0)]
    g = m.groupby(["proto", "sig", "kem"]).agg(srv=("srv_d_pkts", "median"), cli=("cli_d_pkts", "median")).reset_index()
    rows = []
    for proto in ("tls", "quic"):
        x = g[g.proto == proto].copy()
        x["S"] = [A_TLS + kem_shares(k)[1] + chain[s] + SIG_BYTES[s] for k, s in zip(x.kem, x.sig)]
        r = float(np.corrcoef(x.S, x.srv)[0, 1])
        b, a = np.polyfit(x.S, x.srv, 1)
        rows.append(dict(proto=proto, n_paires=len(x), r_pearson=r, pente_paquets_visite_par_octet=b, ordonnee=a))
        log("   %s : r = %.3f sur %d paires (compteurs agreges par tour de visite : valide la proportionnalite aux octets, "
            "ne resout pas +-1 segment)" % (proto.upper(), r, len(x)))
    pd.DataFrame(rows).to_csv(os.path.join(OUT, "p3_packets_validation.csv"), index=False)


# ---------------------------------------------------------------------------------------------- 5. TLS mutuelle : CPU client
def mutual_cpu(c):
    log("\n=== 5. TLS MUTUELLE A RTT 0 : d'ou vient le surcout de ML-DSA ? (CPU par connexion, difference-de-differences mutuelle - simple) ===")
    m = c[(c.family == "main") & (c.proto == "tls") & (c.rtt == 0) & (c.fail == 0) & (~c.hard_excluded)].copy()
    cols = {"app_ms": 1.0, "cli_cpu_us": 1000.0, "srv_cpu_us": 1000.0}
    rows = []
    for lv in ("L1", "L3", "L5"):
        for kem in KEMS[lv]:
            pass
    # un KEM de reference par niveau suffit, mais on les utilise tous (blocs communs) puis on resume par niveau
    g = m.groupby(["auth", "level", "kem", "sig", "sig_class", "block"])[list(cols)].median().reset_index()
    for k, dv in cols.items():
        g[k] = g[k] / dv
    out = {}
    for lv in ("L1", "L3", "L5"):
        s = g[g.level == lv]
        for met in cols:
            per = []
            for au in ("single", "mutual"):
                a = s[s.auth == au]
                ml = a[a.sig_class == "pqc"].groupby("block")[met].mean()
                cl = a[a.sig_class == "classical"].groupby("block")[met].mean()
                per.append((ml - cl).rename(au))
            dd = pd.concat(per, axis=1).dropna()
            did = dd["mutual"] - dd["single"]
            mu, lo, hi = boot_mean(did.values, seed=41)
            rows.append(dict(level=lv, metrique=met, D_single=float(dd.single.mean()), D_mutual=float(dd.mutual.mean()),
                             did=mu, did_lo=lo, did_hi=hi, n_blocks=len(dd)))
            out[(lv, met)] = (mu, lo, hi)
    r = pd.DataFrame(rows)
    r.to_csv(os.path.join(OUT, "p3_mutual_cpu.csv"), index=False)
    for lv in ("L1", "L3", "L5"):
        a, cc, ss = out[(lv, "app_ms")], out[(lv, "cli_cpu_us")], out[(lv, "srv_cpu_us")]
        log("   %s : surcout mutuel ML-DSA = +%.1f ms [%.1f;%.1f] ; dont CPU client +%.1f ms [%.1f;%.1f], CPU serveur %+.1f ms [%.1f;%.1f]"
            % (lv, a[0], a[1], a[2], cc[0], cc[1], cc[2], ss[0], ss[1], ss[2]))
    log("   Lecture : si le CPU client explique l'essentiel et que le CPU serveur est inchange, le cout n'est pas reseau mais un calcul cote client.")
    return r


# ---------------------------------------------------------------------------------------------- 6. HQC : calcul client contre tau
def hqc_compute(c, tau):
    log("\n=== 6. HQC : calcul client (RTT 0, signature classique) face a tau ===")
    m = c[(c.family == "main") & (c.rtt == 0) & (c.auth == "single") & (c.fail == 0) & (~c.hard_excluded) & (c.sig_class == "classical")].copy()
    m["cli_ms"] = m.cli_cpu_us / 1000.0
    m["srv_ms"] = m.srv_cpu_us / 1000.0
    g = m.groupby(["proto", "level", "kem"])[["cli_ms", "srv_ms", "hs_ms"]].median().reset_index()
    rows = []
    for proto in ("tls", "quic"):
        for lv, ref, hq in (("L1", "mlkem512", "hqc128"), ("L3", "mlkem768", "hqc192"), ("L5", "mlkem1024", "hqc256")):
            a = g[(g.proto == proto) & (g.level == lv)].set_index("kem")
            if ref in a.index and hq in a.index:
                r = dict(proto=proto, level=lv, kem=hq, d_cli_cpu_ms=a.loc[hq, "cli_ms"] - a.loc[ref, "cli_ms"],
                         d_srv_cpu_ms=a.loc[hq, "srv_ms"] - a.loc[ref, "srv_ms"], d_hs_ms=a.loc[hq, "hs_ms"] - a.loc[ref, "hs_ms"], tau_ms=np.nan)
                if tau is not None:
                    t = tau[(tau.proto == proto) & (tau.kem == "hqc192")]
                    if lv == "L3" and len(t) and t.slope.iloc[0] > 0.4:
                        r["tau_ms"] = float(t.tau_ms.iloc[0])
                rows.append(r)
    r = pd.DataFrame(rows)
    r.to_csv(os.path.join(OUT, "p3_hqc_compute.csv"), index=False)
    for _, x in r.iterrows():
        log("   %s %s %s : CPU client +%.1f ms, CPU serveur +%.1f ms, handshake +%.1f ms%s"
            % (x.proto.upper(), x.level, x.kem, x.d_cli_cpu_ms, x.d_srv_cpu_ms, x.d_hs_ms,
               "  | tau mesure (sans perte) = %.1f ms" % x.tau_ms if np.isfinite(x.tau_ms) else ""))
    log("   Hypothese a tester (non demontree) : tau = partie du calcul client (decapsulation HQC) qui recouvre l'aller-retour supplementaire.")
    return r


# ---------------------------------------------------------------------------------------------- figures
def figures(best, rtts, tau, fx_pts):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    col = {"hqc": "#CC79A7", "autre": "#0072B2"}
    fig, axes = plt.subplots(1, 2, figsize=(9.6, 5.6), sharey=False)
    for ax, proto, tl in zip(axes, ("quic", "tls"), ("QUIC", "TLS (preuve secondaire sous perte)")):
        s = best[best.proto == proto].sort_values(["level", "kem"]).reset_index(drop=True)
        y = np.arange(len(s))[::-1]
        for yi, (_, r) in zip(y, s.iterrows()):
            ax.plot([r.k_pool_lo, r.k_pool_hi], [yi, yi], color=col[r.family], lw=1.4)
            ax.plot(r.k_pool, yi, "o", color=col[r.family], ms=4.5)
            ax.plot(r.k_pred, yi, marker="|", color="k", ms=11, mew=1.8)
        ax.set_yticks(y)
        ax.set_yticklabels(["%s %s" % (a, b) for a, b in zip(s.level, s.kem)], fontsize=7)
        ax.axvline(0, color="k", lw=0.5)
        ax.axvline(1, color="k", lw=0.5, ls=":")
        ax.set_xlim(-0.25, 1.8)
        ax.set_xlabel("allers-retours supplementaires k (ML-DSA - classique)")
        ax.set_title(tl, fontsize=9.5)
        ax.grid(alpha=0.25)
    from matplotlib.lines import Line2D
    h = [Line2D([], [], marker="o", color=col["autre"], ls="", label="observé, hors HQC"),
         Line2D([], [], marker="o", color=col["hqc"], ls="", label="observé, HQC"),
         Line2D([], [], marker="|", color="k", ls="", ms=10, mew=1.8, label="prédit (octets, constantes fixées)")]
    fig.legend(handles=h, loc="lower center", ncol=3, frameon=False, fontsize=8, bbox_to_anchor=(0.5, -0.01))
    fig.tight_layout(rect=(0, 0.04, 1, 1))
    for ext in ("png", "pdf"):
        fig.savefig(os.path.join(OUT, "fig6_modele_seuil_k_predit_observe.%s" % ext), dpi=300 if ext == "png" else None, bbox_inches="tight")
    plt.close(fig)
    log("  figure: fig6_modele_seuil_k_predit_observe")
    if tau is not None and fx_pts is not None and len(fx_pts):
        fig, axes = plt.subplots(1, 2, figsize=(7.6, 3.0), sharey=True)
        for ax, proto in zip(axes, ("quic", "tls")):
            for kem, c0, mk in (("x448_mlkem768", "#0072B2", "o"), ("hqc192", "#CC79A7", "s")):
                s = fx_pts[(fx_pts.proto == proto) & (fx_pts.kem == kem)].sort_values("rtt")
                if len(s):
                    ax.errorbar(s.rtt, s["mean"], yerr=[s["mean"] - s.lo, s.hi - s["mean"]], color=c0, marker=mk, ms=4, capsize=2, lw=1.2,
                                label={"x448_mlkem768": "X448+ML-KEM-768", "hqc192": "HQC-192"}[kem])
            xs = np.linspace(0, 150, 20)
            ax.plot(xs, np.maximum(xs - 2.4, -2.4), ls="--", color="#666666", lw=0.9, label="k = 1, tau = 0")
            ax.axhline(0, color="k", lw=0.5)
            ax.set_title(proto.upper(), fontsize=9.5)
            ax.set_xlabel("RTT (ms)")
            ax.grid(alpha=0.25)
        axes[0].set_ylabel("effet ML-DSA − classique (ms)")
        axes[0].legend(frameon=False, fontsize=7.5)
        fig.tight_layout()
        for ext in ("png", "pdf"):
            fig.savefig(os.path.join(OUT, "fig7_tau_sans_perte.%s" % ext), dpi=300 if ext == "png" else None, bbox_inches="tight")
        plt.close(fig)
        log("  figure: fig7_tau_sans_perte")


def fx_points(d):
    f = d[(d.family == "fx") & (d.process == "none") & (d.loss_nom == 0)]
    if f.empty:
        return None
    e = contrast(per_block(f, "app_ms", "mean"))
    rows = []
    for (proto, kem, rtt), g in e.groupby(["proto", "kem", "rtt"]):
        m, lo, hi = boot_mean(g.D.values, seed=51)
        rows.append(dict(proto=proto, kem=kem, rtt=rtt, mean=m, lo=lo, hi=hi))
    return pd.DataFrame(rows)


def main():
    global OUT
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="indir", default="analysis_v2")
    ap.add_argument("--out", default="analysis_v2/phase3")
    ap.add_argument("--manifest", default=None, help="manifests.csv (defaut : <in>/manifests.csv)")
    ap.add_argument("--no-fig", action="store_true")
    a = ap.parse_args()
    OUT = a.out
    os.makedirs(OUT, exist_ok=True)
    p4 = load_p4()
    c = p4.load(a.indir)
    d, _ = p4.scenario(c, "primary")
    chain = chain_sizes(a.manifest or os.path.join(a.indir, "manifests.csv"))
    log("PHASE 3 -- modele de seuil. Tailles de chaine serveur utilisees (octets) : %s" % {k: chain[k] for k in sorted(chain)})
    log("Constantes : A_TLS=%d SH_FIX=%d RHO_QUIC=%.3f MSS=%d IW=%d | QUIC : dgram=%d IW=%d CH_BASE=%d CH_CAP=%d" %
        (A_TLS, SH_FIX, RHO_QUIC, TCP_MSS, TCP_IW, QUIC_DGRAM, QUIC_IW, CH_BASE, CH_CAP))
    tau = tau_lossless(d)
    best, rtts = compare(d, chain, tau)
    quic_sensitivity(best, chain)
    packets_validation(c, chain)
    mutual_cpu(c)
    hqc_compute(c, tau)
    if not a.no_fig:
        figures(best, rtts, tau, fx_points(d))
    with open(os.path.join(OUT, "p3_report.txt"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(REP))
    log("\nTermine -> %s" % OUT)


OUT = "."
if __name__ == "__main__":
    main()
