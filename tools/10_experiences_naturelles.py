#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""10_experiences_naturelles.py -- PHASE 5 : tests du modele de seuil sur des cellules DEJA mesurees, jamais utilisees pour le construire.

Aucune nouvelle experience. Le campagne contient, en plus du plan principal, des cellules qui deplacent les seuils du modele :
  chain  : chaine de certificats a 2 niveaux (ML-DSA-65 : 11 032 o au lieu de 5 494 ; ECDSA P-384 : ~904 o), RTT 50, KEM x448_mlkem768 et hqc192
  mech   : MTU 1500 contre 1280 (TCP : MSS 1448 -> 1228 ; QUIC : datagrammes 1472 -> 1252 et plafond 3 x Initial client)
  size   : ECDSA P-384 REMPLI a 8 700 o (meme volume qu'ML-DSA-65, sans calcul PQ)
  fx     : RTT 0/50/100/150 sans perte (cellule de reference, deja exploitee par 07)
Les constantes du modele (07) sont GELEES : on ne change que les parametres physiques de la cellule (tailles de chaine, MSS, taille de
datagramme, fenetre initiale QUIC). Les predictions sont calculees avant toute comparaison dans ce script (section 1, bloc "PREDICTIONS").
Transparence : l'auteur de ce script a vu les medianes brutes de ces cellules lors d'un inventaire des donnees, AVANT d'ecrire ce code ;
le modele, lui, n'a pas ete modifie apres.

Sections
  1. Cellules sans perte, RTT 50 : k observe (par bloc, IC95 % bootstrap sur les 20 blocs) contre k predit (variantes 'octets' et 'deux ecritures'),
     contre le modele trivial ; marge au seuil. Pour HQC-192 : recouvrement du calcul client (T, mesure sur fx) : k_apparent = 1 - T/RTT.
  2. Constance de T (HQC) entre RTT 50-150 sans perte (fx) et RTT 125 / 167 (profils main) ; comparaison au surcout CPU serveur de HQC.
  3. Reponse a la perte i.i.d. (1, 2, 5 %, RTT 50) : pente de la penalite ML-DSA (ms par % de perte), chaine simple contre chaine a 2 niveaux.
     QUIC = ROBUSTE ; TLS = SECONDAIRE (defaut GSO, pertes groupees).
  4. Verification par les vols reconstitues par 06 (--timeline) : plafond 3 x octets client QUIC a deux tailles de datagramme ; octets du 1er vol TLS.
  5. (facultatif, --root) tailles de segments du 1er vol serveur lues dans les pcap : le ServerHello est-il ecrit a part ?

Entrees : <in>/conn.csv.gz, <in>/visit_flags.csv, <in>/manifests.csv (via 04_confirmatory.load) ; modele importe de 07 ; 04 pour le chargement.
Sorties (dossier --out) : p5_natural_lossless.csv, p5_tau_profiles.csv, p5_loss_dose.csv, p5_timeline_check.csv, p5_segments.csv, p5_report.txt
Usage : python3 tools/10_experiences_naturelles.py --in analysis_v2 --out analysis_v2/phase5 \
            [--timeline analysis_v2/phase2/flight_timeline_summary.csv] [--phase4 analysis_v2/phase4] [--root captures_v2]
"""
from __future__ import annotations
import argparse, bisect, collections, csv, glob, importlib.util, math, os, re, sys, warnings
import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")
HERE = os.path.dirname(os.path.abspath(__file__))
REP: list[str] = []
B = 10000


def log(msg=""):
    print(msg, flush=True)
    REP.append(str(msg))


def load_mod(fname, name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, fname))
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


def verdict(kp, ko):
    dev = abs(ko - kp)
    return "conforme" if dev <= 0.25 else ("partiel" if dev <= 0.75 else "infirme")


def f2(m, lo, hi, d=2):
    return ("%." + str(d) + "f [%." + str(d) + "f ; %." + str(d) + "f]") % (m, lo, hi)


# ------------------------------------------------------------------------------------------------ selection des donnees
def series(d, col, stat, proto, kem, sig, rtt, family=None, label=None, process="none", loss=0.0):
    """Une valeur par bloc (mediane ou moyenne des connexions) pour une cellule precise."""
    m = (d.proto == proto) & (d.kem == kem) & (d.sig == sig) & ((d.rtt - rtt).abs() < 1.0) & (d.process == process) & ((d.loss_nom - loss).abs() < 1e-9)
    if family is not None:
        m &= d.family == family
    if label is not None:
        m &= d.label == label
    g = d[m].groupby("block")[col]
    return (g.median() if stat == "median" else g.mean())


def d_series(d, col, stat, proto, kem, test, ref, rtt):
    """D par bloc = test - ref. test/ref = dict(sig, family, label)."""
    a = series(d, col, stat, proto, kem, test["sig"], rtt, test.get("family"), test.get("label"))
    b = series(d, col, stat, proto, kem, ref["sig"], rtt, ref.get("family"), ref.get("label"))
    return (a - b).dropna()


# ------------------------------------------------------------------------------------------------ modele (constantes de 07 gelees)
PAR_DEFAULT = dict(mss=1448, dgram=1252, qiw=12520, chcap=1200)
PAR = {"mtu1500": PAR_DEFAULT,
       "mtu1280": dict(mss=1228, dgram=1252, qiw=12520, chcap=1200),                 # MSS = 1280 - 40 (IP+TCP) - 12 (options horodatage)
       "qmtu1500": dict(mss=1448, dgram=1472, qiw=14720, chcap=1420),                # RFC 9002 : min(10 x 1472, max(14720, 2 x 1472))
       "qmtu1280": dict(mss=1448, dgram=1252, qiw=12520, chcap=1200)}


def rounds(p3, proto, kem, sig, chain_bytes, par, variant):
    """-> (tours, octets du vol, plafond du 1er vol en octets). Les constantes physiques de la cellule sont posees puis restaurees."""
    saved = dict(TCP_MSS=p3.TCP_MSS, QUIC_DGRAM=p3.QUIC_DGRAM, QUIC_IW=p3.QUIC_IW)
    try:
        p3.TCP_MSS, p3.QUIC_DGRAM, p3.QUIC_IW = par["mss"], par["dgram"], par["qiw"]
        ch = {sig: chain_bytes}
        if proto == "tls":
            r, segs, nb = p3.tls_rounds(kem, sig, ch, variant)
            return r, nb, p3.TCP_MSS * p3.TCP_IW
        r, s, b1, cb = p3.quic_rounds(kem, sig, ch, p3.CH_BASE, par["chcap"])
        return r, s, b1
    finally:
        p3.TCP_MSS, p3.QUIC_DGRAM, p3.QUIC_IW = saved["TCP_MSS"], saved["QUIC_DGRAM"], saved["QUIC_IW"]


def tau_from_fx(d, proto, kem, col="app_ms", stat="median"):
    """T = RTT - (D(RTT) - D(0)) moyenne sur RTT in {50,100,150} ; une valeur par bloc (suppose k = 1, pente mesuree ~ 1)."""
    mlc, cl = "mldsa65", "secp384r1"
    D = {}
    for r in (0, 50, 100, 150):
        D[r] = (series(d, col, stat, proto, kem, mlc, r, "fx") - series(d, col, stat, proto, kem, cl, r, "fx")).dropna()
    t = pd.concat([(r - (D[r] - D[0])) for r in (50, 100, 150)], axis=1).mean(axis=1).dropna()
    return t


# ------------------------------------------------------------------------------------------------ 1. cellules sans perte
LAB = {  # (proto, condition) -> (label non rempli, label rempli)
    ("tls", "mtu1500"): ("delayonly_delay25ms__pcap__mb2", "delayonly_delay25ms__padto8700__pcap__mb2"),
    ("tls", "mtu1280"): ("delayonly_delay25ms_mtu1280__pcap__mb2", "delayonly_delay25ms_mtu1280__padto8700__pcap__mb2"),
    ("quic", "qmtu1500"): ("delayonly_delay25ms__qmtu__pcap__mb2", "delayonly_delay25ms__qmtu__padto8700__pcap__mb2"),
    ("quic", "qmtu1280"): ("delayonly_delay25ms_mtu1280__qmtu__pcap__mb2", "delayonly_delay25ms_mtu1280__qmtu__padto8700__pcap__mb2"),
}
CH2_LABEL = "delayonly_delay25ms__chain2__mb2"
KEM_T = "x448_mlkem768"


def experiments(chain):
    """Liste des experiences naturelles. kind : sig (ML-DSA-65 contre ECDSA P-384) ou size (ECDSA rempli contre ECDSA non rempli)."""
    E = []
    for proto in ("tls", "quic"):
        for kem in ("x448_mlkem768", "hqc192"):
            E.append(dict(grp="REFERENCE chaine simple (fx, deja utilisee)", proto=proto, kem=kem, kind="sig", par="mtu1500", rtt=50,
                          test=dict(sig="mldsa65", family="fx"), ref=dict(sig="secp384r1", family="fx"),
                          ch_t=chain["mldsa65"], ch_r=chain["secp384r1"], sig_t="mldsa65", sig_r="secp384r1", d0=True, in_sample=True))
            E.append(dict(grp="CHAINE A 2 NIVEAUX", proto=proto, kem=kem, kind="sig", par="mtu1500", rtt=50,
                          test=dict(sig="mldsa65", family="chain", label=CH2_LABEL), ref=dict(sig="secp384r1", family="chain", label=CH2_LABEL),
                          ch_t=11032, ch_r=903 if proto == "tls" else 904, sig_t="mldsa65", sig_r="secp384r1", d0=True, in_sample=False))
    for (proto, cond), (lab_u, lab_p) in LAB.items():
        par = cond
        E.append(dict(grp="MTU " + ("1280" if "1280" in cond else "1500"), proto=proto, kem=KEM_T, kind="sig", par=par, rtt=50,
                      test=dict(sig="mldsa65", family="mech", label=lab_u), ref=dict(sig="secp384r1", family="mech", label=lab_u),
                      ch_t=chain["mldsa65"], ch_r=chain["secp384r1"], sig_t="mldsa65", sig_r="secp384r1", d0=True, in_sample=False))
        E.append(dict(grp="ECDSA REMPLI 8700 o (" + ("MTU 1280" if "1280" in cond else "MTU 1500") + ")", proto=proto, kem=KEM_T, kind="size", par=par, rtt=50,
                      test=dict(sig="secp384r1", family="size", label=lab_p), ref=dict(sig="secp384r1", family="mech", label=lab_u),
                      ch_t=8700, ch_r=chain["secp384r1"], sig_t="secp384r1", sig_r="secp384r1", d0=False, in_sample=False))
    return E


def section1(d, p3, chain):
    log("\n=== 1. CELLULES SANS PERTE, RTT 50 : k predit (constantes gelees) CONTRE k observe ===")
    log("    k observe = [D(50) - D(0)] / 50 par bloc, D = ML-DSA-65 - ECDSA P-384 (estimateur : MEDIANE par bloc ; moyenne en sensibilite) ;")
    log("    D(0) = meme contraste a RTT 0 (fx, memes blocs). Contraste ECDSA rempli - ECDSA non rempli : D(0) pris egal a 0 (non mesure).")
    E = experiments(chain)
    T = {}
    for proto in ("tls", "quic"):
        t = tau_from_fx(d, proto, "hqc192")
        T[proto] = t
        m, lo, hi = boot(t.values, seed=5)
        log("    T (recouvrement HQC-192 mesure sur fx) %s : %s ms" % (proto.upper(), f2(m, lo, hi, 1)))
    log("")
    # --- PREDICTIONS (aucune donnee de comparaison utilisee ci-dessous)
    log("    -- PREDICTIONS (calculees avant la comparaison) --")
    for e in E:
        par = PAR[e["par"]]
        variants = ("bytes", "writes") if e["proto"] == "tls" else ("bytes",)
        e["pred"] = {}
        for v in variants:
            rt, bt, capt = rounds(p3, e["proto"], e["kem"], e["sig_t"], e["ch_t"], par, v)
            rr, br, capr = rounds(p3, e["proto"], e["kem"], e["sig_r"], e["ch_r"], par, v)
            e["pred"][v] = dict(R_t=rt, R_r=rr, k=rt - rr, bytes_t=bt, bytes_r=br, cap=capt)
        e["triv"] = (1 if e["proto"] == "quic" else 0) if e["kind"] == "sig" else 0
        if not e["in_sample"]:
            p = e["pred"]["writes"] if e["proto"] == "tls" else e["pred"]["bytes"]
            log("    %-34s %-4s %-14s k_pred=%d (octets : test %6.0f / ref %6.0f ; plafond 1er vol %6.0f)%s" % (
                e["grp"][:34], e["proto"].upper(), e["kem"], p["k"], p["bytes_t"], p["bytes_r"], p["cap"],
                "   [HQC : k_apparent = 1 - T/RTT]" if "hqc" in e["kem"] and p["k"] == 1 else ""))
    # --- OBSERVATIONS
    log("")
    rows = []
    for e in E:
        proto, kem, rtt = e["proto"], e["kem"], float(e["rtt"])
        out = dict(groupe=e["grp"], proto=proto, kem=kem, kind=e["kind"], in_sample=e["in_sample"])
        for stat in ("median", "mean"):
            D50 = d_series(d, "app_ms", stat, proto, kem, e["test"], e["ref"], rtt)
            if e["d0"]:
                D0 = d_series(d, "app_ms", stat, proto, kem, dict(sig=e["sig_t"], family="fx"), dict(sig=e["sig_r"], family="fx"), 0.0)
                kb = ((D50 - D0) / rtt).dropna()
            else:
                kb = (D50 / rtt).dropna()
            m, lo, hi = boot(kb.values, seed=17)
            out["k_obs_" + stat], out["k_obs_%s_lo" % stat], out["k_obs_%s_hi" % stat] = m, lo, hi
            out["D50_" + stat] = float(D50.mean())
            out["n_blocks"] = len(kb)
        # controle : meme calcul sur le handshake seul (la penalite doit y etre entierement)
        D50h = d_series(d, "hs_ms", "median", proto, kem, e["test"], e["ref"], rtt)
        if e["d0"]:
            D0h = d_series(d, "hs_ms", "median", proto, kem, dict(sig=e["sig_t"], family="fx"), dict(sig=e["sig_r"], family="fx"), 0.0)
            out["k_obs_hs_median"] = float(((D50h - D0h) / rtt).mean())
        else:
            out["k_obs_hs_median"] = float((D50h / rtt).mean())
        pv = e["pred"]["writes"] if proto == "tls" else e["pred"]["bytes"]
        out["k_round_pred"] = pv["k"]
        out["k_pred_bytes_only"] = e["pred"]["bytes"]["k"]
        out["k_pred_writes"] = pv["k"]
        kp = float(pv["k"])
        if "hqc" in kem and kp >= 1:
            Tm = float(T[proto].mean())
            kp = kp * max(0.0, 1.0 - Tm / rtt)
        out["k_pred_final"] = kp
        out["k_trivial"] = e["triv"]
        out["informative"] = bool(round(pv["k"]) != e["triv"])
        out["verdict"] = verdict(kp, out["k_obs_median"])
        out["verdict_bytes_only"] = verdict(float(e["pred"]["bytes"]["k"]) * (max(0.0, 1.0 - float(T[proto].mean()) / rtt) if ("hqc" in kem and e["pred"]["bytes"]["k"] >= 1) else 1.0),
                                            out["k_obs_median"])
        out["ci_contains_pred"] = bool(out["k_obs_median_lo"] <= kp <= out["k_obs_median_hi"])
        out["bytes_ml_or_test"] = pv["bytes_t"]
        out["bytes_ref"] = pv["bytes_r"]
        out["cap_first_flight"] = pv["cap"]
        out["margin_test_pct"] = 100.0 * (pv["bytes_t"] - pv["cap"]) / pv["cap"]
        out["margin_ref_pct"] = 100.0 * (pv["bytes_r"] - pv["cap"]) / pv["cap"]
        rows.append(out)
    r = pd.DataFrame(rows)
    hdr = "    %-34s %-4s %-14s %7s %20s %7s %6s %9s %-8s %s" % ("cellule", "prot", "KEM", "k_pred", "k_obs (mediane) [IC95 %]", "k_moy", "trivial", "informatif", "verdict", "marge test/ref au plafond")
    log(hdr)
    for _, x in r.iterrows():
        log("    %-34s %-4s %-14s %7.2f %20s %7.2f %6d %9s %-8s %+.1f %% / %+.1f %%%s" % (
            x.groupe[:34], x.proto.upper(), x.kem, x.k_pred_final, f2(x.k_obs_median, x.k_obs_median_lo, x.k_obs_median_hi), x.k_obs_mean,
            x.k_trivial, "OUI" if x.informative else "non", x.verdict, x.margin_test_pct, x.margin_ref_pct,
            "   (in-sample)" if x.in_sample else ""))
    new = r[~r.in_sample]
    inf = new[new.informative]
    log("\n    Hors echantillon (%d cellules) : %s" % (len(new), dict(new.verdict.value_counts())))
    log("    Dont INFORMATIVES (le modele trivial echoue) : %d -> %s" % (len(inf), dict(inf.verdict.value_counts())))
    for _, x in inf.iterrows():
        log("      * %s %s %s : k_obs %.2f [%.2f ; %.2f] contre predit %.2f, trivial %d" % (
            x.groupe, x.proto.upper(), x.kem, x.k_obs_median, x.k_obs_median_lo, x.k_obs_median_hi, x.k_pred_final, x.k_trivial))
    mx = float(np.max(np.abs(r.k_obs_hs_median - r.k_obs_median)))
    log("    Controle handshake seul : ecart max |k(hs) - k(app)| = %.3f" % mx)
    log("    Limites : un seul RTT (50 ms) ; baseline D(0) issue de fx ; contraste rempli - non rempli sans D(0) ; HQC : T calibre sur fx (non independant de la chaine simple).")
    r.to_csv(os.path.join(OUT, "p5_natural_lossless.csv"), index=False)
    return r, T


# ------------------------------------------------------------------------------------------------ 2. constance de T (HQC)
def section2(d, p3, chain, T, phase4):
    log("\n=== 2. LE RECOUVREMENT T (calcul client HQC pendant le tour supplementaire) EST-IL CONSTANT ? ===")
    log("    Hypothese : si le client dechiffre le chiffre HQC (decapsulation) pendant l'attente du 2e vol, alors D(RTT) - D(0) = k x max(0, RTT - T)")
    log("    et le k apparent d'un profil de RTT donne vaut 1 - T/RTT. On estime T = RTT x (1 - k) sur chaque profil (mediane par bloc) et on compare.")
    obs, rtts = p3.observed_k_main(d, "app_ms", "median")
    obs = obs[obs.auth == "single"]                    # TLS mutuelle exclue (D0 different : voir 07, mutual_cpu)
    cpu = None
    if phase4 and os.path.exists(os.path.join(phase4, "p4_res_kem_contrasts.csv")):
        cpu = pd.read_csv(os.path.join(phase4, "p4_res_kem_contrasts.csv"))
    rows = []
    for _, x in obs.iterrows():
        if "hqc" not in x.kem:
            continue
        sig_pair = (p3.CLASSICAL_OF[x.level], p3.MLDSA_OF[x.level])
        v = "writes" if x.proto == "tls" else "bytes"
        rc = rounds(p3, x.proto, x.kem, sig_pair[0], chain[sig_pair[0]], PAR_DEFAULT, v)[0]
        rm, _, cap_ml = rounds(p3, x.proto, x.kem, sig_pair[1], chain[sig_pair[1]], PAR_DEFAULT, v)
        if rm - rc != 1:
            continue
        # QUIC : le 1er vol est borne soit par l'anti-amplification (3 x Initial client < fenetre initiale), soit par la fenetre initiale
        lim = "anti-amplification" if (x.proto == "quic" and cap_ml < p3.QUIC_IW) else "fenetre initiale"
        row = dict(proto=x.proto, level=x.level, kem=x.kem, limite_1er_vol=lim)
        for rt in rtts:
            key = "k%d" % round(rt)
            # IC de T par retournement monotone de l'IC de k
            row["T_%d" % round(rt)] = rt * (1 - x[key])
            row["T_%d_lo" % round(rt)] = rt * (1 - x[key + "_hi"])
            row["T_%d_hi" % round(rt)] = rt * (1 - x[key + "_lo"])
        if cpu is not None:
            def ef(contr, met):
                s = cpu[(cpu.proto == x.proto) & (cpu.level == x.level) & (cpu.contraste == contr) & (cpu.metrique == met)]
                return float(s.effet.iloc[0]) if len(s) else np.nan
            base = ef("HQC pur - ML-KEM pur", "srv_cpu_ms")
            add = 0.0 if x.kem.startswith("hqc") else ef(x.kem + " - HQC pur", "srv_cpu_ms")
            row["srv_cpu_excess_ms"] = base + (0.0 if np.isnan(add) else add)
        row["T_fx"] = float(T[x.proto].mean()) if (x.kem == "hqc192") else np.nan
        rows.append(row)
    r = pd.DataFrame(rows)
    if r.empty:
        log("    (aucune paire HQC a un tour supplementaire predit)")
        return r
    log("    %-5s %-3s %-14s %22s %22s %9s %12s  %s" % ("prot", "niv", "KEM", "T(RTT 125) ms", "T(RTT 167) ms", "T fx", "CPU srv HQC", "1er vol borne par"))
    t1, t2 = "T_%d" % round(rtts[0]), "T_%d" % round(rtts[1])
    for _, x in r.iterrows():
        log("    %-5s %-3s %-14s %22s %22s %9s %12s  %s" % (
            x.proto.upper(), x.level, x.kem, f2(x[t1], x[t1 + "_lo"], x[t1 + "_hi"], 1), f2(x[t2], x[t2 + "_lo"], x[t2 + "_hi"], 1),
            "%.1f" % x.T_fx if np.isfinite(x.T_fx) else "-", ("%.1f" % x.srv_cpu_excess_ms) if "srv_cpu_excess_ms" in r.columns and np.isfinite(x.srv_cpu_excess_ms) else "-",
            x.limite_1er_vol))
    for proto in ("tls", "quic"):
        s = r[r.proto == proto]
        if len(s):
            log("    %s : |T(125) - T(167)| moyen = %.1f ms sur %d paires" % (proto.upper(), float(np.mean(np.abs(s[t1] - s[t2]))), len(s)))
        if len(s) and "srv_cpu_excess_ms" in r.columns:
            tm = (s[t1] + s[t2]) / 2.0
            log("    %s : |T moyen - CPU serveur HQC| : moyenne %.1f ms, maximum %.1f ms (%d paires)" % (
                proto.upper(), float(np.mean(np.abs(tm - s.srv_cpu_excess_ms))), float(np.max(np.abs(tm - s.srv_cpu_excess_ms))), len(s)))
    log("    Lecture : T constant entre profils ET egal au cout CPU de HQC = mecanisme de recouvrement compatible ; un T qui croit avec le RTT l'infirme.")
    log("    QUIC : si le 1er vol est borne par l'anti-amplification, le serveur attend un paquet Handshake du client, donc la fin du calcul de decapsulation : T attendu ~ 0")
    log("    (hypothese POST HOC, non testee directement : aucun pcap HQC). Si le 1er vol est borne par la fenetre initiale, les ACK Initial suffisent : recouvrement possible.")
    log("    ATTENTION : profils main avec perte -> TLS = preuve SECONDAIRE ; T(fx) vient de cellules sans perte (independantes des profils main).")
    r.to_csv(os.path.join(OUT, "p5_tau_profiles.csv"), index=False)
    return r


# ------------------------------------------------------------------------------------------------ 3. reponse a la perte
def section3(d):
    log("\n=== 3. REPONSE A LA PERTE i.i.d. (RTT 50) : pente de la penalite ML-DSA en ms par % de perte, chaine simple contre chaine a 2 niveaux ===")
    log("    D(p) = ML-DSA-65 - ECDSA P-384 (moyenne par bloc, car l'exposition aux pertes est le phenomene mesure) ; pente OLS sur p in {0, 1, 2, 5} par bloc ;")
    log("    difference de pentes chaine 2 - chaine 1 appariee par bloc, IC95 % bootstrap sur 20 blocs. Hypothese a priori : plus de paquets exposes -> pente plus forte.")
    ps = [0.0, 1.0, 2.0, 5.0]
    rows = []
    for proto in ("quic", "tls"):
        for kem in ("x448_mlkem768", "hqc192"):
            for stat in ("mean", "median"):
                sl = {}
                for ch, fam, lab in (("chaine 1", "fx", None), ("chaine 2", "chain", None)):   # famille chain = chaine a 2 niveaux seulement (labels differents selon la perte)
                    Dp = []
                    for p in ps:
                        proc = "none" if p == 0 else "iid"
                        a = series(d, "app_ms", stat, proto, kem, "mldsa65", 50.0, fam, lab, proc, p)
                        b = series(d, "app_ms", stat, proto, kem, "secp384r1", 50.0, fam, lab, proc, p)
                        Dp.append((a - b))
                    M = pd.concat(Dp, axis=1, keys=ps).dropna()
                    x = np.array(ps)
                    slope = np.array([np.polyfit(x, r.values.astype(float), 1)[0] for _, r in M.iterrows()])
                    sl[ch] = pd.Series(slope, index=M.index)
                    m, lo, hi = boot(slope, seed=23)
                    rows.append(dict(proto=proto, kem=kem, stat=stat, chaine=ch, pente_ms_par_pct=m, lo=lo, hi=hi,
                                     D0=float(M[0.0].mean()), D1=float(M[1.0].mean()), D2=float(M[2.0].mean()), D5=float(M[5.0].mean()),
                                     evidence="ROBUSTE" if proto == "quic" else "SECONDAIRE_tls_perte_groupee"))
                df = (sl["chaine 2"] - sl["chaine 1"]).dropna()
                m, lo, hi = boot(df.values, seed=29)
                rows.append(dict(proto=proto, kem=kem, stat=stat, chaine="chaine 2 - chaine 1", pente_ms_par_pct=m, lo=lo, hi=hi,
                                 D0=np.nan, D1=np.nan, D2=np.nan, D5=np.nan, evidence="ROBUSTE" if proto == "quic" else "SECONDAIRE_tls_perte_groupee"))
    r = pd.DataFrame(rows)
    log("    %-5s %-14s %-7s %-20s %26s   D(0)/D(1)/D(2)/D(5) ms" % ("prot", "KEM", "estim.", "chaine", "pente ms/%  [IC95 %]"))
    for _, x in r.iterrows():
        extra = "" if np.isnan(x.D0) else "%6.1f /%6.1f /%6.1f /%6.1f" % (x.D0, x.D1, x.D2, x.D5)
        log("    %-5s %-14s %-7s %-20s %26s   %s%s" % (x.proto.upper(), x.kem, x.stat, x.chaine, f2(x.pente_ms_par_pct, x.lo, x.hi, 2), extra,
                                                      "" if x.evidence == "ROBUSTE" else "  (secondaire)"))
    log("    Lecture : la penalite ML-DSA sous perte croit-elle avec le volume du vol ? Differences de pentes dont l'IC exclut 0 = oui (QUIC seul interprete).")
    r.to_csv(os.path.join(OUT, "p5_loss_dose.csv"), index=False)
    return r


# ------------------------------------------------------------------------------------------------ 4. verification par les vols (06)
def find_timeline(a):
    cands = [a.timeline] if a.timeline else []
    cands += [os.path.join(a.indir, "phase2", "flight_timeline_summary.csv"), os.path.join(a.indir, "out2", "flight_timeline_summary.csv"),
              os.path.join(a.indir, "flight_timeline_summary.csv")]
    for c in cands:
        if c and os.path.exists(c):
            return c
    return None


def section4(p3, chain, a):
    log("\n=== 4. VERIFICATION PAR LES VOLS RECONSTITUES (06, pcap reels) ===")
    path = find_timeline(a)
    if path is None:
        log("    (flight_timeline_summary.csv introuvable : lancer 06_flight_timeline.py puis --timeline)")
        return None
    t = pd.read_csv(path)
    rows = []
    for _, x in t.iterrows():
        lab = x.label
        pair = x.pair
        sig, kem = pair.split("_", 1)
        padded = "padto8700" in lab
        ch = 8700 if padded else chain[sig]
        if x.proto == "quic":
            cond = "qmtu1280" if "mtu1280" in lab else "qmtu1500"
            par = PAR[cond]
            r, s, b1 = rounds(p3, "quic", kem, sig, ch, par, "bytes")
            fl_obs = x.b1_bytes + (x.b2_bytes if r == 2 else 0.0)          # vol de poignee de main = 1re + 2e rafale quand 2 tours
            rows.append(dict(proto="quic", label=lab, pair=pair, client_bytes=x.client_bytes, b1_obs=x.b1_bytes, b1_over_client=x.b1_over_client,
                             b1_pred_3x_client=3 * x.client_bytes, b1_minus_3x=x.b1_bytes - 3 * x.client_bytes,
                             n_bursts=x.n_bursts, tours_pred=r, flight_pred=s, cap_pred=b1, flight_obs=fl_obs))
        else:
            mss = PAR["mtu1280"]["mss"] if "mtu1280" in lab else PAR_DEFAULT["mss"]
            r, nb, cap = rounds(p3, "tls", kem, sig, ch, dict(PAR_DEFAULT, mss=mss), "writes")
            rows.append(dict(proto="tls", label=lab, pair=pair, client_bytes=x.client_bytes, b1_obs=x.b1_bytes, b1_over_client=x.b1_over_client,
                             b1_pred_3x_client=np.nan, b1_minus_3x=np.nan, n_bursts=x.n_bursts, tours_pred=r, flight_pred=nb, cap_pred=cap))
    r = pd.DataFrame(rows)
    log("    QUIC : le 1er vol serveur vaut-il 3 x octets client, y compris quand la taille du datagramme change (2 944 o a MTU 1500, 2 504 o a MTU 1280) ?")
    q = r[r.proto == "quic"]
    for _, x in q.iterrows():
        log("      %-58s %-26s client %5.0f  b1 %5.0f  b1/client %.3f  b1-3x %+5.0f | vol obs (b1+b2 si 2 tours) %6.0f  vol modele %7.0f (%+.2f %%)  plafond modele %6.0f  tours modele %d  rafales %d" % (
            x.label[:58], x.pair, x.client_bytes, x.b1_obs, x.b1_over_client, x.b1_minus_3x, x.flight_obs, x.flight_pred,
            100.0 * (x.flight_pred - x.flight_obs) / x.flight_obs, x.cap_pred, x.tours_pred, x.n_bursts))
    log("    NB : RHO_QUIC (1,037) a ete cale sur la ligne ML-DSA-65 / MTU 1500 (10 594 o) : cette ligne est une identite, pas une validation.")
    log("    Les lignes MTU 1280, ECDSA rempli et classique sont independantes de ce calage.")
    log("    TLS : octets du 1er vol observes contre octets du vol modelises (A_TLS calee sur ML-DSA-65 seulement ; classique et rempli = verifications independantes)")
    tl = r[r.proto == "tls"]
    for _, x in tl.iterrows():
        log("      %-58s %-26s b1 obs %6.0f  vol modele %7.0f  ecart %+4.0f o  rafales %d  tours modele %d" % (
            x.label[:58], x.pair, x.b1_obs, x.flight_pred, x.b1_obs - x.flight_pred, x.n_bursts, x.tours_pred))
    if len(tl):
        log("    TLS : ecart absolu max entre octets observes et modelises = %.0f o (sur %d cellules)" % (float(np.max(np.abs(tl.b1_obs - tl.flight_pred))), len(tl)))
    log("    Les rafales (n_bursts) comptent le vol de poignee de main et les emissions post-handshake ; le nombre de tours est lu sur D(RTT), pas ici.")
    r.to_csv(os.path.join(OUT, "p5_timeline_check.csv"), index=False)
    return r


# ------------------------------------------------------------------------------------------------ 5. segments dans les pcap (facultatif)
def first_burst_sizes(ft, pcap, windows):
    """-> liste (proto, [charges utiles du 1er vol serveur]) par flux rattache a une execution."""
    flows = {}
    starts = [w[1] for w in windows]
    for ts, link, pkt in ft.read_packets(pcap):
        t = ft.l4_of(link, pkt)
        if t is None:
            continue
        pr, s, dst, sp, dp, fl, pl = t
        a, b = (s, sp), (dst, dp)
        key = (pr,) + ((a, b) if a <= b else (b, a))
        f = flows.get(key)
        if f is None:
            flows[key] = f = dict(first_src=a, pk=[], proto=pr)
        f["pk"].append((ts, a == f["first_src"], pl))
    out = []
    for key, f in flows.items():
        pk = sorted(f["pk"])
        i = bisect.bisect_right(starts, pk[0][0] + 0.001) - 1
        if i < 0 or not (windows[i][1] - 0.001 <= pk[0][0] <= windows[i][2] + 0.001):
            continue
        flip = not pk[0][1]
        seq, seen = [], False
        for ts, fc, pl in pk:
            fc = (not fc) if flip else fc
            if not fc and pl > 0:
                seq.append(pl)
                seen = True
            elif fc and seen:
                break
        if seq:
            out.append((f["proto"], seq))
    return out


def rle(seq):
    """[1448,1448,79] -> '1448x2,79'"""
    out, i = [], 0
    while i < len(seq):
        j = i
        while j < len(seq) and seq[j] == seq[i]:
            j += 1
        out.append("%d" % seq[i] if j - i == 1 else "%dx%d" % (seq[i], j - i))
        i = j
    return ",".join(out)


def section5(p3, chain, a):
    log("\n=== 5. SEGMENTS DU 1er VOL SERVEUR DANS LES PCAP : le ServerHello est-il ecrit a part ? ===")
    if not a.root:
        log("    (option --root absente : section ignoree)")
        return None
    ft = load_mod(os.path.join("06_flight_timeline.py") if os.path.exists(os.path.join(HERE, "06_flight_timeline.py")) else os.path.join("tools", "06_flight_timeline.py"), "p6_ft")
    root = a.root
    files = sorted(glob.glob(os.path.join(root, "*", "*", "*", "pcap_perconn", "*", "*", "block.pcap")))
    by = collections.defaultdict(list)
    for p in files:
        parts = os.path.relpath(p, root).split(os.sep)
        by[(parts[0], parts[2], parts[5])].append(p)
    rows = []
    for (proto, label, pair), L in sorted(by.items()):
        if re.search(r"loss[1-9]", label):
            continue
        sig, kem = pair.split("_", 1)
        seqs = []
        for p in L[: a.max_files]:
            cw = os.path.join(os.path.dirname(p), "conn_windows.csv")
            if not os.path.exists(cw):
                continue
            W = sorted([(int(r["execution"]), float(r["t_start_epoch"]), float(r["t_end_epoch"])) for r in csv.DictReader(open(cw))], key=lambda z: z[1])
            seqs += [s for pr, s in first_burst_sizes(ft, p, W) if pr == ("tcp" if proto == "tls" else "udp")]
        if not seqs:
            continue
        first = collections.Counter(s[0] for s in seqs)
        allv = collections.Counter(v for s in seqs for v in s)
        mx = max(allv)
        mss = collections.Counter(v for v in allv.elements()).most_common(1)[0][0]
        sep = float(np.mean([len(s) > 1 and s[0] < s[1] for s in seqs]))
        gso = float(np.mean([any(v > 1.1 * mss for v in s) for s in seqs]))
        _, ss = p3.kem_shares(kem)
        keys = [rle(sq) for sq in seqs]
        pats = collections.Counter(keys)
        pat1, n1 = pats.most_common(1)[0]
        modal = seqs[keys.index(pat1)]
        tot = int(sum(modal))
        sh = ss + p3.SH_FIX
        nseg = collections.Counter(len(sq) for sq in seqs)
        row = dict(proto=proto, label=label, pair=pair, n_flux=len(seqs), mediane_nb_segments=float(np.median([len(sq) for sq in seqs])),
                   taille_modale_segment=mss, taille_1er_segment_modale=first.most_common(1)[0][0], part_1er_segment_plus_court=sep,
                   part_flux_avec_super_paquet=gso, taille_ServerHello_modele=sh, taille_max=mx,
                   sequence_modale=pat1, part_flux_sequence_modale=n1 / len(seqs),
                   distribution_nb_segments=";".join("%d:%d" % (k, v) for k, v in sorted(nseg.items())),
                   octets_vol_modal=tot, nb_segments_obs_modal=len(modal), nb_segments_si_octets=int(math.ceil(tot / mss)),
                   nb_segments_si_deux_ecritures=int(math.ceil(sh / mss) + math.ceil((tot - sh) / mss)))
        rows.append(row)
        log("    %-4s %-58s %-26s flux %3d  taille modale %5d  1er segment modal %5d  1er < 2e : %3.0f %%  super-paquets : %.0f %%  (SH modele %d o)" % (
            proto.upper(), label[:58], pair, row["n_flux"], mss, row["taille_1er_segment_modale"], 100 * sep, 100 * gso, sh))
        log("         sequence modale (%3.0f %% des flux) : %s   | %d o : segments observes %d ; modele 'octets' %d ; modele 'deux ecritures' %d ; repartition %s" % (
            100 * n1 / len(seqs), pat1, tot, len(modal), row["nb_segments_si_octets"], row["nb_segments_si_deux_ecritures"], row["distribution_nb_segments"]))
    if not rows:
        log("    (aucun block.pcap exploitable sous %s)" % root)
        return None
    log("    Lecture TLS : variante 'deux ecritures' -> 1er segment ~ taille du ServerHello (< MSS) puis segments pleins ; variante 'octets' -> segments pleins des le debut.")
    log("    Si 'super-paquets' > 0 %, la capture voit des segments agreges (GSO) : la structure en segments n'est alors pas observable pour ces flux.")
    r = pd.DataFrame(rows)
    r.to_csv(os.path.join(OUT, "p5_segments.csv"), index=False)
    return r



# ------------------------------------------------------------------------------------------------ figure 8
def figure8(r1, r2, lang="fr"):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    BLUE, ORANGE, INK, GRID = "#2a6fb0", "#c4651a", "#222222", "#dddddd"
    fr = lang == "fr"
    new = r1[~r1.in_sample].copy().reset_index(drop=True)
    new["lab"] = ["%s %s %s" % (g.replace("ECDSA REMPLI 8700 o", "ECDSA rempli" if fr else "padded ECDSA").replace("CHAINE A 2 NIVEAUX", "chaine 2 niv." if fr else "2-level chain").title()
                               if False else g.replace("ECDSA REMPLI 8700 o", "ECDSA rempli" if fr else "padded ECDSA").replace("CHAINE A 2 NIVEAUX", "chaine 2 niv." if fr else "2-level chain"),
                               pr.upper(), kem) for g, pr, kem in zip(new.groupe, new.proto, new.kem)]
    fig, ax = plt.subplots(1, 2, figsize=(12.5, 5.4), gridspec_kw=dict(width_ratios=[1.35, 1]))
    a = ax[0]
    y = np.arange(len(new))[::-1]
    for yi, (_, x) in zip(y, new.iterrows()):
        c = BLUE if x.proto == "tls" else ORANGE
        a.plot([x.k_obs_median_lo, x.k_obs_median_hi], [yi, yi], color=c, lw=2, solid_capstyle="round", zorder=2)
        a.plot(x.k_obs_median, yi, "o" if x.proto == "tls" else "s", color=c, ms=7, mec="white", mew=1.2, zorder=3)
        a.plot(x.k_pred_final, yi, marker="D", mfc="none", mec=INK, ms=9, mew=1.4, zorder=4)
        if x.informative:
            a.text(1.32, yi, "\u2605", ha="center", va="center", fontsize=11, color=INK)
    a.set_yticks(y)
    a.set_yticklabels(new.lab, fontsize=8.5)
    a.set_xlim(-0.15, 1.38)
    a.set_xlabel("k (tours supplementaires)" if fr else "k (extra round trips)")
    a.set_title("A. k predit (losange) et observe (IC 95 % sur 20 blocs)" if fr else "A. predicted (diamond) and observed k (95 % CI over 20 blocks)", fontsize=10, loc="left")
    a.grid(axis="x", color=GRID, lw=0.7); a.set_axisbelow(True)
    for sp in ("top", "right"): a.spines[sp].set_visible(False)
    a.plot([], [], "o", color=BLUE, label="TLS"); a.plot([], [], "s", color=ORANGE, label="QUIC")
    a.plot([], [], "D", mfc="none", mec=INK, label="predit" if fr else "predicted")
    a.plot([], [], "*", color=INK, ls="", label="informative (modele trivial en echec)" if fr else "informative (trivial model fails)")
    a.legend(loc="lower left", fontsize=8, frameon=False)
    b = ax[1]
    if r2 is not None and len(r2) and "srv_cpu_excess_ms" in r2.columns:
        for pr, mk, c in (("tls", "o", BLUE), ("quic", "s", ORANGE)):
            s_ = r2[r2.proto == pr]
            tcols = [k for k in s_.columns if re.fullmatch(r"T_\d+", k)]
            tm = s_[tcols].mean(axis=1)
            b.scatter(s_.srv_cpu_excess_ms, tm, marker=mk, s=60, color=c, edgecolor="white", linewidth=1.2, zorder=3, label=pr.upper())
        lim = [0, 50]
        b.plot(lim, lim, color=INK, lw=1, ls="--", zorder=1)
        b.set_xlim(lim); b.set_ylim(-3, 50)
        b.set_xlabel("surcout CPU serveur de HQC (ms, RTT 0)" if fr else "HQC server CPU excess (ms, RTT 0)")
        b.set_ylabel("T estime (ms)" if fr else "estimated T (ms)")
        b.set_title("B. recouvrement T contre cout CPU de HQC" if fr else "B. overlap T vs HQC CPU cost", fontsize=10, loc="left")
        b.grid(color=GRID, lw=0.7); b.set_axisbelow(True)
        for sp in ("top", "right"): b.spines[sp].set_visible(False)
        b.legend(loc="upper left", fontsize=8, frameon=False)
    fig.tight_layout()
    for ext in ("pdf", "png"):
        fig.savefig(os.path.join(OUT, "fig8_experiences_naturelles." + ext), dpi=170)
    plt.close(fig)

# ------------------------------------------------------------------------------------------------ programme
OUT = "."


def main():
    global OUT
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="indir", default="analysis_v2")
    ap.add_argument("--out", default="analysis_v2/phase5")
    ap.add_argument("--manifest", default=None)
    ap.add_argument("--timeline", default=None, help="flight_timeline_summary.csv de 06 (defaut : <in>/phase2/ ou <in>/out2/)")
    ap.add_argument("--phase4", default=None, help="dossier de 09 (p4_res_kem_contrasts.csv) pour comparer T au CPU serveur (defaut : <in>/phase4)")
    ap.add_argument("--root", default=None, help="captures_v2 : active la section 5 (pcap par connexion)")
    ap.add_argument("--max-files", type=int, default=3, help="section 5 : nombre de block.pcap lus par (cellule, paire)")
    a = ap.parse_args()
    OUT = a.out
    os.makedirs(OUT, exist_ok=True)
    p3 = load_mod("07_threshold_model.py", "p3_threshold")
    p4 = load_mod("04_confirmatory.py", "p4_confirmatory")
    c = p4.load(a.indir)
    d, _ = p4.scenario(c, "primary")
    chain = p3.chain_sizes(a.manifest or os.path.join(a.indir, "manifests.csv"))
    log("PHASE 5 -- experiences naturelles. Constantes GELEES de 07 : A_TLS=%d SH_FIX=%d RHO_QUIC=%.3f MSS=%d IW=%d QUIC_IW=%d ; chaines : %s" % (
        p3.A_TLS, p3.SH_FIX, p3.RHO_QUIC, p3.TCP_MSS, p3.TCP_IW, p3.QUIC_IW, {k: chain[k] for k in ("secp384r1", "mldsa65")}))
    r1, T = section1(d, p3, chain)
    r2 = section2(d, p3, chain, T, a.phase4 or os.path.join(a.indir, "phase4"))
    section3(d)
    section4(p3, chain, a)
    section5(p3, chain, a)
    try:
        figure8(r1, r2)
        log("Figure : %s" % os.path.join(OUT, "fig8_experiences_naturelles.pdf"))
    except Exception as e:  # matplotlib facultatif
        log("(figure 8 non produite : %s)" % e)
    with open(os.path.join(OUT, "p5_report.txt"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(REP))
    log("\nTermine -> %s" % OUT)


if __name__ == "__main__":
    main()
