#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""13_analyse_extensions.py -- analyse des trois campagnes v3 (niveau de securite 3) :
   reprise de session, compression de certificat (RFC 8879), charge concurrente.

Lit l'arborescence produite par Launcher_ext.sh / run_campaign_ext.sh :
    <root>/<proto>/<auth>/<label>/handshake_logs/handshake_<proto>_<auth>_<sig>_<kem>_<label>_block<k>of<N>[_mb<r>of<M>].log
    <root>/<proto>/<auth>/<label>/load_traces/block<k>of<N>/<sig>_<kem>/{srv,cli}_cpu_trace.csv        (charge uniquement)

METHODE (identique a la campagne v2) : l'unite d'inference est le BLOC (20) ; chaque statistique est calculee sur des
medianes par bloc, et son IC a 95 % est un bootstrap (percentile) sur les blocs (rechantillonnage des blocs entiers, donc
conjoint pour toutes les cellules d'un meme bloc). Les connexions d'un bloc ne sont JAMAIS traitees comme independantes.

PREDICTIONS ENREGISTREES AVANT LES DONNEES : les bandes d'acceptation ci-dessous (dict PRED_*) sont figees dans ce fichier
(a horodater / commiter avant le premier bloc). Verdict a trois etats, regle fixe :
    PASS          IC95 % entierement dans la bande
    FAIL          IC95 % entierement hors de la bande
    INCONCLUSIF   sinon (IC chevauche la bande)
Une prediction FAIL est un resultat a rapporter tel quel (pas de re-calage des bandes apres coup).

Sorties (dossier --out) : p6_resume_*.csv, p6_comp_*.csv, p6_load_*.csv, p6_predictions.csv, p6_load_curves.pdf (si matplotlib).

Usage : python3 13_analyse_extensions.py --root captures_v3_resume captures_v3_comp captures_v3_load --out analysis_v3 [--v2-root captures_v2] [--boot 4000]
"""
from __future__ import annotations
import argparse, glob, os, re, sys
import numpy as np
import pandas as pd

SIGS = ["secp384r1", "mldsa65", "ed25519", "mldsa44", "mldsa87", "secp521r1"]
PRED = []        # liste de dicts : voir add_pred()


# ═════════════════════════════════════════════════════════════════════════════════════════════════════════════════
# 1. Lecture des journaux
# ═════════════════════════════════════════════════════════════════════════════════════════════════════════════════
def parse_label(label: str) -> dict:
    d = dict(rtt=np.nan, loss=0.0, chain=1, pad=0, comp="", res=0, zrtt=0, load=0, tls_server="", srv_cpus=np.nan,
             conc_tag="", sentinel="")
    m = re.search(r"delay(\d+(?:\.\d+)?)ms", label)
    d["rtt"] = 2 * float(m.group(1)) if m else (0.0 if label.startswith("none") else np.nan)
    m = re.search(r"loss(\d+(?:\.\d+)?)", label)
    if m and label.startswith("simple"):
        d["loss"] = float(m.group(1))
    if "__chain2" in label: d["chain"] = 2
    m = re.search(r"__padto(\d+)", label)
    if m: d["pad"] = int(m.group(1))
    m = re.search(r"__comp([a-z0-9]+)", label)
    if m: d["comp"] = m.group(1)
    if "__res" in label:
        d["res"] = 1
        d["zrtt"] = int("__res0rtt" in label)
    m = re.search(r"__load_(mt|stock)_srv(\d+)cpu", label)
    if m:
        d["load"] = 1; d["tls_server"] = m.group(1); d["srv_cpus"] = int(m.group(2))
    m = re.search(r"__c([0-9-]+)", label)
    if m: d["conc_tag"] = m.group(1)
    m = re.search(r"__sentinel_(\w+)", label)
    if m: d["sentinel"] = m.group(1)
    return d


def split_name(fname: str, proto: str, auth: str, label: str):
    """handshake_<proto>_<auth>_<sig>_<kem>_<label>_block<k>of<N>[_mb<r>of<M>].log -> sig, kem, block, nblocks"""
    b = os.path.basename(fname)
    m = re.match(r"^handshake_%s_%s_(.+)_block(\d+)of(\d+)(?:_mb(\d+)of(\d+))?\.log$" % (proto, auth), b)
    if not m:
        return None
    mid, blk, nb = m.group(1), int(m.group(2)), int(m.group(3))
    if mid.endswith("_" + label):
        mid = mid[: -(len(label) + 1)]
    sig = next((s for s in SIGS if mid.startswith(s + "_")), None)
    if sig is None:
        return None
    return sig, mid[len(sig) + 1:], blk, nb


NUM = r"([0-9]+(?:\.[0-9]+)?|NaN)"


def fnum(x):
    return np.nan if x is None or x == "NaN" else float(x)


def parse_conn_log(path):
    """Journal 'une connexion par bloc Execution' -> liste de dict."""
    rows, cur = [], None
    with open(path, errors="replace") as f:
        for ln in f:
            ln = ln.rstrip("\n")
            m = re.match(r"^Execution (\S+) - (TLS|QUIC) (Single|Mutual)", ln)
            if m:
                if cur is not None: rows.append(cur)
                cur = dict(idx=m.group(1), mode="", resumed=np.nan, rx=np.nan, tx=np.nan, cert_type=np.nan,
                           cert_comp=np.nan, cert_plain=np.nan, hs_ms=np.nan, app_ms=np.nan, ticket_in="", zrtt=np.nan,
                           ticket=np.nan)
                continue
            if cur is None:
                continue
            for key, pat, fn in (
                ("mode", r"^Mode: (\S+)", str), ("resumed", r"^Resumed: (\d)", float), ("rx", r"^Rx-bytes: (\d+)", float),
                ("tx", r"^Tx-bytes: (\d+)", float), ("hs_ms", r"^Handshake duration: " + NUM, fnum),
                ("app_ms", r"^App-ready duration: " + NUM, fnum), ("ticket_in", r"^Ticket-in: (\S+)", str),
                ("zrtt", r"^ZeroRTT-sent: (\d)", float), ("ticket", r"^Ticket: (\d)", float)):
                m = re.match(pat, ln)
                if m:
                    cur[key] = fn(m.group(1)); break
            m = re.match(r"^CertMsg: type=(\d+) len_comp=(\d+) len_plain=(\d+)", ln)
            if m:
                cur["cert_type"], cur["cert_comp"], cur["cert_plain"] = int(m.group(1)), int(m.group(2)), int(m.group(3))
    if cur is not None: rows.append(cur)
    return rows


def parse_load_log(path):
    meta, levels, conns = {}, [], []
    with open(path, errors="replace") as f:
        for ln in f:
            ln = ln.strip()
            if ln.startswith("LOADMETA"):
                meta = dict(re.findall(r'(\w+)=("[^"]*"|\S+)', ln))
            elif ln.startswith("LEVEL "):
                d = dict(re.findall(r"(\w+)=(\S+)", ln))
                levels.append(dict(conc=int(d["conc"]), t_start=int(d["t_start"]), t_end=int(d["t_end"]), order=int(d["order"])))
            elif ln.startswith("LOADCONN"):
                d = dict(re.findall(r"(\w+)=(\S+)", ln))
                conns.append(dict(conc=int(d["conc"]), t_end=int(d["t_end"]), ok=int(d["ok"]), hs_ms=fnum(d["hs_ms"]),
                                  app_ms=fnum(d["app_ms"]), rx=fnum(d["rx"]) if d["rx"] != "NA" else np.nan))
    return meta, levels, conns


def read_trace(path):
    if not os.path.exists(path): return None
    try:
        t = pd.read_csv(path)
        t = t.dropna()
        return t["t_epoch"].to_numpy(float), t["cpu_usec"].to_numpy(float)
    except Exception:
        return None


def util(trace, t0_ms, t1_ms):
    """CPU cumule -> CPU-secondes consommees dans [t0,t1] (interpolation lineaire)."""
    if trace is None: return np.nan
    t, c = trace
    if len(t) < 2 or t0_ms / 1000 < t[0] - 1 or t1_ms / 1000 > t[-1] + 1: return np.nan
    c0, c1 = np.interp([t0_ms / 1000, t1_ms / 1000], t, c)
    return (c1 - c0) / 1e6


def walk(root, arm=None):
    arm = arm or os.path.basename(os.path.normpath(root))
    conn, load = [], []
    for ldir in sorted(glob.glob(os.path.join(root, "*", "*", "*"))):
        if not os.path.isdir(ldir): continue
        label = os.path.basename(ldir); auth = os.path.basename(os.path.dirname(ldir)); proto = os.path.basename(os.path.dirname(os.path.dirname(ldir)))
        if proto not in ("tls", "quic"): continue
        info = parse_label(label)
        for lf in sorted(glob.glob(os.path.join(ldir, "handshake_logs", "*.log"))):
            sp = split_name(lf, proto, auth, label)
            if sp is None: continue
            sig, kem, blk, nb = sp
            if info["load"]:
                meta, levels, conns = parse_load_log(lf)
                if not levels: continue
                tdir = os.path.join(ldir, "load_traces", "block%dof%d" % (blk, nb), "%s_%s" % (sig, kem))
                st, ct = read_trace(os.path.join(tdir, "srv_cpu_trace.csv")), read_trace(os.path.join(tdir, "cli_cpu_trace.csv"))
                trim = int(meta.get("trim_s", 2)) * 1000
                nproc = float(meta.get("nproc", 1))
                cdf = pd.DataFrame(conns)
                for lv in levels:
                    w0, w1 = lv["t_start"] + trim, lv["t_end"] - trim
                    sub = cdf[(cdf.conc == lv["conc"]) & (cdf.t_end >= w0) & (cdf.t_end < w1)] if len(cdf) else cdf
                    ok = sub[sub.ok == 1]
                    wsec = (w1 - w0) / 1000.0
                    n = len(sub)
                    srv_cpu = util(st, w0, w1); cli_cpu = util(ct, w0, w1)
                    load.append(dict(arm=arm, proto=proto, label=label, rtt=info["rtt"], tls_server="quic" if proto == "quic" else info["tls_server"],
                                     srv_cpus=info["srv_cpus"], sig=sig, kem=kem, block=blk, conc=lv["conc"], n=n, n_ok=len(ok),
                                     X=len(ok) / wsec if wsec > 0 else np.nan, fail=(n - len(ok)) / n if n else np.nan,
                                     app_med=ok.app_ms.median() if len(ok) else np.nan, app_mean=ok.app_ms.mean() if len(ok) else np.nan,
                                     hs_med=ok.hs_ms.median() if len(ok) else np.nan,
                                     util_srv=srv_cpu / wsec / info["srv_cpus"] if np.isfinite(srv_cpu) else np.nan,
                                     util_cli=cli_cpu / wsec / nproc if np.isfinite(cli_cpu) else np.nan,
                                     S_ms=1000.0 * srv_cpu / len(ok) if np.isfinite(srv_cpu) and len(ok) else np.nan,
                                     Scli_ms=1000.0 * cli_cpu / len(ok) if np.isfinite(cli_cpu) and len(ok) else np.nan))
            else:
                for r in parse_conn_log(lf):
                    r.update(arm=arm, proto=proto, label=label, sig=sig, kem=kem, block=blk, nblocks=nb, **{k: v for k, v in info.items()})
                    conn.append(r)
    cdf = pd.DataFrame(conn); ldf = pd.DataFrame(load)
    if len(cdf):
        cdf = cdf.rename(columns={"mode": "mode_planned"})
    if len(ldf):
        ldf["cli_bound"] = ldf.util_cli > 0.85
    return cdf, ldf


# ═════════════════════════════════════════════════════════════════════════════════════════════════════════════════
# 2. Bootstrap sur les blocs
# ═════════════════════════════════════════════════════════════════════════════════════════════════════════════════
class BlockTable:
    """Valeurs par bloc (lignes) x cles (colonnes). means() -> moyennes des blocs rechantillonnes (B x ncol)."""
    def __init__(self, df: pd.DataFrame, keycols, valcol):
        self.piv = df.groupby(["block"] + list(keycols))[valcol].median().unstack(list(keycols))
        self.cols = {k: i for i, k in enumerate(self.piv.columns)}
        self.X = self.piv.to_numpy(float)
        self.blocks = list(self.piv.index)

    def has(self, *keys): return all(k in self.cols for k in keys)

    def boot(self, B, rng):
        nb = self.X.shape[0]
        idx = rng.integers(0, nb, size=(B, nb))
        with np.errstate(all="ignore"):
            M = np.nanmean(self.X[idx], axis=1)          # B x ncol
            m0 = np.nanmean(self.X, axis=0)
        return m0, M

    def col(self, M, m0, key): return m0[self.cols[key]], M[:, self.cols[key]]


def ci(b):
    b = b[np.isfinite(b)]
    return (np.nan, np.nan) if len(b) < 20 else (float(np.percentile(b, 2.5)), float(np.percentile(b, 97.5)))


def slope(rtts, Y):           # Y : (..., len(rtts))
    r = np.asarray(rtts, float); rc = r - r.mean()
    Yc = Y - Y.mean(axis=-1, keepdims=True)
    return (Yc * rc).sum(axis=-1) / (rc ** 2).sum()


def verdict(lo, hi, a, b):
    if not (np.isfinite(lo) and np.isfinite(hi)): return "NA"
    if lo >= a and hi <= b: return "PASS"
    if hi < a or lo > b: return "FAIL"
    return "INCONCLUSIF"


def add_pred(pid, arm, desc, est, lo, hi, band, note=""):
    PRED.append(dict(id=pid, arm=arm, description=desc, estimate=est, ic_lo=lo, ic_hi=hi, band_lo=band[0], band_hi=band[1],
                     verdict=verdict(lo, hi, *band), note=note))


# ═════════════════════════════════════════════════════════════════════════════════════════════════════════════════
# 3. Reprise de session
# ═════════════════════════════════════════════════════════════════════════════════════════════════════════════════
def analyse_resume(cdf, out, B, rng):
    d = cdf[(cdf.res == 1) & (cdf.zrtt == 0)].copy()
    if d.empty:
        print("  (aucune donnee de reprise)"); return
    d["mode"] = np.where(d.resumed == 1, "res", "full")        # mode REEL (rapporte par le client), pas le mode prevu
    d = d[d.app_ms.notna()]
    d["loss"] = d["loss"].astype(float)
    ok_rate = d.groupby(["proto", "label", "sig", "kem", "mode"]).size().unstack("mode", fill_value=0)
    ok_rate.to_csv(os.path.join(out, "p6_resume_comptes.csv"))

    # Octets recus (deterministes) : medianes par cellule
    by = d.groupby(["proto", "rtt", "loss", "sig", "kem", "mode"]).agg(rx_med=("rx", "median"), tx_med=("tx", "median"),
                                                                       app_med=("app_ms", "median"), hs_med=("hs_ms", "median"), n=("app_ms", "size")).reset_index()
    by.to_csv(os.path.join(out, "p6_resume_cellules.csv"), index=False)

    rows = []
    for proto in sorted(d.proto.unique()):
        dp = d[d.proto == proto]
        for metric in ("app_ms", "hs_ms"):
            T = BlockTable(dp, ["loss", "rtt", "kem", "sig", "mode"], metric)
            m0, M = T.boot(B, rng)
            for kem in sorted(dp.kem.unique()):
                # --- 3a. D(RTT) = ML-DSA - ECDSA, perte nulle, pour chaque mode
                rtts = sorted(dp[(dp.loss == 0) & (dp.kem == kem)].rtt.unique())
                res_sl = {}
                for mode in ("full", "res"):
                    keys = [(0.0, r, kem, s, mode) for r in rtts for s in ("mldsa65", "secp384r1")]
                    if len(rtts) < 3 or not T.has(*keys): continue
                    D0 = np.array([T.col(M, m0, (0.0, r, kem, "mldsa65", mode))[0] - T.col(M, m0, (0.0, r, kem, "secp384r1", mode))[0] for r in rtts])
                    DB = np.stack([T.col(M, m0, (0.0, r, kem, "mldsa65", mode))[1] - T.col(M, m0, (0.0, r, kem, "secp384r1", mode))[1] for r in rtts], axis=1)
                    s0, sb = slope(rtts, D0), slope(rtts, DB); lo, hi = ci(sb)
                    res_sl[mode] = (s0, sb)
                    rows.append(dict(proto=proto, metric=metric, kem=kem, quantite="pente D(RTT) %s" % mode, estimate=s0, lo=lo, hi=hi, n_rtt=len(rtts)))
                if "full" in res_sl and "res" in res_sl:
                    s0 = res_sl["full"][0] - res_sl["res"][0]; sb = res_sl["full"][1] - res_sl["res"][1]; lo, hi = ci(sb)
                    rows.append(dict(proto=proto, metric=metric, kem=kem, quantite="pente D(RTT) full - res", estimate=s0, lo=lo, hi=hi, n_rtt=len(rtts)))
                    if metric == "app_ms" and kem == "x448_mlkem768":
                        if proto == "tls":
                            for mode in ("full", "res"):
                                e, b = res_sl[mode]; l, h = ci(b)
                                add_pred("R1-%s" % mode, "reprise", "TLS x448_mlkem768 : pente de D(RTT)=ML-DSA-ECDSA, mode %s, ~0" % mode, e, l, h, (-0.10, 0.10))
                        else:
                            e, b = res_sl["full"]; l, h = ci(b)
                            add_pred("R2-full", "reprise", "QUIC x448_mlkem768 : pente de D(RTT) en connexion complete ~1 (penalite ML-DSA = 1 RTT)", e, l, h, (0.80, 1.20))
                            e, b = res_sl["res"]; l, h = ci(b)
                            add_pred("R2-res", "reprise", "QUIC x448_mlkem768 : pente de D(RTT) en reprise ~0 (plus de certificat => plus de penalite)", e, l, h, (-0.15, 0.15))
                            add_pred("R2-diff", "reprise", "QUIC x448_mlkem768 : difference des pentes complete - reprise ~1", s0, lo, hi, (0.80, 1.20))
                # --- 3b. economie de la reprise (full - res), par signature, en ms, par RTT (perte nulle)
                for sig in ("secp384r1", "mldsa65"):
                    for r in rtts:
                        kf, kr = (0.0, r, kem, sig, "full"), (0.0, r, kem, sig, "res")
                        if not T.has(kf, kr): continue
                        e0 = T.col(M, m0, kf)[0] - T.col(M, m0, kr)[0]; eb = T.col(M, m0, kf)[1] - T.col(M, m0, kr)[1]; lo, hi = ci(eb)
                        rows.append(dict(proto=proto, metric=metric, kem=kem, quantite="economie full-res (ms) %s RTT%g" % (sig, r), estimate=e0, lo=lo, hi=hi, n_rtt=np.nan))
                # --- 3c. surcout CPU du KEM HQC (ECDSA, RTT 0) : identique en full et en reprise ? (psk_dhe_ke refait l'echange de cles)
                if kem == "hqc192" and metric == "app_ms":
                    k0 = {m: (0.0, 0.0, "hqc192", "secp384r1", m) for m in ("full", "res")}
                    q0 = {m: (0.0, 0.0, "x448_mlkem768", "secp384r1", m) for m in ("full", "res")}
                    if T.has(*k0.values(), *q0.values()):
                        sh = {m: (T.col(M, m0, k0[m])[0] - T.col(M, m0, q0[m])[0], T.col(M, m0, k0[m])[1] - T.col(M, m0, q0[m])[1]) for m in ("full", "res")}
                        for m in ("full", "res"):
                            l, h = ci(sh[m][1])
                            rows.append(dict(proto=proto, metric=metric, kem=kem, quantite="decalage HQC - ML-KEM (ms, RTT0, ECDSA) %s" % m, estimate=sh[m][0], lo=l, hi=h, n_rtt=np.nan))
                        e = sh["full"][0] - sh["res"][0]; b = sh["full"][1] - sh["res"][1]; l, h = ci(b)
                        add_pred("R3-%s" % proto, "reprise", "%s : le surcout CPU de HQC n'est pas economise par la reprise (decalage full - res ~0 ms)" % proto.upper(), e, l, h, (-3.0, 3.0))
            # --- 3d. pente en perte (RTT 50) du D : la reprise reduit-elle la sensibilite a la perte ? (QUIC, x448_mlkem768)
            if metric == "app_ms":
                kem = "x448_mlkem768"
                losses = sorted(dp[(dp.rtt == 50) & (dp.kem == kem)].loss.unique())
                if len(losses) >= 3:
                    sl = {}
                    for mode in ("full", "res"):
                        if not all(T.has((L, 50.0, kem, s, mode)) for L in losses for s in ("mldsa65", "secp384r1")): break
                        D0 = np.array([T.col(M, m0, (L, 50.0, kem, "mldsa65", mode))[0] - T.col(M, m0, (L, 50.0, kem, "secp384r1", mode))[0] for L in losses])
                        DB = np.stack([T.col(M, m0, (L, 50.0, kem, "mldsa65", mode))[1] - T.col(M, m0, (L, 50.0, kem, "secp384r1", mode))[1] for L in losses], axis=1)
                        sl[mode] = (slope(losses, D0), slope(losses, DB))
                    if len(sl) == 2:
                        e = sl["full"][0] - sl["res"][0]; b = sl["full"][1] - sl["res"][1]; l, h = ci(b)
                        rows.append(dict(proto=proto, metric=metric, kem=kem, quantite="pente en perte de D (ms par %) full - res, RTT50", estimate=e, lo=l, hi=h, n_rtt=len(losses)))
                        if proto == "quic":
                            add_pred("R5", "reprise", "QUIC : la reprise reduit la pente en perte de D=ML-DSA-ECDSA (full - res > 0)", e, l, h, (0.0, np.inf), note="sens seulement")
    pd.DataFrame(rows).to_csv(os.path.join(out, "p6_resume_contrastes.csv"), index=False)

    # --- 3e. octets : la reprise supprime le certificat et la signature
    rx = d[(d.loss == 0) & (d.kem == "x448_mlkem768")].groupby(["proto", "sig", "mode"]).rx.median().unstack("mode")
    if {"full", "res"} <= set(rx.columns):
        rx["ratio_res_full"] = rx["res"] / rx["full"]
        rx.reset_index().to_csv(os.path.join(out, "p6_resume_octets.csv"), index=False)
        for proto in rx.index.get_level_values(0).unique():
            if (proto, "mldsa65") not in rx.index: continue
            r = rx.loc[(proto, "mldsa65")]["ratio_res_full"]
            band = (0.0, 0.25) if proto == "tls" else (0.0, 0.30)
            add_pred("R4-%s" % proto, "reprise", "%s ML-DSA-65 : octets recus en reprise <= %d %% de ceux d'une connexion complete (le certificat ML-DSA disparait ; "
                     "pour ECDSA le certificat est petit, le ratio reste eleve : non teste)" % (proto.upper(), int(100 * band[1])), r, r, r, band,
                     note="valeur deterministe (mediane), sans IC")
    # --- 3f. taux de reprise reellement obtenue (R0 : la mesure n'a de sens que si les reprises prevues ont reellement eu lieu)
    for proto in sorted(d.proto.unique()):
        pl = d[(d.proto == proto) & (d.mode_planned == "resumed")]
        if len(pl):
            r = float((pl.resumed == 1).mean())
            add_pred("R0-%s" % proto, "reprise", "%s : >= 98 %% des connexions prevues en reprise ont reellement repris (ticket accepte)" % proto.upper(), r, r, r, (0.98, 1.0),
                     note="proportion globale ; voir p6_resume_taux_reprise.csv par cellule")
    ok = d.groupby(["proto", "label", "sig", "kem"]).apply(lambda g: pd.Series(dict(
        part_reprises=(g.resumed == 1).mean(), n=len(g)))).reset_index()
    ok.to_csv(os.path.join(out, "p6_resume_taux_reprise.csv"), index=False)


# ═════════════════════════════════════════════════════════════════════════════════════════════════════════════════
# 4. Compression de certificat
# ═════════════════════════════════════════════════════════════════════════════════════════════════════════════════
def analyse_comp(cdf, out, B, rng):
    d = cdf[cdf.comp != ""].copy()
    if d.empty:
        print("  (aucune donnee de compression)"); return
    d = d[d.app_ms.notna()]
    d["groupe"] = np.where(d["pad"] > 0, "ctl" + d["pad"].astype(int).astype(str), "chain" + d.chain.astype(int).astype(str))
    # tailles de messages Certificate observees sur le fil
    cm = d.groupby(["proto", "groupe", "sig", "kem", "comp"]).agg(rx_med=("rx", "median"), cert_type=("cert_type", "median"),
                                                                   cert_comp=("cert_comp", "median"), cert_plain=("cert_plain", "median"), n=("rx", "size")).reset_index()
    cm.to_csv(os.path.join(out, "p6_comp_octets.csv"), index=False)
    t = d[(d.proto == "tls") & d.cert_type.notna()]
    on = t[t.groupe.str.startswith("ctl") & t.comp.isin(["zlib", "brotli"])]
    off = t[t.comp == "none"]
    if len(on):
        r = float((on.cert_type == 25).mean())
        add_pred("C0-on", "compression", "TLS temoins ECDSA remplis, zlib/brotli : >= 98 % des Certificate sont compresses (type 25) : la compression est effective", r, r, r, (0.98, 1.0), note="verification de manipulation")
    if len(off):
        r = float((off.cert_type == 25).mean())
        add_pred("C0-off", "compression", "TLS bras 'none' : aucun Certificate compresse (<= 1 %)", r, r, r, (0.0, 0.01), note="verification de manipulation")
    rows = []
    for proto in sorted(d.proto.unique()):
        dp = d[d.proto == proto]
        Ta = BlockTable(dp, ["groupe", "rtt", "kem", "sig", "comp"], "app_ms")
        Tr = BlockTable(dp, ["groupe", "rtt", "kem", "sig", "comp"], "rx")
        ma0, Ma = Ta.boot(B, rng); mr0, Mr = Tr.boot(B, rng)
        for grp in sorted(dp.groupe.unique()):
            for kem in sorted(dp.kem.unique()):
                for sig in sorted(dp.sig.unique()):
                    rtts = sorted(dp[(dp.groupe == grp) & (dp.kem == kem) & (dp.sig == sig)].rtt.unique())
                    for alg in sorted(set(dp.comp.unique()) - {"none"}):
                        if not rtts or not all(Ta.has((grp, r, kem, sig, a)) for r in rtts for a in ("none", alg)): continue
                        # gain en octets (RTT le plus faible) -- deterministe
                        g0 = Tr.col(Mr, mr0, (grp, rtts[0], kem, sig, "none"))[0] - Tr.col(Mr, mr0, (grp, rtts[0], kem, sig, alg))[0]
                        gb = Tr.col(Mr, mr0, (grp, rtts[0], kem, sig, "none"))[1] - Tr.col(Mr, mr0, (grp, rtts[0], kem, sig, alg))[1]
                        gl, gh = ci(gb)
                        rows.append(dict(proto=proto, groupe=grp, kem=kem, sig=sig, alg=alg, quantite="gain octets recus", estimate=g0, lo=gl, hi=gh))
                        dT0 = np.array([Ta.col(Ma, ma0, (grp, r, kem, sig, alg))[0] - Ta.col(Ma, ma0, (grp, r, kem, sig, "none"))[0] for r in rtts])
                        dTB = np.stack([Ta.col(Ma, ma0, (grp, r, kem, sig, alg))[1] - Ta.col(Ma, ma0, (grp, r, kem, sig, "none"))[1] for r in rtts], axis=1)
                        for r, e, b in zip(rtts, dT0, dTB.T):
                            l, h = ci(b); rows.append(dict(proto=proto, groupe=grp, kem=kem, sig=sig, alg=alg, quantite="dT app (ms) RTT%g" % r, estimate=e, lo=l, hi=h))
                        if len(rtts) >= 2:
                            s0, sb = slope(rtts, dT0), slope(rtts, dTB); l, h = ci(sb)
                            rows.append(dict(proto=proto, groupe=grp, kem=kem, sig=sig, alg=alg, quantite="pente dT(RTT) = -delta k", estimate=s0, lo=l, hi=h))
                            if kem == "x448_mlkem768":
                                tag = "%s/%s/%s/%s" % (proto, grp, sig, alg)
                                if sig == "mldsa65" and grp in ("chain1", "chain2"):
                                    add_pred("C2:" + tag, "compression", "%s : ML-DSA-65 %s compresse (%s) ne change pas k (pente ~0)" % (proto.upper(), grp, alg), s0, l, h, (-0.15, 0.15))
                                    add_pred("C1:" + tag, "compression", "%s : gain en octets pour ML-DSA-65 %s (%s) <= 400 o (donnees quasi aleatoires)" % (proto.upper(), grp, alg), g0, gl, gh, (-10.0, 400.0))
                                if sig == "secp384r1" and grp == "ctl16000":
                                    add_pred("C3:" + tag, "compression", "%s : temoin ECDSA rempli a 16000 o, compression => k 1 -> 0 (pente ~ -1)" % proto.upper(), s0, l, h, (-1.30, -0.70))
                                if sig == "secp384r1" and grp == "ctl8700":
                                    if proto == "tls":
                                        add_pred("C4:" + tag, "compression", "TLS : temoin ECDSA 8700 o, k reste 0 (vol < IW10) : pente ~0", s0, l, h, (-0.15, 0.15))
                                    else:
                                        add_pred("C4:" + tag, "compression", "QUIC : temoin ECDSA 8700 o, compression => k 1 -> 0 (pente ~ -1)", s0, l, h, (-1.30, -0.70))
                        # cout CPU de la decompression (RTT le plus bas)
                        if sig == "mldsa65" and kem == "x448_mlkem768" and grp == "chain1":
                            l, h = ci(dTB[:, 0])
                            add_pred("C5:%s/%s" % (proto, alg), "compression", "%s : |dT| a RTT %g (cout CPU de la decompression) <= 0,5 ms" % (proto.upper(), rtts[0]), dT0[0], l, h, (-0.5, 0.5))
    pd.DataFrame(rows).to_csv(os.path.join(out, "p6_comp_contrastes.csv"), index=False)


# ═════════════════════════════════════════════════════════════════════════════════════════════════════════════════
# 5. Charge concurrente
# ═════════════════════════════════════════════════════════════════════════════════════════════════════════════════
def analyse_load(ldf, out, B, rng):
    if ldf.empty:
        print("  (aucune donnee de charge)"); return
    ldf.to_csv(os.path.join(out, "p6_load_niveaux.csv"), index=False)
    # garde : generateur de charge
    top = ldf[ldf.conc == ldf.conc.max()]
    part_ok = 1 - top.cli_bound.mean() if len(top) else np.nan
    print("  garde generateur : %.0f %% des niveaux c=%d ont un client < 85 %% de ses coeurs" % (100 * part_ok, ldf.conc.max()))
    PRED.append(dict(id="L0", arm="charge", description="garde : >= 90 % des niveaux de concurrence maximale ont un client non sature (< 85 % CPU)",
                     estimate=part_ok, ic_lo=part_ok, ic_hi=part_ok, band_lo=0.90, band_hi=1.0, verdict="PASS" if part_ok >= 0.9 else "FAIL",
                     note="si FAIL : donnees de saturation INUTILISABLES (le client est le goulot) -> ajouter des coeurs client"))
    good = ldf[~ldf.cli_bound].copy()
    # CPU serveur MARGINAL par connexion : pente de (CPU-s/s) sur X, sur les niveaux non satures (< 85 % CPU). L'ordonnee a l'origine
    # absorbe le CPU de fond ; S(c=1)=CPU/conn serait biaise par ce fond a faible debit.
    keys = ["proto", "tls_server", "rtt", "sig", "kem", "block"]
    smarg = {}
    for k, g in good.groupby(keys):
        gg = g[(g.util_srv < 0.85) & g.util_srv.notna() & (g.X > 0)]
        smarg[k] = 1000.0 * np.polyfit(gg.X, gg.util_srv * gg.srv_cpus, 1)[0] if gg.X.nunique() >= 3 else np.nan
    good["S_marg_ms"] = [smarg[tuple(r)] for r in good[keys].itertuples(index=False, name=None)]
    summ = good.groupby(["proto", "tls_server", "rtt", "sig", "kem", "conc"]).agg(
        X=("X", "mean"), app_med=("app_med", "mean"), hs_med=("hs_med", "mean"), fail=("fail", "mean"), util_srv=("util_srv", "mean"),
        util_cli=("util_cli", "mean"), S_ms=("S_ms", "mean"), S_marg_ms=("S_marg_ms", "mean"), Scli_ms=("Scli_ms", "mean"), n_blocs=("block", "nunique")).reset_index()
    summ.to_csv(os.path.join(out, "p6_load_resume.csv"), index=False)

    # table de blocs pour les statistiques de rapport
    def tab(df, v): return BlockTable(df, ["proto", "tls_server", "rtt", "sig", "kem", "conc"], v)
    TX, TA, TS, TU, TM = tab(good, "X"), tab(good, "app_med"), tab(good, "S_ms"), tab(good, "util_srv"), tab(good, "S_marg_ms")
    mx0, MX = TX.boot(B, rng); ma0, MA = TA.boot(B, rng); ms0, MS = TS.boot(B, rng); mu0, MU = TU.boot(B, rng); mm0, MM = TM.boot(B, rng)
    cmax = int(ldf.conc.max())
    rows = []

    def key(proto, srv, rtt, sig, kem, c): return (proto, srv, float(rtt), sig, kem, c)

    # L1 : la saturation est bien celle du CPU du serveur (utilisation mesuree) ; L1b : X(cmax) * S_marginal ~ 1
    for (proto, srv, rtt, sig, kem), g in good.groupby(["proto", "tls_server", "rtt", "sig", "kem"]):
        kc = key(proto, srv, rtt, sig, kem, cmax)
        if not (TX.has(kc) and TM.has(kc) and TU.has(kc)): continue
        eu, bu = TU.col(MU, mu0, kc); lu, hu = ci(bu)
        e = TX.col(MX, mx0, kc)[0] * TM.col(MM, mm0, kc)[0] / 1000.0
        b = TX.col(MX, mx0, kc)[1] * TM.col(MM, mm0, kc)[1] / 1000.0
        l, h = ci(b)
        rows.append(dict(proto=proto, srv=srv, rtt=rtt, sig=sig, kem=kem, quantite="utilisation CPU serveur a c=%d" % cmax, estimate=eu, lo=lu, hi=hu))
        rows.append(dict(proto=proto, srv=srv, rtt=rtt, sig=sig, kem=kem, quantite="X(c=%d) x S_marginal (1 = CPU serveur sature)" % cmax, estimate=e, lo=l, hi=h))
        if proto == "tls" and srv == "mt" and rtt == 0 and kem == "x448_mlkem768" and sig == "mldsa65":
            add_pred("L1", "charge", "TLS (MT) ML-DSA-65+ML-KEM-768, RTT 0 : utilisation CPU du serveur a c max dans [0.90, 1.05] (le serveur sature)", eu, lu, hu, (0.90, 1.05))
            add_pred("L1b", "charge", "TLS (MT) ML-DSA-65+ML-KEM-768, RTT 0 : X(c max) x S_marginal dans [0.85, 1.15] (debit sature = 1/CPU marginal)", e, l, h, (0.85, 1.15))
    # L2 : rapport des debits satures ML-KEM / HQC (ECDSA, TLS-MT, RTT0)
    for rtt in (0.0, 50.0):
        a, bk = key("tls", "mt", rtt, "secp384r1", "x448_mlkem768", cmax), key("tls", "mt", rtt, "secp384r1", "hqc192", cmax)
        if TX.has(a, bk):
            e = TX.col(MX, mx0, a)[0] / TX.col(MX, mx0, bk)[0]; bb = TX.col(MX, mx0, a)[1] / TX.col(MX, mx0, bk)[1]; l, h = ci(bb)
            rows.append(dict(proto="tls", srv="mt", rtt=rtt, sig="secp384r1", kem="x448_mlkem768/hqc192", quantite="X_sat(ML-KEM)/X_sat(HQC)", estimate=e, lo=l, hi=h))
            if rtt == 0:
                add_pred("L2", "charge", "TLS (MT) ECDSA, RTT 0 : X_sat(ML-KEM-768)/X_sat(HQC-192) dans [3.0, 4.6] (rapport des CPU serveur 51/13,5)", e, l, h, (3.0, 4.6))
    # L3 : effet de la signature sur le debit sature (ML-KEM, TLS-MT, RTT 0)
    a, bk = key("tls", "mt", 0.0, "mldsa65", "x448_mlkem768", cmax), key("tls", "mt", 0.0, "secp384r1", "x448_mlkem768", cmax)
    if TX.has(a, bk):
        e = TX.col(MX, mx0, a)[0] / TX.col(MX, mx0, bk)[0]; bb = TX.col(MX, mx0, a)[1] / TX.col(MX, mx0, bk)[1]; l, h = ci(bb)
        rows.append(dict(proto="tls", srv="mt", rtt=0.0, sig="mldsa65/secp384r1", kem="x448_mlkem768", quantite="X_sat(ML-DSA)/X_sat(ECDSA)", estimate=e, lo=l, hi=h))
        add_pred("L3", "charge", "TLS (MT) ML-KEM-768, RTT 0 : X_sat(ML-DSA-65)/X_sat(ECDSA P-384) dans [0.90, 1.20] (la signature pese peu face au KEM)", e, l, h, (0.90, 1.20))
    # L4 : QUIC, penalite ML-DSA : +1 RTT a c=1, mais noyee sous la file a forte charge
    for rtt in (50.0,):
        for kem in ("x448_mlkem768",):
            k1m, k1e = key("quic", "quic", rtt, "mldsa65", kem, 1), key("quic", "quic", rtt, "secp384r1", kem, 1)
            kcm, kce = key("quic", "quic", rtt, "mldsa65", kem, cmax), key("quic", "quic", rtt, "secp384r1", kem, cmax)
            if TA.has(k1m, k1e):
                e = TA.col(MA, ma0, k1m)[0] - TA.col(MA, ma0, k1e)[0]; bb = TA.col(MA, ma0, k1m)[1] - TA.col(MA, ma0, k1e)[1]; l, h = ci(bb)
                rows.append(dict(proto="quic", srv="quic", rtt=rtt, sig="mldsa65-secp384r1", kem=kem, quantite="D(c=1) ms", estimate=e, lo=l, hi=h))
                add_pred("L4a", "charge", "QUIC RTT 50, c=1 : D = R(ML-DSA) - R(ECDSA) dans [35, 65] ms (penalite = 1 RTT)", e, l, h, (35.0, 65.0))
            if TA.has(kcm, kce) and TX.has(kce, key("quic", "quic", rtt, "secp384r1", kem, max(1, cmax // 2))):
                Xc, Xh = TX.col(MX, mx0, kce), TX.col(MX, mx0, key("quic", "quic", rtt, "secp384r1", kem, max(1, cmax // 2)))
                sat = Xc[0] / Xh[0] < 1.15 if np.isfinite(Xh[0]) else False
                e = (TA.col(MA, ma0, kcm)[0] - TA.col(MA, ma0, kce)[0]) / TA.col(MA, ma0, kce)[0]
                bb = (TA.col(MA, ma0, kcm)[1] - TA.col(MA, ma0, kce)[1]) / TA.col(MA, ma0, kce)[1]; l, h = ci(bb)
                rows.append(dict(proto="quic", srv="quic", rtt=rtt, sig="mldsa65-secp384r1", kem=kem, quantite="D(c=%d)/R_ecdsa(c=%d)" % (cmax, cmax), estimate=e, lo=l, hi=h, note="sature" if sat else "NON sature"))
                if sat:
                    add_pred("L4b", "charge", "QUIC RTT 50, serveur sature : D(c max)/R_ECDSA(c max) <= 0.15 (la penalite RTT est noyee sous la file)", e, l, h, (-0.05, 0.15))
                else:
                    PRED.append(dict(id="L4b", arm="charge", description="QUIC RTT 50 : D(c max)/R <= 0.15 (si sature)", estimate=e, ic_lo=l, ic_hi=h, band_lo=-0.05, band_hi=0.15,
                                     verdict="NON TESTABLE", note="serveur QUIC non sature a c=%d : augmenter CONC_LEVELS" % cmax))
    # L5 : calibration serveur stock vs MT a c=1
    for rtt in (0.0, 50.0):
        for sig in ("secp384r1", "mldsa65"):
            for kem in ("x448_mlkem768", "hqc192"):
                a, bk = key("tls", "mt", rtt, sig, kem, 1), key("tls", "stock", rtt, sig, kem, 1)
                if TA.has(a, bk):
                    e = TA.col(MA, ma0, a)[0] - TA.col(MA, ma0, bk)[0]; bb = TA.col(MA, ma0, a)[1] - TA.col(MA, ma0, bk)[1]; l, h = ci(bb)
                    rows.append(dict(proto="tls", srv="mt-stock", rtt=rtt, sig=sig, kem=kem, quantite="calibration : app MT - stock a c=1 (ms)", estimate=e, lo=l, hi=h))
                    if kem == "x448_mlkem768":
                        add_pred("L5:%s/rtt%g" % (sig, rtt), "charge", "calibration RTT %g, %s : serveur MT equivalent au serveur stock a c=1 (|dApp| <= %s ms)" % (rtt, sig, "0,5" if rtt == 0 else "1"),
                                 e, l, h, (-0.5, 0.5) if rtt == 0 else (-1.0, 1.0))
                if TS.has(a, bk):
                    e = TS.col(MS, ms0, a)[0] / TS.col(MS, ms0, bk)[0]; bb = TS.col(MS, ms0, a)[1] / TS.col(MS, ms0, bk)[1]; l, h = ci(bb)
                    rows.append(dict(proto="tls", srv="mt/stock", rtt=rtt, sig=sig, kem=kem, quantite="calibration : CPU serveur par connexion MT/stock", estimate=e, lo=l, hi=h))
                    if kem == "x448_mlkem768" and sig == "mldsa65":
                        add_pred("L5cpu:rtt%g" % rtt, "charge", "calibration RTT %g : CPU serveur par connexion MT/stock dans [0.85, 1.15]" % rtt, e, l, h, (0.85, 1.15))
    # L6 : pas d'echec en dessous de la saturation
    low = good[good.conc <= 8]
    if len(low):
        f = low.groupby("block").fail.mean(); e = f.mean(); bb = rng.choice(f.to_numpy(), size=(B, len(f))).mean(axis=1); l, h = ci(bb)
        add_pred("L6", "charge", "taux d'echec moyen pour c <= 8 inferieur a 1 %", e, l, h, (0.0, 0.01))
    pd.DataFrame(rows).to_csv(os.path.join(out, "p6_load_contrastes.csv"), index=False)

    # modele ferme : X(c)=min(c/Rcyc0, 1/S), R(c) = max(R0, c*S - Z)
    mod = []
    for (proto, srv, rtt, sig, kem), g in summ.groupby(["proto", "tls_server", "rtt", "sig", "kem"]):
        g = g.set_index("conc")
        if 1 not in g.index or not np.isfinite(g.loc[1, "S_marg_ms"]): continue
        Rcyc0 = 1.0 / g.loc[1, "X"]; S = g.loc[1, "S_marg_ms"] / 1000.0; R0 = g.loc[1, "app_med"] / 1000.0; Z = max(0.0, Rcyc0 - R0)
        for c, r in g.iterrows():
            Xp = min(c / Rcyc0, 1.0 / S) if S > 0 else np.nan
            Rp = max(R0, c * S - Z)
            mod.append(dict(proto=proto, srv=srv, rtt=rtt, sig=sig, kem=kem, conc=c, X_obs=r.X, X_pred=Xp, X_err_pct=100 * (r.X - Xp) / Xp,
                            R_obs_ms=r.app_med, R_pred_ms=1000 * Rp, R_err_pct=100 * (r.app_med - 1000 * Rp) / (1000 * Rp), util_srv=r.util_srv, util_cli=r.util_cli))
    if mod:
        pd.DataFrame(mod).to_csv(os.path.join(out, "p6_load_modele.csv"), index=False)
    try:
        import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
        fig, ax = plt.subplots(1, 2, figsize=(10, 3.8))
        for (proto, srv, rtt, sig, kem), g in summ.groupby(["proto", "tls_server", "rtt", "sig", "kem"]):
            if rtt != 0.0 or kem != "x448_mlkem768": continue
            ax[0].plot(g.conc, g.X, marker="o", label="%s-%s %s" % (proto, srv, sig)); ax[1].plot(g.conc, g.app_med, marker="o")
        ax[0].set_xscale("log", base=2); ax[1].set_xscale("log", base=2); ax[1].set_yscale("log")
        ax[0].set_xlabel("concurrence c"); ax[0].set_ylabel("debit X (conn/s)"); ax[1].set_xlabel("concurrence c"); ax[1].set_ylabel("latence app (ms)")
        ax[0].legend(fontsize=7); fig.tight_layout(); fig.savefig(os.path.join(out, "p6_load_curves.pdf")); plt.close(fig)
    except Exception as e:
        print("  (figure non produite : %s)" % e)


# ═════════════════════════════════════════════════════════════════════════════════════════════════════════════════
# 6. Pont avec la campagne v2 (sentinelles) : l'image v3 ne doit pas avoir deplace la mesure de base
# ═════════════════════════════════════════════════════════════════════════════════════════════════════════════════
def analyse_bridge(cdf3, root2, out, B, rng):
    if not root2 or not os.path.isdir(root2): return
    c2, _ = walk(root2)
    if c2.empty or cdf3.empty: return
    s3 = cdf3[(cdf3.sentinel != "") & cdf3.app_ms.notna()].copy(); s2 = c2[(c2.sentinel != "") & c2.app_ms.notna()].copy()
    if s3.empty or s2.empty: print("  (pas de sentinelles comparables)"); return
    rows = []
    for (proto, sig, kem), g3 in s3.groupby(["proto", "sig", "kem"]):
        g2 = s2[(s2.proto == proto) & (s2.sig == sig) & (s2.kem == kem)]
        if g2.empty: continue
        b3 = g3.groupby(["arm", "block"]).app_ms.median().to_numpy(); b2 = g2.groupby(["arm", "block"]).app_ms.median().to_numpy()
        e = np.median(b3) - np.median(b2)
        bb = np.array([np.median(rng.choice(b3, len(b3))) - np.median(rng.choice(b2, len(b2))) for _ in range(B)]); l, h = ci(bb)
        rows.append(dict(proto=proto, sig=sig, kem=kem, delta_med_ms=e, lo=l, hi=h, n3=len(b3), n2=len(b2)))
        add_pred("B1:%s/%s" % (proto, sig), "pont v2", "sentinelle %s %s : mediane v3 - v2 dans +-0,5 ms (l'image v3 n'a pas deplace la mesure)" % (proto.upper(), sig), e, l, h, (-0.5, 0.5))
    pd.DataFrame(rows).to_csv(os.path.join(out, "p6_pont_v2.csv"), index=False)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True, nargs="+", help="un ou plusieurs dossiers de captures (un par bras : captures_v3_resume captures_v3_comp captures_v3_load)"); ap.add_argument("--out", default="analysis_v3")
    ap.add_argument("--v2-root", default=""); ap.add_argument("--boot", type=int, default=4000); ap.add_argument("--seed", type=int, default=20261027)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    rng = np.random.default_rng(a.seed)
    print("lecture de %s ..." % " ".join(a.root))
    parts = [walk(r) for r in a.root]
    cdf = pd.concat([c for c, _ in parts if len(c)], ignore_index=True) if any(len(c) for c, _ in parts) else pd.DataFrame()
    ldf = pd.concat([l for _, l in parts if len(l)], ignore_index=True) if any(len(l) for _, l in parts) else pd.DataFrame()
    print("  %d connexions (hors charge), %d niveaux de charge" % (len(cdf), len(ldf)))
    if len(cdf):
        cdf.to_csv(os.path.join(a.out, "p6_connexions.csv.gz"), index=False)
    print("== reprise ==");      analyse_resume(cdf, a.out, a.boot, rng) if len(cdf) else None
    print("== compression ==");  analyse_comp(cdf, a.out, a.boot, rng) if len(cdf) else None
    print("== charge ==");       analyse_load(ldf, a.out, a.boot, rng)
    print("== pont v2 ==");      analyse_bridge(cdf, a.v2_root, a.out, a.boot, rng)
    P = pd.DataFrame(PRED)
    if len(P):
        P.to_csv(os.path.join(a.out, "p6_predictions.csv"), index=False)
        print("\n== PREDICTIONS ENREGISTREES : verdicts ==")
        for _, r in P.iterrows():
            print("  [%-11s] %-22s %s  est=%.3f IC[%.3f ; %.3f] bande[%g ; %g]" % (r.verdict, r.id, r.description[:88], r.estimate, r.ic_lo, r.ic_hi, r.band_lo, r.band_hi))
        print("\nBILAN : %s" % dict(P.verdict.value_counts()))
    else:
        print("aucune prediction evaluable (donnees absentes)")


if __name__ == "__main__":
    main()
