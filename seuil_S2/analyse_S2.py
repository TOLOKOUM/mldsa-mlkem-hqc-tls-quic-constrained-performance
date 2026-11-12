#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""analyse_S2.py -- analyse CONFIRMATOIRE de la campagne S2 (interventions sur la capacite du premier tour), selon PREREGISTRATION_S2.md.
Copie de analyse_seuil.py (campagne S) ; differences (toutes declarees) : (i) E1 / E2 portent sur la ou les familles TLS / QUIC du dossier de gel donne (une famille par dossier),
avec les noms de regles lus dans predictions_frozen.csv ; (ii) E7 (rapport inter-KEM) supprime ; (iii) graine du bootstrap 20261113 ; (iv) figure generique.
Estimateur, bootstrap, seuils de decision (fraction >= 0,80 ET quantile 2,5 % >= 0,60), tolerance 0,25 : INCHANGES.
(Docstring d'origine :)

Entrees : l'arborescence produite par Launcher_ext.sh / run_campaign_ext.sh
    <root>/<proto>/<auth>/<label>/handshake_logs/handshake_<proto>_<auth>_<sig>_<kem>_<label>_block<k>of<N>[_mb<r>of<M>].log
et les predictions gelees (predictions_frozen.csv, thresholds_frozen.csv), dont l'empreinte sha256 est VERIFIEE avant toute lecture
des donnees (--sums SHA256SUMS_frozen.txt).

METHODE (inchangee par rapport a la v2) : l'unite d'inference est le BLOC (20). Pour chaque cellule (famille, taille de chaine X) :
    D_b(X, RTT) = mediane_b(app_ms | chaine remplie X) - mediane_b(app_ms | chaine de base), meme famille, meme signature, meme bloc, meme RTT
    k_b(X)      = [D_b(X, 150 ms) - D_b(X, 50 ms)] / 100 ms        (pente en RTT : nombre d'allers-retours ajoutes ; independante de D(0) et de T)
    k(X)        = moyenne des k_b sur les blocs ; IC95 % = bootstrap percentile sur les blocs (rechantillonnage JOINT de tous les blocs entiers).
Verdict par cellule et par regle r : PASS = IC95 % entierement dans [k_r - 0,25 ; k_r + 0,25] ; FAIL = entierement hors ; INCONCLUSIF sinon.
Critere d'echec/succes des points d'arret primaires : voir PREREGISTRATION_S.md (E1, E2, E3).

Usage :
    python3 analyse_seuil.py --root captures_S --pred freeze_S --out analysis_S [--boot 10000] [--metric app_ms|hs_ms]
    python3 analyse_seuil.py --selftest --out selftest_S      (donnees synthetiques ; ne necessite aucune campagne)
"""
from __future__ import annotations
import argparse, glob, hashlib, json, os, re, sys
import numpy as np
import pandas as pd

SIGS = ["secp384r1", "mldsa65", "ed25519", "mldsa44", "mldsa87", "secp521r1"]
TOL = 0.25
SEED = 20261113
RTTS = (50, 150)
MIN_BLOCKS = 15
NUM = r"([0-9]+(?:\.[0-9]+)?|NaN)"


# ═══════════════════════════════════════════════════════════════════════════════════════ lecture
def fnum(x):
    return np.nan if x in (None, "NaN") else float(x)


def parse_conn_log(path):
    rows, cur = [], None
    with open(path, errors="replace") as f:
        for ln in f:
            ln = ln.rstrip("\n")
            m = re.match(r"^Execution (\S+) - (TLS|QUIC) (Single|Mutual)", ln)
            if m:
                if cur is not None:
                    rows.append(cur)
                cur = dict(idx=m.group(1), rx=np.nan, hs_ms=np.nan, app_ms=np.nan)
                continue
            if cur is None:
                continue
            for key, pat in (("rx", r"^Rx-bytes: (\d+)"), ("hs_ms", r"^Handshake duration: " + NUM), ("app_ms", r"^App-ready duration: " + NUM)):
                m = re.match(pat, ln)
                if m:
                    cur[key] = fnum(m.group(1))
                    break
    if cur is not None:
        rows.append(cur)
    return rows


def split_name(fname, proto, auth, label):
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


def parse_label(label):
    d = dict(rtt=np.nan, mtu=1500, pad=0, pcap=False, loss=False)
    m = re.search(r"delay(\d+(?:\.\d+)?)ms", label)
    d["rtt"] = 2 * float(m.group(1)) if m else (0.0 if label.startswith("none") else np.nan)
    m = re.search(r"_mtu(\d+)", label)
    if m:
        d["mtu"] = int(m.group(1))
    m = re.search(r"__padto(\d+)", label)
    if m:
        d["pad"] = int(m.group(1))
    d["pcap"] = "__pcap" in label
    d["loss"] = bool(re.search(r"loss\d", label))
    return d


def walk(roots):
    out = []
    for root in roots:
        for ldir in sorted(glob.glob(os.path.join(root, "*", "*", "*"))):
            if not os.path.isdir(ldir):
                continue
            label = os.path.basename(ldir)
            auth = os.path.basename(os.path.dirname(ldir))
            proto = os.path.basename(os.path.dirname(os.path.dirname(ldir)))
            if proto not in ("tls", "quic") or label.startswith("simple_loss") or "sentinel" in label:
                continue
            info = parse_label(label)
            for lf in sorted(glob.glob(os.path.join(ldir, "handshake_logs", "*.log"))):
                sp = split_name(lf, proto, auth, label)
                if sp is None:
                    continue
                sig, kem, blk, nb = sp
                for r in parse_conn_log(lf):
                    r.update(proto=proto, label=label, sig=sig, kem=kem, block=blk, nblocks=nb, **info)
                    out.append(r)
    return pd.DataFrame(out)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def verify_freeze(pred_dir, sums_file=None):
    sums_file = sums_file or os.path.join(pred_dir, "SHA256SUMS_frozen.txt")
    ok = True
    for ln in open(sums_file):
        h, n = ln.split()
        got = sha256(os.path.join(pred_dir, n))
        if got != h:
            ok = False
            print("[!!] empreinte differente pour %s : attendu %s, calcule %s" % (n, h, got))
    return ok


# ═══════════════════════════════════════════════════════════════════════════════════════ statistiques
def verdict(lo, hi, a, b):
    if not (np.isfinite(lo) and np.isfinite(hi)):
        return "NA"
    if lo >= a and hi <= b:
        return "PASS"
    if hi < a or lo > b:
        return "FAIL"
    return "INCONCLUSIF"


def pct(b, q):
    b = b[np.isfinite(b)]
    return float(np.percentile(b, q)) if len(b) >= 100 else np.nan


class Frame:
    """Tables par bloc : med[(fam,sig,pad,rtt)] -> Series indexee par bloc."""

    def __init__(self, df, fams, metric):
        df = df.copy()
        df["family"] = [fam_of(r.proto, r.kem, r.mtu, fams) for r in df.itertuples()]
        df = df[df.family.notna() & ~df.pcap]
        self.df = df
        g = df[df[metric].notna()].groupby(["family", "sig", "pad", "rtt", "block"])[metric].median()
        self.med = {k: v.droplevel([0, 1, 2, 3]) for k, v in g.groupby(level=[0, 1, 2, 3])}
        self.blocks = sorted(df.block.unique())

    def series(self, fam, sig, pad, rtt):
        return self.med.get((fam, sig, pad, float(rtt)), pd.Series(dtype=float)).reindex(self.blocks)


def fam_of(proto, kem, mtu, fams):
    for name, f in fams.items():
        if f["proto"] == proto and f["kem"] == kem and int(f["mtu"]) == int(mtu):
            return name
    return None


def k_per_block(F, fam, sig, pad, base_sig, lo=RTTS[0], hi=RTTS[1]):
    d = {}
    for r in (lo, hi):
        d[r] = F.series(fam, sig, pad, r) - F.series(fam, base_sig, 0, r)
    return ((d[hi] - d[lo]) / (hi - lo)).to_numpy(float)


def boot_means(K, B, rng):
    """K : blocs x cellules -> (estimation, replicats B x cellules) ; rechantillonnage JOINT des blocs."""
    nb = K.shape[0]
    idx = rng.integers(0, nb, size=(B, nb))
    with np.errstate(all="ignore"):
        est = np.nanmean(K, axis=0)
        M = np.nanmean(K[idx], axis=1)
    nvalid = np.isfinite(K).sum(axis=0)
    est[nvalid < MIN_BLOCKS] = np.nan
    M[:, nvalid < MIN_BLOCKS] = np.nan
    return est, M, nvalid


# ═══════════════════════════════════════════════════════════════════════════════════════ analyse
def analyse(df, pred_dir, out, B, metric, log):
    pred = pd.read_csv(os.path.join(pred_dir, "predictions_frozen.csv"))
    thr = pd.read_csv(os.path.join(pred_dir, "thresholds_frozen.csv"))
    const = json.load(open(os.path.join(pred_dir, "constants_frozen.json")))
    fams = const["FAMILIES"]
    F = Frame(df, fams, metric)
    rng = np.random.default_rng(SEED)

    cells = pred[pred.kind.isin(["pad", "bridge"])].reset_index(drop=True)
    cols, meta = [], []
    for r in cells.itertuples():
        base_sig = fams[r.family]["sig"]
        cols.append(k_per_block(F, r.family, r.sig, int(r.chain_target), base_sig))
    K = np.column_stack(cols) if cols else np.empty((len(F.blocks), 0))
    est, M, nvalid = boot_means(K, B, rng)
    cells["khat"] = est
    cells["ci_lo"] = [pct(M[:, j], 2.5) for j in range(M.shape[1])]
    cells["ci_hi"] = [pct(M[:, j], 97.5) for j in range(M.shape[1])]
    cells["n_blocks"] = nvalid
    cells["verdict_a"] = [verdict(r.ci_lo, r.ci_hi, r.k_a - TOL, r.k_a + TOL) for r in cells.itertuples()]
    cells["verdict_b"] = [verdict(r.ci_lo, r.ci_hi, r.k_b - TOL, r.k_b + TOL) for r in cells.itertuples()]
    cells["nearest_integer"] = np.rint(cells.khat)
    # taux d'echec et octets recus (controle de taille) par cellule, tous RTT confondus
    d = F.df
    fr, rx = [], []
    for r in cells.itertuples():
        x = d[(d.family == r.family) & (d.sig == r.sig) & (d["pad"] == int(r.chain_target))]
        fr.append(float(x[metric].isna().mean()) if len(x) else np.nan)
        rx.append(float(x.rx.median()) if len(x) else np.nan)
    cells["fail_rate"] = fr
    cells["rx_median"] = rx
    cells["rx_err_a"] = cells.rx_median - cells.flight_a
    cells.to_csv(os.path.join(out, "S2_cells.csv"), index=False)

    P = lambda s="": log(s)

    # ------------------------------------------------------------------ E1 / E2 : cellules discriminantes primaires
    def endpoint(name, fam_list, ra, rb, bridge=False):
        sel = cells[(cells.family.isin(fam_list)) & (cells.disc == 1) & (cells.tier == "primary") & (cells.kind == "pad")]
        ix = sel.index.to_numpy()
        n = len(ix)
        if n == 0:
            P("%s : aucune cellule" % name); return None
        ka, kb = sel.k_a.to_numpy(float), sel.k_b.to_numpy(float)
        ok_a_boot = (np.abs(M[:, ix] - ka) <= TOL)
        ok_b_boot = (np.abs(M[:, ix] - kb) <= TOL)
        valid = np.isfinite(M[:, ix]).all(axis=1)
        fa_boot = ok_a_boot[valid].mean(axis=1)
        fb_boot = ok_b_boot[valid].mean(axis=1)
        fa = float((np.abs(sel.khat.to_numpy(float) - ka) <= TOL).mean())
        fb = float((np.abs(sel.khat.to_numpy(float) - kb) <= TOL).mean())
        res = dict(endpoint=name, n_cells=n, rule_a=ra, rule_b=rb, frac_a=fa, frac_a_lo=pct(fa_boot, 2.5), frac_a_hi=pct(fa_boot, 97.5),
                   frac_b=fb, frac_b_lo=pct(fb_boot, 2.5), frac_b_hi=pct(fb_boot, 97.5),
                   pass_a=int((sel.verdict_a == "PASS").sum()), pass_b=int((sel.verdict_b == "PASS").sum()))
        # decision FIGEE : confirme si fraction observee >= 0,80 ET quantile 2,5 % du bootstrap >= 0,60
        conf_a = res["frac_a"] >= 0.80 and res["frac_a_lo"] >= 0.60
        conf_b = res["frac_b"] >= 0.80 and res["frac_b_lo"] >= 0.60
        res["decision"] = ("%s CONFIRMEE" % ra) if conf_a and not conf_b else ("%s CONFIRMEE" % rb) if conf_b and not conf_a else "AUCUNE REGLE CONFIRMEE"
        return res

    ends = []
    tls_f = [f for f in fams if fams[f]["proto"] == "tls"]
    quic_f = [f for f in fams if fams[f]["proto"] == "quic"]
    rn = lambda fl: (cells[cells.family.isin(fl)].rule_a.iloc[0], cells[cells.family.isin(fl)].rule_b.iloc[0]) if len(cells[cells.family.isin(fl)]) else ("a", "b")
    e1 = endpoint("E1 TLS (cellules discriminantes primaires)", tls_f, *rn(tls_f)) if tls_f else None
    e2 = endpoint("E2 QUIC (cellules discriminantes primaires)", quic_f, *rn(quic_f)) if quic_f else None
    for e in (e1, e2):
        if e:
            ends.append(e)

    # ------------------------------------------------------------------ E3 : cellules non discriminantes primaires (escalier)
    sel = cells[(cells.disc == 0) & (cells.tier == "primary") & (cells.kind == "pad")]
    if len(sel):
        ok = (np.abs(sel.khat - sel.k_a) <= TOL)
        ends.append(dict(endpoint="E3 cellules non discriminantes primaires (toutes les regles s'accordent)", n_cells=len(sel),
                         frac_a=float(ok.mean()), pass_a=int((sel.verdict_a == "PASS").sum()),
                         decision="CONFORME" if ok.mean() >= 0.90 else "NON CONFORME"))
    # ------------------------------------------------------------------ garde : E1/E2 ne sont interpretables que si l'escalier de base est reproduit (E3)
    e3 = [e for e in ends if e["endpoint"].startswith("E3")]
    if e3 and e3[0]["decision"] != "CONFORME":
        for e in ends:
            if e["endpoint"].startswith(("E1", "E2")):
                e["decision"] = "NON INTERPRETABLE (E3 non conforme : " + e["decision"] + ")"
    # ------------------------------------------------------------------ E4 : paliers superieurs (k >= 2), secondaires
    sel = cells[(cells.tier == "secondary") & (cells.kind == "pad")]
    if len(sel):
        ends.append(dict(endpoint="E4 (secondaire) cellules a palier k>=2 : fraction proche de la regle a / b", n_cells=len(sel),
                         frac_a=float((np.abs(sel.khat - sel.k_a) <= TOL).mean()), frac_b=float((np.abs(sel.khat - sel.k_b) <= TOL).mean()),
                         pass_a=int((sel.verdict_a == "PASS").sum()), pass_b=int((sel.verdict_b == "PASS").sum()), decision="descriptif"))
    # ------------------------------------------------------------------ E5 : monotonie
    viol = []
    for fam, g in cells[cells.kind == "pad"].groupby("family"):
        g = g.sort_values("chain_target")
        v = np.diff(g.khat.to_numpy(float))
        viol.append(dict(family=fam, max_decrease=float(-np.nanmin(v)) if len(v) else np.nan, n_decreases_gt_0_10=int((v < -0.10).sum())))
    mono = pd.DataFrame(viol)
    # ------------------------------------------------------------------ E6 : encadrement des seuils
    br = []
    for fam, g in cells[cells.kind == "pad"].groupby("family"):
        g = g.sort_values("chain_target")
        for step in (1, 2):
            below = g[(g.ci_hi < step - 0.5)]
            above = g[(g.ci_lo > step - 0.5)]
            lo_x = float(below.chain_target.max()) if len(below) else np.nan
            hi_x = float(above[above.chain_target > (lo_x if np.isfinite(lo_x) else -1)].chain_target.min()) if len(above) else np.nan
            row = dict(family=fam, step=step, bracket_low=lo_x, bracket_high=hi_x)
            for t in thr[(thr.family == fam) & (thr.step == step)].itertuples():
                row["pred_%s" % t.rule] = t.chain_threshold
                row["inside_%s" % t.rule] = bool(np.isfinite(lo_x) and np.isfinite(hi_x) and lo_x < t.chain_threshold <= hi_x)
            br.append(row)
    brk = pd.DataFrame(br)
    # ------------------------------------------------------------------ E7 : rapport des seuils (octets de vol) QUIC_A / QUIC_B, etape 1
    e7 = None   # E7 (rapport inter-KEM) : sans objet en S2

    # ------------------------------------------------------------------ controles
    ctl = []
    # C1 placebo : base contre base, connexions paires contre impaires (indice d'execution)
    for fam, f in fams.items():
        x = d[(d.family == fam) & (d.sig == f["sig"]) & (d["pad"] == 0)].copy()
        if x.empty:
            continue
        x["par"] = pd.to_numeric(x.idx, errors="coerce") % 2
        g = x[x[metric].notna()].groupby(["rtt", "block", "par"])[metric].median().unstack("par")
        if not {0, 1}.issubset(g.columns):
            continue
        dd = (g[0] - g[1]).unstack("rtt")
        if not set(RTTS).issubset(dd.columns):
            continue
        kb = ((dd[RTTS[1]] - dd[RTTS[0]]) / (RTTS[1] - RTTS[0])).reindex(F.blocks).to_numpy(float)
        e, Mp, nv = boot_means(kb[:, None], B, rng)
        lo, hi = pct(Mp[:, 0], 2.5), pct(Mp[:, 0], 97.5)
        ctl.append(dict(control="C1 placebo (base paire vs impaire)", family=fam, estimate=float(e[0]), ci_lo=lo, ci_hi=hi,
                        band="[-0.05, 0.05]", verdict=verdict(lo, hi, -0.05, 0.05)))
    # C2 pont : signature post-quantique sans remplissage
    for r in cells[cells.kind == "bridge"].itertuples():
        ctl.append(dict(control="C2 pont %s (k_a=%d, k_b=%d)" % (r.sig, r.k_a, r.k_b), family=r.family, estimate=r.khat, ci_lo=r.ci_lo, ci_hi=r.ci_hi,
                        band="a:[%.2f,%.2f] b:[%.2f,%.2f]" % (r.k_a - TOL, r.k_a + TOL, r.k_b - TOL, r.k_b + TOL),
                        verdict="a:%s b:%s" % (r.verdict_a, r.verdict_b)))
    # C3 controle de taille : octets recus contre vol predit
    pads = cells[cells.kind == "pad"]
    for fam, g in pads.groupby("family"):
        tol = 10.0 if fams[fam]["proto"] == "tls" else None
        if fams[fam]["proto"] == "tls":
            ok = (g.rx_err_a.abs() <= tol)
            ctl.append(dict(control="C3 octets recus = vol predit +-10 o (TLS)", family=fam, estimate=float(ok.mean()), ci_lo=np.nan, ci_hi=np.nan,
                            band=">=0.95 des cellules", verdict="PASS" if ok.mean() >= 0.95 else "FAIL"))
        else:
            rel = (g.rx_err_a / g.flight_a).abs()
            ctl.append(dict(control="C3 octets recus = vol predit +-3 % (QUIC)", family=fam, estimate=float((rel <= 0.03).mean()), ci_lo=np.nan, ci_hi=np.nan,
                            band=">=0.95 des cellules", verdict="PASS" if (rel <= 0.03).mean() >= 0.95 else "FAIL"))
    # C4 qualite : taux d'echec
    ctl.append(dict(control="C4 taux d'echec maximal par cellule (<= 2 %)", family="toutes", estimate=float(np.nanmax(cells.fail_rate)) if len(cells) else np.nan,
                    ci_lo=np.nan, ci_hi=np.nan, band="<=0.02", verdict="PASS" if (len(cells) and np.nanmax(cells.fail_rate) <= 0.02) else "A SIGNALER"))
    ctl = pd.DataFrame(ctl)

    # ------------------------------------------------------------------ sorties
    pd.DataFrame(ends).to_csv(os.path.join(out, "S_endpoints.csv"), index=False)
    brk.to_csv(os.path.join(out, "S_brackets.csv"), index=False)
    ctl.to_csv(os.path.join(out, "S_controls.csv"), index=False)
    mono.to_csv(os.path.join(out, "S_monotonicity.csv"), index=False)

    P("\n=================== RESULTATS CONFIRMATOIRES (metrique : %s, %d blocs, %d replicats) ===================" % (metric, len(F.blocks), B))
    for e in ends:
        P("\n%s  [n = %d]" % (e["endpoint"], e["n_cells"]))
        for k, v in e.items():
            if k in ("endpoint", "n_cells"):
                continue
            P("   %-12s %s" % (k, ("%.3f" % v) if isinstance(v, float) else v))
    P("\n--- E5 monotonie ---\n" + mono.to_string(index=False))
    P("\n--- E6 encadrement des seuils (tailles de chaine, octets) ---\n" + brk.to_string(index=False))
    P("\n--- E7 rapport des seuils QUIC_A / QUIC_B (octets de vol) ---\n   %s" % e7)
    P("\n--- Controles ---\n" + ctl.to_string(index=False))
    show = cells[cells.kind == "pad"][["family", "chain_target", "tier", "disc", "k_a", "k_b", "khat", "ci_lo", "ci_hi", "verdict_a", "verdict_b", "fail_rate"]]
    P("\n--- Cellules (k observe contre k predit) ---\n" + show.to_string(index=False, float_format=lambda x: "%.3f" % x))
    figure(cells, thr, out)
    return dict(cells=cells, ends=ends, brackets=brk, controls=ctl)


def figure(cells, thr, out):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception:
        return
    fams = sorted(set(cells.family))
    fig, axs = plt.subplots(2, 2, figsize=(10, 6.5), constrained_layout=True)
    for ax, fam in zip(axs.ravel(), fams):
        g = cells[(cells.family == fam) & (cells.kind == "pad")].sort_values("chain_target")
        ax.step(g.chain_target, g.k_a, where="post", color="#d95f02", lw=1.4, label="règle a (%s)" % g.rule_a.iloc[0])
        ax.step(g.chain_target, g.k_b, where="post", color="#1b9e77", lw=1.4, ls="--", label="règle b (%s)" % g.rule_b.iloc[0])
        ax.errorbar(g.chain_target, g.khat, yerr=[g.khat - g.ci_lo, g.ci_hi - g.khat], fmt="o", color="k", ms=3.5, capsize=2, label="k observé (IC 95 %)")
        ax.set_title(fam); ax.set_xlabel("chaîne remplie (octets DER)"); ax.set_ylabel("k = allers-retours ajoutés")
        ax.set_xscale("log"); ax.set_ylim(-0.4, 2.6); ax.grid(alpha=0.3)
    axs[0, 0].legend(fontsize=7, loc="upper left")
    fig.savefig(os.path.join(out, "S2_staircase.pdf"))
    plt.close(fig)


# ═══════════════════════════════════════════════════════════════════════════════════════ donnees synthetiques (test de l'analyse)
def make_synthetic(root, pred_dir, world, n_blocks=20, per_block=10, seed=1, sd_conn=4.0, sd_block=1.0):
    """world : 'b' (la regle b est vraie), 'a' (la regle a), 'shift' (ni l'une ni l'autre : seuil decale de +700 o), 'flat' (k=0 partout)"""
    rng = np.random.default_rng(seed)
    pred = pd.read_csv(os.path.join(pred_dir, "predictions_frozen.csv"))
    const = json.load(open(os.path.join(pred_dir, "constants_frozen.json")))
    thr = pd.read_csv(os.path.join(pred_dir, "thresholds_frozen.csv"))

    def k_true(r):
        if world == "a": return r.k_a
        if world == "b": return r.k_b
        if world == "flat": return 0
        # shift : la regle b avec seuils decales de +700 o (ni a ni b ne sont exactes)
        t = thr[(thr.family == r.family) & (thr.rule == r.rule_b)]
        return int(sum(1 for x in t.itertuples() if r.chain_target > 0 and r.chain_target >= x.chain_threshold + 700)) if r.kind == "pad" else r.k_b
    blk_eff = {}
    for _, r in pred.iterrows():
        proto = r.proto
        for rtt in RTTS:
            delay = rtt // 2
            label = "delayonly_delay%dms" % delay + ("_mtu%d" % r.mtu if r.mtu != 1500 else "") + ("__padto%d" % r.chain_target if r.chain_target else "") + "__mb2"
            d = os.path.join(root, proto, "single", label, "handshake_logs")
            os.makedirs(d, exist_ok=True)
            kt = k_true(r)
            for b in range(1, n_blocks + 1):
                eff = blk_eff.setdefault((r.family, rtt, b), rng.normal(0, sd_block))   # effet de bloc partage entre cellules d'une meme famille/RTT/bloc
                for mb in (1, 2):
                    fn = "handshake_%s_single_%s_%s_%s_block%dof%d_mb%dof2.log" % (proto, r.sig, r.kem, label, b, n_blocks, mb)
                    with open(os.path.join(d, fn), "w") as f:
                        f.write("Warm-up: 5\n")
                        for i in range(1, per_block // 2 + 1):
                            hs = 30 + (2 if proto == "tls" else 1) * rtt + kt * rtt + eff + rng.normal(0, sd_conn)
                            app = hs + 2 * rtt * 0 + 0.5 + rng.normal(0, 0.3)
                            f.write("Execution %d - %s Single\nMode: %s\nRx-bytes: %d\nHandshake duration: %.2f ms\nApp-ready duration: %.2f ms\n" % (
                                i, proto.upper(), "full", int(round(r.flight_a)), hs, app))
    return root


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", nargs="+")
    ap.add_argument("--pred", default="freeze_S")
    ap.add_argument("--sums", default=None)
    ap.add_argument("--out", default="analysis_S")
    ap.add_argument("--boot", type=int, default=10000)
    ap.add_argument("--metric", default="app_ms", choices=["app_ms", "hs_ms"])
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--world", default="b", choices=["a", "b", "shift", "flat"])
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    lines = []

    def log(s=""):
        print(s, flush=True); lines.append(str(s))

    if not verify_freeze(a.pred, a.sums):
        sys.exit("ARRET : les predictions ne correspondent plus aux empreintes gelees.")
    log("Empreintes gelees verifiees.")
    if a.selftest:
        root = os.path.join(a.out, "synthetic_%s" % a.world)
        make_synthetic(root, a.pred, a.world)
        a.root = [root]
    if not a.root:
        sys.exit("--root requis")
    df = walk(a.root)
    if df.empty:
        sys.exit("aucune donnee lue")
    log("connexions lues : %d ; blocs : %s" % (len(df), sorted(df.block.unique())[:3]))
    analyse(df, a.pred, a.out, a.boot, a.metric, log)
    with open(os.path.join(a.out, "S2_report.txt"), "w") as f:
        f.write("\n".join(lines))


if __name__ == "__main__":
    main()
