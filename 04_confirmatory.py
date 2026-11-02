#!/usr/bin/env python3
"""04_confirmatory.py -- PHASE 2 : contrastes confirmatoires sur la campagne captures_v2 (20 blocs).

Entrees  (produites par 01_ingest.py / 02_qc.py) : conn.csv.gz, visits.csv, visit_flags.csv
Sorties  : p2_*.csv et p2_report.txt dans --out

PRINCIPES (a figer avant de regarder les effets)
  * Unite statistique = le BLOC (20). Chaque contraste est calcule bloc par bloc (moyenne d'app_ms dans le bloc, par cellule x paire),
    puis resume sur les blocs : moyenne, IC95 bootstrap par blocs, p exacte d'inversion de signe, Hodges-Lehmann en sensibilite.
  * Metrique primaire : duree app-ready (app_ms), commune a TLS et QUIC. hs_ms n'est PAS compare entre protocoles.
  * Population d'analyse primaire : toutes les visites sauf exclusions DURES de la phase 1 (visit_flags.hard_excluded).
  * Preuve a deux niveaux (colonne `evidence`) :
        ROBUSTE   : QUIC (toutes cellules) et TLS sans perte (delai seul) -> le processus de perte emule est conforme.
        SECONDAIRE: TLS avec perte -> 'perte groupee par super-paquet' (defaut GSO documente, voir rapport phase 1) ;
                    l'intensite de perte TLS n'est pas i.i.d. par paquet et n'est PAS comparable a celle de QUIC.
  * Aucune comparaison TLS-vs-QUIC 'a perte egale'. Les contrastes TLS-vs-QUIC ne portent que sur les cellules sans perte.
  * Multiplicite : Holm au sein de chaque famille de contrastes (proto x auth x profil), BH sur l'ensemble (exploratoire).
  * Sensibilites : sans visites 'soft', sans noyau minoritaire (visit_flags.kernel_minor), sans bloc 20, defaillances imputees au
    delai d'expiration (RMST au delai), mediane par bloc, Hodges-Lehmann, effet relatif (log-ratio).

Usage : python3 04_confirmatory.py --in analysis_v2 --out analysis_v2/phase2
"""
from __future__ import annotations
import argparse, os, sys, time, warnings
import numpy as np
import pandas as pd
from scipy import stats

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pq_common import (SIGS, kem_info, paired_summary, signflip_exact, boot_ci, holm, bh, demean, pct)

warnings.filterwarnings("ignore", category=FutureWarning)
KEY = ["proto", "auth", "label", "block", "round", "sig", "kem"]
PROFILES = ["ideal", "moderate", "degraded"]
LEVEL_KEMS = {"L1": ["P-256", "x25519", "p256_mlkem512", "x25519_mlkem512", "mlkem512", "hqc128", "p256_hqc128", "x25519_hqc128"],
              "L3": ["P-384", "x448", "p384_mlkem768", "x448_mlkem768", "mlkem768", "hqc192", "p384_hqc192", "x448_hqc192"],
              "L5": ["P-521", "p521_mlkem1024", "mlkem1024", "hqc256", "p521_hqc256"]}
CLASSICAL_OF = {"L1": "ed25519", "L3": "secp384r1", "L5": "secp521r1"}
MLDSA_OF = {"L1": "mldsa44", "L3": "mldsa65", "L5": "mldsa87"}
B_BOOT = 10000


def log(msg):
    print(msg, flush=True)
    REP.append(msg)


REP: list[str] = []


# ----------------------------------------------------------------------------------------------- chargement
def load(indir):
    c = pd.read_csv(os.path.join(indir, "conn.csv.gz"), low_memory=False)
    fl = pd.read_csv(os.path.join(indir, "visit_flags.csv"))
    opt = ["hard_excluded", "soft_flagged", "kernel_minor", "warmup_timeout", "thermal_hot", "load_high", "duration_outlier"]
    for k in opt:                       # tolere un visit_flags.csv produit par une version anterieure de 02_qc.py
        if k not in fl.columns:
            fl[k] = False
    c = c.merge(fl[KEY + opt], on=KEY, how="left", validate="many_to_one")
    for k in ["hard_excluded", "soft_flagged", "kernel_minor"]:
        c[k] = c[k].fillna(False).astype(bool)
    c["cellkey"] = [cid.replace("_" + p + "_", "_", 1) for cid, p in zip(c.cell_id, c.proto)]
    c["profile"] = np.where(c.family == "main", c.cell_id.str.split("_").str[-1], "")
    c["timeout_ms"] = c.timeout_s.fillna(150.0) * 1000.0
    c["lossy"] = c.loss_nom.fillna(0) > 0
    # niveau de preuve
    c["evidence"] = np.where((c.proto == "tls") & c.lossy, "SECONDAIRE_tls_perte_groupee", "ROBUSTE")
    return c


def scenario(c, name):
    """Retourne (df, colonne de duree) pour un scenario de sensibilite."""
    d = c[~c.hard_excluded].copy()
    d["y"] = d.app_ms
    if name == "primary":
        pass
    elif name == "no_soft":
        d = d[~d.soft_flagged]
    elif name == "no_kernel_minor":
        d = d[~d.kernel_minor]
    elif name == "no_block20":
        d = d[d.block != 20]
    elif name == "timeout_imputed":
        d["y"] = np.where(d.fail == 1, d.timeout_ms, d.app_ms)
        return d, "y"
    elif name == "median":
        pass
    else:
        raise ValueError(name)
    d = d[d.fail == 0]
    return d, "y"


# ----------------------------------------------------------------------------------------------- tableau par bloc
def block_table(d, stat="mean"):
    g = d.groupby(["proto", "auth", "family", "cell_id", "cellkey", "level", "kem", "sig", "sig_class", "block"], sort=False)["y"]
    if stat == "mean":
        t = g.agg(m="mean", n="size").reset_index()
    else:
        t = g.agg(m="median", n="size").reset_index()
    return t


def effects(t):
    """Une ligne par (cellule, niveau, KEM, bloc) : moyenne ML-DSA, moyenne classique, differences."""
    cl = t[t.sig_class == "classical"].rename(columns={"m": "m_cl", "n": "n_cl", "sig": "sig_cl"}).drop(columns="sig_class")
    ml = t[t.sig_class == "pqc"].rename(columns={"m": "m_ml", "n": "n_ml", "sig": "sig_ml"}).drop(columns="sig_class")
    k = ["proto", "auth", "family", "cell_id", "cellkey", "level", "kem", "block"]
    e = cl.merge(ml, on=k, how="inner", validate="one_to_one")
    e["D"] = e.m_ml - e.m_cl
    e["L"] = np.log(e.m_ml / e.m_cl)
    return e


def ser(e, col="D", **flt):
    s = e
    for k, v in flt.items():
        s = s[s[k].isin(v)] if isinstance(v, (list, tuple, set)) else s[s[k] == v]
    return s.set_index("block")[col].sort_index()


def summ(d, prefix=""):
    r = paired_summary(np.asarray(d, float))
    return {prefix + k: v for k, v in r.items()}


def light(d, B=B_BOOT, seed=12345):
    d = np.asarray(d, float); d = d[np.isfinite(d)]; n = len(d)
    if n < 3:
        return dict(n=n, mean=np.nan, lo=np.nan, hi=np.nan, p=np.nan)
    idx = np.random.default_rng(seed).integers(0, n, (B, n))
    lo, hi = np.quantile(d[idx].mean(axis=1), [0.025, 0.975])
    return dict(n=n, mean=float(d.mean()), lo=float(lo), hi=float(hi), p=signflip_exact(d))


def sig_str(r):
    return "*" if (r["lo"] > 0 or r["hi"] < 0) else ""


# ----------------------------------------------------------------------------------------------- C1 contrastes principaux
def main_contrasts(c, scen_names):
    """ML-DSA - classique, KEM fixe, famille 'main' : 21 contrastes x 3 profils x (TLS single, TLS mutual, QUIC single)."""
    base_d, _ = scenario(c, "primary")
    e = effects(block_table(base_d[base_d.family == "main"]))
    e["profile"] = e.cell_id.str.split("_").str[-1]
    rows = []
    for (proto, auth, prof), g in e.groupby(["proto", "auth", e.profile]):
        for (lvl, kem), h in g.groupby(["level", "kem"]):
            s = h.set_index("block").sort_index()
            r = dict(proto=proto, auth=auth, profile=prof, level=lvl, kem=kem, sig_cl=CLASSICAL_OF[lvl], sig_ml=MLDSA_OF[lvl],
                     kem_family=kem_info(kem)[0], kem_form=kem_info(kem)[1],
                     m_cl_ms=s.m_cl.mean(), m_ml_ms=s.m_ml.mean(),
                     evidence="SECONDAIRE_tls_perte_groupee" if (proto == "tls" and prof != "ideal") else "ROBUSTE")
            r.update(summ(s.D))
            ls = paired_summary(s.L.values)
            r.update(rel_pct=pct(ls["mean"]), rel_lo=pct(ls["lo"]), rel_hi=pct(ls["hi"]), rel_p=ls["p"])
            rows.append(r)
    T = pd.DataFrame(rows)
    T["p_holm"] = np.nan
    for _, ix in T.groupby(["proto", "auth", "profile"]).groups.items():
        T.loc[ix, "p_holm"] = holm(T.loc[ix, "p"].values)
    T["q_bh_global"] = bh(T.p.values)
    # sensibilites : meme contraste sous scenarios
    sens = {}
    for sc in scen_names:
        d, _ = scenario(c, sc)
        es = effects(block_table(d[d.family == "main"], "median" if sc == "median" else "mean"))
        es["profile"] = es.cell_id.str.split("_").str[-1]
        for (proto, auth, prof, lvl, kem), h in es.groupby(["proto", "auth", "profile", "level", "kem"]):
            s = h.set_index("block").sort_index().D
            r = light(s.values)
            sens[(proto, auth, prof, lvl, kem, sc)] = r
    for sc in scen_names:
        T[f"mean_{sc}"] = [sens.get((a, b, p, l, k, sc), {}).get("mean", np.nan) for a, b, p, l, k in zip(T.proto, T.auth, T.profile, T.level, T.kem)]
        T[f"lo_{sc}"] = [sens.get((a, b, p, l, k, sc), {}).get("lo", np.nan) for a, b, p, l, k in zip(T.proto, T.auth, T.profile, T.level, T.kem)]
        T[f"hi_{sc}"] = [sens.get((a, b, p, l, k, sc), {}).get("hi", np.nan) for a, b, p, l, k in zip(T.proto, T.auth, T.profile, T.level, T.kem)]
    # robustesse : IC95 exclut 0 dans le meme sens pour la primaire ET tous les scenarios (y compris la mediane, plus stricte)
    def robust(r):
        sg = np.sign(r["mean"])
        if not (r["lo"] > 0 or r["hi"] < 0):
            return "non_significatif"
        ok = True
        for sc in scen_names:
            lo, hi = r[f"lo_{sc}"], r[f"hi_{sc}"]
            ok &= (lo > 0) if sg > 0 else (hi < 0)
        return "robuste_tous_scenarios" if ok else "fragile_selon_scenario"
    T["robustesse"] = T.apply(robust, axis=1)
    # signe de l'effet
    T["sens_signe"] = np.where(T["mean"] > 0, "ML-DSA plus lent", "ML-DSA plus rapide")
    # equivalence a +-5 % (marge a fixer a priori ; IC95 bilateral inclus dans la marge = TOST conservateur au niveau 2,5 %)
    T["equiv_pm5pct"] = (T.rel_lo > -5.0) & (T.rel_hi < 5.0)
    return T, e


# ----------------------------------------------------------------------------------------------- C2 heterogeneite KEM
def kem_heterogeneity(T_blocks):
    """Differences d'effet ML-DSA entre familles de KEM (classique / ML-KEM / HQC), par niveau, profil, protocole."""
    e = T_blocks.copy()
    e["fam"] = [kem_info(k)[0] for k in e.kem]
    rows = []
    for (proto, auth, prof, lvl), g in e.groupby(["proto", "auth", "profile", "level"]):
        piv = g.groupby(["fam", "block"]).D.mean().unstack(0)   # moyenne sur les KEM d'une meme famille, par bloc
        for a, b in [("hqc", "mlkem"), ("mlkem", "classical"), ("hqc", "classical")]:
            if a in piv and b in piv:
                s = (piv[a] - piv[b]).dropna()
                r = dict(proto=proto, auth=auth, profile=prof, level=lvl, contrast=f"effet_ML-DSA[{a}] - effet_ML-DSA[{b}]",
                         eff_a=piv[a].mean(), eff_b=piv[b].mean(),
                         evidence="SECONDAIRE_tls_perte_groupee" if (proto == "tls" and prof != "ideal") else "ROBUSTE")
                r.update(summ(s)); rows.append(r)
    T = pd.DataFrame(rows)
    T["p_holm"] = np.nan
    for _, ix in T.groupby(["proto", "auth", "profile"]).groups.items():
        T.loc[ix, "p_holm"] = holm(T.loc[ix, "p"].values)
    return T


# ----------------------------------------------------------------------------------------------- C3 cout de l'authentification mutuelle
def mutual_cost(d):
    """TLS mutuelle - TLS serveur seul, par signature/KEM/profil ; puis difference d'effet ML-DSA vs classique."""
    m = d[(d.family == "main") & (d.proto == "tls")].copy()
    m["profile"] = m.cell_id.str.split("_").str[-1]
    t = m.groupby(["auth", "profile", "level", "sig", "sig_class", "kem", "block"]).y.mean().reset_index()
    pv = t.pivot_table(index=["profile", "level", "sig", "sig_class", "kem", "block"], columns="auth", values="y").reset_index()
    pv["dM"] = pv.mutual - pv.single
    rows = []
    for (prof, lvl, sig, scl, kem), g in pv.groupby(["profile", "level", "sig", "sig_class", "kem"]):
        s = g.set_index("block").dM.sort_index()
        r = dict(profile=prof, level=lvl, sig=sig, sig_class=scl, kem=kem, evidence="SECONDAIRE_tls_perte_groupee" if prof != "ideal" else "ROBUSTE")
        r.update(summ(s)); rows.append(r)
    A = pd.DataFrame(rows)
    A["p_holm"] = np.nan
    for _, ix in A.groupby("profile").groups.items():
        A.loc[ix, "p_holm"] = holm(A.loc[ix, "p"].values)
    # DiD : cout mutuel ML-DSA - cout mutuel classique
    rows = []
    for (prof, lvl, kem), g in pv.groupby(["profile", "level", "kem"]):
        a = g[g.sig_class == "pqc"].set_index("block").dM; b = g[g.sig_class == "classical"].set_index("block").dM
        s = (a - b).dropna()
        r = dict(profile=prof, level=lvl, kem=kem, contrast="cout_mutuel[ML-DSA] - cout_mutuel[classique]",
                 evidence="SECONDAIRE_tls_perte_groupee" if prof != "ideal" else "ROBUSTE")
        r.update(summ(s)); rows.append(r)
    D = pd.DataFrame(rows)
    D["p_holm"] = np.nan
    for _, ix in D.groupby("profile").groups.items():
        D.loc[ix, "p_holm"] = holm(D.loc[ix, "p"].values)
    return A, D


# ----------------------------------------------------------------------------------------------- C4 interaction protocole (sans perte)
def protocol_interaction(e_all):
    """DiD : (ML-DSA - classique)_QUIC - (ML-DSA - classique)_TLS, cellules SANS perte uniquement (main ideal ; fx delai seul)."""
    e = e_all[(e_all.auth == "single") & e_all.cell_id.str.contains("ideal|loss0")].copy()
    rows = []
    for (fam, ck, lvl, kem), g in e.groupby(["family", "cellkey", "level", "kem"]):
        q = g[g.proto == "quic"].set_index("block").D; t = g[g.proto == "tls"].set_index("block").D
        if len(q) < 3 or len(t) < 3:
            continue
        s = (q - t).dropna()
        r = dict(family=fam, cellkey=ck, level=lvl, kem=kem, eff_quic=q.mean(), eff_tls=t.mean(), contrast="effet_ML-DSA[QUIC] - effet_ML-DSA[TLS]")
        r.update(summ(s)); rows.append(r)
    T = pd.DataFrame(rows)
    if len(T):
        T["p_holm"] = np.nan
        for _, ix in T.groupby("family").groups.items():
            T.loc[ix, "p_holm"] = holm(T.loc[ix, "p"].values)
    return T


# ----------------------------------------------------------------------------------------------- C5 factoriel
def ols_cluster(y, X, cluster, fes):
    """MCO avec effets fixes (demean) et variance CR1 groupee par bloc ; inference t(G-1)."""
    y = np.asarray(y, float)
    Xd = np.column_stack([demean(X[:, j], fes) for j in range(X.shape[1])])
    yd = demean(y, fes)
    XtX = Xd.T @ Xd
    try:
        inv = np.linalg.inv(XtX)
    except np.linalg.LinAlgError:
        return None
    b = inv @ (Xd.T @ yd); e = yd - Xd @ b
    cl = pd.factorize(np.asarray(cluster))[0]; G = cl.max() + 1
    S = np.zeros((G, Xd.shape[1]))
    for j in range(Xd.shape[1]):
        S[:, j] = np.bincount(cl, weights=Xd[:, j] * e)
    V = inv @ (S.T @ S) @ inv * G / (G - 1)
    se = np.sqrt(np.diag(V)); q = stats.t.ppf(0.975, G - 1)
    return b, se, b - q * se, b + q * se, 2 * stats.t.sf(np.abs(b / se), G - 1), G


def factorial(e_all):
    """Cellules par cellule + regression de l'effet relatif ML-DSA/classique sur (RTT, perte, burstiness, famille KEM)."""
    f = e_all[(e_all.family == "fx") & (e_all.level == "L3")].copy()
    parsed = f.cell_id.str.extract(r"rtt(?P<rtt>\d+)_loss(?P<loss>\d+)(?:_(?P<proc>iid|gemild|gesevere))?")
    f["rtt"] = parsed.rtt.astype(float); f["loss"] = parsed.loss.astype(float); f["proc"] = parsed.proc.fillna("none")
    f["hqc"] = [1.0 if kem_info(k)[0] == "hqc" else 0.0 for k in f.kem]
    # (a) effets par cellule
    rows = []
    for (proto, cid, kem), g in f.groupby(["proto", "cell_id", "kem"]):
        s = g.set_index("block").sort_index()
        r = dict(proto=proto, cell_id=cid, kem=kem, rtt=s.rtt.iloc[0], loss=s.loss.iloc[0], proc=s.proc.iloc[0],
                 m_cl_ms=s.m_cl.mean(), m_ml_ms=s.m_ml.mean(),
                 evidence="SECONDAIRE_tls_perte_groupee" if (proto == "tls" and s.loss.iloc[0] > 0) else "ROBUSTE")
        r.update(summ(s.D)); ls = paired_summary(s.L.values)
        r.update(rel_pct=pct(ls["mean"]), rel_lo=pct(ls["lo"]), rel_hi=pct(ls["hi"]))
        rows.append(r)
    cells = pd.DataFrame(rows)
    cells["p_holm"] = np.nan
    for _, ix in cells.groupby("proto").groups.items():
        cells.loc[ix, "p_holm"] = holm(cells.loc[ix, "p"].values)
    # (b) regressions (variable dependante : log-ratio ML-DSA/classique ; EF bloc ; ecarts-types groupes par bloc)
    regs = []
    for proto in ["quic", "tls"]:
        g0 = f[f.proto == proto]
        # modele A : sans perte -> effet du RTT
        a = g0[g0.loss == 0]
        if len(a) > 30:
            X = np.column_stack([a.rtt.values / 100.0, a.hqc.values])
            r = ols_cluster(a.L.values, X, a.block.values, [a.block.values])
            if r:
                for nm, bb, se, lo, hi, p in zip(["rtt_par_100ms", "kem_hqc"], r[0], r[1], r[2], r[3], r[4]):
                    regs.append(dict(proto=proto, modele="A_sans_perte", terme=nm, coef_log=bb, pct=pct(bb), pct_lo=pct(lo), pct_hi=pct(hi), p=p, G=r[5], n=len(a),
                                     evidence="ROBUSTE"))
        # modele B : cellules avec perte
        bdf = g0[g0.loss > 0]
        if len(bdf) > 60:
            X = np.column_stack([bdf.rtt.values / 100.0, np.log2(bdf.loss.values), (bdf.proc == "gemild").astype(float).values,
                                 (bdf.proc == "gesevere").astype(float).values, bdf.hqc.values,
                                 (bdf.rtt.values / 100.0) * np.log2(bdf.loss.values)])
            names = ["rtt_par_100ms", "log2_perte_nominale", "burst_gemild_vs_iid", "burst_gesevere_vs_iid", "kem_hqc", "rtt_x_log2perte"]
            r = ols_cluster(bdf.L.values, X, bdf.block.values, [bdf.block.values])
            if r:
                for nm, bb, se, lo, hi, p in zip(names, r[0], r[1], r[2], r[3], r[4]):
                    regs.append(dict(proto=proto, modele="B_avec_perte", terme=nm, coef_log=bb, pct=pct(bb), pct_lo=pct(lo), pct_hi=pct(hi), p=p, G=r[5], n=len(bdf),
                                     evidence="SECONDAIRE_tls_perte_groupee" if proto == "tls" else "ROBUSTE"))
    R = pd.DataFrame(regs)
    if len(R):
        R["p_holm"] = np.nan
        for _, ix in R.groupby(["proto", "modele"]).groups.items():
            R.loc[ix, "p_holm"] = holm(R.loc[ix, "p"].values)
    return cells, R


# ----------------------------------------------------------------------------------------------- C6 direction, C8 chaine
def did_vs_baseline(e_all, fam, base_fam, pairs_map, label):
    """DiD generique : effet ML-DSA dans les cellules de `fam` moins effet ML-DSA dans la cellule de reference correspondante.
    pairs_map : liste de (cell_id_test, cell_id_ref)."""
    rows = []
    for ct, cr in pairs_map:
        for proto in ["quic", "tls"]:
            a = e_all[(e_all.proto == proto) & (e_all.cell_id == ct.format(p=proto))]
            b = e_all[(e_all.proto == proto) & (e_all.cell_id == cr.format(p=proto))]
            for kem in sorted(set(a.kem) & set(b.kem)):
                sa = a[a.kem == kem].set_index("block"); sb = b[b.kem == kem].set_index("block")
                idx = sa.index.intersection(sb.index)
                if len(idx) < 3:
                    continue
                lossy = ("loss0" not in ct) and ("loss0" not in cr) and ("ideal" not in ct)
                r = dict(contrast=label, proto=proto, kem=kem, cell_test=ct.format(p=proto), cell_ref=cr.format(p=proto),
                         eff_test=sa.D.loc[idx].mean(), eff_ref=sb.D.loc[idx].mean(),
                         evidence="SECONDAIRE_tls_perte_groupee" if (proto == "tls" and lossy) else "ROBUSTE")
                r.update(summ(sa.D.loc[idx] - sb.D.loc[idx]))
                # cout brut de la variation de configuration pour chaque classe de signature
                rows.append(r)
    T = pd.DataFrame(rows)
    if len(T):
        T["p_holm"] = np.nan
        for _, ix in T.groupby("proto").groups.items():
            T.loc[ix, "p_holm"] = holm(T.loc[ix, "p"].values)
    return T


def direction_and_chain(e_all):
    dirmap = [("dir_{p}_iid_c2s", "fx_{p}_rtt100_loss2_iid"), ("dir_{p}_iid_both", "fx_{p}_rtt100_loss2_iid"),
              ("dir_{p}_gemild_c2s", "fx_{p}_rtt100_loss2_gemild"), ("dir_{p}_gemild_both", "fx_{p}_rtt100_loss2_gemild")]
    D = did_vs_baseline(e_all, "dir", "fx", dirmap, "effet_ML-DSA[direction] - effet_ML-DSA[s2c]")
    chmap = [("chain_{p}_rtt50_loss0", "fx_{p}_rtt50_loss0"), ("chain_{p}_rtt50_loss1_iid", "fx_{p}_rtt50_loss1_iid"),
             ("chain_{p}_rtt50_loss2_iid", "fx_{p}_rtt50_loss2_iid"), ("chain_{p}_rtt50_loss5_iid", "fx_{p}_rtt50_loss5_iid")]
    C = did_vs_baseline(e_all, "chain", "fx", chmap, "effet_ML-DSA[chaine a 2] - effet_ML-DSA[chaine a 1]")
    return D, C


# ----------------------------------------------------------------------------------------------- C7 decomposition taille / calcul
def size_decomposition(d):
    """Cellules appariees mech (secp384r1, mldsa65) / size (ECDSA rempli a 8700 o) : meme reseau, meme pcap, meme MTU.
    total = ML-DSA - ECDSA ; taille = ECDSA_rempli - ECDSA ; residu = ML-DSA - ECDSA_rempli."""
    x = d[(d.family.isin(["mech", "size"])) & (d.kem == "x448_mlkem768")].copy()
    x["cfg"] = np.where(x.family == "size", "ecdsa_pad", np.where(x.sig_class == "pqc", "mldsa65", "ecdsa"))
    # cle de reseau commune : proto, mtu, perte nominale, qmtu
    x["netkey"] = x.proto + "|mtu" + x.mtu.astype(int).astype(str) + "|loss" + x.loss_nom.astype(int).astype(str)
    t = x.groupby(["proto", "netkey", "mtu", "loss_nom", "cfg", "block"]).y.mean().reset_index()
    pv = t.pivot_table(index=["proto", "netkey", "mtu", "loss_nom", "block"], columns="cfg", values="y").reset_index().dropna(subset=["ecdsa", "ecdsa_pad", "mldsa65"])
    pv["total"] = pv.mldsa65 - pv.ecdsa; pv["taille"] = pv.ecdsa_pad - pv.ecdsa; pv["residu"] = pv.mldsa65 - pv.ecdsa_pad
    rows = []
    for (proto, nk, mtu, ln), g in pv.groupby(["proto", "netkey", "mtu", "loss_nom"]):
        g = g.set_index("block").sort_index()
        for comp in ["total", "taille", "residu"]:
            r = dict(proto=proto, mtu=int(mtu), loss_nom=ln, composante=comp,
                     evidence="SECONDAIRE_tls_perte_groupee" if (proto == "tls" and ln > 0) else "ROBUSTE",
                     m_ecdsa=g.ecdsa.mean(), m_pad=g.ecdsa_pad.mean(), m_mldsa65=g.mldsa65.mean())
            r.update(summ(g[comp])); rows.append(r)
        # part du total expliquee par la taille (ratio de moyennes inter-blocs, bootstrap par blocs)
        n = len(g); idx = np.random.default_rng(7).integers(0, n, (B_BOOT, n))
        tot = g.total.values[idx].mean(axis=1); siz = g.taille.values[idx].mean(axis=1)
        with np.errstate(divide="ignore", invalid="ignore"):
            share = siz / tot
        tlo, thi = np.quantile(tot, [0.025, 0.975])
        defined = (tlo > 0) or (thi < 0)   # le rapport n'a de sens que si l'effet total est distinct de 0
        lo, hi = np.quantile(share, [0.025, 0.975]) if defined else (np.nan, np.nan)
        rows.append(dict(proto=proto, mtu=int(mtu), loss_nom=ln, composante="part_taille/total",
                         mean=g.taille.mean() / g.total.mean() if (defined and g.total.mean()) else np.nan,
                         lo=lo, hi=hi, note="" if defined else "non defini : effet total non distinct de 0",
                         evidence="SECONDAIRE_tls_perte_groupee" if (proto == "tls" and ln > 0) else "ROBUSTE"))
    T = pd.DataFrame(rows)
    m = T.composante != "part_taille/total"
    T.loc[m, "p_holm"] = np.nan
    for _, ix in T[m].groupby(["proto", "composante"]).groups.items():
        T.loc[ix, "p_holm"] = holm(T.loc[ix, "p"].values)
    return T


# ----------------------------------------------------------------------------------------------- C9 effet de l'instrumentation (tcpdump)
def instrumentation(d):
    """Cellules avec capture (mech, MTU 1500) vs cellules equivalentes sans capture (fx rtt50) : memes paires, meme reseau."""
    rows = []
    for proto in ["tls", "quic"]:
        for ln in [0, 1, 2, 5]:
            ref = f"fx_{proto}_rtt50_loss{ln}" + ("" if ln == 0 else "_iid")
            tst = f"mech_{proto}_mtu1500_loss{ln}"
            for sig in ["secp384r1", "mldsa65"]:
                a = d[(d.cell_id == tst) & (d.sig == sig) & (d.kem == "x448_mlkem768")].groupby("block").y.mean()
                b = d[(d.cell_id == ref) & (d.sig == sig) & (d.kem == "x448_mlkem768")].groupby("block").y.mean()
                idx = a.index.intersection(b.index)
                if len(idx) < 3:
                    continue
                r = dict(proto=proto, loss_nom=ln, sig=sig, ref=ref, test=tst, m_sans_capture=b.loc[idx].mean(), m_avec_capture=a.loc[idx].mean(),
                         confondu_qmtu=(proto == "quic"),
                         evidence="SECONDAIRE_tls_perte_groupee" if (proto == "tls" and ln > 0) else "ROBUSTE")
                r.update(summ(a.loc[idx] - b.loc[idx])); rows.append(r)
    T = pd.DataFrame(rows)
    if len(T):
        T["p_holm"] = holm(T.p.values)
    return T


# ----------------------------------------------------------------------------------------------- queues de distribution
def tails(d, qs=(0.5, 0.9, 0.95, 0.99), B=2000, seed=99):
    """Quantiles groupes (tous blocs) ML-DSA - classique, famille main ; IC95 par bootstrap de BLOCS."""
    rng = np.random.default_rng(seed); rows = []
    m = d[d.family == "main"].copy(); m["profile"] = m.cell_id.str.split("_").str[-1]
    for (proto, auth, prof, lvl, kem), g in m.groupby(["proto", "auth", "profile", "level", "kem"]):
        sc, sm = g[g.sig_class == "classical"], g[g.sig_class == "pqc"]
        bl = sorted(set(sc.block) & set(sm.block))
        A = {b: sc[sc.block == b].y.values for b in bl}; M = {b: sm[sm.block == b].y.values for b in bl}
        qa = np.quantile(np.concatenate(list(A.values())), qs); qm = np.quantile(np.concatenate(list(M.values())), qs)
        diffs = np.empty((B, len(qs)))
        for i in range(B):
            pick = rng.integers(0, len(bl), len(bl))
            a = np.concatenate([A[bl[j]] for j in pick]); mm = np.concatenate([M[bl[j]] for j in pick])
            diffs[i] = np.quantile(mm, qs) - np.quantile(a, qs)
        lo, hi = np.quantile(diffs, [0.025, 0.975], axis=0)
        for k, q in enumerate(qs):
            rows.append(dict(proto=proto, auth=auth, profile=prof, level=lvl, kem=kem, q=q, q_cl=qa[k], q_ml=qm[k], diff=qm[k] - qa[k], lo=lo[k], hi=hi[k],
                             evidence="SECONDAIRE_tls_perte_groupee" if (proto == "tls" and prof != "ideal") else "ROBUSTE"))
    return pd.DataFrame(rows)


# ----------------------------------------------------------------------------------------------- completion
def cp_ci(k, n, a=0.05):
    if n == 0:
        return (np.nan, np.nan)
    lo = 0.0 if k == 0 else stats.beta.ppf(a / 2, k, n - k + 1)
    hi = 1.0 if k == n else stats.beta.ppf(1 - a / 2, k + 1, n - k)
    return lo, hi


def mantel_haenszel(tabs):
    """OR commun de Mantel-Haenszel, IC95 de Robins-Breslow-Greenland et test CMH (correction de continuite). tabs : liste de [[a,b],[c,d]]."""
    R = S = P = Q = PS = QR = 0.0; A = E = V = 0.0
    for t in tabs:
        a, b, c_, d = t[0, 0], t[0, 1], t[1, 0], t[1, 1]; n = a + b + c_ + d
        if n < 2:
            continue
        r_, s_ = a * d / n, b * c_ / n; p_, q_ = (a + d) / n, (b + c_) / n
        R += r_; S += s_; PS += p_ * s_; QR += q_ * r_
        P += p_ * r_; Q += q_ * s_
        A += a; E += (a + b) * (a + c_) / n
        V += (a + b) * (c_ + d) * (a + c_) * (b + d) / (n ** 2 * (n - 1))
    if R <= 0 or S <= 0:
        return dict(or_mh=np.nan, or_lo=np.nan, or_hi=np.nan, p_cmh=np.nan)
    orr = R / S
    var = P / (2 * R ** 2) + (PS + QR) / (2 * R * S) + Q / (2 * S ** 2)
    lo, hi = np.exp(np.log(orr) + np.array([-1.96, 1.96]) * np.sqrt(var))
    chi = (abs(A - E) - 0.5) ** 2 / V if V > 0 else np.nan
    return dict(or_mh=orr, or_lo=lo, or_hi=hi, p_cmh=float(stats.chi2.sf(chi, 1)) if np.isfinite(chi) else np.nan)


def completion(c):
    d = c[~c.hard_excluded].copy()
    d["sig_class"] = np.where(d.family == "size", "classical_padded", d.sig_class)
    fr = d.fail_reason.astype(str).str.lower()
    is_timeout = fr.str.contains("timeout", na=False)          # "client-side timeout after 150s"
    d["fail_kind"] = np.where(d.fail == 0, "ok", np.where(is_timeout, "timeout_150s", "sans_raison"))   # NaN, 'unspecified', ... = sans raison
    rows = []
    for (proto, fam, sc), g in d.groupby(["proto", "family", "sig_class"]):
        k, n = int(g.fail.sum()), len(g); lo, hi = cp_ci(k, n)
        rows.append(dict(proto=proto, family=fam, sig_class=sc, n=n, echecs=k, taux_pct=100 * k / n, cp_lo_pct=100 * lo, cp_hi_pct=100 * hi,
                         sans_raison=int((g.fail_kind == "sans_raison").sum()), timeout=int((g.fail_kind == "timeout_150s").sum())))
    A = pd.DataFrame(rows)
    # ML-DSA vs classique STRATIFIE par (cellule, niveau, KEM) -- Cochran-Mantel-Haenszel ; ECDSA rempli exclu (controle de taille).
    # Descriptif : les connexions d'un meme bloc ne sont pas independantes, et les echecs sont rares.
    rows = []
    for proto, g in d[d.sig_class.isin(["pqc", "classical"])].groupby("proto"):
        tabs = []
        for _, h in g.groupby(["cell_id", "level", "kem"]):
            a_ = h[h.sig_class == "pqc"]; b_ = h[h.sig_class == "classical"]
            if len(a_) and len(b_) and (a_.fail.sum() + b_.fail.sum()) > 0:
                tabs.append(np.array([[a_.fail.sum(), len(a_) - a_.fail.sum()], [b_.fail.sum(), len(b_) - b_.fail.sum()]], float))
        a_ = g[g.sig_class == "pqc"]; b_ = g[g.sig_class == "classical"]
        r = dict(proto=proto, ml_echecs=int(a_.fail.sum()), ml_n=len(a_), cl_echecs=int(b_.fail.sum()), cl_n=len(b_), strates_informatives=len(tabs))
        if len(tabs) >= 3:
            r.update(mantel_haenszel(tabs))
        rows.append(r)
    B = pd.DataFrame(rows)
    C = d[d.fail == 1].groupby(["proto", "family", "cell_id", "sig_class", "fail_kind"]).size().rename("n").reset_index()
    return A, B, C


# ----------------------------------------------------------------------------------------------- exposition aux evenements de perte
def exposure(c, visits):
    """Evenements de perte reellement injectes par execution (compteur netem 'dropped' = decisions par skb), par cellule x classe de signature."""
    n_exec = c.groupby(KEY).size().rename("n_exec").reset_index()
    v = visits.merge(n_exec, on=KEY, how="inner")
    v = v.merge(c.drop_duplicates(KEY)[KEY + ["cell_id", "family", "loss_nom", "loss_dir", "sig_class", "hard_excluded"]], on=KEY, how="left")
    v = v[~v.hard_excluded.fillna(False)]
    drop = np.where(v.loss_dir == "c2s", v.cli_d_drop, np.where(v.loss_dir == "both", v.cli_d_drop.fillna(0) + v.srv_d_drop.fillna(0), v.srv_d_drop))
    pk = np.where(v.loss_dir == "c2s", v.cli_d_pkts, np.where(v.loss_dir == "both", v.cli_d_pkts.fillna(0) + v.srv_d_pkts.fillna(0), v.srv_d_pkts))
    v["ev_per_exec"] = drop / v.n_exec; v["pkts_per_exec"] = pk / v.n_exec
    v["ratio_ev_pkts_pct"] = 100 * drop / np.where(pk + drop > 0, pk + drop, np.nan)
    g = v[v.loss_nom > 0].groupby(["proto", "family", "cell_id", "loss_nom", "sig_class"]).agg(
        visites=("ev_per_exec", "size"), evt_par_exec=("ev_per_exec", "mean"), paquets_par_exec=("pkts_per_exec", "mean"),
        perte_reelle_pct=("ratio_ev_pkts_pct", "mean")).reset_index()
    g["ratio_reel_sur_nominal"] = g.perte_reelle_pct / g.loss_nom
    return g


# ----------------------------------------------------------------------------------------------- controle negatif (ordre des rounds)
def negative_control(d):
    """Contraste factice 'round 1 - round 2' pour une MEME signature/KEM/cellule (famille fx : seule famille a plusieurs rounds en nombre suffisant ; main n'a qu'un round). L'ordre des paires est randomise :
    sous l'absence d'effet d'ordre, ~5 % des p < 0.05 et p ~ uniforme. Sert de calibration du pipeline d'inference (bloc = unite)."""
    m = d[d.family == "fx"]
    t = m.groupby(["proto", "auth", "cell_id", "sig", "kem", "block", "round"]).y.mean().unstack("round")
    rows = []
    if t.shape[1] < 2:
        return pd.DataFrame()
    r1, r2 = t.columns[0], t.columns[1]
    t = t.dropna(subset=[r1, r2]); t["dD"] = t[r1] - t[r2]
    for (proto, auth, cid, sig, kem), g in t.groupby(["proto", "auth", "cell_id", "sig", "kem"]):
        s_ = g.dD.values
        rows.append(dict(proto=proto, auth=auth, cell_id=cid, sig=sig, kem=kem, mean=s_.mean(), p=signflip_exact(s_)))
    T = pd.DataFrame(rows)
    return T


# ----------------------------------------------------------------------------------------------- principal
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="indir", default="analysis_v2")
    ap.add_argument("--out", default=None)
    ap.add_argument("--no-tails", action="store_true")
    a = ap.parse_args()
    out = a.out or os.path.join(a.indir, "phase2"); os.makedirs(out, exist_ok=True)
    t0 = time.time()
    c = load(a.indir)
    visits = pd.read_csv(os.path.join(a.indir, "visits.csv"))
    d0, _ = scenario(c, "primary")
    log("=" * 100)
    log("PHASE 2 -- CONTRASTES CONFIRMATOIRES (unite = bloc ; 20 blocs)")
    log("=" * 100)
    log(f"Connexions mesurees : {len(c):,} ; apres exclusions dures : {int((~c.hard_excluded).sum()):,} ; reussies : {len(d0):,}")
    log(f"Visites exclues (dures) : {int(c[c.hard_excluded].drop_duplicates(KEY).shape[0])} ; soft : {int(c[c.soft_flagged].drop_duplicates(KEY).shape[0])} ; "
        f"noyau minoritaire : {int(c[c.kernel_minor].drop_duplicates(KEY).shape[0])}")
    log("Niveaux de preuve : ROBUSTE = QUIC (tout) + TLS sans perte ; SECONDAIRE = TLS avec perte (perte groupee par super-paquet).")

    # --- C1
    scen = ["no_soft", "no_kernel_minor", "no_block20", "timeout_imputed", "median"]
    T1, e_main = main_contrasts(c, scen)
    T1.to_csv(os.path.join(out, "p2_c1_main_contrasts.csv"), index=False)
    log("\n[C1] ML-DSA - classique, KEM fixe, famille main (21 contrastes par proto/auth/profil)")
    for (proto, auth, prof), g in T1.groupby(["proto", "auth", "profile"], sort=False):
        sig = g[(g.lo > 0) | (g.hi < 0)]
        log(f"  {proto:4s} {auth:6s} {prof:9s} [{g.evidence.iloc[0][:9]}] : {len(sig)}/{len(g)} IC95 excluent 0 ; "
            f"Holm<0.05 : {(g.p_holm < 0.05).sum()} ; plus lent : {(g['mean'] > 0).sum()} ; robustes tous scenarios : {(g.robustesse == 'robuste_tous_scenarios').sum()} ; "
            f"effet moyen {g['mean'].min():.1f}..{g['mean'].max():.1f} ms")

    # --- tableau complet d'effets (toutes familles) pour les contrastes suivants
    e_all = effects(block_table(d0))
    e_all = e_all.merge(d0.drop_duplicates("cell_id")[["cell_id", "loss_nom", "mtu"]], on="cell_id", how="left")
    ee = e_main.copy()
    ee["profile"] = ee.cell_id.str.split("_").str[-1]

    # --- C2
    T2 = kem_heterogeneity(ee); T2.to_csv(os.path.join(out, "p2_c2_kem_heterogeneity.csv"), index=False)
    log("\n[C2] Heterogeneite de l'effet ML-DSA selon la famille de KEM (DiD, famille main)")
    s = T2[(T2.p_holm < 0.05)]
    log(f"  {len(s)}/{len(T2)} contrastes DiD significatifs apres Holm (par proto/auth/profil)")

    # --- C3
    A3, D3 = mutual_cost(d0)
    A3.to_csv(os.path.join(out, "p2_c3_mutual_cost.csv"), index=False); D3.to_csv(os.path.join(out, "p2_c3_mutual_did.csv"), index=False)
    log("\n[C3] Cout de l'authentification mutuelle TLS")
    for prof in PROFILES:
        g = A3[A3.profile == prof]
        if len(g):
            log(f"  {prof:9s}: classique {g[g.sig_class == 'classical']['mean'].min():.1f}..{g[g.sig_class == 'classical']['mean'].max():.1f} ms ; "
                f"ML-DSA {g[g.sig_class == 'pqc']['mean'].min():.1f}..{g[g.sig_class == 'pqc']['mean'].max():.1f} ms")

    # --- C4
    T4 = protocol_interaction(e_all); T4.to_csv(os.path.join(out, "p2_c4_protocol_interaction_lossfree.csv"), index=False)
    log("\n[C4] Interaction protocole x signature (cellules sans perte uniquement)")
    if len(T4):
        log(f"  {len(T4)} contrastes ; Holm<0.05 : {(T4.p_holm < 0.05).sum()} ; effet ML-DSA plus grand en QUIC : {(T4['mean'] > 0).sum()}")

    # --- C5
    cells5, reg5 = factorial(e_all)
    cells5.to_csv(os.path.join(out, "p2_c5_factorial_cells.csv"), index=False); reg5.to_csv(os.path.join(out, "p2_c5_factorial_regression.csv"), index=False)
    log("\n[C5] Plan factoriel (fx, niveau L3) : regression de l'effet relatif ML-DSA/classique, EF bloc, ES groupes par bloc")
    for _, r in reg5.iterrows():
        log(f"  {r.proto:4s} {r.modele:13s} {r.terme:24s} {r.pct:+8.2f} % [{r.pct_lo:+.2f}, {r.pct_hi:+.2f}] p={r.p:.3g} ({r.evidence[:9]})")

    # --- C6/C8
    T6, T8 = direction_and_chain(e_all)
    T6.to_csv(os.path.join(out, "p2_c6_direction.csv"), index=False); T8.to_csv(os.path.join(out, "p2_c8_chain.csv"), index=False)
    log("\n[C6] Direction de la perte (c2s / both vs s2c) ; [C8] chaine de certificats a 2 niveaux")
    log(f"  direction : {len(T6)} contrastes, Holm<0.05 : {(T6.p_holm < 0.05).sum() if len(T6) else 0} ; chaine : {len(T8)} contrastes, Holm<0.05 : {(T8.p_holm < 0.05).sum() if len(T8) else 0}")

    # --- C7
    T7 = size_decomposition(d0); T7.to_csv(os.path.join(out, "p2_c7_size_decomposition.csv"), index=False)
    log("\n[C7] Decomposition taille / calcul (ECDSA rempli a 8700 o)")
    try:   # note informative : octets reellement envoyes (manifestes) ; ignoree si les colonnes sont absentes
        mm = pd.read_csv(os.path.join(a.indir, "manifests.csv"), low_memory=False)
        mm = mm[(mm.proto == "tls") & mm.label.str.contains("pcap") & mm.sig.isin(["secp384r1", "mldsa65"]) & ~mm.label.str.contains("mtu1280")]
        mm["cfg"] = np.where(mm.label.str.contains("padto8700"), "ECDSA rempli", mm.sig)
        sz = mm.groupby("cfg").server_chain_sent.median()
        if len(sz):
            log("  Octets de chaine serveur envoyes (manifestes) : " + " ; ".join(f"{k} = {int(v)} o" for k, v in sz.items())
                + "  -> le controle de taille n'est PAS apparie en octets (voir lecture dans le rapport)")
    except Exception:
        pass
    for _, r in T7[T7.composante == "part_taille/total"].iterrows():
        txt = f"{100 * r['mean']:.0f} % [{100 * r.lo:.0f}, {100 * r.hi:.0f}]" if np.isfinite(r["mean"]) else "non defini (effet total non distinct de 0)"
        log(f"  {r.proto:4s} mtu{int(r.mtu)} perte {r.loss_nom:g} % : part de l'effet ML-DSA reproduite par la taille seule = {txt} ({r.evidence[:9]})")

    # --- C9
    T9 = instrumentation(d0); T9.to_csv(os.path.join(out, "p2_c9_instrumentation_tcpdump.csv"), index=False)
    log("\n[C9] Effet de l'instrumentation tcpdump (cellules mech vs fx equivalentes)")
    if len(T9):
        g = T9[~T9.confondu_qmtu]
        log(f"  TLS : effet moyen de la capture {g['mean'].min():.1f}..{g['mean'].max():.1f} ms ; IC95 excluant 0 : {int(((g.lo > 0) | (g.hi < 0)).sum())}/{len(g)}")
        g = T9[T9.confondu_qmtu]
        log(f"  QUIC (confondu par QUIC_MTU_SYNC) : {g['mean'].min():.1f}..{g['mean'].max():.1f} ms")

    # --- queues
    if not a.no_tails:
        log("\n[Q] Queues (quantiles groupes, IC95 bootstrap par blocs) -- famille main ; calcul en cours ...")
        TQ = tails(d0); TQ.to_csv(os.path.join(out, "p2_q_tails.csv"), index=False)
        for prof in PROFILES:
            g = TQ[(TQ.profile == prof) & (TQ.auth == "single")]
            for proto in ["quic", "tls"]:
                h = g[g.proto == proto]
                if len(h):
                    q99 = h[h.q == 0.99]
                    log(f"  {proto:4s} {prof:9s}: P99 ML-DSA - classique  {q99['diff'].min():.0f}..{q99['diff'].max():.0f} ms ; IC95 excluant 0 : {int(((q99.lo > 0) | (q99.hi < 0)).sum())}/{len(q99)}")

    # --- controle negatif
    NC = negative_control(d0)
    if len(NC):
        NC.to_csv(os.path.join(out, "p2_n_negative_control_rounds.csv"), index=False)
        ks = stats.kstest(NC.p.values, "uniform")
        log("\n[N] Controle negatif : 'round 1 - round 2' pour une meme signature (famille fx) -- calibration de l'inference par blocs")
        log(f"  {len(NC)} contrastes factices ; p<0.05 : {100 * (NC.p < 0.05).mean():.1f} % (attendu ~5 %) ; Holm<0.05 : {int((holm(NC.p.values) < 0.05).sum())} ; "
            f"KS vs uniforme p={ks.pvalue:.3g}")

    # --- completion
    A8, B8, C8 = completion(c)
    A8.to_csv(os.path.join(out, "p2_f_completion.csv"), index=False); B8.to_csv(os.path.join(out, "p2_f_completion_test.csv"), index=False)
    C8.to_csv(os.path.join(out, "p2_f_failures_by_cell.csv"), index=False)
    log("\n[F] Completion (echecs de connexion)")
    for _, r in A8.groupby("proto")[["n", "echecs", "sans_raison", "timeout"]].sum().reset_index().iterrows():
        log(f"  {r.proto:4s}: {int(r.echecs)} echecs / {int(r.n):,} (dont sans raison : {int(r.sans_raison)}, expiration : {int(r.timeout)})")
    for _, r in B8.iterrows():
        log(f"  {r.proto:4s}: ML-DSA {int(r.ml_echecs)}/{int(r.ml_n):,} vs classique {int(r.cl_echecs)}/{int(r.cl_n):,} ; OR de Mantel-Haenszel (strates cellule x niveau x KEM, "
            f"{int(r.strates_informatives)} informatives) = {r.get('or_mh', float('nan')):.2f} [{r.get('or_lo', float('nan')):.2f}, {r.get('or_hi', float('nan')):.2f}] p={r.get('p_cmh', float('nan')):.3g} (descriptif)")

    # --- exposition
    X = exposure(c, visits); X.to_csv(os.path.join(out, "p2_exposure_loss_events.csv"), index=False)
    log("\n[X] Evenements de perte reellement injectes par execution (decisions netem), par classe de signature")
    if len(X):
        for proto, g in X.groupby("proto"):
            log(f"  {proto:4s}: rapport perte-reelle/nominale moyen {g.ratio_reel_sur_nominal.mean():.3f} ; "
                f"classique {g[g.sig_class == 'classical'].ratio_reel_sur_nominal.mean():.3f} ; ML-DSA {g[g.sig_class == 'pqc'].ratio_reel_sur_nominal.mean():.3f}")
    log(f"\nTermine en {time.time() - t0:.0f} s. Fichiers dans {out}")
    with open(os.path.join(out, "p2_report.txt"), "w") as fh:
        fh.write("\n".join(REP) + "\n")


if __name__ == "__main__":
    main()
