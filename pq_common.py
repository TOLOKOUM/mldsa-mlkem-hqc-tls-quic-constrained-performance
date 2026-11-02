#!/usr/bin/env python3
"""pq_common.py -- constantes, lecture des labels du Launcher et outils statistiques partages.
Aucune dependance au contenu des donnees (importable par tous les scripts d'analyse)."""
from __future__ import annotations
import re
import numpy as np
import pandas as pd
from scipy import stats

N_BLOCKS = 20
SIGS = {"ed25519": ("L1", "classical"), "mldsa44": ("L1", "pqc"),
        "secp384r1": ("L3", "classical"), "mldsa65": ("L3", "pqc"),
        "secp521r1": ("L5", "classical"), "mldsa87": ("L5", "pqc")}
_KEMS = {"L1": ["P-256", "x25519", "p256_mlkem512", "x25519_mlkem512", "mlkem512", "hqc128", "p256_hqc128", "x25519_hqc128"],
         "L3": ["P-384", "x448", "p384_mlkem768", "x448_mlkem768", "mlkem768", "hqc192", "p384_hqc192", "x448_hqc192"],
         "L5": ["P-521", "p521_mlkem1024", "mlkem1024", "hqc256", "p521_hqc256"]}
ALL_PAIRS = [(s, k) for s, (lv, _) in SIGS.items() for k in _KEMS[lv]]
assert len(ALL_PAIRS) == 42


def kem_info(kem: str):
    """(famille, forme) : famille classical|mlkem|hqc ; forme classical|hybrid|pure."""
    k = kem.lower()
    fam = "hqc" if "hqc" in k else "mlkem" if "mlkem" in k else "classical"
    hyb = fam != "classical" and any(t in k for t in ("p256", "p384", "p521", "x25519", "x448"))
    return fam, ("classical" if fam == "classical" else "hybrid" if hyb else "pure")


# Gilbert-Elliott du Launcher : (pg, pb, 1-h, 1-k) en %. Perte marginale = pg/(pg+pb) (1-h=100, 1-k=0).
GE_PARAMS = {"ge-mild-1": (0.546, 54, 100, 0), "ge-mild-2": (1.102, 54, 100, 0), "ge-mild-5": (2.842, 54, 100, 0),
             "ge-severe-1": (0.202, 20, 100, 0), "ge-severe-2": (0.408, 20, 100, 0), "ge-severe-5": (1.053, 20, 100, 0)}


def ge_marginal(name):  # en %
    pg, pb, _, _ = GE_PARAMS[name]
    return 100.0 * pg / (pg + pb)


def ge_burst_len(name):  # paquets perdus consecutifs moyens
    return 100.0 / GE_PARAMS[name][1]


def plan_label(row: dict) -> str:
    """Reproduit EXACTEMENT NETWORK_PROFILE_LABEL de Launcher_pq_mldsa_mlkem_hqc.sh pour une ligne de plan."""
    prof, loss, delay = row["profile"].strip(), row["loss"].strip(), row["delay"].strip()
    env = dict(kv.split("=", 1) for kv in (row.get("extra_env") or "").split(";") if "=" in kv)
    lab = {"simple": f"simple_loss{loss}_delay{delay}ms", "delay-only": f"delayonly_delay{delay}ms",
           "loss-only": f"lossonly_loss{loss}"}.get(prof, prof)
    if prof.startswith(("ge-mild-", "ge-severe-")):
        lab = f"{prof}_delay{delay}ms"
    if env.get("MTU", "1500") != "1500":
        lab += f"_mtu{env['MTU']}"
    if env.get("LOSS_DIRECTION", "s2c") != "s2c" and (prof in ("simple", "loss-only") or prof.startswith("ge-")):
        lab += f"_dir{env['LOSS_DIRECTION']}"
    if env.get("QUIC_MTU_SYNC") == "1":
        lab += "__qmtu"
    if env.get("CHAIN_DEPTH") == "2":
        lab += "__chain2"
    if int(env.get("CERT_PAD_BYTES", "0") or 0) > 0:
        lab += f"__pad{env['CERT_PAD_BYTES']}b"
    if int(env.get("CERT_PAD_TARGET_DER", "0") or 0) > 0:
        lab += f"__padto{env['CERT_PAD_TARGET_DER']}"
    if env.get("PER_CONN_PCAP") == "1":
        lab += "__pcap"
    if int(env.get("MICRO_BATCHES", "1") or 1) > 1:
        lab += f"__mb{env['MICRO_BATCHES']}"
    return lab


_LABEL_RE = re.compile(
    r"^(?:simple_loss(?P<sl>[\d.]+)_delay(?P<sd>[\d.]+)ms|lossonly_loss(?P<ll>[\d.]+)|delayonly_delay(?P<dd>[\d.]+)ms"
    r"|(?P<ge>ge-(?:mild|severe)-\d)_delay(?P<gd>[\d.]+)ms|(?P<plain>none|stable|unstable))"
    r"(?:_mtu(?P<mtu>\d+))?(?:_dir(?P<dir>c2s|both))?(?P<qmtu>__qmtu)?(?P<chain>__chain2)?"
    r"(?:__pad(?P<padb>\d+)b)?(?:__padto(?P<padto>\d+))?(?P<pcap>__pcap)?(?:__mb(?P<mb>\d+))?"
    r"(?:__sentinel_(?P<sent>[A-Za-z0-9]+))?$")


def parse_label(label: str):
    """Facteurs de conception portes par le label (None si le label n'est pas reconnu)."""
    m = _LABEL_RE.match(label)
    if not m:
        return None
    g = m.groupdict()
    if g["sl"] is not None:
        kind, proc, loss, delay = "simple", "iid", float(g["sl"]), float(g["sd"])
    elif g["ll"] is not None:
        kind, proc, loss, delay = "lossonly", "iid", float(g["ll"]), 0.0
    elif g["dd"] is not None:
        kind, proc, loss, delay = "delayonly", "none", 0.0, float(g["dd"])
    elif g["ge"] is not None:
        kind, proc, loss, delay = "ge", g["ge"].rsplit("-", 1)[0], float(g["ge"].rsplit("-", 1)[1]), float(g["gd"])
    else:
        kind, proc, loss, delay = ("none", "none", 0.0, 0.0) if g["plain"] == "none" else ("legacy", "ge-legacy", np.nan, 0.0)
    return dict(kind=kind, process=proc, ge_name=g["ge"] or "", loss_nom=loss, delay_ow=delay, rtt=2 * delay,
                mtu=int(g["mtu"] or 1500), loss_dir=g["dir"] or "s2c", qmtu=bool(g["qmtu"]), chain2=bool(g["chain"]),
                padto=int(g["padto"] or 0), padb=int(g["padb"] or 0), pcap=bool(g["pcap"]), mb=int(g["mb"] or 1),
                sentinel=g["sent"] or "")


def family_of(cell_id: str) -> str:
    return cell_id.split("_")[0]


# ---------------------------------------------------------------- statistiques par blocs
def signflip_exact(d, B=400_000, seed=1):
    """p bilaterale exacte (2^n signes, n<=22) du test d'inversion de signe sur les differences par bloc.
    Avec n=20 blocs la plus petite p atteignable est 2/2^20 ~ 1.9e-6 (contre 0.125 avec 4 blocs)."""
    d = np.asarray(d, float); d = d[np.isfinite(d)]; n = len(d)
    if n == 0:
        return float("nan")
    obs = abs(d.sum()); tol = 1e-9 * max(1.0, np.abs(d).sum())
    if n <= 22:
        s = np.zeros(1)
        for x in d:
            s = np.concatenate([s + x, s - x])
        return float((np.abs(s) >= obs - tol).mean())
    sg = np.random.default_rng(seed).choice([-1.0, 1.0], size=(B, n))
    return float(((np.abs(sg @ d) >= obs - tol).sum() + 1) / (B + 1))


def boot_ci(x, B=10000, seed=12345, stat=np.mean):
    x = np.asarray(x, float); x = x[np.isfinite(x)]
    if len(x) < 2:
        return (float("nan"), float("nan"))
    idx = np.random.default_rng(seed).integers(0, len(x), size=(B, len(x)))
    lo, hi = np.quantile(stat(x[idx], axis=1), [0.025, 0.975])
    return float(lo), float(hi)


def paired_summary(d, B=10000, seed=12345):
    """Resume d'une serie de differences par bloc.
    mean/lo/hi : moyenne et IC95 bootstrap PAR BLOCS de cette moyenne ; p : test d'inversion de signe exact sur la moyenne
    (meme statistique que l'estimateur). hl/hl_lo/hl_hi : Hodges-Lehmann et son IC bootstrap (sensibilite robuste)."""
    d = np.asarray(d, float); d = d[np.isfinite(d)]; n = len(d)
    if n < 2:
        return dict(n=n, mean=np.nan, lo=np.nan, hi=np.nan, hl=np.nan, hl_lo=np.nan, hl_hi=np.nan, p=np.nan, same_sign=0)
    idx = np.random.default_rng(seed).integers(0, n, (B, n))
    X = d[idx]
    lo, hi = np.quantile(X.mean(axis=1), [0.025, 0.975])
    i, j = np.triu_indices(n)
    hl = float(np.median((d[i] + d[j]) / 2))
    hl_lo, hl_hi = np.quantile(np.median((X[:, i] + X[:, j]) / 2, axis=1), [0.025, 0.975])
    return dict(n=n, mean=float(d.mean()), lo=float(lo), hi=float(hi), hl=hl, hl_lo=float(hl_lo), hl_hi=float(hl_hi),
                p=signflip_exact(d), same_sign=int((np.sign(d) == np.sign(d.mean())).sum()))


def holm(p):
    p = np.asarray(p, float); m = len(p); o = np.argsort(p); adj = np.empty(m)
    run = 0.0
    for r, i in enumerate(o):
        run = max(run, (m - r) * p[i]); adj[i] = min(1.0, run)
    return adj


def bh(p):
    p = np.asarray(p, float); m = len(p); o = np.argsort(p); adj = np.empty(m); prev = 1.0
    for r in range(m - 1, -1, -1):
        prev = min(prev, p[o[r]] * m / (r + 1)); adj[o[r]] = prev
    return adj


def _codes(g):
    return pd.factorize(np.asarray(g))[0]


def demean(v, groups, iters=300, tol=1e-10):
    """Projection alternee : retire les effets fixes de chaque facteur (regression a effets fixes multiples)."""
    v = np.asarray(v, float).copy(); cs = [_codes(g) for g in groups]
    for _ in range(iters):
        mx = 0.0
        for c in cs:
            m = np.bincount(c, v) / np.bincount(c); v -= m[c]; mx = max(mx, float(np.abs(m).max()))
        if mx < tol:
            break
    return v


def fe_slope(y, x, fes, cluster):
    """Pente de y sur x apres effets fixes `fes` ; ecart-type robuste groupe par `cluster` (ici le bloc), t(G-1)."""
    y = np.asarray(y, float); x = np.asarray(x, float)
    yt = demean(y, fes or [np.zeros(len(y))]); xt = demean(x, fes or [np.zeros(len(y))])
    sxx = float((xt ** 2).sum()); g = _codes(cluster); G = int(g.max()) + 1
    if sxx <= 0 or G < 3:
        return dict(b=np.nan, se=np.nan, lo=np.nan, hi=np.nan, p=np.nan, G=G, n=len(y))
    b = float((xt * yt).sum() / sxx); e = yt - b * xt
    sc = np.bincount(g, weights=xt * e)
    se = float(np.sqrt((sc ** 2).sum() * G / (G - 1)) / sxx); q = stats.t.ppf(0.975, G - 1)
    return dict(b=b, se=se, lo=b - q * se, hi=b + q * se, p=float(2 * stats.t.sf(abs(b / se), G - 1)) if se > 0 else np.nan,
                G=G, n=len(y))


def pct(b):  # coefficient log -> variation relative en %
    return 100.0 * (np.exp(b) - 1.0)
