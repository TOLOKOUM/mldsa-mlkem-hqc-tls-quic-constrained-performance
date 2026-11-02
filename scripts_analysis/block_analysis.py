#!/usr/bin/env python3
"""
block_analysis.py - Analyse AU NIVEAU DES BLOCS (critique 2 de l'AE, TDSC-2026-09-3862).

Principe : l'unite statistique est le BLOC (25 connexions consecutives d'une paire dans une
cellule), jamais la connexion. Pour chaque (protocole, cellule, KEM) on forme, bloc par bloc,
la difference appariee  mediane(App-ready PQ) - mediane(App-ready classique), puis :
  - IC bootstrap percentile en re-echantillonnant les BLOCS ;
  - test de permutation par inversion de signe sur les differences par bloc
    (exact si n_blocs <= 20, sinon Monte-Carlo) ; avec 4 blocs, p bilateral minimal = 0.125 ;
  - ecart-type des differences, et difference minimale detectable (puissance 80 %, alpha 5 %).
Egalement : variance intra/inter-blocs, taux d'echec, derive des sentinelles.

Entree  : <racine>/<proto>/single/<cellule>/csv/handshake_<proto>_single_<sig>_<kem>_<cellule>_block<k>of<N>[_mb<r>of<M>].csv
          (produits par logs_to_csv.py ; <sig> = premier mot, <kem> = le reste)
Sortie  : <out>/block_medians.csv, <out>/block_contrasts.csv, <out>/summary.txt

Usage   : python3 block_analysis.py --root captures_pilot --out analysis_pilot
          [--classic secp384r1] [--pq mldsa65] [--boot 10000] [--seed 20261000]
          [--metric app_ready_ms|handshake_duration_ms]
"""
import argparse, glob, itertools, os, re, sys
import numpy as np
import pandas as pd

FN = re.compile(r"^handshake_(?P<proto>[a-z]+)_single_(?P<rest>.+?)_block(?P<k>\d+)of(?P<n>\d+)(?:_mb(?P<r>\d+)of(?P<m>\d+))?\.csv$")


def load(root):
    rows = []
    for f in sorted(glob.glob(os.path.join(root, "*", "single", "*", "csv", "*.csv"))):
        parts = f.split(os.sep)
        proto, cell = parts[-5], parts[-3]
        m = FN.match(os.path.basename(f))
        if not m:
            print(f"[AVERTISSEMENT] nom non reconnu, ignore: {f}", file=sys.stderr)
            continue
        rest = m.group("rest")
        suffix = "_" + cell
        if not rest.endswith(suffix):
            print(f"[AVERTISSEMENT] cellule absente du nom, ignore: {f}", file=sys.stderr)
            continue
        pair = rest[: -len(suffix)]
        sig, _, kem = pair.partition("_")
        d = pd.read_csv(f)
        d["proto"], d["cell"], d["sig"], d["kem"] = proto, cell, sig, kem
        d["block"] = int(m.group("k"))
        d["n_blocks_decl"] = int(m.group("n"))
        rows.append(d)
    if not rows:
        sys.exit(f"Aucun CSV sous {root}/*/single/*/csv/. Lancez d'abord logs_to_csv.py {root} --all")
    return pd.concat(rows, ignore_index=True)


def block_table(df, metric):
    df = df.copy()
    ok = (df["app_success"] == 1) if metric == "app_ready_ms" else (df["success"] == 1)
    df["ok"] = ok
    df["val"] = df[metric].where(ok)
    g = df.groupby(["proto", "cell", "sig", "kem", "block"])
    out = g.agg(n=("ok", "size"), n_ok=("ok", "sum"),
                med=("val", "median"), mean=("val", "mean"),
                gmean=("val", lambda x: float(np.exp(np.log(x.dropna()[x.dropna() > 0]).mean())) if x.notna().any() else np.nan), p90=("val", lambda x: x.quantile(0.9)),
                sd_within=("val", "std")).reset_index()
    out["fail_rate"] = 1 - out["n_ok"] / out["n"]
    return out


def signflip_p(d, rng, mc=200000):
    d = np.asarray(d, float)
    n = len(d)
    obs = abs(d.mean())
    if n <= 20:
        signs = np.array(list(itertools.product([-1, 1], repeat=n)))
        stat = np.abs((signs * d).mean(axis=1))
        return float((stat >= obs - 1e-12).mean()), "exact"
    signs = rng.choice([-1, 1], size=(mc, n))
    stat = np.abs((signs * d).mean(axis=1))
    return float(((stat >= obs - 1e-12).sum() + 1) / (mc + 1)), "monte-carlo"


def boot_ci(d, rng, B):
    d = np.asarray(d, float)
    idx = rng.integers(0, len(d), size=(B, len(d)))
    m = d[idx].mean(axis=1)
    return float(np.percentile(m, 2.5)), float(np.percentile(m, 97.5))


def mde(sd, n):
    """Difference minimale detectable, test t apparie, bilateral 5 %, puissance 80 %."""
    if n < 2 or not np.isfinite(sd):
        return float("nan")
    try:
        from scipy import stats
        return float((stats.t.ppf(0.975, n - 1) + stats.t.ppf(0.80, n - 1)) * sd / np.sqrt(n))
    except Exception:
        return float((1.96 + 0.84) * sd / np.sqrt(n))   # approximation normale (optimiste si n petit)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default="captures_pilot")
    ap.add_argument("--out", default="analysis_pilot")
    ap.add_argument("--classic", default="secp384r1")
    ap.add_argument("--pq", default="mldsa65")
    ap.add_argument("--boot", type=int, default=10000)
    ap.add_argument("--seed", type=int, default=20261000)
    ap.add_argument("--metric", default="app_ready_ms", choices=["app_ready_ms", "handshake_duration_ms"])
    ap.add_argument("--stat", default="mean", choices=["mean", "med", "p90", "gmean"],
                    help="statistique PAR BLOC servant au contraste (defaut: mean). Sous perte la mediane de 25 "
                         "connexions tombe sur le mode sans perte et masque la queue : a comparer a la moyenne et au P90.")
    ap.add_argument("--proj-blocks", type=int, default=20,
                    help="PROJECTION de puissance : nombre de blocs de la campagne (defaut 20)")
    ap.add_argument("--proj-conns", type=int, default=10,
                    help="PROJECTION de puissance : connexions par paire et par bloc (defaut 10 = plans cibles ; 25 = plan_main)")
    ap.add_argument("--exclude-blocks", default="",
                    help="blocs a exclure (ex. 1 ou 1,2) : analyse de sensibilite (ex. bloc 1 du pilote, touche par l'hibernation)")
    a = ap.parse_args()
    rng = np.random.default_rng(a.seed)
    os.makedirs(a.out, exist_ok=True)

    df = load(a.root)
    if a.exclude_blocks:
        ex = {int(x) for x in a.exclude_blocks.split(",") if x.strip()}
        df = df[~df["block"].isin(ex)]
        if df.empty:
            sys.exit("Plus aucun bloc apres exclusion.")
    bt = block_table(df, a.metric)
    bt.to_csv(os.path.join(a.out, "block_medians.csv"), index=False)

    lines = []
    P = lines.append
    if a.exclude_blocks:
        P(f"[SENSIBILITE] blocs exclus : {a.exclude_blocks}")
    P(f"Metrique: {a.metric} (statistique par bloc: {a.stat}, succes uniquement) | classique={a.classic} PQ={a.pq}")
    P(f"Racine: {a.root} | {df['proto'].nunique()} protocole(s), {df.groupby(['proto','cell']).ngroups} cellule(s), "
      f"{bt['block'].nunique()} bloc(s), {len(df)} connexions (hors echauffement)")
    P("Avertissement: avec n blocs, le test par inversion de signe a un p bilateral minimal de 2/2^n "
      "(n=4 -> 0.125) : sur le pilote ce script sert a CALIBRER variance et puissance, pas a conclure.")
    P("")

    # contrastes
    res = []
    piv = bt.pivot_table(index=["proto", "cell", "kem", "block"], columns="sig", values=a.stat)
    for (proto, cell, kem), sub in piv.groupby(level=[0, 1, 2]):
        if a.classic not in sub.columns or a.pq not in sub.columns:
            continue
        s = sub[[a.classic, a.pq]].dropna()
        if len(s) < 2:
            continue
        d = (s[a.pq] - s[a.classic]).values
        lr = np.log(s[a.pq].values / s[a.classic].values)
        lo, hi = boot_ci(d, rng, a.boot)
        p, how = signflip_p(d, rng)
        # Projection de puissance (approximative, surtout valable pour --stat mean) : variance par connexion tiree de la
        # variance INTRA-bloc des deux bras, plus la composante inter-blocs residuelle observee.
        arms = bt[(bt["proto"] == proto) & (bt["cell"] == cell) & (bt["kem"] == kem)]
        vc = np.nanmean(arms[arms["sig"] == a.classic]["sd_within"] ** 2)
        vp = np.nanmean(arms[arms["sig"] == a.pq]["sd_within"] ** 2)
        m_obs = float(np.nanmean(arms[arms["sig"].isin([a.classic, a.pq])]["n_ok"]))
        between = max(0.0, float(d.var(ddof=1)) - (vc + vp) / m_obs) if m_obs > 0 else float("nan")
        proj_var = (vc + vp) / (a.proj_blocks * a.proj_conns) + between / a.proj_blocks
        proj_mde = mde(float(np.sqrt(proj_var * a.proj_blocks)), a.proj_blocks)
        res.append(dict(proto=proto, cell=cell, kem=kem, n_blocks=len(d),
                        sd_conn_diff=float(np.sqrt(vc + vp)), proj_mde_80=proj_mde,
                        med_classic=s[a.classic].mean(), med_pq=s[a.pq].mean(),
                        diff_mean=d.mean(), diff_sd=d.std(ddof=1), ci_lo=lo, ci_hi=hi,
                        ratio_geo=float(np.exp(lr.mean())), p_signflip=p, p_method=how,
                        mde_80=mde(d.std(ddof=1), len(d)), same_sign_blocks=int((np.sign(d) == np.sign(d.mean())).sum())))
    ct = pd.DataFrame(res)
    ct.to_csv(os.path.join(a.out, "block_contrasts.csv"), index=False)
    P(f"== Contrastes apparies par bloc (PQ - classique), en ms == [proj_mde_80 = difference minimale detectable PROJETEE "
      f"pour {a.proj_blocks} blocs x {a.proj_conns} connexions/paire/bloc, puissance 80 %, alpha 5 % ; approximation]")
    if ct.empty:
        P(f"(aucun contraste: il faut les deux signatures {a.classic} et {a.pq} avec le meme KEM dans une cellule)")
    else:
        P(ct.round(3).to_string(index=False))
    P("")

    # variance intra / inter
    P("== Variance intra-bloc vs inter-blocs (par paire et cellule) ==")
    v = []
    for (proto, cell, sig, kem), s in bt.groupby(["proto", "cell", "sig", "kem"]):
        if len(s) < 2:
            continue
        within = np.nanmean(s["sd_within"] ** 2)
        between = s[a.stat].var(ddof=1)
        v.append(dict(proto=proto, cell=cell, sig=sig, kem=kem, n_blocks=len(s),
                      sd_within=np.sqrt(within), sd_between_blocks=np.sqrt(between),
                      ratio_between_over_within=np.sqrt(between / within) if within > 0 else np.nan,
                      fail_rate=s["fail_rate"].mean()))
    vt = pd.DataFrame(v)
    if not vt.empty:
        vt.to_csv(os.path.join(a.out, "variance_by_cell.csv"), index=False)
        P(vt.round(3).to_string(index=False))
    P("")

    # sentinelles
    sen = bt[bt["cell"].str.contains("__sentinel_")].copy()
    if not sen.empty:
        sen["visite"] = sen["cell"].str.extract(r"__sentinel_(\w+)$")[0]
        P("== Sentinelles (mediane par bloc et visite) : estimateur direct de la derive ==")
        P(sen.pivot_table(index=["proto", "sig", "kem", "block"], columns="visite", values=a.stat)
             .reindex(columns=["pre", "mid", "post"]).round(3).to_string())
        P("")

    txt = "\n".join(lines)
    open(os.path.join(a.out, "summary.txt"), "w").write(txt + "\n")
    print(txt)
    print(f"\nFichiers ecrits dans {a.out}/ : block_medians.csv, block_contrasts.csv, variance_by_cell.csv, summary.txt")


if __name__ == "__main__":
    main()
