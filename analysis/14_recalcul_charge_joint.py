#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""14_recalcul_charge_joint.py -- recalcul des statistiques de charge (campagne B3) apres l'audit du 15 novembre 2026.

Corrige trois points de analysis/13_analyse_extensions.py SANS modifier ce fichier ni les donnees :
  (1) effectifs reels de blocs pour le cout marginal S (S est NaN dans un bloc si < 3 debits distincts avec util_srv < 0,85) ;
  (2) bootstrap CONJOINT : une seule matrice d'indices de blocs est utilisee pour X, S et U (la version 13 tirait des indices
      differents pour chaque table, ce qui perd l'appariement dans le produit X x S) ;
  (3) sensibilite de S au seuil d'utilisation et a une estimation groupee (pente poolee sur tous les blocs d'une cellule).
Entree : analysis_v3/p6_load_niveaux.csv (publie).  Sorties : <out>/p6_load_effectifs_S.csv, p6_load_L1b_conjoint.csv,
p6_load_S_sensibilite.csv.   Usage : python3 14_recalcul_charge_joint.py --csv analysis_v3/p6_load_niveaux.csv --out analysis_v3 [--boot 100000] [--seed 20261115]
"""
import argparse, os
import numpy as np, pandas as pd

KEYS = ["proto", "tls_server", "rtt", "sig", "kem"]


def s_marg_block(g, thr=0.85, nmin=3):
    gg = g[(g.util_srv < thr) & g.util_srv.notna() & (g.X > 0)]
    if gg.X.nunique() < nmin:
        return np.nan
    return 1000.0 * np.polyfit(gg.X, gg.util_srv * gg.srv_cpus, 1)[0]


def per_block(good, thr, nmin=3):
    rows = []
    for k, g in good.groupby(KEYS + ["block"]):
        rows.append(dict(zip(KEYS + ["block"], k), S=s_marg_block(g, thr, nmin)))
    return pd.DataFrame(rows)


def ci(b):
    b = b[np.isfinite(b)]
    return (np.nan, np.nan) if len(b) < 20 else (float(np.percentile(b, 2.5)), float(np.percentile(b, 97.5)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True); ap.add_argument("--out", required=True)
    ap.add_argument("--boot", type=int, default=100000); ap.add_argument("--seed", type=int, default=20261115)
    a = ap.parse_args()
    d = pd.read_csv(a.csv)
    good = d[~d.cli_bound].copy()
    blocks = sorted(good.block.unique()); nb = len(blocks)
    cmax = int(d.conc.max())

    # ---- (1) effectifs reels et (3) sensibilite -------------------------------------------------------------
    sens = []
    for thr in (0.80, 0.85, 0.90, 0.95):
        pb = per_block(good, thr)
        for k, g in pb.groupby(KEYS):
            sens.append(dict(zip(KEYS, k), seuil_util=thr, n_blocs_S=int(g.S.notna().sum()), n_blocs=len(g), S_moyen_ms=g.S.mean(), S_ecart_type_ms=g.S.std()))
    sens = pd.DataFrame(sens)
    # estimation groupee : pente CPU-s/s sur X, tous blocs d'une cellule ensemble, niveaux util < seuil
    pooled = []
    for thr in (0.85, 0.95):
        for k, g in good.groupby(KEYS):
            gg = g[(g.util_srv < thr) & g.util_srv.notna() & (g.X > 0)]
            if gg.X.nunique() >= 3:
                s = 1000.0 * np.polyfit(gg.X, gg.util_srv * gg.srv_cpus, 1)[0]
                rng = np.random.default_rng(a.seed)
                bl = gg.block.unique(); bs = []
                for _ in range(2000):
                    pick = rng.choice(bl, len(bl)); x = pd.concat([gg[gg.block == b] for b in pick])
                    if x.X.nunique() >= 3: bs.append(1000.0 * np.polyfit(x.X, x.util_srv * x.srv_cpus, 1)[0])
                lo, hi = ci(np.array(bs))
                pooled.append(dict(zip(KEYS, k), seuil_util=thr, S_groupe_ms=s, ic_lo=lo, ic_hi=hi, n_points=len(gg), n_blocs=gg.block.nunique()))
    pooled = pd.DataFrame(pooled)
    os.makedirs(a.out, exist_ok=True)
    sens.to_csv(os.path.join(a.out, "p6_load_S_sensibilite.csv"), index=False)
    pooled.to_csv(os.path.join(a.out, "p6_load_S_groupe.csv"), index=False)
    eff = sens[sens.seuil_util == 0.85][KEYS + ["n_blocs_S", "n_blocs", "S_moyen_ms"]]
    eff.to_csv(os.path.join(a.out, "p6_load_effectifs_S.csv"), index=False)
    print("== effectifs de blocs pour S marginal (seuil 0,85) ==")
    print(eff.to_string(index=False))
    print("== sensibilite de S moyen au seuil ==")
    print(sens.pivot_table(index=KEYS, columns="seuil_util", values="S_moyen_ms").round(2).to_string())
    print("== S groupe (pente poolee) ==")
    print(pooled.round(3).to_string(index=False))

    # ---- (2) bootstrap conjoint de L1b ---------------------------------------------------------------------
    pb = per_block(good, 0.85)
    top = good[good.conc == cmax]
    out = []
    rng = np.random.default_rng(a.seed)
    idx = rng.integers(0, nb, size=(a.boot, nb))           # UNE matrice d'indices pour toutes les grandeurs
    pos = {b: i for i, b in enumerate(blocks)}
    for k, g in top.groupby(KEYS):
        X = np.full(nb, np.nan); U = np.full(nb, np.nan); S = np.full(nb, np.nan)
        for r in g.itertuples():
            X[pos[r.block]] = r.X; U[pos[r.block]] = r.util_srv
        s = pb[(pb.proto == k[0]) & (pb.tls_server == k[1]) & (pb.rtt == k[2]) & (pb.sig == k[3]) & (pb.kem == k[4])]
        for r in s.itertuples():
            S[pos[r.block]] = r.S
        with np.errstate(all="ignore"):
            mX, mS, mU = np.nanmean(X[idx], axis=1), np.nanmean(S[idx], axis=1), np.nanmean(U[idx], axis=1)
            e = np.nanmean(X) * np.nanmean(S) / 1000.0
            b_joint = mX * mS / 1000.0
            # appariement sur blocs ou S est defini : produit par bloc, puis moyenne
            XS = X * S / 1000.0
            b_blk = np.nanmean(XS[idx], axis=1)
            # version "tirages independants" (methode du script 13), pour comparaison
            r2 = np.random.default_rng(a.seed + 1)
            iX = r2.integers(0, nb, size=(a.boot, nb)); iS = r2.integers(0, nb, size=(a.boot, nb))
            b_ind = np.nanmean(X[iX], axis=1) * np.nanmean(S[iS], axis=1) / 1000.0
        out.append(dict(zip(KEYS, k), n_blocs_S=int(np.isfinite(S).sum()), U_estim=np.nanmean(U), U_lo=ci(mU)[0], U_hi=ci(mU)[1],
                        XS_estim=e, joint_lo=ci(b_joint)[0], joint_hi=ci(b_joint)[1],
                        parbloc_estim=np.nanmean(XS), parbloc_lo=ci(b_blk)[0], parbloc_hi=ci(b_blk)[1],
                        indep_lo=ci(b_ind)[0], indep_hi=ci(b_ind)[1]))
    out = pd.DataFrame(out)
    out.to_csv(os.path.join(a.out, "p6_load_L1b_conjoint.csv"), index=False)
    print("== X(c=%d) x S_marginal : estimation, IC conjoint, IC par bloc, IC independant ==" % cmax)
    print(out.round(4).to_string(index=False))


if __name__ == "__main__":
    main()
