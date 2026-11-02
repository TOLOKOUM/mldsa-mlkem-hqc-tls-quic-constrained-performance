#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""08_robustesse_modele.py -- PHASE 3c : que vaut vraiment le modele de seuil ?

Trois questions, posees AVANT de lire les resultats, qui limitent la portee de ce que dit 07 :
  Q1  Le modele bat-il des modeles triviaux (k = 0 partout, k = 1 partout, k constant par protocole) ?
      Sur combien de paires la reponse differe-t-elle d'un modele trivial (= paires informatives) ?
  Q2  A quelle distance (octets, %) du seuil se trouve chaque vol ? Les predictions fragiles sont-elles identifiees ?
  Q3  Les verdicts survivent-ils a un balayage des constantes (surcout QUIC, ServerHello, taille de chaine, fenetre initiale
      TCP/QUIC, MSS) ? Le reglage de reference est-il meilleur que ses voisins (signe de sur-ajustement) ou non ?

Entree : <phase3>/p3_k_pred_vs_obs.csv (produit par 07) ; le modele est importe depuis 07_threshold_model.py (meme dossier).
Sorties : p3c_null_models.csv, p3c_margins.csv, p3c_sweep_one_at_a_time.csv, p3c_sweep_grid_summary.csv, p3c_sweep_pairs.csv,
          p3c_report.txt

Usage : python3 tools/08_robustesse_modele.py --phase3 analysis_v2/phase3 [--manifest analysis_v2/manifests.csv]
"""
from __future__ import annotations
import argparse, importlib.util, itertools, os, re, sys, warnings
import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")
HERE = os.path.dirname(os.path.abspath(__file__))
REP: list[str] = []


def log(msg=""):
    print(msg, flush=True)
    REP.append(str(msg))


def load_p3():
    sys.path.insert(0, HERE)
    spec = importlib.util.spec_from_file_location("p3_threshold", os.path.join(HERE, "07_threshold_model.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def verdict(kp, ks):
    dev = float(np.max(np.abs(np.asarray(ks, float) - kp)))
    return "conforme" if dev <= 0.25 else ("partiel" if dev <= 0.75 else "infirme")


def load_obs(path):
    d = pd.read_csv(path)
    km = [c for c in d.columns if re.fullmatch(r"k\d+", c)]
    kd = [c + "_med" for c in km]
    obs = {}
    for _, r in d.iterrows():
        obs[(r.proto, r.level, r.kem)] = dict(mean=np.array([r[c] for c in km], float), med=np.array([r[c] for c in kd], float))
    return obs


def predict(p3, chain, proto, variant="writes"):
    out = {}
    for lv in ("L1", "L3", "L5"):
        cl, ml = p3.CLASSICAL_OF[lv], p3.MLDSA_OF[lv]
        for kem in p3.KEMS[lv]:
            if proto == "tls":
                out[("tls", lv, kem)] = p3.tls_rounds(kem, ml, chain, variant)[0] - p3.tls_rounds(kem, cl, chain, variant)[0]
            else:
                out[("quic", lv, kem)] = p3.quic_rounds(kem, ml, chain)[0] - p3.quic_rounds(kem, cl, chain)[0]
    return out


def counts(pred, obs, est, proto=None, keys=None):
    c = dict(conforme=0, partiel=0, infirme=0)
    for k, kp in pred.items():
        if (proto and k[0] != proto) or (keys is not None and k not in keys):
            continue
        c[verdict(kp, obs[k][est])] += 1
    c["n"] = sum(c.values())
    return c


# ------------------------------------------------------------------------------------------------ Q1 modeles triviaux
def null_models(p3, chain, obs):
    log("\n=== Q1. LE MODELE BAT-IL DES MODELES TRIVIAUX ? (verdicts sur les 21 paires par protocole) ===")
    pb = {**predict(p3, chain, "quic"), **predict(p3, chain, "tls", "bytes")}
    pw = {**predict(p3, chain, "quic"), **predict(p3, chain, "tls", "writes")}
    models = {"trivial k=0": {k: 0 for k in pb}, "trivial k=1": {k: 1 for k in pb},
              "constant par protocole (QUIC=1, TLS=0)": {k: (1 if k[0] == "quic" else 0) for k in pb},
              "seuil, octets seuls (ecrit avant les resultats)": pb,
              "seuil, deux ecritures (ajoute apres avoir vu TLS L5 ML-KEM-1024)": pw}
    ref = models["constant par protocole (QUIC=1, TLS=0)"]
    # paires informatives = celles ou le modele constant par protocole n'est PAS conforme (estimateur median)
    info = {k for k in ref if verdict(ref[k], obs[k]["med"]) != "conforme"}
    log("  Paires informatives (le modele 'constant par protocole' y echoue, estimateur median) : %d" % len(info))
    for k in sorted(info):
        log("     %s %s %-14s : k median observe = %s | predit (octets seuls / deux ecritures) = %d / %d"
            % (k[0].upper(), k[1], k[2], "/".join("%.2f" % v for v in obs[k]["med"]), pb[k], pw[k]))
    rows = []
    for name, pr in models.items():
        for est in ("med", "mean"):
            for proto in ("quic", "tls"):
                r = counts(pr, obs, est, proto)
                ri = counts(pr, obs, est, proto, info)
                rows.append(dict(modele=name, estimateur=est, proto=proto, **{"tous_" + k: v for k, v in r.items()},
                                 **{"informatives_" + k: v for k, v in ri.items()}))
    t = pd.DataFrame(rows)
    t.to_csv(os.path.join(OUT, "p3c_null_models.csv"), index=False)
    for est, nm in (("med", "estimateur MEDIAN par bloc"), ("mean", "estimateur MOYENNE par bloc")):
        log("\n  -- %s : conformes / partiels / infirmes --" % nm)
        log("  %-68s %-16s %-16s %-16s" % ("modele", "QUIC (21)", "TLS (21)", "informatives (%d)" % len(info)))
        for name in models:
            q = t[(t.modele == name) & (t.estimateur == est) & (t.proto == "quic")].iloc[0]
            s = t[(t.modele == name) & (t.estimateur == est) & (t.proto == "tls")].iloc[0]
            f = lambda x, p="tous_": "%d/%d/%d" % (x[p + "conforme"], x[p + "partiel"], x[p + "infirme"])
            ninf = (q.informatives_conforme + s.informatives_conforme, q.informatives_partiel + s.informatives_partiel,
                    q.informatives_infirme + s.informatives_infirme)
            log("  %-68s %-16s %-16s %-16s" % (name, f(q), f(s), "%d/%d/%d" % ninf))
    log("\n  Lecture : seules les paires informatives distinguent le modele de seuil d'une regle triviale. Le test de prediction")
    log("  honnete = la ligne 'octets seuls' (ecrite avant les temps) ; la ligne 'deux ecritures' est une correction post hoc.")
    return info


# ------------------------------------------------------------------------------------------------ Q2 marges au seuil
def margins(p3, chain):
    log("\n=== Q2. MARGE DE CHAQUE VOL AU SEUIL LE PLUS PROCHE (octets et % du seuil) ===")
    rows = []
    for lv in ("L1", "L3", "L5"):
        cl, ml = p3.CLASSICAL_OF[lv], p3.MLDSA_OF[lv]
        for kem in p3.KEMS[lv]:
            for proto in ("tls", "quic"):
                for role, sig in (("classique", cl), ("ML-DSA", ml)):
                    if proto == "tls":
                        total = p3.tls_rounds(kem, sig, chain, "bytes")[2]
                        first, growth, u, ub = p3.TCP_IW, p3.TCP_IW, total / p3.TCP_MSS, p3.TCP_MSS
                    else:
                        _, s, b1, _ = p3.quic_rounds(kem, sig, chain)
                        first, growth, u, ub = b1, p3.QUIC_IW, s, 1.0
                    R = p3.rounds_needed(u, first, growth)
                    cap = lambda r: first + growth * (2 ** r - 2)
                    up = (cap(R) - u) * ub
                    dn = (u - cap(R - 1)) * ub if R > 1 else np.inf
                    mp = 100 * up / (cap(R) * ub)
                    md = 100 * dn / (cap(R - 1) * ub) if R > 1 else np.inf
                    rows.append(dict(proto=proto, level=lv, kem=kem, vol=role, tours=R, octets=u * ub, seuil_haut=cap(R) * ub,
                                     marge_haut_o=up, marge_haut_pct=mp, marge_basse_o=dn, marge_basse_pct=md, marge_min_pct=min(mp, md)))
    t = pd.DataFrame(rows)
    t.to_csv(os.path.join(OUT, "p3c_margins.csv"), index=False)
    pair = t.groupby(["proto", "level", "kem"]).marge_min_pct.min().reset_index().sort_values("marge_min_pct")
    log("  Paires dont un vol est a moins de 5 %% d'un seuil (predictions fragiles) : %d sur %d" % ((pair.marge_min_pct < 5).sum(), len(pair)))
    for _, r in pair.head(8).iterrows():
        w = t[(t.proto == r.proto) & (t.level == r.level) & (t.kem == r.kem)].sort_values("marge_min_pct").iloc[0]
        side = "sous le seuil de %d o (marge %+.0f o)" % (w.seuil_haut, w.marge_haut_o) if w.marge_haut_pct <= w.marge_basse_pct \
            else "au-dessus du seuil precedent (marge %+.0f o)" % w.marge_basse_o
        log("     %s %s %-14s : vol %-9s de %.0f o, %s, soit %.1f %%" % (r.proto.upper(), r.level, r.kem, w.vol, w.octets, side, r.marge_min_pct))
    log("  (TLS : octets / MSS compares a IW=10 segments, estimation sans l'arrondi par ecriture ; QUIC : octets du vol chiffre x 1,037.)")
    return pair


# ------------------------------------------------------------------------------------------------ Q3 balayage des constantes
AXES = [("RHO_QUIC", [1.00, 1.02, 1.037, 1.06, 1.08]), ("A_TLS", [167, 267, 367]), ("SH_FIX", [50, 100, 150]),
        ("chain_scale", [0.95, 1.0, 1.05]), ("TCP_IW", [4, 8, 10, 12, 16]), ("QUIC_IW", [12000, 12520, 14720]), ("TCP_MSS", [1428, 1448, 1460])]


def run_combo(p3, base_chain, combo, obs):
    saved = {k: getattr(p3, k) for k, _ in AXES if k != "chain_scale"}
    try:
        for k, v in combo.items():
            if k != "chain_scale":
                setattr(p3, k, v)
        chain = {s: int(round(c * combo.get("chain_scale", 1.0))) for s, c in base_chain.items()}
        q = predict(p3, chain, "quic")
        res = {("quic", "bytes"): q, ("quic", "writes"): q,
               ("tls", "bytes"): predict(p3, chain, "tls", "bytes"), ("tls", "writes"): predict(p3, chain, "tls", "writes")}
    finally:
        for k, v in saved.items():
            setattr(p3, k, v)
    return res


def sweep(p3, base_chain, obs):
    log("\n=== Q3. BALAYAGE DES CONSTANTES DU MODELE (estimateur median ; reglage de reference = celui de 07) ===")
    base = {k: getattr(p3, k) for k, _ in AXES if k != "chain_scale"}
    base["chain_scale"] = 1.0
    ref = run_combo(p3, base_chain, base, obs)
    # --- un parametre a la fois
    rows = []
    for name, vals in AXES:
        for v in vals:
            cb = dict(base)
            cb[name] = v
            r = run_combo(p3, base_chain, cb, obs)
            for (proto, var), pr in r.items():
                chg = sum(pr[k] != ref[(proto, var)][k] for k in pr)
                c = counts(pr, obs, "med")
                rows.append(dict(parametre=name, valeur=v, proto=proto, variante=var, paires_changees=chg, conformes_med=c["conforme"], n=c["n"],
                                 reference=(v == base[name])))
    one = pd.DataFrame(rows)
    one.to_csv(os.path.join(OUT, "p3c_sweep_one_at_a_time.csv"), index=False)
    log("  -- un parametre a la fois (autres = reference) : nombre de predictions qui changent / conformes (median) --")
    for name, vals in AXES:
        parts = []
        for v in vals:
            q = one[(one.parametre == name) & (one.valeur == v) & (one.proto == "quic") & (one.variante == "writes")].iloc[0]
            t = one[(one.parametre == name) & (one.valeur == v) & (one.proto == "tls") & (one.variante == "writes")].iloc[0]
            parts.append("%s: QUIC %d chg/%d ok, TLS %d chg/%d ok%s" % (v, q.paires_changees, q.conformes_med, t.paires_changees, t.conformes_med,
                                                                     " [ref]" if q.reference else ""))
        log("   %-12s " % name + " | ".join(parts))
    # --- le mecanisme : la fenetre initiale TCP n'est pas une constante de nuisance, c'est l'hypothese testee
    log("\n  -- TEST DU MECANISME : quelle fenetre initiale TCP les donnees selectionnent-elles ? (TLS, conformes sur 21, median) --")
    for var in ("bytes", "writes"):
        s_ = one[(one.parametre == "TCP_IW") & (one.proto == "tls") & (one.variante == var)]
        log("   variante %-6s : " % var + " | ".join("IW=%d : %d/21 (%d predictions changees)" % (r.valeur, r.conformes_med, r.paires_changees) for _, r in s_.iterrows()))
    log("   (le defaut Linux est IW=10 ; la valeur n'est pas ajustee sur les temps)")
    # --- grille complete sur les constantes de nuisance (IW fixe a sa valeur de reference)
    gaxes = [(n, v) for n, v in AXES if n != "TCP_IW"]
    grid = list(itertools.product(*[vals for _, vals in gaxes]))
    log("\n  -- grille complete sur les constantes de nuisance (IW TCP = %d) : %d combinaisons de %d constantes --" % (base["TCP_IW"], len(grid), len(gaxes)))
    keys = [k for k in obs]
    same = {(k, v): 0 for k in keys for v in ("bytes", "writes")}
    ok = {(k, v): 0 for k in keys for v in ("bytes", "writes")}
    tot = {}
    for g in grid:
        combo = dict(base)
        combo.update({n: val for (n, _), val in zip(gaxes, g)})
        r = run_combo(p3, base_chain, combo, obs)
        for var in ("bytes", "writes"):
            for proto in ("quic", "tls"):
                pr = r[(proto, var)]
                tot.setdefault((proto, var), []).append(counts(pr, obs, "med")["conforme"])
                for k, kp in pr.items():
                    same[(k, var)] += int(kp == ref[(proto, var)][k])
                    ok[(k, var)] += int(verdict(kp, obs[k]["med"]) == "conforme")
    N = len(grid)
    srows = []
    for (proto, var), arr in tot.items():
        arr = np.array(arr)
        b = counts(ref[(proto, var)], obs, "med")["conforme"]
        srows.append(dict(proto=proto, variante=var, conformes_reference=b, min=int(arr.min()), mediane=float(np.median(arr)), max=int(arr.max()),
                          part_grille_au_moins_reference=float((arr >= b).mean()), part_grille_strictement_meilleure=float((arr > b).mean()), n_combinaisons=N))
        log("   %-4s %-6s : reference %d/21 conformes ; sur la grille min %d, mediane %.0f, max %d ; %.0f %% des combinaisons font >= la reference, %.0f %% font mieux"
            % (proto.upper(), var, b, arr.min(), np.median(arr), arr.max(), 100 * (arr >= b).mean(), 100 * (arr > b).mean()))
    pd.DataFrame(srows).to_csv(os.path.join(OUT, "p3c_sweep_grid_summary.csv"), index=False)
    prow = []
    for (k, var) in same:
        prow.append(dict(proto=k[0], level=k[1], kem=k[2], variante=var, k_pred_reference=ref[(k[0], var)][k], part_prediction_inchangee=same[(k, var)] / N,
                         part_conforme_median=ok[(k, var)] / N))
    pt = pd.DataFrame(prow)
    pt.to_csv(os.path.join(OUT, "p3c_sweep_pairs.csv"), index=False)
    fr = pt[(pt.variante == "writes") & (pt.part_prediction_inchangee < 0.95)].sort_values("part_prediction_inchangee")
    log("\n  Paires dont la prediction (variante deux ecritures) change dans plus de 5 %% des combinaisons de nuisance : %d sur 42" % len(fr))
    for _, r in fr.iterrows():
        log("     %s %s %-14s : prediction de reference k=%d, inchangee dans %.0f %% des combinaisons, conforme dans %.0f %%"
            % (r.proto.upper(), r.level, r.kem, r.k_pred_reference, 100 * r.part_prediction_inchangee, 100 * r.part_conforme_median))
    rb = pt[(pt.variante == "bytes") & (pt.proto == "tls") & (pt.kem.str.contains("mlkem1024"))]
    for _, r in rb.iterrows():
        log("     (octets seuls) TLS %s %-14s : conforme dans %.0f %% des combinaisons" % (r.level, r.kem, 100 * r.part_conforme_median))
    return pt


def main():
    global OUT
    ap = argparse.ArgumentParser()
    ap.add_argument("--phase3", default="analysis_v2/phase3")
    ap.add_argument("--manifest", default=None)
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    OUT = a.out or a.phase3
    os.makedirs(OUT, exist_ok=True)
    p3 = load_p3()
    obs = load_obs(os.path.join(a.phase3, "p3_k_pred_vs_obs.csv"))
    man = a.manifest or os.path.join(os.path.dirname(os.path.abspath(a.phase3)), "manifests.csv")
    chain = p3.chain_sizes(man)
    log("PHASE 3c -- robustesse du modele de seuil. %d paires observees. Tailles de chaine : %s" % (len(obs), {k: chain[k] for k in sorted(chain)}))
    null_models(p3, chain, obs)
    margins(p3, chain)
    sweep(p3, chain, obs)
    with open(os.path.join(OUT, "p3c_report.txt"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(REP))
    log("\nTermine -> %s" % OUT)


OUT = "."
if __name__ == "__main__":
    main()
