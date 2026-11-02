#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""make_figures.py -- genere TOUTES les figures de l'etude (v2 + extensions v3), chacune dans son dossier propre.

Usage (depuis la racine du depot) :
    python3 figures/make_figures.py --v2-dir ~/.../analysis_v2 --v3-dir analysis_v3 --out figures_out
    python3 figures/make_figures.py --v2-dir ... --campaign v2 --only F01 F04
    python3 figures/make_figures.py --list

  --v2-dir  dossier contenant (au premier niveau ou en sous-dossiers) conn.csv.gz, flight_timeline_summary.csv, p3_k_pred_vs_obs.csv
  --v3-dir  dossier de sortie de 13_analyse_extensions.py (p6_connexions.csv.gz, p6_load_niveaux.csv, p6_pont_v2.csv)
  --force   regenere meme si les entrees n'ont pas change (l'ancienne version est archivee, jamais ecrasee)
Une figure dont les entrees sont absentes est SAUTEE avec un message (pas d'erreur) : on peut donc lancer le script avant
que tous les bras v3 soient termines ; il ne produit que ce que les donnees permettent.
"""
import argparse
import sys
import time
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import figkit as fk            # noqa: E402
import fig_v2                  # noqa: E402,F401
import fig_v3                  # noqa: E402,F401


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--v2-dir", default=""); ap.add_argument("--v3-dir", default="")
    ap.add_argument("--out", default="figures_out")
    ap.add_argument("--campaign", nargs="*", default=None, choices=fk.CAMPAIGNS)
    ap.add_argument("--only", nargs="*", default=None, help="identifiants de figure (ex. F01 R02)")
    ap.add_argument("--force", action="store_true"); ap.add_argument("--list", action="store_true")
    a = ap.parse_args()

    specs = [s for s in fk.REGISTRY.values()
             if (a.campaign is None or s.campaign in a.campaign) and (a.only is None or s.fid in a.only)]
    specs.sort(key=lambda s: (fk.CAMPAIGNS.index(s.campaign), s.fid))
    if a.list:
        for s in specs:
            print(f"{s.campaign:10s} {s.fid:5s} {s.slug:34s} entrees={','.join(s.inputs)}  {s.title}")
        return 0
    ctx = fk.Ctx({"v2_dir": a.v2_dir or None, "v3_dir": a.v3_dir or None})
    out = fk.OutDir(a.out)
    n_ok = n_skip = n_fail = n_nodata = 0
    for s in specs:
        tag = f"[{s.campaign}/{s.fid}_{s.slug}]"
        try:
            missing = [k for k in s.inputs if not ctx.available(k)]
        except RuntimeError as e:
            print(f"{tag} ENTREE AMBIGUE : {e}"); n_fail += 1; continue
        if missing:
            print(f"{tag} entrees absentes : {missing} -> sautee"); n_nodata += 1; continue
        t0 = time.time()
        try:
            fp = ctx.fingerprint(s)
            if out.status(s, fp) == "a_jour" and not a.force:
                print(f"{tag} a jour (entrees et code inchanges)"); n_skip += 1; continue
            variants = s.fn(ctx)
            if not variants:
                print(f"{tag} aucune variante produite (donnees insuffisantes) -> rien ecrit"); n_nodata += 1; continue
            st, path = out.write_figure(s, variants, fp, ctx.inputs_meta(s), force=a.force)
            print(f"{tag} {st} : {len(variants)} variante(s) -> {path}  ({time.time() - t0:.1f}s)"); n_ok += 1
        except Exception:
            n_fail += 1
            print(f"{tag} ECHEC :"); traceback.print_exc()
    idx = out.write_index()
    print(f"\nBilan : {n_ok} generee(s), {n_skip} a jour, {n_nodata} sans donnees, {n_fail} echec(s). INDEX : {out.root/'INDEX.csv'} ({len(idx)} variantes)")
    return 1 if n_fail else 0


if __name__ == "__main__":
    sys.exit(main())
