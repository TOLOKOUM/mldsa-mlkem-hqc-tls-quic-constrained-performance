#!/usr/bin/env python3
"""
check_plan.py - Controle d'un plan de campagne AVANT lancement.

1) Unicite des dossiers de sortie : pour chaque cellule on demande au Launcher son label reel
   (PRINT_LABEL=1, meme code que la campagne) ; deux cellules de meme (protocole, auth, label) dont les
   paires se recouvrent ecraseraient le meme dossier, et la reprise "deja fait" sauterait la seconde
   SANS erreur (trou silencieux dans les donnees).
2) Coherence : cell_id uniques, total_runs divisible par n_blocks, MICRO_BATCHES divise les connexions/bloc,
   paires bien formees, extra_env bien forme.
Code retour 0 = OK, 1 = au moins un probleme.

Usage : check_plan.py plans/plan_all.csv [--launcher chemin/Launcher_pq_mldsa_mlkem_hqc.sh] [--n-blocks 20]
"""
import argparse, csv, os, subprocess, sys, collections

ap = argparse.ArgumentParser()
ap.add_argument("plan")
ap.add_argument("--launcher", default=None)
ap.add_argument("--n-blocks", type=int, default=20)
a = ap.parse_args()

here = os.path.dirname(os.path.abspath(__file__))
cands = [a.launcher] if a.launcher else [os.path.join(here, "Launcher_pq_mldsa_mlkem_hqc.sh"),
                                           os.path.join(here, "..", "launchers", "Launcher_pq_mldsa_mlkem_hqc.sh")]
launcher = next((c for c in cands if c and os.path.isfile(c)), None)
if not launcher:
    sys.exit("Launcher introuvable (utilisez --launcher).")

errors, seen_ids = [], set()
users = collections.defaultdict(list)   # (proto, auth, label) -> [(cell_id, set(pairs) | None)]
rows = list(csv.DictReader(open(a.plan)))
for r in rows:
    cid = r["cell_id"]
    if cid in seen_ids:
        errors.append(f"cell_id en double: {cid}")
    seen_ids.add(cid)
    total = int(r["total_runs"])
    if total % a.n_blocks:
        errors.append(f"{cid}: total_runs={total} non divisible par n_blocks={a.n_blocks}")
        continue
    per_block = total // a.n_blocks
    env = dict(os.environ)
    env.update(TOTAL_RUNS=str(total), PRINT_LABEL="1")
    env.pop("ONLY_PAIRS", None)
    extra = {}
    if r["extra_env"]:
        for kv in r["extra_env"].split(";"):
            if "=" not in kv:
                errors.append(f"{cid}: extra_env mal forme '{kv}'")
                continue
            k, v = kv.split("=", 1)
            extra[k] = v
    env.update(extra)
    mb = int(extra.get("MICRO_BATCHES", "1") or 1)
    if mb > 1 and per_block % mb:
        errors.append(f"{cid}: {per_block} connexions/bloc non divisibles par MICRO_BATCHES={mb}")
    pairs = None
    if r["only_pairs"]:
        pairs = set()
        for p in r["only_pairs"].split(";"):
            if p.count("|") != 1:
                errors.append(f"{cid}: paire mal formee '{p}'")
            pairs.add(p)
    cmd = ["bash", launcher, r["kem_family"], r["protocol"], r["auth"], "nocapture", r["profile"],
           r["loss"], r["delay"], str(a.n_blocks), "1", "1"]
    p = subprocess.run(cmd, env=env, capture_output=True, text=True)
    label = p.stdout.strip().splitlines()[-1] if p.returncode == 0 and p.stdout.strip() else None
    if label is None:
        errors.append(f"{cid}: le Launcher refuse la cellule ({(p.stdout + p.stderr).strip().splitlines()[-1:]})")
        continue
    users[(r["protocol"], r["auth"], label)].append((cid, pairs))

for key, lst in users.items():
    for i in range(len(lst)):
        for j in range(i + 1, len(lst)):
            (c1, p1), (c2, p2) = lst[i], lst[j]
            overlap = (p1 is None or p2 is None) or bool(p1 & p2)
            if overlap:
                shared = "toutes les paires" if (p1 is None or p2 is None) else ", ".join(sorted(p1 & p2))
                errors.append(f"COLLISION de dossier {key[0]}/{key[1]}/{key[2]} : {c1} et {c2} (paires communes : {shared})")

print(f"{a.plan}: {len(rows)} cellules, {len(users)} dossiers distincts (protocole/auth/label)")
if errors:
    print(f"\n{len(errors)} PROBLEME(S) :")
    for e in errors:
        print("  ❌", e)
    sys.exit(1)
print("✅ aucune collision, plan coherent")
