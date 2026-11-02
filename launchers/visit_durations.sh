#!/usr/bin/env bash
###############################################################################
# visit_durations.sh — Duree reelle de chaque visite (cellule/sentinelle) d'apres
# campaign_state/state.csv : sert a calibrer le temps total de la campagne.
# Usage : bash visit_durations.sh [state_dir]   (defaut : campaign_state_pilot)
# La duree d'une visite = ecart avec l'evenement precedent ; les ecarts > 2 h
# (pause, reprise le lendemain) sont ignores.
###############################################################################
STATE="${1:-campaign_state_pilot}/state.csv"
[[ -f "$STATE" ]] || { echo "introuvable: $STATE"; exit 1; }
python3 - "$STATE" <<'PY'
import csv, sys
from datetime import datetime
rows = list(csv.DictReader(open(sys.argv[1])))
prev = None
print("block,kind,cell_id,visit,exit_code,duree_s")
tot = {}
for r in rows:
    t = datetime.fromisoformat(r["timestamp"])
    if r["kind"] == "blockstart":
        prev = t; continue
    d = (t - prev).total_seconds() if prev else None
    prev = t
    if d is None or d > 7200: 
        print(f'{r["block"]},{r["kind"]},{r["cell_id"]},{r["visit"]},{r["exit_code"]},NA'); continue
    print(f'{r["block"]},{r["kind"]},{r["cell_id"]},{r["visit"]},{r["exit_code"]},{d:.0f}')
    tot[r["block"]] = tot.get(r["block"], 0) + d
print()
for b, v in sorted(tot.items(), key=lambda x: int(x[0])):
    print(f"bloc {b} : {v/60:.1f} min")
PY
