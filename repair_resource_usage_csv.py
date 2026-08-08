#!/usr/bin/env python3
"""
repair_resource_usage_csv.py — Répare les fichiers resource_usage_*.csv
corrompus par le bug de locale (virgule décimale au lieu de point dans
cpu_usec_per_handshake, causée par `awk printf "%.3f"` sous locale française).

La corruption est 100% déterministe et mécanique : le champ
cpu_usec_per_handshake (colonne 10) a été coupé en deux colonnes par la
virgule. Ce script les refusionne avec un point, sans toucher au reste.

USAGE:
    python3 repair_resource_usage_csv.py fichier1.csv [fichier2.csv ...]

Chaque fichier est sauvegardé en .bak avant réparation, puis réécrit corrigé
au même endroit.
"""

import csv
import shutil
import sys
from pathlib import Path

EXPECTED_HEADER = ["timestamp", "protocol", "auth_mode", "sig_alg", "kem",
                    "network_profile", "role", "n_runs", "cpu_usec_total",
                    "cpu_usec_per_handshake", "mem_peak_bytes"]


def repair_file(path: Path):
    backup = path.with_suffix(path.suffix + ".bak")
    shutil.copy2(path, backup)

    with open(path, newline="") as f:
        reader = list(csv.reader(f))

    if not reader:
        print(f"  [!] {path.name}: fichier vide, rien à faire.")
        return

    header = reader[0]
    n_expected = len(EXPECTED_HEADER)
    if header != EXPECTED_HEADER:
        print(f"  [!] {path.name}: en-tête inattendu ({header}) — vérifiez "
              f"manuellement, aucune modification appliquée à part la sauvegarde.")
        return

    fixed_rows = [header]
    n_fixed = 0
    n_untouched = 0
    n_unexpected = 0

    for i, row in enumerate(reader[1:], start=2):
        if len(row) == n_expected:
            fixed_rows.append(row)
            n_untouched += 1
        elif len(row) == n_expected + 1:
            # Fusion des colonnes 10 et 11 (0-indexées 9 et 10) avec un point
            merged = row[:9] + [f"{row[9]}.{row[10]}"] + row[11:]
            fixed_rows.append(merged)
            n_fixed += 1
        else:
            print(f"  [!] {path.name} ligne {i}: {len(row)} colonnes au lieu de "
                  f"{n_expected} ou {n_expected + 1} — laissée telle quelle, à vérifier "
                  f"manuellement: {row}")
            fixed_rows.append(row)
            n_unexpected += 1

    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerows(fixed_rows)

    print(f"  {path.name}: {n_fixed} ligne(s) réparée(s), {n_untouched} déjà correcte(s), "
          f"{n_unexpected} anomalie(s) non-résolue(s) (voir ci-dessus).")
    print(f"    Sauvegarde de l'original : {backup.name}")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    for arg in sys.argv[1:]:
        path = Path(arg)
        if not path.exists():
            print(f"[!] Introuvable, ignoré: {path}")
            continue
        print(f"Réparation de {path} ...")
        repair_file(path)


if __name__ == "__main__":
    main()
