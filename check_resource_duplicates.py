#!/usr/bin/env python3
"""
check_resource_duplicates.py
==============================
Diagnostic rapide : pour chaque resource_usage_*.csv trouvé sous captures/,
compte combien de lignes existent par rapport au nombre de combinaisons
uniques (protocol, auth_mode, sig_alg, kem, role). Si une combinaison a
plusieurs lignes (plusieurs timestamps), c'est le symptôme du bug d'append
du launcher (cf. init_resource_csv() dans Launcher_pq_mldsa_mlkem_hqc.sh qui
n'écrit l'en-tête que si le fichier n'existe pas encore, et ajoute toujours
les nouvelles lignes à la suite plutôt que d'écraser).

USAGE (depuis la racine du dépôt) :
    python3 check_resource_duplicates.py
"""

import pandas as pd
from pathlib import Path

KEY_COLS = ["protocol", "auth_mode", "sig_alg", "kem", "role"]


def main():
    csv_paths = sorted(Path("captures").rglob("resource_usage_*.csv"))
    csv_paths = [p for p in csv_paths if p.suffix == ".csv"]  # exclut les .bak

    if not csv_paths:
        print("Aucun resource_usage_*.csv trouvé sous captures/. "
              "Lance ce script depuis la racine du dépôt.")
        return

    n_clean = 0
    n_dirty = 0

    for csv_path in csv_paths:
        try:
            df = pd.read_csv(csv_path)
        except Exception as e:
            print(f"[ERREUR LECTURE] {csv_path}: {e}")
            continue

        if not set(KEY_COLS).issubset(df.columns):
            print(f"[COLONNES INATTENDUES] {csv_path}: {list(df.columns)}")
            continue

        n_total_rows = len(df)
        n_unique_combos = df.drop_duplicates(subset=KEY_COLS).shape[0]
        n_timestamps = df["timestamp"].nunique() if "timestamp" in df.columns else "?"

        if n_total_rows == n_unique_combos:
            status = "OK (1 mesure/combo)"
            n_clean += 1
        else:
            excess = n_total_rows - n_unique_combos
            status = f"DUPLIQUÉ ({excess} ligne(s) en trop)"
            n_dirty += 1

        print(f"{csv_path}")
        print(f"    {n_total_rows} lignes, {n_unique_combos} combos uniques, "
              f"{n_timestamps} timestamps distincts -> {status}")

    print(f"\n=== Résumé : {n_clean} fichier(s) propre(s), {n_dirty} fichier(s) à refaire ===")


if __name__ == "__main__":
    main()
