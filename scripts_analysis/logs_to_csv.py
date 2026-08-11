#!/usr/bin/env python3
"""
logs_to_csv.py — Convertit chaque fichier .log d'un dossier handshake_logs/
en un fichier .csv individuel de MÊME NOM (seule l'extension change), stocké
dans un dossier csv/ FRÈRE de handshake_logs/ — jamais mélangé avec
resource_usage/, sslkeys/, ou tout autre type de données.

Structure produite (exemple) :
    captures/tls/single/none/
        handshake_logs/handshake_tls_single_ed25519_P-256_none.log
        csv/handshake_tls_single_ed25519_P-256_none.csv   <-- généré ici
        resource_usage/...   (inchangé)

USAGE (un dossier à la fois, comme demandé) :
    python3 logs_to_csv.py captures/tls/single/none/handshake_logs

USAGE (mode batch, pour plus tard si besoin — traite tous les dossiers
'handshake_logs' trouvés récursivement sous le chemin donné) :
    python3 logs_to_csv.py captures --all

Chaque CSV produit contient une ligne par exécution :
    execution, mode, handshake_duration_ms, success
"""

import re
import csv
import argparse
from pathlib import Path

# "Execution 498 - TLS Single" / "Execution 1 - QUIC Mutual"
EXEC_RE = re.compile(r"^Execution\s+(\d+)\s*-\s*(.+?)\s*$")
# "Handshake duration: 17.16 ms" ou "Handshake duration: NaN ms" (échec QUIC connu)
DURATION_RE = re.compile(r"Handshake duration:\s*([\d.]+|NaN)\s*ms")


def parse_log_file(path: Path):
    """Scan ligne par ligne, robuste à l'ordre exact des lignes intercalées
    (ex. 's_connection: verify depth is 1' entre Execution et Handshake
    duration) — on garde juste le dernier numéro/mode d'exécution vu."""
    rows = []
    current_exec = None
    current_mode = None
    with open(path, errors="ignore") as f:
        for raw_line in f:
            line = raw_line.strip()

            m = EXEC_RE.match(line)
            if m:
                current_exec = int(m.group(1))
                current_mode = m.group(2)
                continue

            m2 = DURATION_RE.search(line)
            if m2:
                val = m2.group(1)
                if val == "NaN":
                    rows.append({
                        "execution": current_exec,
                        "mode": current_mode,
                        "handshake_duration_ms": "NaN",
                        "success": 0,
                    })
                else:
                    rows.append({
                        "execution": current_exec,
                        "mode": current_mode,
                        "handshake_duration_ms": float(val),
                        "success": 1,
                    })
    return rows


def convert_dir(handshake_logs_dir: Path):
    if not handshake_logs_dir.is_dir():
        print(f"[!] Dossier introuvable, ignoré : {handshake_logs_dir}")
        return 0

    csv_dir = handshake_logs_dir.parent / "csv"
    log_files = sorted(handshake_logs_dir.glob("*.log"))
    if not log_files:
        print(f"[!] Aucun .log trouvé dans {handshake_logs_dir}")
        return 0

    csv_dir.mkdir(parents=True, exist_ok=True)

    n_ok = 0
    for log_path in log_files:
        rows = parse_log_file(log_path)
        if not rows:
            print(f"  [!] {log_path.name} : aucune exécution reconnue, ignoré (fichier vide ou format inattendu).")
            continue

        csv_path = csv_dir / (log_path.stem + ".csv")
        with open(csv_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["execution", "mode", "handshake_duration_ms", "success"])
            writer.writeheader()
            writer.writerows(rows)

        n_fail = sum(1 for r in rows if r["success"] == 0)
        print(f"  {log_path.name} -> csv/{csv_path.name}  ({len(rows)} exécutions, {n_fail} échec(s))")
        n_ok += 1

    return n_ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input_dir", type=Path,
                     help="Dossier handshake_logs à convertir (ou racine à parcourir avec --all)")
    ap.add_argument("--all", action="store_true",
                     help="Parcourt récursivement et convertit tous les dossiers 'handshake_logs' trouvés")
    args = ap.parse_args()

    if args.all:
        targets = sorted(args.input_dir.rglob("handshake_logs"))
        if not targets:
            print(f"Aucun dossier 'handshake_logs' trouvé sous {args.input_dir}")
            return
    else:
        targets = [args.input_dir]

    total = 0
    for d in targets:
        print(f"=== {d} ===")
        total += convert_dir(d)

    print(f"\n{total} fichier(s) CSV généré(s) au total.")


if __name__ == "__main__":
    main()
