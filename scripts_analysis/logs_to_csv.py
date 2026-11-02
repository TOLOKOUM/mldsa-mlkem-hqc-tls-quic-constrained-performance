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
    execution, mode, handshake_duration_ms, success, block_index, n_blocks,
    app_ready_ms, app_success, app_bytes, round_index, n_rounds
    (les 9 premieres colonnes sont inchangees ; round_index/n_rounds = tour de
    micro-lot, 1/1 si MICRO_BATCHES=1)
"""

import re
import csv
import argparse
from pathlib import Path

# "Execution 498 - TLS Single" / "Execution 1 - QUIC Mutual"
EXEC_RE = re.compile(r"^Execution\s+(\d+)\s*-\s*(.+?)\s*$")
# "Handshake duration: 17.16 ms" ou "Handshake duration: NaN ms" (échec QUIC connu)
DURATION_RE = re.compile(r"Handshake duration:\s*([\d.]+|NaN)\s*ms")
# Metrique PRINCIPALE commune TLS/QUIC (critique 4 de l'AE) : "App-ready duration"
APP_RE = re.compile(r"App-ready duration:\s*([\d.]+|NaN)\s*ms")
# Controle de coherence de la charge utile (doit valoir 100 des deux cotes)
APPBYTES_RE = re.compile(r"App-bytes:\s*(\d+)")
# Suffixe de bloc ajouté par le launcher patché (résout le point 2 du rejet :
# "campagne unique, pas de blocs indépendants") : handshake_..._block2of5.log
BLOCK_SUFFIX_RE = re.compile(r"_block(\d+)of(\d+)$")
# Suffixe de TOUR (entrelacement en micro-lots, MICRO_BATCHES=M) : handshake_..._block3of20_mb2of5.log
# Les numeros d'execution REPARTENT de 1 a chaque tour : (bloc, tour, execution) est la cle unique.
ROUND_SUFFIX_RE = re.compile(r"_mb(\d+)of(\d+)$")


def parse_round_suffix(stem: str):
    """Retourne (round_index, n_rounds, stem_sans_suffixe_de_tour). (1, 1) si pas de micro-lots."""
    m = ROUND_SUFFIX_RE.search(stem)
    if m:
        return int(m.group(1)), int(m.group(2)), stem[:m.start()]
    return 1, 1, stem


def parse_block_suffix(stem: str):
    """Retourne (block_index, n_blocks) si le nom de fichier porte un
    suffixe _blockNofM (eventuellement suivi d'un suffixe de tour _mbRofM,
    ignore ici : voir parse_round_suffix), sinon (1, 1) -- traite un fichier
    sans suffixe comme un bloc unique, pour compatibilité avec les logs
    collectés avant l'introduction du découpage en blocs."""
    _, _, stem = parse_round_suffix(stem)
    m = BLOCK_SUFFIX_RE.search(stem)
    if m:
        return int(m.group(1)), int(m.group(2))
    return 1, 1


def _num(val):
    """'NaN' -> None ; sinon float."""
    return None if val == "NaN" else float(val)


def parse_log_file(path: Path, block_index: int = 1, n_blocks: int = 1,
                   round_index: int = 1, n_rounds: int = 1):
    """Une ligne par EXECUTION (delimitee par 'Execution N - ...').

    Colonnes : execution, mode, handshake_duration_ms, success, block_index,
    n_blocks, app_ready_ms, app_success, app_bytes.
      - handshake_* : timer natif (metrique SECONDAIRE, semantique differente
        TLS/QUIC -- cf. critique 4).
      - app_*       : metrique PRINCIPALE commune (debut de connexion ->
        reponse applicative complete). 'NA' si le log ne contient aucune ligne
        'App-ready' (logs anterieurs au patch).
    Si une execution contient plusieurs lignes pour une meme metrique, la
    mesure reelle l'emporte sur un marqueur NaN (anciens logs a double marqueur).
    Les lignes avant la premiere ligne 'Execution' (orphelines) sont ignorees
    et comptees (avertissement).
    """
    execs = []          # liste de dicts, ordre d'apparition
    cur = None
    orphans = 0
    any_app = False
    with open(path, errors="ignore") as f:
        for raw_line in f:
            line = raw_line.strip()

            m = EXEC_RE.match(line)
            if m:
                cur = {"execution": int(m.group(1)), "mode": m.group(2),
                       "hs": "unset", "app": "unset", "bytes": ""}
                execs.append(cur)
                continue

            m2 = DURATION_RE.search(line)
            m3 = APP_RE.search(line)
            m4 = APPBYTES_RE.search(line)
            if not (m2 or m3 or m4):
                continue
            if cur is None:
                orphans += 1
                continue
            if m2:
                v = _num(m2.group(1))
                if cur["hs"] == "unset" or cur["hs"] is None:
                    cur["hs"] = v
            if m3:
                any_app = True
                v = _num(m3.group(1))
                if cur["app"] == "unset" or cur["app"] is None:
                    cur["app"] = v
            if m4:
                cur["bytes"] = int(m4.group(1))

    if orphans:
        print(f"  [!] {path.name} : {orphans} ligne(s) de mesure avant toute 'Execution' (ignorees).")

    rows = []
    for e in execs:
        if e["hs"] == "unset" and e["app"] == "unset":
            continue                      # execution sans aucune mesure reconnue
        hs = None if e["hs"] == "unset" else e["hs"]
        if any_app:
            app = None if e["app"] == "unset" else e["app"]
            app_val = "NaN" if app is None else app
            app_succ = 0 if app is None else 1
        else:
            app_val, app_succ = "NA", "NA"
        rows.append({
            "execution": e["execution"],
            "mode": e["mode"],
            "handshake_duration_ms": "NaN" if hs is None else hs,
            "success": 0 if hs is None else 1,
            "block_index": block_index,
            "n_blocks": n_blocks,
            "app_ready_ms": app_val,
            "app_success": app_succ,
            "app_bytes": e["bytes"],
            "round_index": round_index,
            "n_rounds": n_rounds,
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
        block_index, n_blocks = parse_block_suffix(log_path.stem)
        round_index, n_rounds, _ = parse_round_suffix(log_path.stem)
        rows = parse_log_file(log_path, block_index=block_index, n_blocks=n_blocks,
                              round_index=round_index, n_rounds=n_rounds)
        if not rows:
            print(f"  [!] {log_path.name} : aucune exécution reconnue, ignoré (fichier vide ou format inattendu).")
            continue

        csv_path = csv_dir / (log_path.stem + ".csv")
        with open(csv_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["execution", "mode", "handshake_duration_ms",
                                                     "success", "block_index", "n_blocks",
                                                     "app_ready_ms", "app_success", "app_bytes",
                                                     "round_index", "n_rounds"])
            writer.writeheader()
            writer.writerows(rows)

        n_fail = sum(1 for r in rows if r["success"] == 0)
        block_label = f"bloc {block_index}/{n_blocks}" if n_blocks > 1 else "bloc unique"
        if n_rounds > 1:
            block_label += f", tour {round_index}/{n_rounds}"
        print(f"  {log_path.name} -> csv/{csv_path.name}  ({len(rows)} exécutions, {n_fail} échec(s), {block_label})")
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
