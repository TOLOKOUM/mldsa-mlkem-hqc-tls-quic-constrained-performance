#!/usr/bin/env python3
"""
parse_microbench.py — Convertit la sortie brute d'`openssl speed` (lignes
"Doing X ops for Ns: M ... ops in Ts") en CSV propre, quel que soit
l'algorithme (classique ou PQ, signature ou KEM).

USAGE:
    python3 parse_microbench.py --input microbench_result.txt --out-dir results_microbench/
"""

import argparse
import csv
import re
from pathlib import Path

# "Doing <label> ops for <N>s: <count> <label2...> ops in <T>s"
LINE_RE = re.compile(r"Doing (.+?) ops for \d+s:\s+(\d+)\s+.+?\s+ops in ([\d.]+)s")

BITS_OP_RE = re.compile(r"(\d+)\s*bits?\s+(sign|verify)\s+(\w+)", re.IGNORECASE)
ALGO_OP_RE = re.compile(r"(\S+)\s+(keygen|signs?|verify|encaps|decaps)", re.IGNORECASE)

OP_NORMALIZE = {"signs": "sign", "sign": "sign", "verify": "verify",
                "keygen": "keygen", "encaps": "encaps", "decaps": "decaps"}


def classify_family(algo: str) -> str:
    a = algo.lower()
    if "mldsa" in a or "mlkem" in a or "hqc" in a:
        return "pq_pur"
    return "classique"


FIXED_SIZE_CURVES = {"ed25519", "x25519", "x448", "ed448"}


def parse_label(label: str):
    """Retourne (algo, operation) à partir du texte libre entre 'Doing' et 'ops for'."""
    m = BITS_OP_RE.search(label)
    if m:
        bits, op, algo_name = m.groups()
        algo_name = algo_name.lower()
        # ed25519/x25519/x448 encodent déjà leur taille dans le nom — pas de
        # suffixe redondant, pour rester cohérent avec les identifiants
        # SIG_ALG/KEM_ALG utilisés dans le reste du projet (launcher, doCert.sh).
        algo = algo_name if algo_name in FIXED_SIZE_CURVES else f"{algo_name}{bits}"
        return algo, OP_NORMALIZE.get(op.lower(), op.lower())
    m = ALGO_OP_RE.search(label)
    if m:
        algo_name, op = m.groups()
        return algo_name.lower(), OP_NORMALIZE.get(op.lower(), op.lower())
    # Repli : on garde le label brut tel quel
    return label.strip().lower().replace(" ", "_"), "unknown"


def parse_file(path: Path):
    text = path.read_text(errors="ignore")
    rows = []
    for line in text.splitlines():
        m = LINE_RE.search(line)
        if not m:
            continue
        label, count, elapsed = m.groups()
        algo, op = parse_label(label)
        count = int(count)
        elapsed = float(elapsed)
        ops_per_sec = count / elapsed if elapsed > 0 else 0.0
        mean_time_us = (elapsed / count) * 1_000_000 if count > 0 else 0.0
        rows.append({
            "algo": algo,
            "operation": op,
            "family": classify_family(algo),
            "count": count,
            "elapsed_s": round(elapsed, 3),
            "ops_per_sec": round(ops_per_sec, 1),
            "mean_time_us": round(mean_time_us, 3),
            "raw_label": label.strip(),
        })
    return rows


def write_csv(path, rows):
    if not rows:
        return
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


def write_report(path, rows):
    lines = ["# Microbenchmarks cryptographiques — résultats parsés\n"]
    lines.append(f"**{len(rows)} mesures extraites**\n")
    lines.append("| Algorithme | Opération | Famille | Ops/s | Temps moyen (µs) |")
    lines.append("|---|---|---|---|---|")
    for r in sorted(rows, key=lambda r: (r["family"], r["algo"], r["operation"])):
        lines.append(f"| {r['algo']} | {r['operation']} | {r['family']} | "
                      f"{r['ops_per_sec']} | {r['mean_time_us']} |")
    lines.append("\n## Note méthodologique\n")
    lines.append("Ces mesures portent sur l'opération cryptographique isolée (hors coût réseau, "
                  "hors coût du protocole TLS/QUIC). Elles sont complémentaires — pas redondantes — "
                  "avec les mesures CPU/mémoire par handshake capturées par `Launcher_unified.sh` "
                  "(qui incluent le harnais de test complet). Les KEM hybrides ne sont pas "
                  "benchmarkés isolément ici : leur coût de calcul est approximativement composable "
                  "à partir de leurs composantes classique et PQ mesurées séparément ci-dessus ; "
                  "leur coût réel en contexte de handshake complet reste mesuré par le launcher "
                  "principal.")
    Path(path).write_text("\n".join(lines))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, type=Path)
    ap.add_argument("--out-dir", default="results_microbench", type=Path)
    args = ap.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)

    if not args.input.exists():
        print(f"ERREUR: fichier introuvable: {args.input}")
        return

    rows = parse_file(args.input)
    print(f"{len(rows)} lignes de mesure extraites.")
    if not rows:
        print("Aucune ligne 'Doing ... ops for Ns: ...' trouvée — vérifiez le format du fichier.")
        return

    write_csv(args.out_dir / "microbench_parsed.csv", rows)
    write_report(args.out_dir / "microbench_report.md", rows)

    print(f"Fichiers écrits dans {args.out_dir}/: microbench_parsed.csv, microbench_report.md")


if __name__ == "__main__":
    main()
