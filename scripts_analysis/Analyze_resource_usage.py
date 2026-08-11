#!/usr/bin/env python3
"""
analyze_resource_usage.py — Agrège resource_usage.csv (produit par
Launcher_unified.sh) en un tableau comparatif CPU/mémoire par combinaison
SIG_ALG/KEM, avec calcul du surcoût relatif PQ vs classique.

USAGE:
    python3 analyze_resource_usage.py --input ~/captures/resource_usage/resource_usage.csv \
                                       --out-dir results_resources/

LIMITE MÉTHODOLOGIQUE (reprise du launcher, à documenter dans l'article) :
    Les mesures CPU/mémoire portent sur le conteneur entier (harnais de test
    perftestClientTlsQuic.sh / perftestServerTlsQuic.sh inclus), pas
    uniquement sur les opérations cryptographiques isolées. Le surcoût
    relatif PQ-vs-classique reste néanmoins valide car ce biais de mesure
    est constant à travers toutes les combinaisons.
"""

import argparse
import csv
import statistics
from pathlib import Path
from collections import defaultdict


def classify_kem(kem: str) -> str:
    """Classe un KEM en classique / hybride / PQ pur, pour regroupement.
    Normalise la casse et les tirets car les noms hybrides utilisent
    'p256_mlkem512' (minuscule, sans tiret) alors que le KEM classique pur
    s'appelle 'P-256' (majuscule, avec tiret) dans le launcher."""
    k = kem.lower().replace("-", "")
    is_pq = any(tag in k for tag in ("mlkem", "hqc"))
    is_classical_component = any(tag in k for tag in ("p256", "p384", "p521", "x25519", "x448"))
    if is_pq and is_classical_component:
        return "hybride"
    if is_pq:
        return "pq_pur"
    return "classique"


def load_rows(path: Path):
    rows = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for r in reader:
            if r["cpu_usec_per_handshake"] in ("NA", "", None) and r["mem_peak_bytes"] in ("NA", "", None):
                continue
            rows.append(r)
    return rows


def load_rows_multi(paths):
    """Charge et concatène plusieurs resource_usage_*.csv (structure éclatée
    par protocole/auth_mode/network_profile depuis Launcher_pq_mldsa_mlkem_hqc.sh).
    Chaque ligne garde ses propres colonnes protocol/auth_mode/network_profile,
    donc l'agrégation en aval (par protocole/rôle/classe KEM) reste correcte
    même en mélangeant des fichiers de scénarios différents."""
    rows = []
    for p in paths:
        rows.extend(load_rows(p))
    return rows


def to_float(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def aggregate(rows):
    """Regroupe par (protocol, role, kem_class) et calcule moyennes."""
    groups = defaultdict(lambda: {"cpu": [], "mem": []})
    for r in rows:
        kem_class = classify_kem(r["kem"])
        key = (r["protocol"], r["role"], kem_class)
        cpu = to_float(r["cpu_usec_per_handshake"])
        mem = to_float(r["mem_peak_bytes"])
        if cpu is not None:
            groups[key]["cpu"].append(cpu)
        if mem is not None:
            groups[key]["mem"].append(mem)

    summary = []
    for (protocol, role, kem_class), vals in sorted(groups.items()):
        cpu_vals, mem_vals = vals["cpu"], vals["mem"]
        summary.append({
            "protocol": protocol,
            "role": role,
            "kem_class": kem_class,
            "n_combinations": max(len(cpu_vals), len(mem_vals)),
            "cpu_usec_per_handshake_mean": round(statistics.mean(cpu_vals), 1) if cpu_vals else "NA",
            "cpu_ms_per_handshake_mean": round(statistics.mean(cpu_vals) / 1000, 3) if cpu_vals else "NA",
            "mem_peak_bytes_mean": round(statistics.mean(mem_vals), 0) if mem_vals else "NA",
            "mem_peak_MiB_mean": round(statistics.mean(mem_vals) / (1024 * 1024), 2) if mem_vals else "NA",
        })
    return summary


def compute_overhead(summary):
    """Calcule le surcoût relatif (%) de chaque classe vs le baseline classique,
    par protocole et par rôle."""
    baseline = {}
    for row in summary:
        if row["kem_class"] == "classique" and row["cpu_ms_per_handshake_mean"] != "NA":
            baseline[(row["protocol"], row["role"])] = row["cpu_ms_per_handshake_mean"]

    overhead_rows = []
    for row in summary:
        base = baseline.get((row["protocol"], row["role"]))
        if base and row["cpu_ms_per_handshake_mean"] != "NA" and base > 0:
            pct = round((row["cpu_ms_per_handshake_mean"] - base) / base * 100, 1)
        else:
            pct = "NA"
        overhead_rows.append({**row, "cpu_overhead_pct_vs_classique": pct})
    return overhead_rows


def write_csv(path, rows):
    if not rows:
        return
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def write_report(path, overhead_rows, n_raw_rows):
    lines = ["# Annexe méthodologique — Consommation CPU/mémoire des handshakes\n"]
    lines.append(f"**Lignes brutes agrégées : {n_raw_rows}**\n")
    lines.append("| Protocole | Rôle | Classe KEM | N combinaisons | CPU moyen/handshake (ms) | "
                  "Surcoût CPU vs classique (%) | Pic mémoire moyen (MiB) |")
    lines.append("|---|---|---|---|---|---|---|")
    for r in overhead_rows:
        lines.append(f"| {r['protocol']} | {r['role']} | {r['kem_class']} | {r['n_combinations']} | "
                      f"{r['cpu_ms_per_handshake_mean']} | {r['cpu_overhead_pct_vs_classique']} | "
                      f"{r['mem_peak_MiB_mean']} |")

    lines.append("\n## Note méthodologique (à inclure telle quelle dans l'article)\n")
    lines.append("Les mesures CPU proviennent des compteurs cgroup (`cpu.stat`/`cpuacct.usage`) "
                  "du conteneur, capturés en delta entre le début et la fin de chaque batch de "
                  "handshakes, puis divisés par le nombre de handshakes. Le pic mémoire provient de "
                  "`memory.peak` (cgroup v2) ou `memory.max_usage_in_bytes` (cgroup v1). Ces mesures "
                  "portent sur le conteneur entier, harnais de test inclus, et non sur les seules "
                  "opérations cryptographiques ; ce biais constant à travers toutes les combinaisons "
                  "ne remet pas en cause la comparaison relative classique/hybride/PQ pur.")

    Path(path).write_text("\n".join(lines))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", type=Path,
                     help="Chemin vers un unique resource_usage*.csv (rétrocompatibilité)")
    ap.add_argument("--input-dir", type=Path,
                     help="Dossier racine (ex: captures/) sous lequel chercher récursivement "
                          "tous les resource_usage_*.csv (structure éclatée par "
                          "protocole/auth_mode/network_profile)")
    ap.add_argument("--out-dir", default="results_resources", type=Path)
    args = ap.parse_args()

    if not args.input and not args.input_dir:
        print("ERREUR: fournir --input <fichier.csv> OU --input-dir <dossier racine captures/>")
        return

    args.out_dir.mkdir(parents=True, exist_ok=True)

    if args.input_dir:
        if not args.input_dir.exists():
            print(f"ERREUR: dossier introuvable: {args.input_dir}")
            return
        csv_paths = sorted(args.input_dir.rglob("resource_usage_*.csv"))
        # Rétrocompatibilité : ancien format non-éclaté, un seul fichier nommé
        # exactement "resource_usage.csv" quelque part dans l'arborescence.
        csv_paths += sorted(args.input_dir.rglob("resource_usage.csv"))
        if not csv_paths:
            print(f"ERREUR: aucun resource_usage*.csv trouvé sous {args.input_dir}")
            return
        print(f"{len(csv_paths)} fichier(s) resource_usage trouvé(s) sous {args.input_dir} :")
        for p in csv_paths:
            print(f"  - {p}")
        rows = load_rows_multi(csv_paths)
    else:
        if not args.input.exists():
            print(f"ERREUR: fichier introuvable: {args.input}")
            return
        rows = load_rows(args.input)

    print(f"Lignes exploitables (CPU ou mémoire non-NA) : {len(rows)}")
    if not rows:
        print("Aucune donnée exploitable — vérifiez que le launcher a bien pu lire les cgroups "
              "(certains environnements Docker restreignent l'accès à /sys/fs/cgroup depuis un "
              "conteneur ; voir la limite documentée dans le script).")
        return

    summary = aggregate(rows)
    overhead = compute_overhead(summary)

    write_csv(args.out_dir / "resource_summary.csv", overhead)
    write_report(args.out_dir / "rapport_ressources.md", overhead, len(rows))

    print(f"\nTerminé. Fichiers écrits dans {args.out_dir}/:")
    print("  - resource_summary.csv")
    print("  - rapport_ressources.md")


if __name__ == "__main__":
    main()
