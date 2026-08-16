#!/usr/bin/env python3
"""
analyze_concurrent_load.py — Agrège les CSV de charge concurrente produits par
launcher_advanced_test.sh (mode 'concurrent') en un tableau latence/succès par
niveau de concurrence, pour révéler l'asymétrie TLS (openssl s_server,
traitement séquentiel) vs QUIC (msquic, événementiel).

STRUCTURE RÉELLE (confirmée par vos logs et check_advanced_test_setup.sh) :
    <base>/captures/tls/single/none/concurrent_load/csv/*.csv
    <base>/captures/quic/single/none/concurrent_load/csv/*.csv

Chaque CSV correspond à UN client et contient (sans préfixe de niveau) :
    run_id,duration_ms,success

IMPORTANT — le niveau de concurrence N n'est PAS encodé dans le nom de fichier
(le dossier concurrent_load/csv/ est RÉÉCRIT à chaque invocation du launcher).
Il faut donc lancer ce script juste après CHAQUE `launcher_advanced_test.sh
concurrent both N`, en passant --concurrency N.

ARCHIVAGE AUTOMATIQUE DES CSV BRUTS — puisque le dossier csv/ est écrasé au
run suivant, ce script copie systématiquement les fichiers clients du niveau
courant vers un dossier d'historique dédié AVANT tout traitement :
    <base>/captures/<protocol>/single/none/concurrent_load/history_c<N>/*.csv
Ainsi les données brutes de chaque niveau (1, 5, 10, 20, ...) restent
consultables en permanence, même après un nouveau run du launcher à un autre
niveau. Un même niveau relancé écrase simplement son propre dossier
d'historique (mêmes noms de fichiers), sans toucher aux autres niveaux.

Les résultats agrégés sont ACCUMULÉS, avec DÉDOUBLONNAGE par (protocole,
niveau) : relancer un même niveau remplace la ligne existante plutôt que de
la dupliquer.

DÉBIT — la latence moyenne par connexion ne dit RIEN du débit réel du serveur
sous charge : sommer les latences individuelles et diviser par N suppose un
passage à l'échelle parfaitement linéaire, ce qui est exactement ce que ce
test cherche à vérifier (pas à présumer). Le seul débit honnête nécessite le
temps mur du batch complet, déjà imprimé par votre launcher
("All N clients finished in X ms") mais absent des CSV individuels. Passez-le
via --wall-clock-ms-tls/--wall-clock-ms-quic pour obtenir un débit réel ;
sinon le champ reste "NA" plutôt que d'afficher un nombre trompeur.

SORTIE — un dossier d'analyse séparé par protocole :
    <out-dir>/tls/concurrent_load_summary.csv
    <out-dir>/tls/concurrent_load_report.md
    <out-dir>/quic/concurrent_load_summary.csv
    <out-dir>/quic/concurrent_load_report.md
    <out-dir>/concurrent_load_comparison.md   (TLS vs QUIC côte à côte)

USAGE (à répéter après chaque niveau N, dans l'ordre de vos runs) :
    python3 analyze_concurrent_load.py --base-dir ~/Documents/mldsa-mlkem-hqc-tls-quic-constrained-performance \
        --concurrency 1  --combo mldsa65_mlkem768 --wall-clock-ms-tls 10215 --wall-clock-ms-quic 23157
    python3 analyze_concurrent_load.py --base-dir ... --concurrency 5  --combo mldsa65_mlkem768 --wall-clock-ms-tls 23280  --wall-clock-ms-quic 42974
    python3 analyze_concurrent_load.py --base-dir ... --concurrency 10 --combo mldsa65_mlkem768 --wall-clock-ms-tls 40961  --wall-clock-ms-quic 69136
    python3 analyze_concurrent_load.py --base-dir ... --concurrency 20 --combo mldsa65_mlkem768 --wall-clock-ms-tls 78912  --wall-clock-ms-quic 127158

(--wall-clock-ms-tls/quic sont optionnels ; sans eux, latency_mean_ms/p95/max
restent calculés normalement, seul throughput_true_hs_per_s devient "NA".)
"""

import argparse
import csv
import shutil
import statistics
from pathlib import Path

PROTOCOLS = ["tls", "quic"]


def percentile(values, p):
    if not values:
        return None
    s = sorted(values)
    k = (len(s) - 1) * (p / 100)
    f, c = int(k), min(int(k) + 1, len(s) - 1)
    if f == c:
        return s[f]
    return s[f] + (s[c] - s[f]) * (k - f)


def archive_raw_csv(base_dir: Path, protocol: str, concurrency: int, csv_dir: Path):
    """Copie les CSV bruts du niveau courant vers un dossier d'historique dédié,
    car concurrent_load/csv/ est réécrit à chaque invocation du launcher."""
    archive_dir = (base_dir / "captures" / protocol / "single" / "none"
                    / "concurrent_load" / f"history_c{concurrency}")
    archive_dir.mkdir(parents=True, exist_ok=True)

    copied = 0
    for f in csv_dir.glob("*.csv"):
        shutil.copy2(f, archive_dir / f.name)
        copied += 1

    if copied:
        print(f"  [{protocol}] {copied} fichier(s) archivé(s) dans {archive_dir}")
    return archive_dir


def load_protocol(base_dir: Path, protocol: str, expected_concurrency: int):
    """Charge tous les CSV clients pour un protocole donné, un fichier par client.
    Archive d'abord les CSV bruts du niveau courant avant de les lire."""
    csv_dir = base_dir / "captures" / protocol / "single" / "none" / "concurrent_load" / "csv"
    if not csv_dir.is_dir():
        print(f"  [SKIP] {protocol}: dossier introuvable ({csv_dir})")
        return []

    files = sorted(csv_dir.glob("*.csv"))
    if len(files) != expected_concurrency:
        print(f"  [WARN] {protocol}: {len(files)} fichier(s) client trouvé(s) mais "
              f"--concurrency={expected_concurrency} attendu(s) — vérifiez que tous les "
              f"clients ont bien démarré, ou que le dossier n'a pas été mélangé avec un "
              f"run précédent.")

    archive_raw_csv(base_dir, protocol, expected_concurrency, csv_dir)

    rows = []
    for f in files:
        with open(f, newline="") as fh:
            reader = csv.DictReader(fh)
            for r in reader:
                duration = r.get("duration_ms")
                success = r.get("success")
                if duration in (None, "", "NA"):
                    continue
                rows.append({
                    "duration_ms": float(duration),
                    "success": success == "1",
                })
    print(f"  [{protocol}] {len(files)} fichier(s) client trouvé(s), {len(rows)} connexions au total")
    return rows


def aggregate(rows, protocol, combo, concurrency, wall_clock_ms):
    if not rows:
        return None
    elapsed = [r["duration_ms"] for r in rows]
    n_total = len(rows)
    n_success = sum(1 for r in rows if r["success"])
    throughput_true = (
        round(n_total / (wall_clock_ms / 1000), 2) if wall_clock_ms else "NA"
    )
    return {
        "protocol": protocol,
        "combo": combo,
        "network_scenario": "ideal",
        "concurrency": concurrency,
        "n_connections": n_total,
        "success_rate_pct": round(100 * n_success / n_total, 1),
        "latency_mean_ms": round(statistics.mean(elapsed), 2),
        "latency_p95_ms": round(percentile(elapsed, 95), 2),
        "latency_max_ms": round(max(elapsed), 2),
        "wall_clock_ms": wall_clock_ms if wall_clock_ms else "NA",
        "throughput_true_hs_per_s": throughput_true,
    }


def upsert_csv(path: Path, row: dict, key_fields=("protocol", "concurrency")):
    """Ajoute une ligne, en remplaçant toute ligne existante avec la même clé
    (protocole, concurrence) au lieu de la dupliquer si ce niveau a déjà été
    analysé (ex.: re-run accidentel du même --concurrency)."""
    existing = []
    if path.exists():
        with open(path, newline="") as f:
            existing = list(csv.DictReader(f))

    key = tuple(str(row[k]) for k in key_fields)
    replaced = False
    for i, r in enumerate(existing):
        if tuple(str(r[k]) for k in key_fields) == key:
            existing[i] = {k: str(v) for k, v in row.items()}
            replaced = True
            break
    if not replaced:
        existing.append({k: str(v) for k, v in row.items()})

    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(row.keys()))
        w.writeheader()
        w.writerows(existing)

    if replaced:
        print(f"  [{row['protocol']}] niveau {row['concurrency']} déjà présent — ligne remplacée (pas dupliquée).")


def regenerate_protocol_report(csv_path: Path, report_path: Path, protocol: str):
    """Reconstruit le rapport markdown pour UN protocole à partir de son CSV cumulatif."""
    if not csv_path.exists():
        return
    with open(csv_path, newline="") as f:
        rows = list(csv.DictReader(f))

    lines = [f"# Charge concurrente — {protocol.upper()} — latence et succès par niveau\n"]
    lines.append("| Concurrence | N connexions | Succès (%) | Latence moy. (ms) | "
                  "Latence p95 (ms) | Latence max (ms) | Débit réel (hs/s) |")
    lines.append("|---|---|---|---|---|---|---|")
    for r in sorted(rows, key=lambda x: int(x["concurrency"])):
        lines.append(f"| {r['concurrency']} | {r['n_connections']} | {r['success_rate_pct']} | "
                      f"{r['latency_mean_ms']} | {r['latency_p95_ms']} | {r['latency_max_ms']} | "
                      f"{r['throughput_true_hs_per_s']} |")

    lines.append("\nLe débit réel n'est calculable que si `--wall-clock-ms-tls/--wall-clock-ms-quic` "
                  "a été fourni (temps mur du batch complet, tel qu'imprimé par le launcher). Sans "
                  "lui, il apparaît en \"NA\" plutôt qu'estimé, pour éviter de présumer un passage à "
                  "l'échelle linéaire — ce que ce test sert justement à vérifier.")
    lines.append("\nLes CSV bruts de chaque niveau sont conservés en permanence dans "
                  "`captures/<protocole>/single/none/concurrent_load/history_c<N>/`.")
    report_path.write_text("\n".join(lines))


def regenerate_comparison(out_dir: Path):
    """Reconstruit un rapport comparatif TLS vs QUIC à partir des deux CSV protocole."""
    data = {}
    for protocol in PROTOCOLS:
        csv_path = out_dir / protocol / "concurrent_load_summary.csv"
        if not csv_path.exists():
            continue
        with open(csv_path, newline="") as f:
            data[protocol] = {int(r["concurrency"]): r for r in csv.DictReader(f)}

    if not data:
        return

    levels = sorted(set().union(*[d.keys() for d in data.values()]))
    lines = ["# Charge concurrente — comparaison TLS vs QUIC\n"]
    lines.append("| Concurrence | TLS lat. moy. (ms) | TLS débit (hs/s) | "
                  "QUIC lat. moy. (ms) | QUIC débit (hs/s) |")
    lines.append("|---|---|---|---|---|")
    for n in levels:
        t = data.get("tls", {}).get(n)
        q = data.get("quic", {}).get(n)
        lines.append(f"| {n} | {t['latency_mean_ms'] if t else 'NA'} | "
                      f"{t['throughput_true_hs_per_s'] if t else 'NA'} | "
                      f"{q['latency_mean_ms'] if q else 'NA'} | "
                      f"{q['throughput_true_hs_per_s'] if q else 'NA'} |")

    lines.append("\n## Note méthodologique (asymétrie TLS/QUIC attendue)\n")
    lines.append("`openssl s_server` traite les connexions séquentiellement (accept → handshake → "
                  "close → accept suivant), sans multi-threading explicite. Sous charge concurrente "
                  "croissante côté TLS, une hausse marquée de la latence moyenne et p95, et un "
                  "plafonnement du débit réel, sont donc attendus — ils reflètent la mise en file "
                  "d'attente TCP, pas un surcoût cryptographique par connexion. Côté QUIC (msquic, "
                  "événementiel), débit et latence devraient rester plus stables à mesure que la "
                  "concurrence augmente. Si les deux protocoles montrent un comportement similaire, "
                  "cela invaliderait cette hypothèse et mériterait d'être creusé avant publication.")

    (out_dir / "concurrent_load_comparison.md").write_text("\n".join(lines))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-dir", default=Path("."), type=Path,
                     help="Racine du dépôt (contient captures/tls/... et captures/quic/...)")
    ap.add_argument("--concurrency", required=True, type=int,
                     help="Niveau N de ce run (1, 5, 10, 20, ...) — non déductible du CSV")
    ap.add_argument("--combo", default="mldsa65_mlkem768",
                     help="Étiquette sig_kem utilisée pour ce run")
    ap.add_argument("--wall-clock-ms-tls", type=float, default=None,
                     help="Temps mur TLS du batch complet (imprimé par le launcher), pour un débit réel")
    ap.add_argument("--wall-clock-ms-quic", type=float, default=None,
                     help="Temps mur QUIC du batch complet (imprimé par le launcher), pour un débit réel")
    ap.add_argument("--out-dir", default="results_concurrent", type=Path)
    args = ap.parse_args()

    wall_clock = {"tls": args.wall_clock_ms_tls, "quic": args.wall_clock_ms_quic}

    print(f"Analyse charge concurrente — niveau N={args.concurrency}, combo={args.combo}")
    for protocol in PROTOCOLS:
        proto_dir = args.out_dir / protocol
        proto_dir.mkdir(parents=True, exist_ok=True)
        summary_csv = proto_dir / "concurrent_load_summary.csv"
        report_md = proto_dir / "concurrent_load_report.md"

        rows = load_protocol(args.base_dir, protocol, args.concurrency)
        agg = aggregate(rows, protocol, args.combo, args.concurrency, wall_clock[protocol])
        if agg is None:
            print(f"  [{protocol}] aucune donnée exploitable, ligne non ajoutée.")
            continue
        upsert_csv(summary_csv, agg)
        regenerate_protocol_report(summary_csv, report_md, protocol)
        print(f"  [{protocol}] mean={agg['latency_mean_ms']}ms p95={agg['latency_p95_ms']}ms "
              f"succès={agg['success_rate_pct']}% débit={agg['throughput_true_hs_per_s']}")

    regenerate_comparison(args.out_dir)
    print(f"\nRésultats écrits dans {args.out_dir}/tls/, {args.out_dir}/quic/ "
          f"et {args.out_dir}/concurrent_load_comparison.md")


if __name__ == "__main__":
    main()
