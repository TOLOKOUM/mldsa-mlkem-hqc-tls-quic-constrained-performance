#!/usr/bin/env python3
"""
analyze_concurrent_load.py — Agrège les concurrent_summary_*.csv (produits par
Launcher_advanced_tests.sh en mode 'concurrent') en un tableau latence/échec
par niveau de concurrence, pour révéler l'asymétrie TLS (openssl s_server,
traitement séquentiel) vs QUIC (msquic, événementiel).

USAGE:
    python3 analyze_concurrent_load.py --input-dir ~/captures/advanced_tests --out-dir results_concurrent/
"""

import argparse
import csv
import re
import statistics
from pathlib import Path
from collections import defaultdict

FNAME_RE = re.compile(r"concurrent_summary_(tls|quic)_(.+)_(ideal|modere|degrade)_c(\d+)\.csv$")


def percentile(values, p):
    if not values:
        return None
    s = sorted(values)
    k = (len(s) - 1) * (p / 100)
    f, c = int(k), min(int(k) + 1, len(s) - 1)
    if f == c:
        return s[f]
    return s[f] + (s[c] - s[f]) * (k - f)


def load_all(input_dir: Path):
    rows = []
    for f in sorted(input_dir.glob("concurrent_summary_*.csv")):
        m = FNAME_RE.search(f.name)
        if not m:
            continue
        protocol, combo, network_scenario, level = m.group(1), m.group(2), m.group(3), int(m.group(4))
        with open(f, newline="") as fh:
            reader = csv.DictReader(fh)
            for r in reader:
                elapsed = r.get("elapsed_ms")
                status = r.get("exit_status")
                if elapsed in (None, "", "NA"):
                    continue
                rows.append({
                    "protocol": protocol,
                    "combo": combo,
                    "network_scenario": network_scenario,
                    "concurrency": level,
                    "elapsed_ms": float(elapsed),
                    "success": status == "0",
                })
    return rows


def aggregate(rows):
    groups = defaultdict(list)
    for r in rows:
        groups[(r["protocol"], r["combo"], r["network_scenario"], r["concurrency"])].append(r)

    summary = []
    for (protocol, combo, network_scenario, level), items in sorted(
            groups.items(), key=lambda x: (x[0][0], x[0][1], x[0][2], x[0][3])):
        elapsed = [i["elapsed_ms"] for i in items]
        n_total = len(items)
        n_success = sum(1 for i in items if i["success"])
        summary.append({
            "protocol": protocol,
            "combo": combo,
            "network_scenario": network_scenario,
            "concurrency": level,
            "n_connections": n_total,
            "success_rate_pct": round(100 * n_success / n_total, 1) if n_total else 0.0,
            "latency_mean_ms": round(statistics.mean(elapsed), 2) if elapsed else "NA",
            "latency_p95_ms": round(percentile(elapsed, 95), 2) if elapsed else "NA",
            "latency_max_ms": round(max(elapsed), 2) if elapsed else "NA",
        })
    return summary


def write_csv(path, rows):
    if not rows:
        return
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


def write_report(path, summary):
    lines = ["# Charge concurrente — latence et taux de succès par niveau\n"]
    lines.append("| Protocole | Combo | Scénario réseau | Concurrence | N connexions | Succès (%) | "
                  "Latence moy. (ms) | Latence p95 (ms) | Latence max (ms) |")
    lines.append("|---|---|---|---|---|---|---|---|---|")
    for r in summary:
        lines.append(f"| {r['protocol']} | {r['combo']} | {r['network_scenario']} | {r['concurrency']} | "
                      f"{r['n_connections']} | {r['success_rate_pct']} | {r['latency_mean_ms']} | "
                      f"{r['latency_p95_ms']} | {r['latency_max_ms']} |")

    lines.append("\n## Note méthodologique (asymétrie TLS/QUIC attendue)\n")
    lines.append("`openssl s_server` traite les connexions séquentiellement (accept → handshake → "
                  "close → accept suivant), sans multi-threading explicite. Sous charge concurrente "
                  "croissante côté TLS, une hausse marquée de la latence moyenne et p95 est donc "
                  "attendue — elle reflète la mise en file d'attente TCP, pas un surcoût "
                  "cryptographique par connexion. Côté QUIC (msquic, événementiel), la latence "
                  "devrait rester plus stable à mesure que la concurrence augmente. Si les deux "
                  "protocoles montrent un comportement similaire, cela invaliderait cette hypothèse "
                  "et mériterait d'être creusé avant publication.")

    Path(path).write_text("\n".join(lines))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input-dir", required=True, type=Path)
    ap.add_argument("--out-dir", default="results_concurrent", type=Path)
    args = ap.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)

    rows = load_all(args.input_dir)
    print(f"{len(rows)} lignes de connexion chargées depuis {args.input_dir}")
    if not rows:
        print("Aucune donnée trouvée — vérifiez le motif de nom de fichier "
              "'concurrent_summary_<tls|quic>_<combo>_c<N>.csv'.")
        return

    summary = aggregate(rows)
    write_csv(args.out_dir / "concurrent_load_summary.csv", summary)
    write_report(args.out_dir / "concurrent_load_report.md", summary)

    print(f"Fichiers écrits dans {args.out_dir}/: concurrent_load_summary.csv, concurrent_load_report.md")


if __name__ == "__main__":
    main()
