#!/usr/bin/env python3
"""
analyze_resumption.py — Agrège les resumption_summary_*.csv (produits par
Launcher_advanced_tests.sh en mode 'resumption') en un tableau comparant
handshake complet vs reprise de session (gain de latence, taux de succès).

USAGE:
    python3 analyze_resumption.py --input-dir ~/captures/advanced_tests --out-dir results_resumption/
"""

import argparse
import csv
import re
import statistics
from pathlib import Path
from collections import defaultdict

FNAME_RE = re.compile(r"resumption_summary_(tls|quic)_(.+)_(ideal|modere|degrade)\.csv$")


def load_all(input_dir: Path):
    rows = []
    for f in sorted(input_dir.glob("resumption_summary_*.csv")):
        m = FNAME_RE.search(f.name)
        if not m:
            continue
        protocol, combo, network_scenario = m.group(1), m.group(2), m.group(3)
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
                    "phase": r["phase"],
                    "elapsed_ms": float(elapsed),
                    "success": status == "0",
                })
    return rows


def aggregate(rows):
    groups = defaultdict(list)
    for r in rows:
        groups[(r["protocol"], r["combo"], r["network_scenario"], r["phase"])].append(r)

    summary = {}
    for (protocol, combo, network_scenario, phase), items in groups.items():
        elapsed = [i["elapsed_ms"] for i in items]
        n_total = len(items)
        n_success = sum(1 for i in items if i["success"])
        summary[(protocol, combo, network_scenario, phase)] = {
            "n": n_total,
            "success_rate_pct": round(100 * n_success / n_total, 1) if n_total else 0.0,
            "mean_ms": round(statistics.mean(elapsed), 2) if elapsed else None,
        }

    comparison = []
    combos = sorted(set((p, c, ns) for (p, c, ns, _ph) in summary.keys()))
    for protocol, combo, network_scenario in combos:
        full = summary.get((protocol, combo, network_scenario, "full_handshake"))
        resumed = summary.get((protocol, combo, network_scenario, "resumed_handshake"))
        if not full or not resumed or resumed["mean_ms"] is None or full["mean_ms"] is None:
            continue
        gain_pct = round((full["mean_ms"] - resumed["mean_ms"]) / full["mean_ms"] * 100, 1) if full["mean_ms"] else "NA"
        comparison.append({
            "protocol": protocol,
            "combo": combo,
            "network_scenario": network_scenario,
            "n_full": full["n"],
            "full_handshake_mean_ms": full["mean_ms"],
            "full_handshake_success_pct": full["success_rate_pct"],
            "n_resumed": resumed["n"],
            "resumed_handshake_mean_ms": resumed["mean_ms"],
            "resumed_handshake_success_pct": resumed["success_rate_pct"],
            "gain_pct": gain_pct,
        })
    return comparison


def write_csv(path, rows):
    if not rows:
        return
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


def write_report(path, comparison):
    lines = ["# Reprise de session — handshake complet vs repris\n"]
    lines.append("| Protocole | Combo | Scénario réseau | Handshake complet (ms) | Succès complet (%) | "
                  "Reprise (ms) | Succès reprise (%) | Gain (%) |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for r in comparison:
        lines.append(f"| {r['protocol']} | {r['combo']} | {r['network_scenario']} | "
                      f"{r['full_handshake_mean_ms']} | "
                      f"{r['full_handshake_success_pct']} | {r['resumed_handshake_mean_ms']} | "
                      f"{r['resumed_handshake_success_pct']} | {r['gain_pct']} |")

    lines.append("\n## Note méthodologique\n")
    lines.append("Mesuré via openssl s_client standard côté TLS (PAS le binaire s_connection "
                  "custom), avec sauvegarde/réutilisation explicite du ticket de session "
                  "(-sess_out/-sess_in). Le serveur (perftestServerTlsQuic.sh) est inchangé. Côté "
                  "QUIC, les flags de reprise de session de quics_connection n'ont pas été vérifiés "
                  "contre son code source — si le taux de succès de reprise QUIC est à 0%, "
                  "vérifiez la syntaxe exacte attendue avant de conclure à une absence de support "
                  "de la reprise de session côté QUIC.")

    Path(path).write_text("\n".join(lines))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input-dir", required=True, type=Path)
    ap.add_argument("--out-dir", default="results_resumption", type=Path)
    args = ap.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)

    rows = load_all(args.input_dir)
    print(f"{len(rows)} lignes chargées depuis {args.input_dir}")
    if not rows:
        print("Aucune donnée trouvée — vérifiez le motif 'resumption_summary_<tls|quic>_<combo>.csv'.")
        return

    comparison = aggregate(rows)
    write_csv(args.out_dir / "resumption_comparison.csv", comparison)
    write_report(args.out_dir / "resumption_report.md", comparison)

    print(f"Fichiers écrits dans {args.out_dir}/: resumption_comparison.csv, resumption_report.md")


if __name__ == "__main__":
    main()
