#!/usr/bin/env python3
"""
analyze_resumption.py — Agrège les CSV de reprise de session produits par
launcher_advanced_test.sh (mode 'resumption') en un tableau comparant
handshake complet vs reprise de session (gain de latence, taux de succès).

STRUCTURE RÉELLE (confirmée par vos logs et check_advanced_test_setup.sh) :
    <base>/captures/tls/single/none/session_resumption/csv/resumption_<n>_<combo>.csv
    <base>/captures/quic/single/none/session_resumption/csv/resumption_<n>_<combo>.csv

Chaque CSV contient (protocole déduit du dossier, PAS du nom de fichier) :
    run_id,handshake_type,duration_ms,success
    (handshake_type ∈ {full, resumed} ; success ∈ {0,1})

⚠️ RAPPEL IMPORTANT : la reprise de session QUIC via quics_connection est
connue non fonctionnelle dans cette stack (-sess_out est accepté silencieusement
mais rien n'est écrit ; resumed ≈ full est donc attendu côté QUIC). Ce script
ajoute automatiquement un avertissement dans le rapport pour ce protocole —
ne concluez pas à un "gain de reprise" côté QUIC sans avoir vérifié la
syntaxe exacte attendue par quics_connection au préalable.

SORTIE — un dossier d'analyse séparé par protocole, comme demandé :
    <out-dir>/tls/resumption_comparison.csv
    <out-dir>/tls/resumption_report.md
    <out-dir>/quic/resumption_comparison.csv
    <out-dir>/quic/resumption_report.md
    <out-dir>/resumption_comparison_combined.md   (TLS vs QUIC côte à côte)

USAGE :
    python3 analyze_resumption.py --base-dir ~/Documents/mldsa-mlkem-hqc-tls-quic-constrained-performance
"""

import argparse
import csv
import re
import statistics
from pathlib import Path
from collections import defaultdict

PROTOCOLS = ["tls", "quic"]
FNAME_RE = re.compile(r"resumption_\d+_(.+)\.csv$")

QUIC_WARNING = (
    "⚠️ Reprise de session QUIC connue non fonctionnelle dans cette stack "
    "(`quics_connection` accepte `-sess_out` silencieusement sans rien écrire). "
    "Les chiffres 'resumed' ci-dessus correspondent en réalité à un second "
    "handshake complet, pas à une vraie reprise — un gain proche de 0% est "
    "donc attendu et NE VALIDE PAS le support de la reprise côté QUIC."
)


def load_protocol(base_dir: Path, protocol: str):
    """Charge tous les CSV de resumption pour un protocole donné."""
    csv_dir = base_dir / "captures" / protocol / "single" / "none" / "session_resumption" / "csv"
    if not csv_dir.is_dir():
        print(f"  [SKIP] {protocol}: dossier introuvable ({csv_dir})")
        return []

    rows = []
    n_files = 0
    for f in sorted(csv_dir.glob("resumption_*.csv")):
        m = FNAME_RE.search(f.name)
        combo = m.group(1) if m else f.stem
        n_files += 1
        with open(f, newline="") as fh:
            reader = csv.DictReader(fh)
            for r in reader:
                duration = r.get("duration_ms")
                handshake_type = r.get("handshake_type")
                success = r.get("success")
                if duration in (None, "", "NA") or handshake_type not in ("full", "resumed"):
                    continue
                rows.append({
                    "combo": combo,
                    "handshake_type": handshake_type,
                    "duration_ms": float(duration),
                    "success": success == "1",
                })
    print(f"  [{protocol}] {n_files} fichier(s) trouvé(s), {len(rows)} lignes exploitables")
    return rows


def aggregate(rows, protocol):
    groups = defaultdict(list)
    for r in rows:
        groups[(r["combo"], r["handshake_type"])].append(r)

    stats = {}
    for (combo, htype), items in groups.items():
        elapsed = [i["duration_ms"] for i in items]
        n_total = len(items)
        n_success = sum(1 for i in items if i["success"])
        stats[(combo, htype)] = {
            "n": n_total,
            "success_rate_pct": round(100 * n_success / n_total, 1) if n_total else 0.0,
            "mean_ms": round(statistics.mean(elapsed), 2) if elapsed else None,
        }

    comparison = []
    combos = sorted(set(c for (c, _h) in stats.keys()))
    for combo in combos:
        full = stats.get((combo, "full"))
        resumed = stats.get((combo, "resumed"))
        if not full or not resumed or full["mean_ms"] is None or resumed["mean_ms"] is None:
            continue
        gain_pct = round((full["mean_ms"] - resumed["mean_ms"]) / full["mean_ms"] * 100, 1) if full["mean_ms"] else "NA"
        comparison.append({
            "protocol": protocol,
            "combo": combo,
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


def write_protocol_report(path, comparison, protocol):
    lines = [f"# Reprise de session — {protocol.upper()} — handshake complet vs repris\n"]
    lines.append("| Combo | Handshake complet (ms) | Succès complet (%) | "
                  "Reprise (ms) | Succès reprise (%) | Gain (%) |")
    lines.append("|---|---|---|---|---|---|")
    for r in comparison:
        lines.append(f"| {r['combo']} | {r['full_handshake_mean_ms']} | {r['full_handshake_success_pct']} | "
                      f"{r['resumed_handshake_mean_ms']} | {r['resumed_handshake_success_pct']} | {r['gain_pct']} |")

    if protocol == "quic":
        lines.append(f"\n## Avertissement\n\n{QUIC_WARNING}")
    else:
        lines.append("\n## Note méthodologique\n")
        lines.append("Mesuré via openssl s_client standard côté TLS, avec sauvegarde/réutilisation "
                      "explicite du ticket de session (-sess_out/-sess_in). Le serveur "
                      "(perftestServerTlsQuic.sh) est inchangé entre phase 1 et phase 2.")

    Path(path).write_text("\n".join(lines))


def write_combined_report(path, all_comparisons):
    lines = ["# Reprise de session — comparaison TLS vs QUIC\n"]
    lines.append("| Protocole | Combo | Complet (ms) | Reprise (ms) | Gain (%) |")
    lines.append("|---|---|---|---|---|")
    for r in all_comparisons:
        lines.append(f"| {r['protocol']} | {r['combo']} | {r['full_handshake_mean_ms']} | "
                      f"{r['resumed_handshake_mean_ms']} | {r['gain_pct']} |")
    lines.append(f"\n{QUIC_WARNING}")
    Path(path).write_text("\n".join(lines))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-dir", default=Path("."), type=Path,
                     help="Racine du dépôt (contient captures/tls/... et captures/quic/...)")
    ap.add_argument("--out-dir", default="results_resumption", type=Path)
    args = ap.parse_args()

    all_comparisons = []
    for protocol in PROTOCOLS:
        proto_dir = args.out_dir / protocol
        proto_dir.mkdir(parents=True, exist_ok=True)

        rows = load_protocol(args.base_dir, protocol)
        if not rows:
            print(f"  [{protocol}] aucune donnée trouvée.")
            continue

        comparison = aggregate(rows, protocol)
        write_csv(proto_dir / "resumption_comparison.csv", comparison)
        write_protocol_report(proto_dir / "resumption_report.md", comparison, protocol)
        all_comparisons.extend(comparison)
        for r in comparison:
            print(f"  [{protocol}] combo={r['combo']} full={r['full_handshake_mean_ms']}ms "
                  f"resumed={r['resumed_handshake_mean_ms']}ms gain={r['gain_pct']}%")

    if all_comparisons:
        write_combined_report(args.out_dir / "resumption_comparison_combined.md", all_comparisons)

    print(f"\nRésultats écrits dans {args.out_dir}/tls/, {args.out_dir}/quic/ "
          f"et {args.out_dir}/resumption_comparison_combined.md")


if __name__ == "__main__":
    main()
