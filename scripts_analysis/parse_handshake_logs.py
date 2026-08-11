#!/usr/bin/env python3
"""
parse_handshake_logs.py — Convertit les logs bruts de handshake (produits par
Launcher_unified.sh, un fichier par combinaison SIG_ALG/KEM/protocole/scénario
réseau) en CSV statistique exploitable pour l'article.

Nom de fichier attendu : handshake_<protocol>_<auth_mode>_<sig_alg>_<kem>_<network_profile>.log

USAGE:
    python3 parse_handshake_logs.py --input-dir ~/captures/handshake_logs --out-dir results_handshake/
"""

import argparse
import csv
import re
import statistics
from pathlib import Path

DURATION_RE = re.compile(r"Handshake duration:\s*([\d.]+|NaN)\s*ms")
FNAME_RE = re.compile(r"handshake_(tls|quic)_(mutual|single)_(.+?)_(.+?)_(none|stable|unstable|simple.*)\.log$")


def percentile(values, p):
    if not values:
        return None
    s = sorted(values)
    k = (len(s) - 1) * (p / 100)
    f, c = int(k), min(int(k) + 1, len(s) - 1)
    if f == c:
        return s[f]
    return s[f] + (s[c] - s[f]) * (k - f)


def parse_log_file(path: Path):
    """Retourne (durations_ms, n_nan) pour un fichier de log."""
    text = path.read_text(errors="ignore")
    values = DURATION_RE.findall(text)
    durations = []
    n_nan = 0
    for v in values:
        if v == "NaN":
            n_nan += 1
        else:
            durations.append(float(v))
    return durations, n_nan


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input-dir", required=True, type=Path)
    ap.add_argument("--out-dir", default="results_handshake", type=Path)
    args = ap.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)

    rows = []
    unmatched = []
    for f in sorted(args.input_dir.glob("handshake_*.log")):
        m = FNAME_RE.search(f.name)
        durations, n_nan = parse_log_file(f)
        n_total = len(durations) + n_nan

        if not m:
            unmatched.append(f.name)
            protocol, auth_mode, sig_alg, kem, network_profile = ("?", "?", "?", "?", "?")
        else:
            protocol, auth_mode, sig_alg, kem, network_profile = m.groups()

        if n_total == 0:
            print(f"[!] {f.name}: aucune ligne 'Handshake duration' trouvée — fichier ignoré.")
            continue

        row = {
            "file": f.name,
            "protocol": protocol,
            "auth_mode": auth_mode,
            "sig_alg": sig_alg,
            "kem": kem,
            "network_profile": network_profile,
            "n_total": n_total,
            "n_success": len(durations),
            "n_failed_nan": n_nan,
            "success_rate_pct": round(100 * len(durations) / n_total, 2) if n_total else 0.0,
        }
        if durations:
            row.update({
                "mean_ms": round(statistics.mean(durations), 3),
                "stdev_ms": round(statistics.stdev(durations), 3) if len(durations) > 1 else 0.0,
                "median_ms": round(statistics.median(durations), 3),
                "p95_ms": round(percentile(durations, 95), 3),
                "p99_ms": round(percentile(durations, 99), 3),
                "min_ms": round(min(durations), 3),
                "max_ms": round(max(durations), 3),
            })
        else:
            row.update({k: "NA" for k in ["mean_ms", "stdev_ms", "median_ms", "p95_ms", "p99_ms", "min_ms", "max_ms"]})

        rows.append(row)

    if not rows:
        print(f"Aucun log exploitable trouvé dans {args.input_dir}. Rien à écrire.")
        return

    out_csv = args.out_dir / "handshake_stats.csv"
    with open(out_csv, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    print(f"{len(rows)} fichier(s) de log analysé(s) -> {out_csv}")
    if unmatched:
        print(f"[!] {len(unmatched)} fichier(s) au nom non conforme au motif attendu, "
              f"traités quand même mais avec protocol/sig/kem/network_profile = '?': {unmatched}")


if __name__ == "__main__":
    main()
