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
import math
import random
import re
import statistics
from pathlib import Path
from collections import defaultdict

DURATION_RE = re.compile(r"Handshake duration:\s*([\d.]+|NaN)\s*ms")
FNAME_RE = re.compile(r"handshake_(tls|quic)_(mutual|single)_(.+?)_(.+?)_(none|stable|unstable|simple.*)\.log$")
# Suffixe de bloc ajouté par le launcher patché (résout le point 2 du rejet :
# "campagne unique, pas de blocs indépendants"). Un même combo SIG_ALG/KEM
# produit désormais N_BLOCKS fichiers .log distincts (..._block1of5.log ...
# ..._block5of5.log) au lieu d'un seul -- ce script les regroupait
# auparavant comme s'ils étaient tous des combos différents (ou ne les
# reconnaissait pas du tout, cf. FNAME_RE ci-dessus qui n'a pas cette
# extension), fragmentant chaque statistique sur 1/N_BLOCKS des données.
BLOCK_SUFFIX_RE = re.compile(r"_block(\d+)of(\d+)$")


def percentile(values, p):
    if not values:
        return None
    s = sorted(values)
    k = (len(s) - 1) * (p / 100)
    f, c = int(k), min(int(k) + 1, len(s) - 1)
    if f == c:
        return s[f]
    return s[f] + (s[c] - s[f]) * (k - f)


def z95_ci(mean, stdev, n):
    """IC normale naïve -- repli utilisé UNIQUEMENT quand un seul bloc est
    disponible pour un combo (cf. block_bootstrap_ci ci-dessous, méthode
    préférée dès que >=2 blocs existent)."""
    if n <= 1 or stdev is None:
        return (None, None)
    margin = 1.96 * stdev / math.sqrt(n)
    return (round(mean - margin, 3), round(mean + margin, 3))


def block_bootstrap_ci(per_block_durations, n_resamples=5000, seed=12345):
    """IC95% de la moyenne par bootstrap de BLOCS ENTIERS -- respecte la
    corrélation intra-bloc documentée dans l'article (rho1=0.563, IC
    bootstrap ~2.2x plus large que l'IC normal naïf) au lieu de supposer les
    runs indépendants. Un fichier .log = un bloc par construction ici (le
    launcher écrit un fichier par bloc), donc per_block_durations est
    directement la liste des durées de CHAQUE fichier retenu pour ce combo.
    Retourne None si moins de 2 blocs sont disponibles."""
    blocks = [d for d in per_block_durations if d]
    if len(blocks) < 2:
        return None
    rng = random.Random(seed)
    means = []
    for _ in range(n_resamples):
        resampled = [rng.choice(blocks) for _ in range(len(blocks))]
        pooled = [v for b in resampled for v in b]
        if pooled:
            means.append(statistics.mean(pooled))
    if not means:
        return None
    return (round(percentile(means, 2.5), 3), round(percentile(means, 97.5), 3))


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

    # ── Regroupement par combo (protocol,auth_mode,sig_alg,kem,network_profile),
    # en retirant le suffixe de bloc du nom de fichier -- plusieurs fichiers
    # .log d'un même combo (un par bloc) sont désormais fusionnés en une
    # seule ligne statistique, au lieu de produire N_BLOCKS lignes
    # fragmentées (ou d'échouer le matching pour les scénarios
    # none/stable/unstable, dont le suffixe de bloc cassait FNAME_RE).
    combo_files = defaultdict(list)
    combo_meta = {}
    unmatched = []
    for f in sorted(args.input_dir.glob("handshake_*.log")):
        stem_no_block = BLOCK_SUFFIX_RE.sub("", f.stem)
        m = FNAME_RE.search(stem_no_block + ".log")
        if not m:
            unmatched.append(f.name)
            key = ("?", "?", "?", "?", "?")
            combo_meta.setdefault(key, ("?", "?", "?", "?", "?"))
        else:
            key = m.groups()
            combo_meta[key] = key
        combo_files[key].append(f)

    rows = []
    n_single_block_combos = 0
    for key, files in combo_files.items():
        protocol, auth_mode, sig_alg, kem, network_profile = combo_meta[key]

        per_block_durations = []
        n_nan_total = 0
        for f in files:
            d, n_nan = parse_log_file(f)
            per_block_durations.append(d)
            n_nan_total += n_nan

        durations = [v for block in per_block_durations for v in block]
        n_total = len(durations) + n_nan_total
        n_blocks_pooled = sum(1 for b in per_block_durations if b)

        if n_total == 0:
            print(f"[!] {key}: aucune ligne 'Handshake duration' trouvée dans "
                  f"{len(files)} fichier(s) — combo ignoré.")
            continue

        row = {
            "file": ";".join(sorted(f.name for f in files)),
            "protocol": protocol,
            "auth_mode": auth_mode,
            "sig_alg": sig_alg,
            "kem": kem,
            "network_profile": network_profile,
            "n_files_pooled": len(files),
            "n_blocks_pooled": n_blocks_pooled,
            "n_total": n_total,
            "n_success": len(durations),
            "n_failed_nan": n_nan_total,
            "success_rate_pct": round(100 * len(durations) / n_total, 2) if n_total else 0.0,
        }
        if durations:
            mean = statistics.mean(durations)
            stdev = statistics.stdev(durations) if len(durations) > 1 else 0.0

            block_ci = block_bootstrap_ci(per_block_durations) if n_blocks_pooled > 1 else None
            if block_ci is not None:
                ci_low, ci_high = block_ci
                ci_method = "bootstrap_blocs"
            else:
                ci_low, ci_high = z95_ci(mean, stdev, len(durations))
                ci_method = "normale_naive (1 seul bloc -- IC probablement trop étroit, cf. §5.4 de l'article)"
                if n_blocks_pooled <= 1:
                    n_single_block_combos += 1

            row.update({
                "mean_ms": round(mean, 3),
                "stdev_ms": round(stdev, 3),
                "ci95_low_ms": ci_low, "ci95_high_ms": ci_high, "ci95_method": ci_method,
                "median_ms": round(statistics.median(durations), 3),
                "p95_ms": round(percentile(durations, 95), 3),
                "p99_ms": round(percentile(durations, 99), 3),
                "min_ms": round(min(durations), 3),
                "max_ms": round(max(durations), 3),
            })
        else:
            row.update({k: "NA" for k in ["mean_ms", "stdev_ms", "ci95_low_ms", "ci95_high_ms",
                                           "ci95_method", "median_ms", "p95_ms", "p99_ms",
                                           "min_ms", "max_ms"]})

        rows.append(row)

    if n_single_block_combos:
        print(f"[i] {n_single_block_combos} combo(s) encore sur un seul bloc -- IC normale "
              f"utilisée en repli (probablement trop étroite, cf. §5.4). Recollecter en "
              f"plusieurs blocs pour ces configs si possible.")

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
