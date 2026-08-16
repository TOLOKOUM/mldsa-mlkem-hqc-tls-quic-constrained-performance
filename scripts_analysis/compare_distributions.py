#!/usr/bin/env python3
"""
compare_distributions.py — Tests statistiques formels (Mann-Whitney U,
Cliff's delta, correction FDR de Benjamini-Hochberg) entre paires de
conditions, à partir des logs bruts de handshake (même format que ceux
consommés par parse_handshake_logs.py).

Contrairement à analyze_handshake_performance.py (qui décrit UN dossier
protocole/auth_mode/network_profile à la fois, comparaisons intra-dossier
vs baseline classique), ce script compare explicitement DEUX conditions
quelconques entre elles (inter-scénario, inter-mode d'authentification,
inter-signature...), avec un test d'hypothèse formel plutôt qu'un simple
chevauchement d'IC95%.

MÉTHODOLOGIE (à citer dans l'article) :
  - Mann-Whitney U calculé manuellement par rangs (avec correction pour
    ex-aequo dans l'approximation normale du z), sans dépendance scipy,
    dans le même esprit que le calcul d'IC95% par approximation normale
    déjà utilisé dans analyze_handshake_performance.py.
  - Cliff's delta dérivé directement de U1 : delta = 2*U1/(n1*n2) - 1,
    interprété selon les seuils usuels (Romano et al. 2006) :
    négligeable (|delta|<0.147), petit (<0.33), moyen (<0.474), grand (>=0.474).
  - Seuls les runs réussis (durée numérique, pas NaN) entrent dans les
    deux distributions comparées — cohérent avec l'exclusion des échecs
    déjà appliquée dans parse_handshake_logs.py et
    analyze_handshake_performance.py (vérifié empiriquement contre les
    logs bruts, voir §5.4 de l'article).
  - Quand plusieurs comparaisons sont exécutées dans le même run, une
    correction de Benjamini-Hochberg (FDR) est appliquée sur l'ensemble
    des p-values obtenues, plutôt que de les interpréter isolément.

USAGE :
    python3 compare_distributions.py --comparisons comparisons.csv --out-dir results_significance/

Format de comparisons.csv (une ligne = une comparaison, en-tête requis) :
    label,file_a,file_b
    ml-dsa_reversal_L5_degraded,handshake_tls_single_secp521r1_p521_mlkem1024_simple_loss0.2_delay65.15ms.log,handshake_tls_single_mldsa87_p521_mlkem1024_simple_loss0.2_delay65.15ms.log
    hqc_nonmonotonic_degraded_vs_gestable,handshake_tls_single_ed25519_hqc128_simple_loss0.2_delay65.15ms.log,handshake_tls_single_ed25519_hqc128_stable.log
    mtls_mldsa44_multiplier,handshake_tls_single_mldsa44_P-256_none.log,handshake_tls_mutual_mldsa44_P-256_none.log

Les chemins de file_a/file_b sont résolus relativement à --log-dir (par
défaut, le répertoire courant).
"""

import argparse
import csv
import math
import statistics
from pathlib import Path
from collections import Counter

# Réutilise la logique d'extraction déjà vérifiée (même regex, même
# traitement NaN) plutôt que de la dupliquer.
from parse_handshake_logs import parse_log_file


def norm_cdf(x):
    return 0.5 * (1 + math.erf(x / math.sqrt(2)))


def mann_whitney_u(x, y):
    """Retourne (U1, z, p_two_tailed, cliffs_delta) pour deux échantillons
    x (groupe 1) et y (groupe 2), avec correction pour ex-aequo."""
    n1, n2 = len(x), len(y)
    combined = sorted([(v, 0) for v in x] + [(v, 1) for v in y])
    n = len(combined)

    ranks = [0.0] * n
    i = 0
    while i < n:
        j = i
        while j < n and combined[j][0] == combined[i][0]:
            j += 1
        avg_rank = (i + j + 1) / 2.0  # rang moyen 1-indexé pour les ex-aequo
        for k in range(i, j):
            ranks[k] = avg_rank
        i = j

    r1 = sum(r for r, (v, g) in zip(ranks, combined) if g == 0)
    u1 = r1 - n1 * (n1 + 1) / 2

    mu_u = n1 * n2 / 2
    counts = Counter(v for v, g in combined)
    tie_term = sum(t**3 - t for t in counts.values())
    if n > 1:
        sigma_u = math.sqrt((n1 * n2 / 12.0) * ((n + 1) - tie_term / (n * (n - 1))))
    else:
        sigma_u = 0.0

    z = (u1 - mu_u) / sigma_u if sigma_u > 0 else 0.0
    p = 2 * (1 - norm_cdf(abs(z)))

    cliffs_delta = (2 * u1) / (n1 * n2) - 1
    return u1, z, p, cliffs_delta


def interpret_cliffs_delta(d):
    ad = abs(d)
    if ad < 0.147:
        return "négligeable"
    elif ad < 0.33:
        return "petit"
    elif ad < 0.474:
        return "moyen"
    else:
        return "grand"


def benjamini_hochberg(pvalues):
    """Retourne les p-values ajustées (FDR), même ordre que l'entrée."""
    m = len(pvalues)
    indexed = sorted(enumerate(pvalues), key=lambda t: t[1])
    adjusted = [0.0] * m
    prev = 1.0
    for rank in range(m, 0, -1):
        idx, p = indexed[rank - 1]
        val = min(prev, p * m / rank)
        adjusted[idx] = val
        prev = val
    return adjusted


def load_comparisons(path: Path):
    rows = []
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            rows.append((row["label"].strip(), row["file_a"].strip(), row["file_b"].strip()))
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--comparisons", required=True, type=Path,
                     help="CSV avec colonnes label,file_a,file_b")
    ap.add_argument("--log-dir", default=Path("."), type=Path,
                     help="Répertoire où résoudre file_a/file_b")
    ap.add_argument("--out-dir", default=Path("results_significance"), type=Path)
    args = ap.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    comparisons = load_comparisons(args.comparisons)

    results = []
    for label, fa, fb in comparisons:
        path_a = args.log_dir / fa
        path_b = args.log_dir / fb
        if not path_a.exists() or not path_b.exists():
            print(f"[!] {label}: fichier manquant ({path_a} ou {path_b}) — ignoré.")
            continue

        durations_a, n_nan_a = parse_log_file(path_a)
        durations_b, n_nan_b = parse_log_file(path_b)

        u1, z, p, delta = mann_whitney_u(durations_a, durations_b)

        results.append({
            "label": label,
            "file_a": fa, "file_b": fb,
            "n_a": len(durations_a), "n_fail_a": n_nan_a,
            "n_b": len(durations_b), "n_fail_b": n_nan_b,
            "median_a": round(statistics.median(durations_a), 3) if durations_a else "NA",
            "median_b": round(statistics.median(durations_b), 3) if durations_b else "NA",
            "U1": round(u1, 1), "z": round(z, 3), "p_raw": p,
            "cliffs_delta": round(delta, 3),
            "effect_size": interpret_cliffs_delta(delta),
        })

    if not results:
        print("Aucune comparaison exploitable. Rien à écrire.")
        return

    p_raw = [r["p_raw"] for r in results]
    p_adj = benjamini_hochberg(p_raw)
    for r, padj in zip(results, p_adj):
        r["p_raw"] = round(r["p_raw"], 6)
        r["p_fdr"] = round(padj, 6)
        r["significant_fdr_0.05"] = "oui" if padj < 0.05 else "non"

    # CSV
    out_csv = args.out_dir / "significance_tests.csv"
    with open(out_csv, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        w.writeheader()
        w.writerows(results)

    # Rapport markdown citable
    lines = ["# Tests statistiques formels — Mann-Whitney U / Cliff's delta\n"]
    lines.append(f"**{len(results)} comparaison(s)**, correction FDR (Benjamini-Hochberg) "
                  f"appliquée sur l'ensemble des p-values de ce batch.\n")
    lines.append("| Comparaison | N_a (fail) | N_b (fail) | Médiane a (ms) | Médiane b (ms) | "
                  "U1 | z | p (brut) | p (FDR) | Cliff's delta | Taille d'effet | Signif. (α=0.05, FDR) |")
    lines.append("|---|---|---|---|---|---|---|---|---|---|---|---|")
    for r in results:
        lines.append(
            f"| {r['label']} | {r['n_a']} ({r['n_fail_a']}) | {r['n_b']} ({r['n_fail_b']}) | "
            f"{r['median_a']} | {r['median_b']} | {r['U1']} | {r['z']} | {r['p_raw']} | "
            f"{r['p_fdr']} | {r['cliffs_delta']} | {r['effect_size']} | {r['significant_fdr_0.05']} |"
        )

    lines.append("\n## Note méthodologique\n")
    lines.append(
        "Mann-Whitney U calculé par rangs avec correction pour ex-aequo dans "
        "l'approximation normale du z (pas de dépendance scipy, cohérent avec "
        "le reste du pipeline). Cliff's delta dérivé directement de U1 : "
        "delta = 2*U1/(n1*n2) - 1. Seuls les runs réussis (durée numérique) "
        "entrent dans chaque distribution comparée ; les échecs (NaN) sont "
        "comptés séparément (colonne 'fail') mais exclus du test, cohérent "
        "avec le traitement déjà appliqué dans parse_handshake_logs.py et "
        "analyze_handshake_performance.py. La correction de Benjamini-Hochberg "
        "est appliquée sur l'ensemble des p-values obtenues dans le même run "
        "de ce script, pas comparaison par comparaison en isolation."
    )

    Path(args.out_dir / "significance_tests_report.md").write_text("\n".join(lines))
    print(f"[OK] {len(results)} comparaison(s) -> {args.out_dir}/significance_tests_report.md")


if __name__ == "__main__":
    main()
