#!/usr/bin/env python3
"""
analyze_auth_cost.py — Remplace la logique de Table~auth-cost (single-vs-
mutual, actuellement un simple rapport de moyennes sans IC sur la
différence) par une comparaison directe sur Delta = mutual - single, avec
IC95% par bootstrap à DEUX ÉCHANTILLONS INDÉPENDANTS et test de
permutation exact.

Pourquoi indépendant et pas apparié (contrairement à
compute_paired_signature_comparisons dans analyze_handshake_performance.py) :
single-auth et mutual-auth proviennent de deux dossiers distincts, très
probablement deux invocations séparées du launcher -- rien ne garantit que
le bloc i de l'un corresponde à la même occasion d'exécution que le bloc i
de l'autre. Appliquer un bootstrap apparié sans le vérifier risquerait de
sous-estimer la variance de Delta. Le bootstrap à échantillons indépendants
est le choix conservateur et toujours valide.

Réutilise PAR IMPORT (pas de réimplémentation) :
  - le parsing de fichiers/blocs de analyze_handshake_performance.py
    (FNAME_RE, BLOCK_SUFFIX_RE, parse_combo_csv, classify_kem_class,
    SECURITY_LEVEL_BY_SIG)
  - independent_block_bootstrap_delta / exact_two_sample_permutation_test
    de compare_distributions.py

USAGE :
    python3 analyze_auth_cost.py \
        --single-dir captures/tls/single/none \
        --mutual-dir captures/tls/mutual/none \
        --out captures/tls/auth_cost_none.csv
"""

import argparse
import csv
import statistics
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from analyze_handshake_performance import (
    FNAME_RE, BLOCK_SUFFIX_RE, parse_combo_csv,
    SECURITY_LEVEL_BY_SIG, SIG_FAMILY,
)
from compare_distributions import (
    independent_block_bootstrap_delta, exact_two_sample_permutation_test,
)


def load_folder_blocks(folder: Path):
    """
    Reproduit le regroupement par combo de analyze_handshake_performance.py
    (analyze_folder, étape 1), mais ne retourne QUE blocks_by_combo --
    {(sig_alg, kem): {block_index: [durées réussies]}} -- pour ce dossier.
    """
    csv_dir = folder / "csv"
    if not csv_dir.is_dir():
        print(f"[!] {folder} : pas de sous-dossier csv/ trouvé.")
        return {}

    combo_files = defaultdict(list)
    combo_meta = {}
    for f in sorted(csv_dir.glob("*.csv")):
        stem_no_block = BLOCK_SUFFIX_RE.sub("", f.stem)
        m = FNAME_RE.search(stem_no_block + ".csv")
        if not m:
            continue
        protocol, auth_mode, sig_alg, kem, network_profile = m.groups()
        key = (sig_alg, kem)
        combo_files[key].append(f)
        combo_meta[key] = (protocol, auth_mode, sig_alg, kem, network_profile)

    blocks_by_combo = {}
    for key, files in combo_files.items():
        by_block = defaultdict(list)
        for f in files:
            records, _ = parse_combo_csv(f)
            for r in records:
                if r["success"] and r["duration"] is not None:
                    by_block[r["block_index"]].append(r["duration"])
        if by_block:
            blocks_by_combo[key] = dict(by_block)
    return blocks_by_combo


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--single-dir", required=True, type=Path)
    ap.add_argument("--mutual-dir", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    args = ap.parse_args()

    blocks_single = load_folder_blocks(args.single_dir)
    blocks_mutual = load_folder_blocks(args.mutual_dir)

    common_combos = sorted(set(blocks_single.keys()) & set(blocks_mutual.keys()))
    if not common_combos:
        print(f"[!] Aucune combinaison (sig_alg, kem) commune entre {args.single_dir} et {args.mutual_dir}.")
        return

    results = []
    for sig_alg, kem in common_combos:
        level = SECURITY_LEVEL_BY_SIG.get(sig_alg, "?")

        block_means_single = [statistics.mean(v) for v in blocks_single[(sig_alg, kem)].values() if v]
        block_means_mutual = [statistics.mean(v) for v in blocks_mutual[(sig_alg, kem)].values() if v]

        if len(block_means_single) < 2 or len(block_means_mutual) < 2:
            results.append({
                "security_level": level, "sig_alg": sig_alg, "kem": kem,
                "n_blocks_single": len(block_means_single), "n_blocks_mutual": len(block_means_mutual),
                "single_mean_ms": "NA", "mutual_mean_ms": "NA",
                "delta_ms": "NA", "delta_ci95_low": "NA", "delta_ci95_high": "NA",
                "significant_independent_bootstrap": "NA (moins de 2 blocs d'un des deux côtés)",
                "exact_permutation_p": "NA", "exact_permutation_min_p": "NA",
                "ratio_mutual_over_single": "NA",
            })
            continue

        boot = independent_block_bootstrap_delta(block_means_single, block_means_mutual)
        # Delta rapporté ici = mutual - single (coût positif attendu de l'authentification mutuelle)
        boot_display = independent_block_bootstrap_delta(block_means_mutual, block_means_single)
        perm = exact_two_sample_permutation_test(block_means_mutual, block_means_single)

        mean_single = statistics.mean(block_means_single)
        mean_mutual = statistics.mean(block_means_mutual)

        results.append({
            "security_level": level, "sig_alg": sig_alg, "kem": kem,
            "n_blocks_single": len(block_means_single), "n_blocks_mutual": len(block_means_mutual),
            "single_mean_ms": round(mean_single, 4), "mutual_mean_ms": round(mean_mutual, 4),
            "delta_ms": boot_display["delta_mean"] if boot_display else "NA",
            "delta_ci95_low": boot_display["ci95_low"] if boot_display else "NA",
            "delta_ci95_high": boot_display["ci95_high"] if boot_display else "NA",
            "significant_independent_bootstrap": ("oui" if boot_display["significant"] else "non") if boot_display else "NA",
            "exact_permutation_p": perm["p_value_two_sided"] if perm else "NA",
            "exact_permutation_min_p": perm["min_achievable_p"] if perm else "NA",
            "ratio_mutual_over_single": round(mean_mutual / mean_single, 3) if mean_single else "NA",
        })

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        w.writeheader()
        w.writerows(results)

    n_sig = sum(1 for r in results if r["significant_independent_bootstrap"] == "oui")
    n_valid = sum(1 for r in results if r["significant_independent_bootstrap"] in ("oui", "non"))
    print(f"[OK] {len(results)} combinaison(s) comparée(s) (single vs mutual) -> {args.out}")
    print(f"     {n_sig}/{n_valid} significative(s) par bootstrap à échantillons indépendants "
          f"(IC95% de Delta=mutual-single exclut zéro)")
    if results and results[0].get("exact_permutation_min_p") not in (None, "NA"):
        print(f"     p-value exacte minimale atteignable : {results[0]['exact_permutation_min_p']} "
              f"(test à 2 échantillons indépendants, plus fin que le test apparié à 4 blocs)")


if __name__ == "__main__":
    main()
