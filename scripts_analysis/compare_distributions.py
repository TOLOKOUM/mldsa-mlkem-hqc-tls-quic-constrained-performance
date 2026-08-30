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

SUPPORT DES BLOCS (résout le point 2 du rejet : "campagne unique, pas de
blocs indépendants") : depuis le découpage en blocs introduit dans le
launcher, une même condition peut correspondre à PLUSIEURS fichiers .log
(un par bloc, ex. ..._block1of5.log ... ..._block5of5.log) plutôt qu'un
seul. file_a et file_b acceptent donc désormais soit un nom de fichier
unique (comportement inchangé), soit une liste de fichiers séparés par
';', soit un motif glob (ex. handshake_tls_single_ed25519_hqc128_none_block*.log)
résolu par rapport à --log-dir -- tous les fichiers ainsi résolus pour un
côté sont poolés (durées concaténées) avant le test. ATTENTION : ce
pooling ne corrige PAS l'hypothèse d'indépendance du test de Mann-Whitney
lui-même (toujours calculé sur l'échantillon poolé comme s'il était i.i.d.)
-- seul le bootstrap de blocs de analyze_handshake_performance.py traite
correctement la corrélation intra-bloc pour les intervalles de confiance.
Un test de significativité tenant compte des blocs (ex. permutation par
bloc entier) n'est pas encore implémenté ici.
"""

import argparse
import csv
import itertools
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


def paired_block_bootstrap_delta(block_means_a, block_means_b, n_resamples=5000, seed=12345):
    """
    IC95% de Delta = mean(A) - mean(B) par bootstrap de blocs APPARIES.

    Remplace la logique "deux IC separes, on regarde s'ils se chevauchent"
    (utilisee jusqu'ici pour Table sig-effect-summary / auth-cost /
    degraded-deepdive) par un IC construit DIRECTEMENT sur la difference.
    Plus puissant que deux IC separes quand les deux bras sont apparies
    par bloc (meme block_index = meme passe du sweep, meme etat thermique/
    systeme du moment), puisque la variance inter-bloc commune aux deux
    bras s'annule dans la difference au lieu de s'additionner dans deux IC
    independants.

    block_means_a, block_means_b : listes de MEME LONGUEUR, block_means_a[i]
    et block_means_b[i] DOIVENT venir du meme block_index (verifie par
    l'appelant, cf. compute_paired_signature_comparisons).

    Meme graine et meme nombre de resamples que le reste du pipeline
    (seed=12345, n_resamples=5000) pour rester coherent avec
    block_bootstrap_ci / block_bootstrap_mean_ci.

    Retourne un dict avec delta_mean, ci_low, ci_high, significant
    (IC exclut zero), ou None si moins de 2 blocs communs.
    """
    import random
    n_blocks = min(len(block_means_a), len(block_means_b))
    if n_blocks < 2:
        return None

    block_means_a = block_means_a[:n_blocks]
    block_means_b = block_means_b[:n_blocks]
    observed_delta = statistics.mean(block_means_a) - statistics.mean(block_means_b)

    rng = random.Random(seed)
    boot_deltas = []
    for _ in range(n_resamples):
        idx = [rng.randrange(n_blocks) for _ in range(n_blocks)]
        resampled_a = [block_means_a[i] for i in idx]
        resampled_b = [block_means_b[i] for i in idx]
        boot_deltas.append(statistics.mean(resampled_a) - statistics.mean(resampled_b))
    boot_deltas.sort()

    n = len(boot_deltas)
    lo = boot_deltas[int(0.025 * n)]
    hi = boot_deltas[min(int(0.975 * n), n - 1)]

    return {
        "delta_mean": round(observed_delta, 4),
        "ci95_low": round(lo, 4),
        "ci95_high": round(hi, 4),
        "significant": (lo > 0) or (hi < 0),
        "n_blocks_paired": n_blocks,
        "n_resamples": n_resamples,
    }


def exact_paired_permutation_test(block_means_a, block_means_b):
    """
    Test de permutation EXACT sur des moyennes de bloc appariees : enumere
    les 2^n_blocks facons d'echanger les labels A/B bloc par bloc (n_blocks
    petit -- typiquement 4, donc 16 arrangements -- rend l'enumeration
    exhaustive triviale, pas d'approximation asymptotique necessaire).

    A UTILISER EN COMPLEMENT du bootstrap ci-dessus, pas a sa place : ce
    test ne fait AUCUNE hypothese distributionnelle, mais sa resolution est
    structurellement limitee par le nombre de blocs (avec n=4, la p-value
    bilaterale minimale atteignable est 2/16=0.125, quelle que soit la
    taille reelle de l'effet) -- a annoncer explicitement dans l'article,
    jamais a interpreter comme "non significatif" sans cette precision.

    Retourne un dict avec delta_observed, p_value_two_sided, n_permutations,
    min_achievable_p. None si moins de 2 blocs communs.
    """
    n_blocks = min(len(block_means_a), len(block_means_b))
    if n_blocks < 2:
        return None
    block_means_a = block_means_a[:n_blocks]
    block_means_b = block_means_b[:n_blocks]

    observed_delta = statistics.mean(block_means_a) - statistics.mean(block_means_b)
    observed_abs = abs(observed_delta)

    null_deltas = []
    for flips in itertools.product([False, True], repeat=n_blocks):
        perm_a = [block_means_b[i] if f else block_means_a[i] for i, f in enumerate(flips)]
        perm_b = [block_means_a[i] if f else block_means_b[i] for i, f in enumerate(flips)]
        null_deltas.append(statistics.mean(perm_a) - statistics.mean(perm_b))

    n_perms = len(null_deltas)
    n_as_extreme = sum(1 for d in null_deltas if abs(d) >= observed_abs - 1e-12)

    return {
        "delta_observed": round(observed_delta, 4),
        "p_value_two_sided": round(n_as_extreme / n_perms, 4),
        "n_permutations": n_perms,
        "min_achievable_p": round(2.0 / n_perms, 4),
    }


def independent_block_bootstrap_delta(block_means_a, block_means_b, n_resamples=5000, seed=12345):
    """
    IC95% de Delta = mean(A) - mean(B) par bootstrap de blocs INDEPENDANTS
    (pas apparies) : les indices de bloc sont rééchantillonnés separement
    pour A et pour B, chacun sur sa propre plage (len(A) et len(B) peuvent
    différer).

    A UTILISER quand A et B viennent de deux campagnes/dossiers distincts
    sans correspondance de bloc verifiee (ex: single-auth vs mutual-auth,
    executes comme deux invocations separees du launcher) -- contrairement
    a paired_block_bootstrap_delta, qui suppose que block_means_a[i] et
    block_means_b[i] partagent la meme occasion d'execution. Rééchantillonner
    avec les MEMES indices dans ce cas supposerait une correlation qu'on
    n'a pas verifiee, et sous-estimerait potentiellement la variance de
    Delta (IC artificiellement trop etroit) -- ce bootstrap independant
    est le choix conservateur et toujours valide par defaut.

    Retourne un dict avec delta_mean, ci_low, ci_high, significant, ou None
    si l'un des deux bras a moins de 2 blocs.
    """
    import random
    n_a, n_b = len(block_means_a), len(block_means_b)
    if n_a < 2 or n_b < 2:
        return None

    observed_delta = statistics.mean(block_means_a) - statistics.mean(block_means_b)

    rng = random.Random(seed)
    boot_deltas = []
    for _ in range(n_resamples):
        resampled_a = [block_means_a[rng.randrange(n_a)] for _ in range(n_a)]
        resampled_b = [block_means_b[rng.randrange(n_b)] for _ in range(n_b)]
        boot_deltas.append(statistics.mean(resampled_a) - statistics.mean(resampled_b))
    boot_deltas.sort()

    n = len(boot_deltas)
    lo = boot_deltas[int(0.025 * n)]
    hi = boot_deltas[min(int(0.975 * n), n - 1)]

    return {
        "delta_mean": round(observed_delta, 4),
        "ci95_low": round(lo, 4),
        "ci95_high": round(hi, 4),
        "significant": (lo > 0) or (hi < 0),
        "n_blocks_a": n_a, "n_blocks_b": n_b,
        "n_resamples": n_resamples,
    }


def exact_two_sample_permutation_test(block_means_a, block_means_b):
    """
    Test de permutation EXACT pour deux echantillons INDEPENDANTS (pas
    apparies) : sous H0, les n_a+n_b moyennes de bloc sont exchangeables
    entre A et B ; on enumere TOUTES les C(n_a+n_b, n_a) facons de repartir
    l'ensemble combine en un groupe de taille n_a et un groupe de taille
    n_b (test de permutation de Fisher-Pitman classique).

    Avec n_a=n_b=4 (cas typique ici), C(8,4)=70 arrangements -- resolution
    bien plus fine que le test apparie a 16 arrangements (min p=2/70≈0.029
    contre 2/16=0.125), PARCE QU'on ne suppose plus de structure d'
    appariement, pas malgre cela.

    Retourne un dict avec delta_observed, p_value_two_sided,
    n_permutations, min_achievable_p. None si l'un des deux bras a moins
    de 2 valeurs.
    """
    n_a, n_b = len(block_means_a), len(block_means_b)
    if n_a < 2 or n_b < 2:
        return None

    combined = list(block_means_a) + list(block_means_b)
    n_total = len(combined)
    observed_delta = statistics.mean(block_means_a) - statistics.mean(block_means_b)
    observed_abs = abs(observed_delta)

    null_deltas = []
    for combo_idx in itertools.combinations(range(n_total), n_a):
        idx_set = set(combo_idx)
        group_a = [combined[i] for i in range(n_total) if i in idx_set]
        group_b = [combined[i] for i in range(n_total) if i not in idx_set]
        null_deltas.append(statistics.mean(group_a) - statistics.mean(group_b))

    n_perms = len(null_deltas)
    n_as_extreme = sum(1 for d in null_deltas if abs(d) >= observed_abs - 1e-12)

    return {
        "delta_observed": round(observed_delta, 4),
        "p_value_two_sided": round(n_as_extreme / n_perms, 4),
        "n_permutations": n_perms,
        "min_achievable_p": round(2.0 / n_perms, 4),
    }


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


def resolve_side(spec: str, log_dir: Path):
    """Résout un côté de comparaison (file_a ou file_b) en liste de Path :
    - "a.log" -> [log_dir/a.log]  (comportement historique, inchangé)
    - "a.log;b.log" -> [log_dir/a.log, log_dir/b.log]
    - "block*.log" -> tous les fichiers correspondants sous log_dir (glob)
    """
    parts = [p.strip() for p in spec.split(";") if p.strip()]
    resolved = []
    for p in parts:
        if any(ch in p for ch in "*?["):
            matches = sorted(log_dir.glob(p))
            if not matches:
                print(f"    [!] Motif '{p}' ne correspond à aucun fichier sous {log_dir}")
            resolved.extend(matches)
        else:
            resolved.append(log_dir / p)
    return resolved


def load_and_pool(paths):
    """Concatène les durées de tous les fichiers d'un côté. Retourne
    (durations, n_nan, n_files_missing)."""
    durations, n_nan, n_missing = [], 0, 0
    for p in paths:
        if not p.exists():
            n_missing += 1
            continue
        d, n = parse_log_file(p)
        durations.extend(d)
        n_nan += n
    return durations, n_nan, n_missing


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
        paths_a = resolve_side(fa, args.log_dir)
        paths_b = resolve_side(fb, args.log_dir)

        durations_a, n_nan_a, n_missing_a = load_and_pool(paths_a)
        durations_b, n_nan_b, n_missing_b = load_and_pool(paths_b)

        if not paths_a or not paths_b or n_missing_a == len(paths_a) or n_missing_b == len(paths_b):
            print(f"[!] {label}: aucun fichier résolu/trouvé pour un des deux côtés — ignoré.")
            continue
        if n_missing_a or n_missing_b:
            print(f"  [i] {label}: {n_missing_a} fichier(s) manquant(s) côté A, "
                  f"{n_missing_b} côté B — pooling effectué sur les fichiers trouvés uniquement.")

        u1, z, p, delta = mann_whitney_u(durations_a, durations_b)

        results.append({
            "label": label,
            "file_a": fa, "file_b": fb,
            "n_files_a": len(paths_a), "n_files_b": len(paths_b),
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
        "de ce script, pas comparaison par comparaison en isolation. Quand un "
        "côté de comparaison correspond à plusieurs fichiers-blocs (colonne "
        "'n_files_a'/'n_files_b' > 1), les durées sont poolées avant le test ; "
        "ce pooling NE corrige PAS l'hypothèse d'indépendance du test lui-même "
        "(toujours calculé comme si l'échantillon poolé était i.i.d.) -- seul "
        "l'intervalle de confiance par bootstrap de blocs de "
        "analyze_handshake_performance.py traite correctement la corrélation "
        "intra-bloc ; les p-values de ce fichier restent donc indicatives."
    )

    Path(args.out_dir / "significance_tests_report.md").write_text("\n".join(lines))
    print(f"[OK] {len(results)} comparaison(s) -> {args.out_dir}/significance_tests_report.md")


if __name__ == "__main__":
    main()
