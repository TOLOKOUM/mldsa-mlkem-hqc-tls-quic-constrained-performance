#!/usr/bin/env python3
"""
analyze_handshake_performance.py — Analyse LOCALE (un dossier protocole/
auth_mode/network_profile à la fois) de la performance de handshake, à
partir des CSV par exécution produits par logs_to_csv.py (csv/*.csv,
colonnes: execution,mode,handshake_duration_ms,success).

Produit, dans <dossier>/analyse/ :
  - handshake_stats.csv      : une ligne par combinaison SIG_ALG/KEM,
                                statistiques complètes (moyenne, médiane,
                                IC95%, p95/p99, taux de succès...)
  - handshake_overhead.csv   : surcoût (%) de chaque combinaison par rapport
                                au baseline classique DE MÊME NIVEAU DE
                                SÉCURITÉ (ex: mldsa65+mlkem768 comparé à la
                                moyenne de secp384r1+{P-384,x448})
  - handshake_report.md      : rapport texte prêt à copier dans un article
  - latency_boxplot.png      : distribution des latences par combinaison
                                (si matplotlib disponible)
  - overhead_by_class.png    : surcoût moyen par niveau de sécurité × classe
                                KEM (si matplotlib disponible)

USAGE (un dossier à la fois) :
    python3 analyze_handshake_performance.py captures/tls/single/none

USAGE (mode batch — tous les dossiers contenant un csv/ sous la racine donnée) :
    python3 analyze_handshake_performance.py captures --all

MÉTHODOLOGIE (à citer dans l'article) :
  - Intervalle de confiance à 95% de la moyenne calculé par approximation
    normale (z=1.96), justifiée par la taille d'échantillon (n=500 par
    combinaison dans la plupart des cas, largement suffisante pour le
    théorème central limite quelle que soit la forme de la distribution
    sous-jacente). Pas de dépendance à scipy.
  - Le surcoût (%) est calculé par rapport à la MOYENNE des combinaisons
    classiques DU MÊME NIVEAU DE SÉCURITÉ NIST (pas un unique KEM classique
    arbitraire), pour lisser le bruit de mesure du baseline lui-même.
  - Médiane et p95 sont reportés en complément de la moyenne : en cas
    d'asymétrie forte (mean très différent de median), c'est un signal à
    interpréter avec prudence, pas à ignorer.
"""

import argparse
import csv
import math
import re
import statistics
import sys
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).resolve().parent))

FNAME_RE = re.compile(r"handshake_(tls|quic)_(mutual|single)_(.+?)_(.+?)_(none|stable|unstable|simple.*)\.csv$")
# Suffixe de bloc ajouté par le launcher patché (ex. ..._block2of5.csv) --
# retiré du nom AVANT d'appliquer FNAME_RE ci-dessus, pour que plusieurs
# fichiers-blocs d'une même combinaison SIG_ALG/KEM se regroupent au lieu
# d'être traités comme des combinaisons distinctes (ou, pour les scénarios
# "none/stable/unstable", de faire simplement échouer le matching).
BLOCK_SUFFIX_RE = re.compile(r"_block(\d+)of(\d+)$")

# ── Classification KEM (identique à Analyze_resource_usage.py) ─────────────
def classify_kem_class(kem: str) -> str:
    k = kem.lower().replace("-", "")
    is_pq = any(tag in k for tag in ("mlkem", "hqc"))
    is_classical_component = any(tag in k for tag in ("p256", "p384", "p521", "x25519", "x448"))
    if is_pq and is_classical_component:
        return "hybride"
    if is_pq:
        return "pq_pur"
    return "classique"

# ── Niveau de sécurité NIST, dérivé du SIG_ALG (non ambigu, contrairement
# au KEM seul) — identique au regroupement fait dans Launcher_pq_mldsa_mlkem_hqc.sh
SECURITY_LEVEL_BY_SIG = {
    "ed25519": "L1", "mldsa44": "L1",
    "secp384r1": "L3", "mldsa65": "L3",
    "secp521r1": "L5", "mldsa87": "L5",
}
SIG_FAMILY = {
    "ed25519": "classique", "secp384r1": "classique", "secp521r1": "classique",
    "mldsa44": "pq", "mldsa65": "pq", "mldsa87": "pq",
}


def z95_ci(mean, stdev, n):
    if n <= 1 or stdev is None:
        return (None, None)
    margin = 1.96 * stdev / math.sqrt(n)
    return (round(mean - margin, 3), round(mean + margin, 3))


def percentile(values, p):
    if not values:
        return None
    s = sorted(values)
    k = (len(s) - 1) * (p / 100)
    f, c = int(k), min(int(k) + 1, len(s) - 1)
    if f == c:
        return s[f]
    return s[f] + (s[c] - s[f]) * (k - f)


def parse_combo_csv(path: Path):
    """Retourne une liste d'enregistrements {duration, block_index, success}
    plutôt que juste les durées -- nécessaire pour le bootstrap de blocs
    ci-dessous. Repli sur block_index=1 si la colonne est absente (CSV
    généré par une version de logs_to_csv.py antérieure au support des
    blocs) : traité comme un bloc unique, comportement inchangé pour ces
    fichiers, mais sans bootstrap de blocs possible pour eux (cf.
    block_bootstrap_ci)."""
    records = []
    n_total = 0
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            n_total += 1
            success = row.get("success") == "1"
            block_raw = row.get("block_index")
            block_index = int(block_raw) if block_raw not in (None, "", "NA") else 1
            duration = None
            if success:
                try:
                    duration = float(row["handshake_duration_ms"])
                except (TypeError, ValueError):
                    success = False
            records.append({"duration": duration, "block_index": block_index, "success": success})
    return records, n_total


def block_bootstrap_ci(records, n_resamples=5000, seed=12345):
    """IC95% de la moyenne par bootstrap de BLOCS ENTIERS (pas d'observations
    individuelles) -- respecte la corrélation intra-bloc documentée dans
    l'article (rho1=0.563 sur la série testée, IC bootstrap ~2.2x plus large
    que l'IC normal naïf) au lieu de supposer les runs indépendants. Retourne
    None si moins de 2 blocs distincts sont disponibles (bootstrap de blocs
    non défini avec un seul bloc -- utiliser z95_ci en repli dans ce cas,
    avec un avertissement explicite dans le rapport)."""
    import random
    by_block = defaultdict(list)
    for r in records:
        if r["success"] and r["duration"] is not None:
            by_block[r["block_index"]].append(r["duration"])
    blocks = [v for v in by_block.values() if v]
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


def analyze_folder(folder: Path):
    csv_dir = folder / "csv"
    if not csv_dir.is_dir():
        print(f"[!] {folder} : pas de sous-dossier csv/ — ignoré "
              f"(lance d'abord logs_to_csv.py sur handshake_logs/).")
        return None

    # ── Étape 1 : regroupement des fichiers par combo (en retirant le
    # suffixe de bloc du nom) -- plusieurs fichiers-blocs d'une même
    # combinaison SIG_ALG/KEM sont désormais fusionnés en une seule analyse,
    # au lieu d'être traités comme des combinaisons séparées (ou de faire
    # échouer le matching de FNAME_RE pour les scénarios none/stable/unstable).
    combo_files = defaultdict(list)
    combo_meta = {}
    for f in sorted(csv_dir.glob("*.csv")):
        stem_no_block = BLOCK_SUFFIX_RE.sub("", f.stem)
        m = FNAME_RE.search(stem_no_block + ".csv")
        if not m:
            print(f"  [!] Nom non conforme, ignoré : {f.name}")
            continue
        protocol, auth_mode, sig_alg, kem, network_profile = m.groups()
        key = (protocol, auth_mode, sig_alg, kem, network_profile)
        combo_files[key].append(f)
        combo_meta[key] = (protocol, auth_mode, sig_alg, kem, network_profile)

    rows = []
    durations_by_combo = {}  # (sig_alg, kem) -> liste de durées (à plat), pour l'affichage/export
    blocks_by_combo = {}     # (sig_alg, kem) -> {block_index: [durées]}, pour le bootstrap de blocs
    n_single_block_combos = 0
    for key, files in combo_files.items():
        protocol, auth_mode, sig_alg, kem, network_profile = combo_meta[key]

        all_records, n_total = [], 0
        for f in files:
            recs, n = parse_combo_csv(f)
            all_records.extend(recs)
            n_total += n
        if n_total == 0:
            print(f"  [!] {key} : fichier(s) vide(s), ignoré.")
            continue

        durations = [r["duration"] for r in all_records if r["success"] and r["duration"] is not None]
        n_fail = sum(1 for r in all_records if not r["success"])
        n_blocks_seen = len(set(r["block_index"] for r in all_records))

        row = {
            "protocol": protocol, "auth_mode": auth_mode, "sig_alg": sig_alg,
            "kem": kem, "kem_class": classify_kem_class(kem),
            "security_level": SECURITY_LEVEL_BY_SIG.get(sig_alg, "?"),
            "sig_family": SIG_FAMILY.get(sig_alg, "?"),
            "network_profile": network_profile,
            "n_total": n_total, "n_success": len(durations), "n_failed": n_fail,
            "success_rate_pct": round(100 * len(durations) / n_total, 2) if n_total else "NA",
            "n_blocks_pooled": n_blocks_seen, "n_files_pooled": len(files),
        }
        if durations:
            mean = statistics.mean(durations)
            stdev = statistics.stdev(durations) if len(durations) > 1 else 0.0
            ci_low, ci_high = z95_ci(mean, stdev, len(durations))

            block_ci = block_bootstrap_ci(all_records) if n_blocks_seen > 1 else None
            if block_ci is not None:
                ci_method = "bootstrap_blocs"
                ci_report_low, ci_report_high = block_ci
            else:
                ci_method = "normale_naive (1 seul bloc -- IC probablement trop étroit, cf. §5.4 de l'article)"
                ci_report_low, ci_report_high = ci_low, ci_high
                if n_blocks_seen <= 1:
                    n_single_block_combos += 1

            row.update({
                "mean_ms": round(mean, 3), "stdev_ms": round(stdev, 3),
                "ci95_low_ms": ci_report_low, "ci95_high_ms": ci_report_high,
                "ci95_method": ci_method,
                "ci95_naive_low_ms": ci_low, "ci95_naive_high_ms": ci_high,
                "median_ms": round(statistics.median(durations), 3),
                "p95_ms": round(percentile(durations, 95), 3),
                "p99_ms": round(percentile(durations, 99), 3),
                "min_ms": round(min(durations), 3), "max_ms": round(max(durations), 3),
            })
            durations_by_combo[(sig_alg, kem)] = durations
            by_block = defaultdict(list)
            for r in all_records:
                if r["success"] and r["duration"] is not None:
                    by_block[r["block_index"]].append(r["duration"])
            blocks_by_combo[(sig_alg, kem)] = dict(by_block)
        else:
            for k in ["mean_ms", "stdev_ms", "ci95_low_ms", "ci95_high_ms", "ci95_method",
                      "ci95_naive_low_ms", "ci95_naive_high_ms",
                      "median_ms", "p95_ms", "p99_ms", "min_ms", "max_ms"]:
                row[k] = "NA"
        rows.append(row)

    if not rows:
        print(f"[!] {folder} : aucune combinaison exploitable trouvée dans csv/.")
        return None

    if n_single_block_combos:
        print(f"  [i] {n_single_block_combos} combo(s) encore sur un seul bloc -- IC normale "
              f"utilisée en repli pour celles-ci (probablement trop étroit, cf. §5.4). "
              f"Relancer la campagne en plusieurs blocs pour ces configs si possible.")

    out_dir = folder / "analyse"
    out_dir.mkdir(parents=True, exist_ok=True)

    with open(out_dir / "handshake_stats.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    overhead_rows = compute_overhead(rows)
    if overhead_rows:
        with open(out_dir / "handshake_overhead.csv", "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(overhead_rows[0].keys()))
            w.writeheader()
            w.writerows(overhead_rows)

    compute_systematic_significance(rows, durations_by_combo, blocks_by_combo, out_dir)

    write_report(out_dir / "handshake_report.md", folder, rows, overhead_rows)
    write_figures(out_dir, rows, overhead_rows)

    print(f"[OK] {folder} : {len(rows)} combinaison(s) -> {out_dir}/")
    return rows


def compute_overhead(rows):
    """Surcoût (%) vs moyenne des combinaisons classiques du MÊME niveau
    de sécurité (pas un unique KEM classique arbitraire)."""
    by_level_baseline = defaultdict(list)
    for r in rows:
        if r["kem_class"] == "classique" and r["mean_ms"] != "NA":
            by_level_baseline[r["security_level"]].append(r["mean_ms"])

    baseline_mean = {
        level: round(statistics.mean(vals), 3)
        for level, vals in by_level_baseline.items() if vals
    }

    overhead_rows = []
    for r in rows:
        base = baseline_mean.get(r["security_level"])
        if base and r["mean_ms"] != "NA" and base > 0:
            pct = round((r["mean_ms"] - base) / base * 100, 1)
        else:
            pct = "NA"
        overhead_rows.append({
            "security_level": r["security_level"], "sig_alg": r["sig_alg"],
            "kem": r["kem"], "kem_class": r["kem_class"],
            "mean_ms": r["mean_ms"],
            "baseline_classique_mean_ms": base if base else "NA",
            "overhead_pct": pct,
        })
    return overhead_rows


def block_bootstrap_cliffs_delta(base_by_block, combo_by_block, n_resamples=5000, seed=12345):
    """IC95% de Cliff's delta par bootstrap de BLOCS ENTIERS (pas d'observations
    individuelles), sur le même principe que block_bootstrap_ci ci-dessus --
    corrige le point signalé par le NOTE de compute_systematic_significance :
    le Mann-Whitney U brut sur les observations poolées suppose l'indépendance
    intra-groupe, ce qui est faux quand les 500 handshakes viennent de blocs
    corrélés (rho1=0.563 documenté dans l'article).

    À chaque rééchantillonnage, on tire avec remise autant de blocs que
    disponibles côté baseline ET côté combo (indépendamment), on poole les
    durées obtenues, puis on recalcule Cliff's delta via mann_whitney_u
    (réutilisée depuis compare_distributions.py -- pas de réimplémentation).
    Retourne (delta_low, delta_high, n_resamples_valides) ou None si l'un des
    deux groupes a moins de 2 blocs distincts (bootstrap de blocs non défini
    dans ce cas -- utiliser le Mann-Whitney brut en repli, avec avertissement)."""
    import random
    from compare_distributions import mann_whitney_u

    base_blocks = [v for v in base_by_block.values() if v]
    combo_blocks = [v for v in combo_by_block.values() if v]
    if len(base_blocks) < 2 or len(combo_blocks) < 2:
        return None

    rng = random.Random(seed)
    deltas = []
    for _ in range(n_resamples):
        base_resampled = [rng.choice(base_blocks) for _ in range(len(base_blocks))]
        combo_resampled = [rng.choice(combo_blocks) for _ in range(len(combo_blocks))]
        base_pooled = [v for b in base_resampled for v in b]
        combo_pooled = [v for b in combo_resampled for v in b]
        if not base_pooled or not combo_pooled:
            continue
        _, _, _, delta = mann_whitney_u(base_pooled, combo_pooled)
        deltas.append(delta)

    if not deltas:
        return None
    return (round(percentile(deltas, 2.5), 3), round(percentile(deltas, 97.5), 3), len(deltas))


def compute_systematic_significance(rows, durations_by_combo, blocks_by_combo, out_dir):
    """Résout le point du rejet sur les tests statistiques ('seulement 3
    comparaisons ciblées') : génère AUTOMATIQUEMENT un test Mann-Whitney U /
    Cliff's delta pour CHAQUE combinaison PQ contre le baseline classique du
    même niveau de sécurité dans ce dossier, avec correction FDR jointe sur
    l'ensemble des tests -- au lieu de sélectionner 3 cas à la main.

    Réutilise mann_whitney_u/benjamini_hochberg/interpret_cliffs_delta de
    compare_distributions.py PAR IMPORT (pas de réimplémentation) pour que
    la méthodologie citée dans l'article reste unique et cohérente entre
    les deux scripts -- cf. le point 5 du rejet sur les incohérences
    manuscrit/artefact.

    Le baseline classique d'un niveau = la distribution POOLÉE de toutes
    les combos classiques de ce niveau (même choix que compute_overhead
    pour la moyenne), pas un unique KEM classique arbitraire."""
    try:
        from compare_distributions import mann_whitney_u, benjamini_hochberg, interpret_cliffs_delta
    except ImportError:
        print("  [!] compare_distributions.py introuvable dans le PYTHONPATH -- "
              "tests de significativité systématiques non générés. Placez ce script "
              "dans le même dossier que analyze_handshake_performance.py.")
        return

    classical_pooled = defaultdict(list)
    classical_pooled_blocks = defaultdict(lambda: defaultdict(list))
    for r in rows:
        if r["kem_class"] == "classique" and r["mean_ms"] != "NA":
            classical_pooled[r["security_level"]].extend(
                durations_by_combo.get((r["sig_alg"], r["kem"]), [])
            )
            for block_idx, vals in blocks_by_combo.get((r["sig_alg"], r["kem"]), {}).items():
                classical_pooled_blocks[r["security_level"]][block_idx].extend(vals)

    results = []
    for r in rows:
        if r["kem_class"] == "classique" or r["mean_ms"] == "NA":
            continue
        base = classical_pooled.get(r["security_level"])
        combo_durations = durations_by_combo.get((r["sig_alg"], r["kem"]))
        if not base or not combo_durations:
            continue
        u1, z, p, delta = mann_whitney_u(base, combo_durations)

        base_blocks = dict(classical_pooled_blocks.get(r["security_level"], {}))
        combo_blocks = blocks_by_combo.get((r["sig_alg"], r["kem"]), {})
        block_result = block_bootstrap_cliffs_delta(base_blocks, combo_blocks)
        if block_result is not None:
            delta_ci_low, delta_ci_high, n_resamples_ok = block_result
            block_method = "bootstrap_blocs"
            significant_blocks = "oui" if (delta_ci_low > 0 or delta_ci_high < 0) else "non"
        else:
            delta_ci_low = delta_ci_high = "NA"
            block_method = "indisponible (<2 blocs d'un des deux côtés -- voir p_raw/p_fdr en repli)"
            significant_blocks = "NA"

        results.append({
            "security_level": r["security_level"], "sig_alg": r["sig_alg"], "kem": r["kem"],
            "kem_class": r["kem_class"], "network_profile": r["network_profile"],
            "n_baseline_classique_pooled": len(base), "n_combo": len(combo_durations),
            "median_baseline_ms": round(statistics.median(base), 3),
            "median_combo_ms": round(statistics.median(combo_durations), 3),
            "U1": round(u1, 1), "z": round(z, 3), "p_raw": p,
            "cliffs_delta": round(delta, 3), "effect_size": interpret_cliffs_delta(delta),
            "cliffs_delta_ci95_low_blocbootstrap": delta_ci_low,
            "cliffs_delta_ci95_high_blocbootstrap": delta_ci_high,
            "significant_blocbootstrap": significant_blocks,
            "block_bootstrap_method": block_method,
        })

    if not results:
        return

    p_adj = benjamini_hochberg([r["p_raw"] for r in results])
    for r, padj in zip(results, p_adj):
        r["p_raw"] = round(r["p_raw"], 6)
        r["p_fdr"] = round(padj, 6)
        r["significant_fdr_0.05"] = "oui" if padj < 0.05 else "non"

    with open(out_dir / "significance_tests_auto.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        w.writeheader()
        w.writerows(results)
    n_block_ok = sum(1 for r in results if r["block_bootstrap_method"] == "bootstrap_blocs")
    print(f"  [OK] {len(results)} test(s) de significativité systématique(s) "
          f"(PQ vs baseline classique pooléé, même niveau) -> {out_dir}/significance_tests_auto.csv")
    print(f"       {n_block_ok}/{len(results)} test(s) disposent d'un IC95% de Cliff's delta par "
          "bootstrap de blocs (colonnes cliffs_delta_ci95_*_blocbootstrap / significant_blocbootstrap) "
          "-- c'est ce résultat qui respecte l'autocorrélation intra-bloc et qui doit être cité "
          "dans l'article, PAS p_raw/p_fdr.")
    print("       NOTE : p_raw/p_fdr (Mann-Whitney U brut) restent calculés à titre indicatif "
          "seulement -- ils supposent les observations indépendantes au sein de chaque groupe "
          "et ne corrigent PAS pour l'autocorrélation intra-bloc (cf. §5.4 de l'article).")


def write_report(path, folder, rows, overhead_rows):
    lines = [f"# Performance de handshake — {folder}\n"]
    lines.append(f"**{len(rows)} combinaison(s) SIG_ALG/KEM analysée(s)**\n")

    lines.append("## Statistiques détaillées\n")
    lines.append("| Niveau | SIG_ALG | KEM | Classe | N | Blocs | Succès% | Moyenne (ms) | "
                  "IC95% | Méthode IC | Médiane (ms) | p95 (ms) | p99 (ms) |")
    lines.append("|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    for r in sorted(rows, key=lambda r: (r["security_level"], r["kem_class"], r["sig_alg"], r["kem"])):
        ci = f"[{r['ci95_low_ms']}, {r['ci95_high_ms']}]" if r["ci95_low_ms"] != "NA" else "NA"
        method = r.get("ci95_method", "NA")
        lines.append(f"| {r['security_level']} | {r['sig_alg']} | {r['kem']} | {r['kem_class']} | "
                      f"{r['n_total']} | {r.get('n_blocks_pooled','?')} | {r['success_rate_pct']} | {r['mean_ms']} | {ci} | {method} | "
                      f"{r['median_ms']} | {r['p95_ms']} | {r['p99_ms']} |")

    if overhead_rows:
        lines.append("\n## Surcoût vs baseline classique (même niveau de sécurité)\n")
        lines.append("| Niveau | SIG_ALG | KEM | Classe | Moyenne (ms) | Baseline classique (ms) | Surcoût (%) |")
        lines.append("|---|---|---|---|---|---|---|")
        for r in sorted(overhead_rows, key=lambda r: (r["security_level"], r["kem_class"], r["kem"])):
            lines.append(f"| {r['security_level']} | {r['sig_alg']} | {r['kem']} | {r['kem_class']} | "
                          f"{r['mean_ms']} | {r['baseline_classique_mean_ms']} | {r['overhead_pct']} |")

    lines.append("\n## Note méthodologique\n")
    lines.append("Intervalle de confiance à 95% calculé par **bootstrap de blocs entiers** "
                  "(5000 rééchantillonnages, respectant la corrélation intra-bloc documentée "
                  "dans l'article, rho1=0.563) pour toute combinaison collectée en plusieurs "
                  "blocs indépendants ; repli sur l'approximation normale (z=1.96) pour les "
                  "combinaisons encore sur un seul bloc, avec la colonne 'Méthode IC' indiquant "
                  "explicitement laquelle a été utilisée ligne par ligne. Le surcoût (%) de "
                  "chaque combinaison est calculé par rapport à la MOYENNE des combinaisons "
                  "classiques du même niveau de sécurité NIST (pas un unique point de "
                  "référence arbitraire), pour lisser le bruit de mesure du baseline "
                  "lui-même. Des tests de significativité formels (Mann-Whitney U, Cliff's "
                  "delta, correction FDR de Benjamini-Hochberg) sont générés systématiquement "
                  "pour chaque combinaison PQ contre le baseline classique pooléé du même "
                  "niveau -- voir significance_tests_auto.csv dans ce même dossier.")

    Path(path).write_text("\n".join(lines))


def write_figures(out_dir, rows, overhead_rows):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("  [i] matplotlib non installé — figures non générées "
              "(pip install matplotlib --break-system-packages pour les activer).")
        return

    # ── Figure 1 : boxplot des latences (nécessite les données brutes,
    #    pas juste les stats agrégées — reconstruit une distribution
    #    synthétique n'est pas fait ici par souci d'exactitude : on saute
    #    silencieusement si les CSV bruts ne sont plus accessibles à ce stade)
    plotted = [r for r in rows if r["mean_ms"] != "NA"]
    if plotted:
        plotted.sort(key=lambda r: (r["security_level"], r["kem_class"]))
        labels = [f"{r['sig_alg']}\n{r['kem']}" for r in plotted]
        means = [r["mean_ms"] for r in plotted]
        errs = [r["mean_ms"] - r["ci95_low_ms"] if r["ci95_low_ms"] != "NA" else 0 for r in plotted]
        colors = {"classique": "#4C72B0", "hybride": "#DD8452", "pq_pur": "#55A868"}
        bar_colors = [colors.get(r["kem_class"], "gray") for r in plotted]

        fig, ax = plt.subplots(figsize=(max(8, len(plotted) * 0.5), 5))
        ax.bar(range(len(plotted)), means, yerr=errs, color=bar_colors, capsize=3)
        ax.set_xticks(range(len(plotted)))
        ax.set_xticklabels(labels, rotation=90, fontsize=7)
        ax.set_ylabel("Latence moyenne de handshake (ms) ± IC95%")
        ax.set_title("Latence de handshake par combinaison SIG_ALG/KEM")
        from matplotlib.patches import Patch
        ax.legend(handles=[Patch(color=c, label=k) for k, c in colors.items()])
        fig.tight_layout()
        fig.savefig(out_dir / "latency_boxplot.png", dpi=150)
        plt.close(fig)

    # ── Figure 2 : surcoût moyen par niveau × classe ──────────────────────
    if overhead_rows:
        groups = defaultdict(list)
        for r in overhead_rows:
            if r["overhead_pct"] != "NA" and r["kem_class"] != "classique":
                groups[(r["security_level"], r["kem_class"])].append(r["overhead_pct"])
        if groups:
            levels = sorted(set(k[0] for k in groups))
            classes = sorted(set(k[1] for k in groups))
            fig, ax = plt.subplots(figsize=(7, 5))
            width = 0.35
            x = range(len(levels))
            for i, cls in enumerate(classes):
                vals = [statistics.mean(groups[(lvl, cls)]) if (lvl, cls) in groups else 0 for lvl in levels]
                ax.bar([xi + i * width for xi in x], vals, width, label=cls)
            ax.set_xticks([xi + width / 2 for xi in x])
            ax.set_xticklabels(levels)
            ax.set_ylabel("Surcoût moyen vs classique (%)")
            ax.set_title("Surcoût de latence par niveau de sécurité et classe KEM")
            ax.legend()
            fig.tight_layout()
            fig.savefig(out_dir / "overhead_by_class.png", dpi=150)
            plt.close(fig)

    print(f"  [OK] Figures écrites dans {out_dir}/")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path", type=Path, help="Dossier à analyser, ou racine si --all")
    ap.add_argument("--all", action="store_true",
                     help="Parcourt récursivement et analyse tous les dossiers contenant un csv/")
    args = ap.parse_args()

    if args.all:
        targets = sorted({p.parent for p in args.path.rglob("csv") if (p.parent / "handshake_logs").is_dir()})
        if not targets:
            print(f"Aucun dossier avec csv/+handshake_logs/ trouvé sous {args.path}")
            return
        print(f"{len(targets)} dossier(s) à analyser sous {args.path}\n")
        for t in targets:
            analyze_folder(t)
    else:
        analyze_folder(args.path)


if __name__ == "__main__":
    main()
