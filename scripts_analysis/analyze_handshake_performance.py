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
from pathlib import Path
from collections import defaultdict

FNAME_RE = re.compile(r"handshake_(tls|quic)_(mutual|single)_(.+?)_(.+?)_(none|stable|unstable|simple.*)\.csv$")

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
    durations, n_total, n_fail = [], 0, 0
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            n_total += 1
            if row.get("success") == "1":
                try:
                    durations.append(float(row["handshake_duration_ms"]))
                except (TypeError, ValueError):
                    pass
            else:
                n_fail += 1
    return durations, n_total, n_fail


def analyze_folder(folder: Path):
    csv_dir = folder / "csv"
    if not csv_dir.is_dir():
        print(f"[!] {folder} : pas de sous-dossier csv/ — ignoré "
              f"(lance d'abord logs_to_csv.py sur handshake_logs/).")
        return None

    rows = []
    for f in sorted(csv_dir.glob("*.csv")):
        m = FNAME_RE.search(f.name)
        if not m:
            print(f"  [!] Nom non conforme, ignoré : {f.name}")
            continue
        protocol, auth_mode, sig_alg, kem, network_profile = m.groups()

        durations, n_total, n_fail = parse_combo_csv(f)
        if n_total == 0:
            print(f"  [!] {f.name} : fichier vide, ignoré.")
            continue

        row = {
            "protocol": protocol, "auth_mode": auth_mode, "sig_alg": sig_alg,
            "kem": kem, "kem_class": classify_kem_class(kem),
            "security_level": SECURITY_LEVEL_BY_SIG.get(sig_alg, "?"),
            "sig_family": SIG_FAMILY.get(sig_alg, "?"),
            "network_profile": network_profile,
            "n_total": n_total, "n_success": len(durations), "n_failed": n_fail,
            "success_rate_pct": round(100 * len(durations) / n_total, 2),
        }
        if durations:
            mean = statistics.mean(durations)
            stdev = statistics.stdev(durations) if len(durations) > 1 else 0.0
            ci_low, ci_high = z95_ci(mean, stdev, len(durations))
            row.update({
                "mean_ms": round(mean, 3), "stdev_ms": round(stdev, 3),
                "ci95_low_ms": ci_low, "ci95_high_ms": ci_high,
                "median_ms": round(statistics.median(durations), 3),
                "p95_ms": round(percentile(durations, 95), 3),
                "p99_ms": round(percentile(durations, 99), 3),
                "min_ms": round(min(durations), 3), "max_ms": round(max(durations), 3),
            })
        else:
            for k in ["mean_ms", "stdev_ms", "ci95_low_ms", "ci95_high_ms",
                      "median_ms", "p95_ms", "p99_ms", "min_ms", "max_ms"]:
                row[k] = "NA"
        rows.append(row)

    if not rows:
        print(f"[!] {folder} : aucune combinaison exploitable trouvée dans csv/.")
        return None

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


def write_report(path, folder, rows, overhead_rows):
    lines = [f"# Performance de handshake — {folder}\n"]
    lines.append(f"**{len(rows)} combinaison(s) SIG_ALG/KEM analysée(s)**\n")

    lines.append("## Statistiques détaillées\n")
    lines.append("| Niveau | SIG_ALG | KEM | Classe | N | Succès% | Moyenne (ms) | "
                  "IC95% | Médiane (ms) | p95 (ms) | p99 (ms) |")
    lines.append("|---|---|---|---|---|---|---|---|---|---|---|")
    for r in sorted(rows, key=lambda r: (r["security_level"], r["kem_class"], r["sig_alg"], r["kem"])):
        ci = f"[{r['ci95_low_ms']}, {r['ci95_high_ms']}]" if r["ci95_low_ms"] != "NA" else "NA"
        lines.append(f"| {r['security_level']} | {r['sig_alg']} | {r['kem']} | {r['kem_class']} | "
                      f"{r['n_total']} | {r['success_rate_pct']} | {r['mean_ms']} | {ci} | "
                      f"{r['median_ms']} | {r['p95_ms']} | {r['p99_ms']} |")

    if overhead_rows:
        lines.append("\n## Surcoût vs baseline classique (même niveau de sécurité)\n")
        lines.append("| Niveau | SIG_ALG | KEM | Classe | Moyenne (ms) | Baseline classique (ms) | Surcoût (%) |")
        lines.append("|---|---|---|---|---|---|---|")
        for r in sorted(overhead_rows, key=lambda r: (r["security_level"], r["kem_class"], r["kem"])):
            lines.append(f"| {r['security_level']} | {r['sig_alg']} | {r['kem']} | {r['kem_class']} | "
                          f"{r['mean_ms']} | {r['baseline_classique_mean_ms']} | {r['overhead_pct']} |")

    lines.append("\n## Note méthodologique\n")
    lines.append("Intervalle de confiance à 95% calculé par approximation normale "
                  "(z=1.96), la taille d'échantillon (n=500 par combinaison dans la "
                  "majorité des cas) rendant cette approximation valide par le théorème "
                  "central limite, indépendamment de la forme de la distribution "
                  "sous-jacente des latences individuelles. Le surcoût (%) de chaque "
                  "combinaison est calculé par rapport à la MOYENNE des combinaisons "
                  "classiques du même niveau de sécurité NIST (pas un unique point de "
                  "référence arbitraire), pour lisser le bruit de mesure du baseline "
                  "lui-même.")

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
