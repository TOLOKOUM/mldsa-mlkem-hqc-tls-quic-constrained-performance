"""
plot_global_sig_comparison.py
===============================
Figure de synthèse GLOBALE : delta de latence dû au choix de SIGNATURE
(classique vs PQ), à KEM constant -- isole l'effet signature de l'effet KEM
(déjà traité dans plot_global_kem_comparison.py), sous réseau IDÉAL.

MÉTHODE : pour chaque niveau de sécurité, chaque KEM exact (ex: P-256,
x25519_hqc128...) existe avec les DEUX signatures (classique et PQ). On
calcule le ratio mean_ms(PQ-sig) / mean_ms(classique-sig) pour CE MÊME KEM,
puis on agrège ces ratios appariés par famille de KEM. C'est un appariement
strict (paired comparison), pas une moyenne brute par sig_family qui
mélangerait des KEM différents -- ça isole proprement l'effet signature.

USAGE (depuis la racine du dépôt) :
    python3 plot_global_sig_comparison.py

SOURCE : captures/{tls,quic}/single/none/analyse/handshake_stats.csv
SORTIE : plots_global/sig_family_latency_delta_by_level.pdf (+ .png)
"""

import sys
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

sys.path.insert(0, str(Path(__file__).resolve().parent))
from plot_style import (
    KEM_FAMILY_COLORS, KEM_FAMILY_ORDER, classify_kem_family,
    SECURITY_LEVEL_ORDER, PROTOCOL_LABELS, style_axes, save_figure,
    kem_family_legend_handles,
)

PROTOCOLS = ["tls", "quic"]
AUTH_MODE = "single"
SCENARIO_DIR = "none"


def load_stats(protocol: str):
    path = Path("captures") / protocol / AUTH_MODE / SCENARIO_DIR / "analyse" / "handshake_stats.csv"
    if not path.exists():
        print(f"  [SKIP] {path} introuvable")
        return None
    df = pd.read_csv(path)
    required = {"security_level", "sig_alg", "sig_family", "kem", "kem_class", "mean_ms"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"{path} : colonnes manquantes {missing}")
    return df


def paired_ratios_by_family(df: pd.DataFrame, level: str):
    """Retourne {kem_family: [ratios PQ/classique appariés par KEM]} pour un niveau donné."""
    sub = df[df["security_level"] == level]
    classical = sub[sub["sig_family"] == "classique"].set_index("kem")
    pq = sub[sub["sig_family"] == "pq"].set_index("kem")
    common = classical.index.intersection(pq.index)

    missing_classical = set(pq.index) - set(classical.index)
    missing_pq = set(classical.index) - set(pq.index)
    if missing_classical or missing_pq:
        print(f"    [ATTENTION] niveau {level} : KEM non apparié(s) -- "
              f"seulement côté PQ: {missing_classical or '-'}, "
              f"seulement côté classique: {missing_pq or '-'} (ignorés pour cette figure)")

    buckets = {fam: [] for fam in KEM_FAMILY_ORDER}
    for kem in common:
        ratio = pq.loc[kem, "mean_ms"] / classical.loc[kem, "mean_ms"]
        fam = classify_kem_family(classical.loc[kem, "kem_class"], kem)
        buckets[fam].append(ratio)
    return buckets


def draw_panel(ax, df: pd.DataFrame):
    levels = [lv for lv in SECURITY_LEVEL_ORDER if (df["security_level"] == lv).any()]
    n_fam = len(KEM_FAMILY_ORDER)
    width = 0.8 / n_fam
    x_base = np.arange(len(levels))

    per_level_buckets = {lv: paired_ratios_by_family(df, lv) for lv in levels}

    for i, fam in enumerate(KEM_FAMILY_ORDER):
        offset = (i - (n_fam - 1) / 2) * width
        means, los, his = [], [], []
        for lv in levels:
            ratios = np.array(per_level_buckets[lv][fam])
            if ratios.size == 0:
                means.append(np.nan); los.append(np.nan); his.append(np.nan)
                continue
            means.append(ratios.mean())
            los.append(ratios.min())
            his.append(ratios.max())
        means, los, his = np.array(means), np.array(los), np.array(his)
        yerr = np.abs(np.vstack([means - los, his - means]))
        ax.bar(x_base + offset, means, width=width * 0.92, color=KEM_FAMILY_COLORS[fam],
               edgecolor="#444444", linewidth=0.4, zorder=3)
        ax.errorbar(x_base + offset, means, yerr=yerr, fmt="none",
                     ecolor="#222222", elinewidth=0.7, capsize=2, zorder=4)

    ax.axhline(1.0, color="#555555", linewidth=0.9, linestyle="--", zorder=2)
    ax.set_yscale("log")
    ax.set_xticks(x_base)
    ax.set_xticklabels(levels)
    style_axes(ax, grid_axis="y")


def main():
    fig, axes = plt.subplots(1, len(PROTOCOLS), figsize=(3.6 * len(PROTOCOLS), 3.4), sharey=True)

    any_data = False
    for ax, protocol in zip(axes, PROTOCOLS):
        df = load_stats(protocol)
        if df is None:
            ax.text(0.5, 0.5, "No data", ha="center", va="center", transform=ax.transAxes)
            continue
        any_data = True
        draw_panel(ax, df)
        ax.set_title(PROTOCOL_LABELS[protocol], fontsize=9)

    if not any_data:
        print("Aucune donnée trouvée, figure non générée.")
        return

    axes[0].set_ylabel("Latency ratio: PQ vs classical signature\n(same KEM, log scale, ideal network)")

    handles = kem_family_legend_handles(KEM_FAMILY_ORDER)
    fig.legend(handles=handles, loc="lower center", ncol=len(handles) if len(handles) <= 5 else 3,
               frameon=False, fontsize=7.5, bbox_to_anchor=(0.5, -0.1))

    fig.tight_layout()
    save_figure(fig, Path("plots_global"), "sig_family_latency_delta_by_level")
    plt.close(fig)


if __name__ == "__main__":
    main()
