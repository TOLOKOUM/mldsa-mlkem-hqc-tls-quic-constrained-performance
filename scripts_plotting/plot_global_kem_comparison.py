"""
plot_global_kem_comparison.py
===============================
Figure de synthèse GLOBALE : overhead relatif ML-KEM vs HQC (pur et hybride)
par niveau de sécurité, sous réseau IDÉAL uniquement -- isole le coût crypto
pur sans le confondre avec l'effet du réseau (qui fait l'objet d'une autre
figure globale dédiée à la sensibilité réseau).

USAGE (depuis la racine du dépôt) :
    python3 plot_global_kem_comparison.py

SOURCE : captures/{tls,quic}/single/none/analyse/handshake_overhead.csv
    (déjà calculé par ton pipeline d'analyse -- ce script ne recalcule
    aucune statistique, il agrège l'overhead déjà validé par KEM family).

SORTIE : plots_global/kem_family_overhead_by_level.pdf (+ .png)
    (à la racine du dépôt, PAS dans un sous-dossier de scénario, puisque
    cette figure agrège plusieurs niveaux dans une vue de synthèse).

MÉTRIQUE : ratio = mean_ms / baseline_classique_mean_ms (PAS un pourcentage)
    -- permet l'échelle log (un %-overhead peut être négatif, un ratio non),
    et se lit plus naturellement ("HQC coûte 12x plus cher" plutôt que
    "+1100%"). Ligne de référence à ratio=1 = coût classique.

    À chaque niveau, 2 signatures existent (classique + PQ) : la barre
    montre leur MOYENNE, et une barre d'erreur verticale montre l'étendue
    (min-max) entre les deux plutôt que de la masquer.
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
SCENARIO_DIR = "none"  # réseau idéal -- isole le coût crypto pur

# Familles non-classiques uniquement (le classique EST la référence, ratio=1)
NON_CLASSICAL_FAMILIES = ["mlkem_pure", "mlkem_hybrid", "hqc_pure", "hqc_hybrid"]


def load_overhead(protocol: str) -> pd.DataFrame:
    path = Path("captures") / protocol / AUTH_MODE / SCENARIO_DIR / "analyse" / "handshake_overhead.csv"
    if not path.exists():
        print(f"  [SKIP] {path} introuvable")
        return None
    df = pd.read_csv(path)
    required = {"security_level", "sig_alg", "kem", "kem_class", "mean_ms", "baseline_classique_mean_ms"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"{path} : colonnes manquantes {missing}")
    df["ratio"] = df["mean_ms"] / df["baseline_classique_mean_ms"]
    df["kem_family"] = [classify_kem_family(kc, k) for kc, k in zip(df["kem_class"], df["kem"])]
    return df


def draw_panel(ax, df: pd.DataFrame):
    levels = [lv for lv in SECURITY_LEVEL_ORDER if (df["security_level"] == lv).any()]
    n_fam = len(NON_CLASSICAL_FAMILIES)
    width = 0.8 / n_fam
    x_base = np.arange(len(levels))

    for i, fam in enumerate(NON_CLASSICAL_FAMILIES):
        offset = (i - (n_fam - 1) / 2) * width
        means, los, his = [], [], []
        for lv in levels:
            sub = df[(df["security_level"] == lv) & (df["kem_family"] == fam)]
            if sub.empty:
                means.append(np.nan); los.append(np.nan); his.append(np.nan)
                continue
            ratios = sub["ratio"].to_numpy()
            means.append(ratios.mean())
            los.append(ratios.min())
            his.append(ratios.max())
        means, los, his = np.array(means), np.array(los), np.array(his)
        yerr = np.vstack([means - los, his - means])
        yerr = np.abs(yerr)  # garde-fou : jamais d'erreur négative même en cas de NaN/arrondi
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
        df = load_overhead(protocol)
        if df is None:
            ax.text(0.5, 0.5, "No data", ha="center", va="center", transform=ax.transAxes)
            continue
        any_data = True
        draw_panel(ax, df)
        ax.set_title(PROTOCOL_LABELS[protocol], fontsize=9)

    if not any_data:
        print("Aucune donnée trouvée, figure non générée.")
        return

    axes[0].set_ylabel("Latency ratio vs classical baseline\n(log scale, ideal network)")

    handles = kem_family_legend_handles(NON_CLASSICAL_FAMILIES)
    fig.legend(handles=handles, loc="lower center", ncol=len(handles),
               frameon=False, fontsize=7.5, bbox_to_anchor=(0.5, -0.08))

    fig.tight_layout()
    save_figure(fig, Path("plots_global"), "kem_family_overhead_by_level")
    plt.close(fig)


if __name__ == "__main__":
    main()
