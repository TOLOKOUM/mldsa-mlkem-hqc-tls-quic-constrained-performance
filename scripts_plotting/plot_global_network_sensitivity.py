"""
plot_global_network_sensitivity.py
=====================================
Figure de synthèse GLOBALE : sensibilité de chaque famille de KEM à la
dégradation des conditions réseau, par niveau de sécurité et par protocole.

MÉTHODE : pour chaque (protocole, niveau, famille de KEM), on calcule la
moyenne de mean_ms sur toutes les combinaisons (sig_alg, kem) de cette
famille à ce niveau, PUIS le ratio de cette moyenne par rapport à la même
quantité sous le scénario "none" (réseau idéal). Chaque courbe part donc de
1.0 sous "Idéal" par construction -- sa pente montre directement la
sensibilité relative de cette famille à la dégradation réseau, indépendamment
de son coût absolu (déjà traité dans les figures précédentes).

USAGE (depuis la racine du dépôt) :
    python3 plot_global_network_sensitivity.py

SOURCE : captures/{tls,quic}/single/<scénario>/analyse/handshake_stats.csv
    pour chacun des 5 scénarios (auth_mode=single uniquement, pour une
    comparabilité directe TLS/QUIC -- mutual n'existe pas côté QUIC).

SORTIE : plots_global/network_sensitivity_by_level.pdf (+ .png)
"""

import sys
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

sys.path.insert(0, str(Path(__file__).resolve().parent))
from plot_style import (
    KEM_FAMILY_COLORS, KEM_FAMILY_ORDER, KEM_FAMILY_LABELS, classify_kem_family,
    SECURITY_LEVEL_ORDER, SCENARIO_ORDER, SCENARIO_LABELS, PROTOCOL_LABELS,
    style_axes, save_figure, kem_family_legend_handles,
)

PROTOCOLS = ["tls", "quic"]
AUTH_MODE = "single"
BASELINE_SCENARIO = "none"


def load_all_stats():
    """Charge handshake_stats.csv pour tous les (protocole, scénario)
    disponibles, agrège par (protocole, scénario, niveau, famille de KEM).
    Retourne un DataFrame long avec colonnes:
        protocol, scenario_dir, security_level, kem_family, mean_of_means, min_, max_
    """
    records = []
    for protocol in PROTOCOLS:
        for scenario_dir in SCENARIO_ORDER:
            path = Path("captures") / protocol / AUTH_MODE / scenario_dir / "analyse" / "handshake_stats.csv"
            if not path.exists():
                print(f"  [SKIP] {path} introuvable")
                continue
            df = pd.read_csv(path)
            required = {"security_level", "kem", "kem_class", "mean_ms"}
            missing = required - set(df.columns)
            if missing:
                raise ValueError(f"{path} : colonnes manquantes {missing}")
            df["kem_family"] = [classify_kem_family(kc, k) for kc, k in zip(df["kem_class"], df["kem"])]
            grouped = (
                df.groupby(["security_level", "kem_family"])["mean_ms"]
                .agg(["mean", "min", "max"])
                .reset_index()
            )
            grouped["protocol"] = protocol
            grouped["scenario_dir"] = scenario_dir
            records.append(grouped)

    if not records:
        return None
    return pd.concat(records, ignore_index=True)


def compute_ratios(big: pd.DataFrame) -> pd.DataFrame:
    """Ajoute ratio_mean/ratio_min/ratio_max par rapport au scénario baseline,
    pour chaque (protocol, security_level, kem_family) séparément."""
    out = []
    keys = ["protocol", "security_level", "kem_family"]
    for key_vals, group in big.groupby(keys):
        baseline_rows = group[group["scenario_dir"] == BASELINE_SCENARIO]
        if baseline_rows.empty:
            print(f"    [ATTENTION] pas de scénario baseline '{BASELINE_SCENARIO}' pour "
                  f"{dict(zip(keys, key_vals))} -- ignoré pour cette combinaison.")
            continue
        baseline_mean = baseline_rows["mean"].iloc[0]
        group = group.copy()
        group["ratio_mean"] = group["mean"] / baseline_mean
        group["ratio_min"] = group["min"] / baseline_mean
        group["ratio_max"] = group["max"] / baseline_mean
        out.append(group)
    return pd.concat(out, ignore_index=True) if out else pd.DataFrame()


def draw_panel(ax, sub: pd.DataFrame):
    scenarios_present = [s for s in SCENARIO_ORDER if s in sub["scenario_dir"].unique()]
    x = np.arange(len(scenarios_present))

    for fam in KEM_FAMILY_ORDER:
        fam_data = sub[sub["kem_family"] == fam].set_index("scenario_dir")
        if fam_data.empty:
            continue
        y = np.array([fam_data.loc[s, "ratio_mean"] if s in fam_data.index else np.nan
                      for s in scenarios_present])
        y_lo = np.array([fam_data.loc[s, "ratio_min"] if s in fam_data.index else np.nan
                          for s in scenarios_present])
        y_hi = np.array([fam_data.loc[s, "ratio_max"] if s in fam_data.index else np.nan
                          for s in scenarios_present])
        color = KEM_FAMILY_COLORS[fam]
        ax.plot(x, y, marker="o", markersize=3, color=color, linewidth=1.3, zorder=3)
        ax.fill_between(x, y_lo, y_hi, color=color, alpha=0.15, zorder=2, linewidth=0)

    ax.axhline(1.0, color="#555555", linewidth=0.8, linestyle="--", zorder=1)
    ax.set_yscale("log")
    ax.set_xticks(x)
    ax.set_xticklabels([SCENARIO_LABELS.get(s, s) for s in scenarios_present],
                        rotation=30, ha="right", fontsize=6.5)
    style_axes(ax, grid_axis="y")


def main():
    big = load_all_stats()
    if big is None:
        print("Aucune donnée trouvée.")
        return
    ratios = compute_ratios(big)
    if ratios.empty:
        print("Aucun ratio calculable (baseline manquante partout).")
        return

    levels_present = [lv for lv in SECURITY_LEVEL_ORDER if lv in ratios["security_level"].unique()]
    n_cols = len(levels_present)
    n_rows = len(PROTOCOLS)

    fig, axes = plt.subplots(n_rows, n_cols, figsize=(2.5 * n_cols, 2.6 * n_rows), squeeze=False)

    panel_letters = "abcdefghijkl"
    letter_idx = 0
    for row_i, protocol in enumerate(PROTOCOLS):
        for col_i, level in enumerate(levels_present):
            ax = axes[row_i][col_i]
            sub = ratios[(ratios["protocol"] == protocol) & (ratios["security_level"] == level)]
            letter = panel_letters[letter_idx]
            letter_idx += 1
            if sub.empty:
                ax.text(0.5, 0.5, "No data", ha="center", va="center",
                         transform=ax.transAxes, fontsize=7, color="#999999")
                continue
            draw_panel(ax, sub)
            ax.text(0.02, 1.08, f"({letter})", transform=ax.transAxes,
                     fontsize=8.5, fontweight="bold", va="bottom")
            ax.set_title(f"{level} \u2013 {PROTOCOL_LABELS[protocol]}", fontsize=8, pad=12)
            if col_i == 0:
                ax.set_ylabel("Latency ratio\nvs ideal network", fontsize=7.5)

    handles = kem_family_legend_handles(KEM_FAMILY_ORDER)
    fig.legend(handles=handles, loc="lower center", ncol=len(handles),
               frameon=False, fontsize=7.2, bbox_to_anchor=(0.5, -0.06))

    fig.tight_layout(rect=[0, 0.06, 1, 1])
    save_figure(fig, Path("plots_global"), "network_sensitivity_by_level")
    plt.close(fig)


if __name__ == "__main__":
    main()
