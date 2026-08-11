"""
plot_traffic_size.py
=====================
Génère les figures de taille du trafic de handshake (barres empilées par
composant du message) à partir de results_traffic_size/traffic_size_summary.csv.

USAGE (depuis la racine du dépôt, à côté de results_traffic_size/) :

    python3 plot_traffic_size.py

STRUCTURE DE LA FIGURE (inspirée de Montenegro et al., Fig. 6, mais adaptée
car contrairement à eux la signature varie à chaque niveau dans ton étude) :

    Deux figures composites séparées :
        traffic_size_classical_sig.pdf  (grille 2x3 : lignes=TLS/QUIC, colonnes=L1/L3/L5)
        traffic_size_pq_sig.pdf         (même grille, signatures post-quantiques)

    Chaque panel : une barre empilée par configuration KEM (même ordre et
    même regroupement par famille que les figures de latence), empilement
    par composant du handshake dans l'ordre CHRONOLOGIQUE (ClientHello en
    bas -> NewSessionTicket en haut), dégradé violet séquentiel.

    Un segment supplémentaire hachuré "Other / transport overhead" = ce qui
    reste entre total_bytes (mesuré, inclut TCP/UDP/IP) et la somme des
    composants nommés (contenu des messages handshake uniquement) -- ce
    n'est PAS du bruit, c'est un résultat en soi (overhead de transport,
    notamment le padding minimum de 1200 octets des paquets QUIC Initial).

    Axe Y partagé PAR COLONNE (même niveau de sécurité) pour permettre une
    comparaison directe TLS vs QUIC à niveau égal ; PAS partagé entre
    colonnes (les niveaux ne sont pas censés être comparés sur un même axe).

SOURCE DES DONNÉES :
    Une seule capture par combinaison (pas de distribution statistique,
    cf. traffic_size_report.md : la taille d'un message handshake est
    déterministe pour une combinaison SIG_ALG/KEM donnée). Donc pas de
    barre d'erreur possible ici, contrairement aux figures de latence.
"""

import sys
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

sys.path.insert(0, str(Path(__file__).resolve().parent))
from plot_style import (
    KEM_FAMILY_COLORS, SIG_ALG_TO_LEVEL, SIG_ALG_TO_FAMILY,
    SECURITY_LEVEL_ORDER, PROTOCOL_LABELS, SIG_FAMILY_LABELS,
    format_kem_label_flat, sorted_kem_rows, style_axes, save_figure,
    TRAFFIC_COMPONENT_COLORS, TRAFFIC_RESIDUAL_STYLE, TRAFFIC_RESIDUAL_LABEL,
    available_traffic_components, fmt_kb,
)

SUMMARY_CSV = "results_traffic_size/traffic_size_summary.csv"
OUTPUT_DIR = "results_traffic_size/plots"

PROTOCOL_ROW_ORDER = ["tls", "quic"]
NEGATIVE_RESIDUAL_TOL_BYTES = 2  # tolérance avant d'avertir (arrondis, etc.)


def load_traffic_data() -> pd.DataFrame:
    path = Path(SUMMARY_CSV)
    if not path.exists():
        print(f"ERREUR : {path} introuvable. Lance ce script depuis la racine du dépôt.")
        sys.exit(1)

    df = pd.read_csv(path)

    required = {"protocol", "auth_mode", "sig_alg", "kem", "kem_class", "total_bytes"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"{path} : colonnes manquantes {missing}")

    unknown_sig = set(df["sig_alg"].unique()) - set(SIG_ALG_TO_LEVEL)
    if unknown_sig:
        raise ValueError(
            f"sig_alg inconnu(s) dans {path} : {unknown_sig}. "
            f"Ajoute-les dans SIG_ALG_TO_LEVEL / SIG_ALG_TO_FAMILY (plot_style.py)."
        )

    df["security_level"] = df["sig_alg"].map(SIG_ALG_TO_LEVEL)
    df["sig_family"] = df["sig_alg"].map(SIG_ALG_TO_FAMILY)
    return df


def draw_stacked_panel(ax, sub_df: pd.DataFrame, components: list):
    """Dessine les barres empilées pour un panel (un protocole x un niveau).
    Retourne le sommet de bar le plus haut du panel (pour le calcul du ylim
    partagé par colonne)."""
    sub_df = sorted_kem_rows(sub_df)

    x = np.arange(len(sub_df))
    bottoms = np.zeros(len(sub_df))
    comp_cols = [f"{c}_bytes" for c in components]
    values_kb = sub_df[comp_cols].fillna(0).to_numpy(dtype=float) / 1024.0

    for i, comp in enumerate(components):
        heights = values_kb[:, i]
        ax.bar(x, heights, bottom=bottoms, width=0.62,
               color=TRAFFIC_COMPONENT_COLORS[comp], edgecolor="#555555", linewidth=0.3,
               zorder=3)
        bottoms += heights

    total_kb = sub_df["total_bytes"].to_numpy(dtype=float) / 1024.0
    residual_kb = total_kb - bottoms
    if np.any(residual_kb < -NEGATIVE_RESIDUAL_TOL_BYTES / 1024.0):
        bad = sub_df.loc[residual_kb < -NEGATIVE_RESIDUAL_TOL_BYTES / 1024.0]
        print(f"    [ATTENTION] somme des composants > total_bytes pour : "
              f"{bad['kem'].tolist()} -- vérifier le pipeline de capture")
    residual_kb_clipped = np.clip(residual_kb, 0, None)
    ax.bar(x, residual_kb_clipped, bottom=bottoms, width=0.62,
           **TRAFFIC_RESIDUAL_STYLE, zorder=3)

    top_of_stack = bottoms + residual_kb_clipped
    for xi, top, total in zip(x, top_of_stack, total_kb):
        ax.text(xi, top, fmt_kb(total * 1024), ha="center", va="bottom",
                 fontsize=6.0, fontweight="bold")

    ax.set_xticks(x)
    ax.set_xticklabels([format_kem_label_flat(k) for k in sub_df["kem"]],
                        rotation=90, ha="center", va="top", fontsize=6.0)

    return float(top_of_stack.max()) if len(top_of_stack) else 0.0


def build_composite_figure(df: pd.DataFrame, sig_family: str, out_path_stem: str):
    fam_df = df[df["sig_family"] == sig_family]
    if fam_df.empty:
        print(f"  [SKIP] aucune donnée pour sig_family={sig_family}")
        return

    components = available_traffic_components(fam_df)
    print(f"  Composants détectés pour {sig_family}: {components}")

    levels_present = [lv for lv in SECURITY_LEVEL_ORDER if (fam_df["security_level"] == lv).any()]
    n_cols = len(levels_present)
    n_rows = len(PROTOCOL_ROW_ORDER)

    fig, axes = plt.subplots(n_rows, n_cols, figsize=(2.35 * n_cols, 2.5 * n_rows),
                              squeeze=False)

    panel_letters = "abcdefghijkl"
    letter_idx = 0
    col_tops = {c: 0.0 for c in range(n_cols)}
    col_axes = {c: [] for c in range(n_cols)}

    for row_i, protocol in enumerate(PROTOCOL_ROW_ORDER):
        for col_i, level in enumerate(levels_present):
            ax = axes[row_i][col_i]
            sub_df = fam_df[(fam_df["protocol"] == protocol) & (fam_df["security_level"] == level)]
            if sub_df.empty:
                ax.text(0.5, 0.5, "No data", ha="center", va="center",
                         transform=ax.transAxes, fontsize=7, color="#999999")
                letter_idx += 1
                continue

            top = draw_stacked_panel(ax, sub_df, components)
            col_tops[col_i] = max(col_tops[col_i], top)
            col_axes[col_i].append(ax)

            letter = panel_letters[letter_idx]
            letter_idx += 1
            sig_alg_here = sub_df["sig_alg"].iloc[0]
            ax.text(0.02, 1.06, f"({letter})", transform=ax.transAxes,
                     fontsize=8.5, fontweight="bold", va="bottom")
            ax.set_title(f"{level} \u2013 {PROTOCOL_LABELS[protocol]}\n{sig_alg_here}",
                         fontsize=7.3, pad=12)
            style_axes(ax, grid_axis="y")

            if col_i == 0:
                ax.set_ylabel("Handshake size (KB)", fontsize=7.5)

    for col_i in range(n_cols):
        top = col_tops[col_i] * 1.18
        for ax in col_axes[col_i]:
            ax.set_ylim(0, top)

    handles = [plt.Rectangle((0, 0), 1, 1, color=TRAFFIC_COMPONENT_COLORS[c])
               for c in components]
    labels = list(components)
    handles.append(plt.Rectangle((0, 0), 1, 1, **TRAFFIC_RESIDUAL_STYLE))
    labels.append(TRAFFIC_RESIDUAL_LABEL)

    fig.legend(handles=handles, labels=labels, loc="lower center",
               ncol=min(len(handles), 5), frameon=False, fontsize=6.8,
               bbox_to_anchor=(0.5, -0.06))

    fig.suptitle("")  # explicitement aucun titre incrusté
    fig.tight_layout(rect=[0, 0.08, 1, 1])

    out_dir = Path(OUTPUT_DIR)
    print(f"  -> {out_path_stem}")
    save_figure(fig, out_dir, out_path_stem)
    plt.close(fig)


def main():
    df = load_traffic_data()
    print(f"[INFO] {len(df)} lignes chargées depuis {SUMMARY_CSV}")
    print(f"[INFO] protocoles: {sorted(df['protocol'].unique())}, "
          f"auth_modes: {sorted(df['auth_mode'].unique())}")

    for sig_family, stem in [("classique", "traffic_size_classical_sig"),
                              ("pq", "traffic_size_pq_sig")]:
        print(f"[{sig_family}]")
        build_composite_figure(df, sig_family, stem)


if __name__ == "__main__":
    main()
