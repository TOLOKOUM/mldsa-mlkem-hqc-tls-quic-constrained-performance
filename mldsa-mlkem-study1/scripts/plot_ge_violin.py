#!/usr/bin/env python3
"""
plot_ge_violins.py
==================
Génère 6 figures violin pour le modèle de Gilbert-Elliott (GE) :
  - 3 figures STABLE  : Level 1 / Level 3 / Level 5
  - 3 figures UNSTABLE : Level 1 / Level 3 / Level 5

"""

import os
import argparse
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from scipy import stats
import warnings
warnings.filterwarnings('ignore')

# ============================================================================
# PALETTE & STYLE
# ============================================================================
COLORS = {
    "classical": "#E69F00",   # Orange — signatures classiques
    "pq":        "#56B4E9",   # Bleu  — ML-DSA
}

BG_STABLE   = "#F0FFF0"   # Vert très pâle
BG_UNSTABLE = "#FFF0F0"   # Rouge très pâle

plt.rcParams.update({
    'font.family':       'serif',
    'font.serif':        ['Times New Roman', 'DejaVu Serif'],
    'font.size':         11,
    'axes.titlesize':    11,
    'axes.labelsize':    10,
    'xtick.labelsize':   9,
    'ytick.labelsize':   9,
    'legend.fontsize':   9,
    'figure.dpi':        300,
    'figure.facecolor':  'white',
    'axes.grid':         True,
    'grid.alpha':        0.25,
    'grid.linestyle':    ':',
    'axes.spines.top':   False,
    'axes.spines.right': False,
    'savefig.dpi':       300,
    'savefig.bbox':      'tight',
})

# ============================================================================
# CONSTANTES
# ============================================================================
SIG_PAIRS = [
    ("ed25519",   "mldsa44", 1, "NIST Level I (128-bit)"),
    ("secp384r1", "mldsa65", 3, "NIST Level III (192-bit)"),
    ("secp521r1", "mldsa87", 5, "NIST Level V (256-bit)"),
]

KEMS_BY_LEVEL = {
    1: ["P-256", "x25519", "p256_mlkem512", "x25519_mlkem512", "mlkem512"],
    3: ["P-384", "x448", "p384_mlkem768", "x448_mlkem768", "mlkem768"],
    5: ["P-521", "p521_mlkem1024", "mlkem1024"],
}

KEM_DISPLAY = {
    "P-256":          "P-256",
    "x25519":         "X25519",
    "P-384":          "P-384",
    "x448":           "X448",
    "P-521":          "P-521",
    "mlkem512":       "ML-KEM-512",
    "mlkem768":       "ML-KEM-768",
    "mlkem1024":      "ML-KEM-1024",
    "p256_mlkem512":  "P-256\n+ML-KEM",
    "x25519_mlkem512":"X25519\n+ML-KEM",
    "p384_mlkem768":  "P-384\n+ML-KEM",
    "x448_mlkem768":  "X448\n+ML-KEM",
    "p521_mlkem1024": "P-521\n+ML-KEM",
}

PURE_PQ_KEM = {1: "mlkem512", 3: "mlkem768", 5: "mlkem1024"}

GE_PARAMS = {
    "stable":   "(p_g=0.10, p_b=0.50, ε_h=0.70, ε_k=0.10)",
    "unstable": "(p_g=0.20, p_b=0.40, ε_h=0.90, ε_k=0.20)"
}

GE_LABELS = {
    "stable":   "Gilbert-Elliott — Stable",
    "unstable": "Gilbert-Elliott — Unstable"
}


# ============================================================================
# CHARGEMENT
# ============================================================================
def load_csv(path):
    if not os.path.isfile(path):
        return None
    try:
        df = pd.read_csv(path)
        return {col: df[col].dropna().astype(float).values for col in df.columns}
    except Exception as e:
        return None


def load_ge_data(data_dir, condition):
    data = {}
    for proto in ["TLS", "QUIC"]:
        data[proto] = {}
        for sig_c, sig_pq, _, _ in SIG_PAIRS:
            for sig in [sig_c, sig_pq]:
                fname = f"{sig}_{proto.lower()}_ge_{condition}.csv"
                path = os.path.join(data_dir, proto, "csv", "ge", fname)
                result = load_csv(path)
                if result is not None:
                    data[proto][sig] = result
    return data


def load_ideal_data(data_dir):
    ideal = {}
    for proto in ["TLS", "QUIC"]:
        ideal[proto] = {}
        for sig_c, sig_pq, _, _ in SIG_PAIRS:
            for sig in [sig_c, sig_pq]:
                fname = f"{sig}_{proto.lower()}_ideal.csv"
                path = os.path.join(data_dir, proto, "csv", fname)
                result = load_csv(path)
                if result is not None:
                    ideal[proto][sig] = result
    return ideal


# ============================================================================
# STATS
# ============================================================================
def mann_whitney_delta(arr_c, arr_pq):
    if len(arr_c) == 0 or len(arr_pq) == 0:
        return np.nan, np.nan
    _, p = stats.mannwhitneyu(arr_c, arr_pq, alternative='two-sided')
    med_c = np.median(arr_c)
    med_pq = np.median(arr_pq)
    if med_c == 0:
        return np.nan, p
    delta = ((med_pq - med_c) / med_c) * 100
    return delta, p


def pval_stars(p):
    if np.isnan(p):
        return "n.s."
    if p < 0.001:
        return "***"
    if p < 0.01:
        return "**"
    if p < 0.05:
        return "*"
    return "n.s."


# ============================================================================
# FIGURE
# ============================================================================
def plot_ge_violin(data_ge, data_ideal, level, sig_c, sig_pq,
                   level_title, condition, out_dir):
    
    kems = KEMS_BY_LEVEL[level]
    pure_kem = PURE_PQ_KEM[level]
    bg_color = BG_STABLE if condition == "stable" else BG_UNSTABLE
    cond_color = "#2d6a2d" if condition == "stable" else "#8b1a1a"
    
    fig, axes = plt.subplots(1, 2, figsize=(13, 5.5))
    fig.patch.set_facecolor('white')

    for col, proto in enumerate(["TLS", "QUIC"]):
        ax = axes[col]
        ax.set_facecolor(bg_color)

        if sig_c not in data_ge[proto] or sig_pq not in data_ge[proto]:
            ax.text(0.5, 0.5, "Missing data", ha='center', va='center', fontsize=12)
            ax.set_title(proto, fontsize=12, fontweight='bold')
            continue

        positions_c, positions_pq = [], []
        vals_c, vals_pq = [], []
        tick_positions, tick_labels = [], []
        x = 1

        for kem in kems:
            disp = KEM_DISPLAY.get(kem, kem)
            if kem not in data_ge[proto][sig_c] or kem not in data_ge[proto][sig_pq]:
                continue

            arr_c = data_ge[proto][sig_c][kem]
            arr_pq = data_ge[proto][sig_pq][kem]
            cap = np.percentile(np.concatenate([arr_c, arr_pq]), 99)
            vals_c.append(np.clip(arr_c, 0, cap))
            vals_pq.append(np.clip(arr_pq, 0, cap))
            positions_c.append(x)
            positions_pq.append(x + 1)
            tick_positions.append(x + 0.5)
            tick_labels.append(disp)
            x += 3.5

        if not vals_c:
            ax.text(0.5, 0.5, "No common KEM", ha='center', va='center')
            continue

        # Violins classiques
        vp_c = ax.violinplot(vals_c, positions=positions_c, showmedians=True, widths=0.8)
        for pc in vp_c['bodies']:
            pc.set_facecolor(COLORS["classical"])
            pc.set_alpha(0.72)
            pc.set_edgecolor('white')
        for part in ['cmedians', 'cmins', 'cmaxes', 'cbars']:
            if part in vp_c:
                vp_c[part].set_color(COLORS["classical"])
                vp_c[part].set_linewidth(1.3)

        # Violins ML-DSA
        vp_pq = ax.violinplot(vals_pq, positions=positions_pq, showmedians=True, widths=0.8)
        for pc in vp_pq['bodies']:
            pc.set_facecolor(COLORS["pq"])
            pc.set_alpha(0.72)
            pc.set_edgecolor('white')
        for part in ['cmedians', 'cmins', 'cmaxes', 'cbars']:
            if part in vp_pq:
                vp_pq[part].set_color(COLORS["pq"])
                vp_pq[part].set_linewidth(1.3)

        # Ligne idéale
        ideal_median = None
        if proto in data_ideal and sig_c in data_ideal[proto] and pure_kem in data_ideal[proto][sig_c]:
            ideal_median = np.median(data_ideal[proto][sig_c][pure_kem])
            ax.axhline(ideal_median, color='#555555', lw=1.2, ls='--', alpha=0.7)

        # Annotation stats sur le KEM pur PQ
        if pure_kem in kems:
            try:
                idx_pure = kems.index(pure_kem)
                if idx_pure < len(vals_c):
                    delta, pval = mann_whitney_delta(vals_c[idx_pure], vals_pq[idx_pure])
                    stars = pval_stars(pval)
                    ymax = max(np.max(vals_c[idx_pure]), np.max(vals_pq[idx_pure]))
                    xcenter = (positions_c[idx_pure] + positions_pq[idx_pure]) / 2
                    
                    if not np.isnan(delta):
                        annotation = f"Δ = {delta:+.1f}%\n{stars}"
                    else:
                        annotation = stars
                    
                    ax.annotate(annotation,
                                xy=(xcenter, ymax),
                                xytext=(xcenter, ymax * 1.08),
                                ha='center', va='bottom',
                                fontsize=7.5, fontweight='bold',
                                color='#CC6677' if delta > 0 else '#44AA77',
                                bbox=dict(boxstyle='round,pad=0.25',
                                          fc='white', ec='#888888', alpha=0.85))
            except (ValueError, IndexError):
                pass

        # Axes
        ax.set_xticks(tick_positions)
        ax.set_xticklabels(tick_labels, rotation=30, ha='right', fontsize=7)
        ax.set_ylabel("Handshake time (ms)", fontsize=10)
        ax.set_title(proto, fontsize=12, fontweight='bold')
        ax.grid(True, alpha=0.2, linestyle=':')

        # Légende
        legend_elements = [
            mpatches.Patch(color=COLORS["classical"], alpha=0.72, label=f"{sig_c} (classical)"),
            mpatches.Patch(color=COLORS["pq"], alpha=0.72, label=f"{sig_pq} (ML-DSA)"),
        ]
        if ideal_median is not None:
            legend_elements.append(plt.Line2D([0], [0], color='#555555', lw=1.2, ls='--',
                                              label=f"Ideal median: {ideal_median:.1f} ms"))
        ax.legend(handles=legend_elements, loc='upper left', framealpha=0.92, fontsize=8)

    # Titre
    #fig.suptitle(
     #   f"{GE_LABELS[condition]} — {level_title}\n"
      #  f"Parameters: {GE_PARAMS[condition]} | Handshake time distributions (500 runs)",
       # fontsize=10, fontweight='bold', color=cond_color, y=0.98
    #)

    plt.tight_layout(rect=[0, 0, 1, 0.95])

    # Sauvegarde dans le bon dossier
    level_tag = {1: "L1", 3: "L3", 5: "L5"}[level]
    basename = f"fig_GE_{condition}_{level_tag}"
    pdf_path = os.path.join(out_dir, basename + ".pdf")
    png_path = os.path.join(out_dir, basename + ".png")
    plt.savefig(pdf_path, format='pdf')
    plt.savefig(png_path, format='png', dpi=150)
    plt.close()
    print(f"  ✅  {basename}.pdf  +  .png")


# ============================================================================
# MAIN
# ============================================================================
def main():
    parser = argparse.ArgumentParser(
        description="Violin plots GE (stable + unstable) — Gilbert-Elliott model"
    )
    parser.add_argument(
        "--data-dir", required=True,
        help="Project root, e.g.: ~/Documents/TLS-QUIC/'5- pq-signatures'"
    )
    parser.add_argument(
        "--out-dir", default=None,
        help="Output directory (default: <data-dir>/plots/ge_violin)"
    )
    args = parser.parse_args()

    data_dir = os.path.expanduser(args.data_dir)
    out_dir = args.out_dir or os.path.join(data_dir, "plots", "ge_violin")
    os.makedirs(out_dir, exist_ok=True)

    print("\n" + "=" * 60)
    print("  VIOLIN PLOTS — GILBERT-ELLIOTT (GE) MODEL")
    print("=" * 60)
    print(f"  Data dir   : {data_dir}")
    print(f"  Output dir : {out_dir}")
    print("=" * 60 + "\n")

    # Chargement
    print("Loading GE and ideal data...")
    data_stable = load_ge_data(data_dir, "stable")
    data_unstable = load_ge_data(data_dir, "unstable")
    data_ideal = load_ideal_data(data_dir)
    print("✓ Data loaded\n")

    # Génération
    for condition, data_ge in [("stable", data_stable), ("unstable", data_unstable)]:
        print(f"── Condition: {condition.upper()} ──")
        for sig_c, sig_pq, level, level_title in SIG_PAIRS:
            plot_ge_violin(data_ge, data_ideal, level, sig_c, sig_pq,
                          level_title, condition, out_dir)
        print()

    print("=" * 60)
    print(f"✅ 6 FIGURES GENERATED (PDF + PNG)")
    print(f"   Output: {out_dir}")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
