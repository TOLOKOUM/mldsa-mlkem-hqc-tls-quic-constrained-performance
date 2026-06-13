#!/usr/bin/env python3
"""
plot_hqc_final.py
=================
Génération complète des figures pour l'étude HQC (Phase 6)

Figures générées :
- Figure 1a/1b/1c : Violin plots par niveau de sécurité (3 PDF)
- Figure 2 : Heatmap des surcoûts ML-DSA (1 PDF)
- Figure 3 : Super-additivité (1 PDF)
- Figure 4 : Impact des signatures Δ% par KEM (1 PDF)

Usage:
    python3 plot_hqc_ideal.py \\
        --data-dir ~/Documents/TLS-QUIC/'6- hqc'/ \\
        --out-dir  ~/Documents/TLS-QUIC/'6- hqc'/plots/
"""

import os
import argparse
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.colors import LinearSegmentedColormap
from scipy import stats
import warnings
warnings.filterwarnings('ignore')

# ============================================================================
# PALETTE PROFESSIONNELLE (identique aux figures ML-KEM)
# ============================================================================
# Signature classique = ORANGE | Signature ML-DSA = BLEU
COLORS = {
    "classical": "#E69F00",  # ORANGE — signature classique
    "pq":        "#56B4E9",  # BLEU — signature ML-DSA
}

# Types de KEM HQC
HQC_COLORS = {
    "classical": "#2E75B6",   # Bleu foncé — KEM classique
    "hqc_pure":  "#C55A11",   # Orange — HQC pur
    "hqc_hybrid":"#BF9000",   # Ocre — HQC hybride
}

# Palette divergente pour heatmap (sans noir)
DIVERGING_CMAP = LinearSegmentedColormap.from_list(
    'rd_yl_gn',
    ['#CC6677', '#DDAA77', '#EEEEAA', '#88CCAA', '#44AA77'],
    N=256
)

plt.rcParams.update({
    'font.family': 'serif',
    'font.serif': ['Times New Roman', 'DejaVu Serif'],
    'font.size': 11,
    'axes.titlesize': 11,
    'axes.labelsize': 10,
    'xtick.labelsize': 9,
    'ytick.labelsize': 9,
    'legend.fontsize': 9,
    'figure.dpi': 300,
    'figure.facecolor': 'white',
    'axes.facecolor': '#FAFAFA',
    'axes.grid': True,
    'grid.alpha': 0.25,
    'grid.linestyle': ':',
    'axes.spines.top': False,
    'axes.spines.right': False,
    'savefig.dpi': 300,
    'savefig.bbox': 'tight',
})

# ============================================================================
# CONSTANTES HQC
# ============================================================================
SIG_PAIRS = [
    ("ed25519",   "mldsa44", 1, "NIST Level I (128-bit)"),
    ("secp384r1", "mldsa65", 3, "NIST Level III (192-bit)"),
    ("secp521r1", "mldsa87", 5, "NIST Level V (256-bit)"),
]

KEMS_BY_LEVEL = {
    1: ["P-256", "x25519", "hqc128", "p256_hqc128", "x25519_hqc128"],
    3: ["P-384", "x448",   "hqc192", "p384_hqc192", "x448_hqc192"],
    5: ["P-521",           "hqc256", "p521_hqc256"],
}

KEM_DISPLAY = {
    "P-256": "P-256", "x25519": "X25519",
    "P-384": "P-384", "x448": "X448", "P-521": "P-521",
    "hqc128": "HQC-128", "hqc192": "HQC-192", "hqc256": "HQC-256",
    "p256_hqc128": "P-256\n+HQC-128", "x25519_hqc128": "X25519\n+HQC-128",
    "p384_hqc192": "P-384\n+HQC-192", "x448_hqc192": "X448\n+HQC-192",
    "p521_hqc256": "P-521\n+HQC-256",
}

KEM_TYPE = {
    "P-256": "classical", "x25519": "classical",
    "P-384": "classical", "x448": "classical", "P-521": "classical",
    "hqc128": "hqc_pure", "hqc192": "hqc_pure", "hqc256": "hqc_pure",
    "p256_hqc128": "hqc_hybrid", "x25519_hqc128": "hqc_hybrid",
    "p384_hqc192": "hqc_hybrid", "x448_hqc192": "hqc_hybrid",
    "p521_hqc256": "hqc_hybrid",
}

SIG_CLASSICAL = {"ed25519", "secp384r1", "secp521r1"}
SIG_PQ = {"mldsa44", "mldsa65", "mldsa87"}
ALL_SIGS = {sig for pair in SIG_PAIRS for sig in (pair[0], pair[1])}

# ============================================================================
# CHARGEMENT DES DONNÉES
# ============================================================================
def load_all(data_dir):
    data = {}
    for proto in ["TLS", "QUIC"]:
        data[proto] = {}
        csv_dir = os.path.join(data_dir, proto.upper(), "csv")
        if not os.path.isdir(csv_dir):
            csv_dir = os.path.join(data_dir, proto.lower(), "csv")
        if not os.path.isdir(csv_dir):
            print(f"⚠️  Directory not found: {csv_dir}")
            continue

        for sig in ALL_SIGS:
            candidates = [
                os.path.join(csv_dir, f"{sig}_{proto.lower()}_ideal.csv"),
                os.path.join(csv_dir, f"{sig}_{proto.upper()}_ideal.csv"),
                os.path.join(csv_dir, f"{sig}_ideal.csv"),
            ]
            path = None
            for c in candidates:
                if os.path.isfile(c):
                    path = c
                    break
            if path is None:
                continue

            df = pd.read_csv(path)
            data[proto][sig] = {
                col: df[col].dropna().astype(float).values
                for col in df.columns
                if len(df[col].dropna()) > 0
            }
            print(f"  ✅ {proto}/{sig} — loaded")

    return data


# ============================================================================
# FIGURE 1A, 1B, 1C — Violin plots par niveau de sécurité (3 PDF)
# ============================================================================
def fig1_violin_by_level(data, out_dir):
    """Figure 1 : 3 PDF (L1, L3, L5) avec violons classique vs ML-DSA"""
    
    for sig_c, sig_pq, level, level_title in SIG_PAIRS:
        kems = KEMS_BY_LEVEL[level]
        display_names = [KEM_DISPLAY.get(kem, kem) for kem in kems]
        
        fig, axes = plt.subplots(1, 2, figsize=(11, 5.5))
        #fig.suptitle(
         #   f"Figure 1 — HQC: ML-DSA vs Classical Signatures — {level_title}\n"
          #  f"Handshake time distributions (500 runs, ideal conditions)",
           # fontsize=11, fontweight='bold', y=0.98
        #)
        
        for col, proto in enumerate(["TLS", "QUIC"]):
            ax = axes[col]
            
            if sig_c not in data[proto] or sig_pq not in data[proto]:
                ax.text(0.5, 0.5, "No data", ha='center', va='center')
                ax.set_title(f"{proto}", fontsize=11, fontweight='bold')
                continue
            
            positions_c, positions_pq = [], []
            vals_c, vals_pq = [], []
            tick_positions, tick_labels = [], []
            x = 1
            spacing = 3
            
            for kem, disp_name in zip(kems, display_names):
                if kem not in data[proto][sig_c] or kem not in data[proto][sig_pq]:
                    continue
                
                arr_c = data[proto][sig_c][kem]
                arr_pq = data[proto][sig_pq][kem]
                cap = np.percentile(np.concatenate([arr_c, arr_pq]), 99)
                vals_c.append(np.clip(arr_c, 0, cap))
                vals_pq.append(np.clip(arr_pq, 0, cap))
                positions_c.append(x)
                positions_pq.append(x + 1)
                tick_positions.append(x + 0.5)
                tick_labels.append(disp_name)
                x += spacing
            
            if not vals_c:
                continue
            
            # Couleurs cohérentes
            color_c = COLORS["classical"]
            color_pq = COLORS["pq"]
            
            # Violin plots
            vp_c = ax.violinplot(vals_c, positions=positions_c, showmedians=True, widths=0.8)
            vp_pq = ax.violinplot(vals_pq, positions=positions_pq, showmedians=True, widths=0.8)
            
            for pc in vp_c['bodies']:
                pc.set_facecolor(color_c)
                pc.set_alpha(0.7)
                pc.set_edgecolor('white')
                pc.set_linewidth(0.5)
            for part in ['cmedians', 'cmins', 'cmaxes', 'cbars']:
                if part in vp_c:
                    vp_c[part].set_color(color_c)
                    vp_c[part].set_linewidth(1.2)
            
            for pc in vp_pq['bodies']:
                pc.set_facecolor(color_pq)
                pc.set_alpha(0.7)
                pc.set_edgecolor('white')
                pc.set_linewidth(0.5)
            for part in ['cmedians', 'cmins', 'cmaxes', 'cbars']:
                if part in vp_pq:
                    vp_pq[part].set_color(color_pq)
                    vp_pq[part].set_linewidth(1.2)
            
            ax.set_xticks(tick_positions)
            ax.set_xticklabels(tick_labels, rotation=30, ha='right', fontsize=7)
            ax.set_ylabel("Handshake time (ms)", fontsize=10)
            ax.set_title(f"{proto}", fontsize=11, fontweight='bold')
            ax.grid(True, alpha=0.25, linestyle=':')
            
            # Légende en haut à gauche
            legend_elements = [
                mpatches.Patch(color=color_c, alpha=0.7, label=f"{sig_c} (classical)"),
                mpatches.Patch(color=color_pq, alpha=0.7, label=f"{sig_pq} (ML-DSA)"),
            ]
            ax.legend(handles=legend_elements, loc='upper left', framealpha=0.9, fontsize=8)
        
        plt.tight_layout(rect=[0, 0, 1, 0.94])
        
        level_map = {1: "a", 3: "b", 5: "c"}
        suffix = level_map[level]
        pdf_path = os.path.join(out_dir, f"fig1{suffix}_level{level}_hqc_violin.pdf")
        png_path = pdf_path.replace('.pdf', '.png')
        
        plt.savefig(pdf_path, format='pdf')
        plt.savefig(png_path, format='png')
        plt.close()
        
        print(f"  ✅ Fig1{suffix} (Level {level}) : {pdf_path} + PNG")
    
    return True


# ============================================================================
# FIGURE 2 — Heatmap des surcoûts ML-DSA (professionnelle, lisible)
# ============================================================================
def fig2_heatmap_overhead(data, out_dir):
    """Figure 2 : Heatmap des surcoûts Δ% pour HQC"""
    
    all_kems = []
    for _, _, level, _ in SIG_PAIRS:
        for kem in KEMS_BY_LEVEL[level]:
            if kem not in all_kems:
                all_kems.append(kem)
    
    display_kems = [KEM_DISPLAY.get(kem, kem) for kem in all_kems]
    
    row_labels = []
    for sig_c, sig_pq, level, level_title in SIG_PAIRS:
        row_labels.append(f"NIST L{level}  |  {sig_c} → {sig_pq}")
    
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    #fig.suptitle(
     #   "Figure 2 — HQC: ML-DSA overhead vs classical signatures (Δ%)\n"
      #  "Green = ML-DSA faster | Red = ML-DSA slower",
       # fontsize=11, fontweight='bold', y=0.98
    #)
    
    for col, proto in enumerate(["TLS", "QUIC"]):
        ax = axes[col]
        mat = np.full((len(SIG_PAIRS), len(all_kems)), np.nan)
        
        for ri, (sig_c, sig_pq, level, _) in enumerate(SIG_PAIRS):
            for kem in KEMS_BY_LEVEL[level]:
                ci = all_kems.index(kem)
                if kem not in data[proto].get(sig_c, {}) or kem not in data[proto].get(sig_pq, {}):
                    continue
                mean_c = np.mean(data[proto][sig_c][kem])
                mean_pq = np.mean(data[proto][sig_pq][kem])
                if mean_c > 0:
                    delta = ((mean_pq - mean_c) / mean_c) * 100
                    mat[ri, ci] = delta
        
        # Échelle symétrique
        max_abs = max(abs(np.nanmin(mat)), abs(np.nanmax(mat))) if not np.all(np.isnan(mat)) else 100
        lim = max(50, np.ceil(max_abs / 25) * 25)
        
        im = ax.imshow(mat, cmap=DIVERGING_CMAP, vmin=-lim, vmax=lim, aspect='auto')
        
        ax.set_xticks(range(len(display_kems)))
        ax.set_xticklabels(display_kems, rotation=45, ha='right', fontsize=7)
        ax.set_yticks(range(len(row_labels)))
        ax.set_yticklabels(row_labels, fontsize=8)
        ax.set_title(f"{proto}", fontsize=11, fontweight='bold')
        ax.grid(False)
        
        # Ajouter les valeurs numériques
        for ri in range(mat.shape[0]):
            for ci in range(mat.shape[1]):
                val = mat[ri, ci]
                if not np.isnan(val):
                    txt_color = 'white' if abs(val) > lim * 0.6 else '#333333'
                    ax.text(ci, ri, f"{val:+.0f}%",
                           ha='center', va='center',
                           fontsize=8, fontweight='bold', color=txt_color)
        
        cbar = plt.colorbar(im, ax=ax, shrink=0.8, aspect=30)
        cbar.set_label("Δ% (ML-DSA minus classical)", fontsize=9)
        cbar.ax.tick_params(labelsize=8)
    
    plt.tight_layout()
    
    pdf_path = os.path.join(out_dir, "fig2_hqc_heatmap_overhead.pdf")
    png_path = pdf_path.replace('.pdf', '.png')
    plt.savefig(pdf_path, format='pdf')
    plt.savefig(png_path, format='png')
    plt.close()
    
    print(f"  ✅ Fig2 : {pdf_path} + PNG")
    return True


# ============================================================================
# FIGURE 3 — Super-additivité pour HQC (identique structure ML-KEM)
# ============================================================================
def fig3_superadditivity(data, out_dir):
    """Figure 3 : Super-additivité pour HQC"""
    
    kem_pairs = {
        1: [("P-256", "hqc128"), ("x25519", "hqc128"),
            ("P-256", "p256_hqc128"), ("x25519", "x25519_hqc128")],
        3: [("P-384", "hqc192"), ("x448", "hqc192"),
            ("P-384", "p384_hqc192"), ("x448", "x448_hqc192")],
        5: [("P-521", "hqc256"), ("P-521", "p521_hqc256")],
    }
    
    fig, axes = plt.subplots(1, 2, figsize=(14, 6))
    #fig.suptitle(
     #   "Figure 3 — HQC: Super-additivity: actual vs expected combined overhead ratio\n"
      #  "Ratio > 1.05 = super-additive | 0.95–1.05 = additive | < 0.95 = sub-additive",
       # fontsize=10, fontweight='bold', y=0.98
    #)
    
    for col, proto in enumerate(["TLS", "QUIC"]):
        ax = axes[col]
        labels, ratios, bar_colors = [], [], []
        
        for sig_c, sig_pq, level, level_title in SIG_PAIRS:
            for kem_c, kem_pq in kem_pairs.get(level, []):
                if (sig_c not in data[proto] or sig_pq not in data[proto] or
                    kem_c not in data[proto][sig_c] or kem_pq not in data[proto][sig_pq] or
                    kem_pq not in data[proto][sig_c] or kem_c not in data[proto][sig_pq]):
                    continue
                
                baseline = np.mean(data[proto][sig_c][kem_c])
                sig_c_kpq = np.mean(data[proto][sig_c][kem_pq])
                sig_pq_kc = np.mean(data[proto][sig_pq][kem_c])
                sig_pq_kpq = np.mean(data[proto][sig_pq][kem_pq])
                
                oh_sum = (sig_c_kpq - baseline) + (sig_pq_kc - baseline)
                oh_both = sig_pq_kpq - baseline
                
                if abs(oh_sum) < 1e-6:
                    continue
                
                ratio = oh_both / oh_sum
                
                # Label explicite
                short_c = sig_c[:6].replace('secp', '')
                short_pq = sig_pq.replace('mldsa', 'ML-')
                kem_short = kem_c.replace('p256_', '').replace('p384_', '').replace('p521_', '')
                labels.append(f"L{level} | {short_c}→{short_pq}\n{kem_short}")
                ratios.append(ratio)
                
                if ratio > 1.05:
                    bar_colors.append(COLORS["pq"])
                elif ratio < 0.95:
                    bar_colors.append(COLORS["classical"])
                else:
                    bar_colors.append("#999999")
        
        if not labels:
            ax.text(0.5, 0.5, "No data", ha='center', va='center')
            ax.set_title(f"{proto}", fontsize=11, fontweight='bold')
            continue
        
        y_pos = np.arange(len(labels))
        bars = ax.barh(y_pos, ratios, color=bar_colors, alpha=0.85,
                      edgecolor='white', linewidth=0.8, height=0.7)
        
        ax.axvline(1.0, color='#333333', lw=1.5, ls='-', alpha=0.7)
        ax.axvline(1.05, color=COLORS["pq"], lw=1, ls='--', alpha=0.6)
        ax.axvline(0.95, color=COLORS["classical"], lw=1, ls='--', alpha=0.6)
        
        ax.set_yticks(y_pos)
        ax.set_yticklabels(labels, fontsize=7)
        ax.set_xlabel("Actual overhead / Expected overhead ratio", fontsize=10)
        ax.set_title(f"{proto} — HQC combined migration", fontsize=11, fontweight='bold')
        ax.grid(True, axis='x', alpha=0.25, linestyle=':')
        
        for i, r in enumerate(ratios):
            ax.text(r + 0.02, i, f"{r:.2f}", va='center', fontsize=7)
    
    # Légende en bas
    legend_elements = [
        mpatches.Patch(color=COLORS["pq"], alpha=0.85, label='Super-additive (>1.05)'),
        mpatches.Patch(color="#999999", alpha=0.85, label='Additive (0.95–1.05)'),
        mpatches.Patch(color=COLORS["classical"], alpha=0.85, label='Sub-additive (<0.95)'),
    ]
    fig.legend(handles=legend_elements, loc='lower center',
              bbox_to_anchor=(0.5, -0.05), ncol=3, fontsize=8,
              frameon=True, fancybox=False, edgecolor='#333333')
    
    plt.tight_layout(rect=[0, 0.05, 1, 0.94])
    
    pdf_path = os.path.join(out_dir, "fig3_hqc_superadditivity.pdf")
    png_path = pdf_path.replace('.pdf', '.png')
    plt.savefig(pdf_path, format='pdf')
    plt.savefig(png_path, format='png')
    plt.close()
    
    print(f"  ✅ Fig3 : {pdf_path} + PNG")
    return True


# ============================================================================
# FIGURE 4 — Impact des signatures (Δ% par KEM) — améliorée et lisible
# ============================================================================
def fig4_sig_impact(data, out_dir):
    """Figure 4 : Impact des signatures — barres Δ% par KEM"""
    
    fig, axes = plt.subplots(1, 3, figsize=(15, 6))
    #fig.suptitle(
     #   "Figure 4 — HQC: Signature impact on KEMs: Δ% ML-DSA vs classical\n"
      #  "Δ% = (ML-DSA − Classical) / Classical × 100  |  Negative = ML-DSA faster",
       # fontsize=11, fontweight='bold', y=0.98
    #)
    
    for col, (sig_c, sig_pq, level, level_title) in enumerate(SIG_PAIRS):
        ax = axes[col]
        kems = KEMS_BY_LEVEL[level]
        display_names = [KEM_DISPLAY.get(kem, kem) for kem in kems]
        
        deltas_tls, deltas_quic = [], []
        valid_kems = []
        
        for i, kem in enumerate(kems):
            try:
                m_tls_c = np.mean(data["TLS"][sig_c][kem])
                m_tls_pq = np.mean(data["TLS"][sig_pq][kem])
                m_quic_c = np.mean(data["QUIC"][sig_c][kem])
                m_quic_pq = np.mean(data["QUIC"][sig_pq][kem])
            except KeyError:
                continue
            
            valid_kems.append(display_names[i])
            deltas_tls.append(((m_tls_pq - m_tls_c) / m_tls_c) * 100)
            deltas_quic.append(((m_quic_pq - m_quic_c) / m_quic_c) * 100)
        
        if not valid_kems:
            ax.set_visible(False)
            continue
        
        x = np.arange(len(valid_kems))
        width = 0.35
        
        bars_tls = ax.bar(x - width/2, deltas_tls, width,
                         color=COLORS["classical"], alpha=0.85,
                         label='TLS', edgecolor='white')
        bars_quic = ax.bar(x + width/2, deltas_quic, width,
                          color=COLORS["pq"], alpha=0.85,
                          label='QUIC', edgecolor='white')
        
        ax.axhline(0, color='#333333', lw=1.2, ls='--', alpha=0.7)
        
        # Zones colorées
        ymin, ymax = ax.get_ylim()
        ax.axhspan(min(ymin, -5), 0, alpha=0.08, color='#44AA77')
        ax.axhspan(0, max(ymax, 5), alpha=0.08, color='#CC6677')
        
        # Ajouter les valeurs
        for bar in list(bars_tls) + list(bars_quic):
            h = bar.get_height()
            va = 'bottom' if h >= 0 else 'top'
            offset = 0.8 if h >= 0 else -0.8
            if abs(h) > 1:  # Éviter l'affichage pour les très petits Δ
                ax.text(bar.get_x() + bar.get_width()/2., h + offset,
                       f'{h:+.1f}%', ha='center', va=va, fontsize=7)
        
        ax.set_xticks(x)
        ax.set_xticklabels(valid_kems, rotation=30, ha='right', fontsize=7)
        ax.set_ylabel("Δ% (ML-DSA vs Classical)", fontsize=9)
        ax.set_title(f"L{level} — {sig_c} → {sig_pq}", fontsize=10, fontweight='bold')
        ax.legend(loc='upper left', fontsize=8, framealpha=0.9)
        ax.grid(True, axis='y', alpha=0.25, linestyle=':')
    
    plt.tight_layout()
    
    pdf_path = os.path.join(out_dir, "fig4_hqc_sig_impact.pdf")
    png_path = pdf_path.replace('.pdf', '.png')
    plt.savefig(pdf_path, format='pdf')
    plt.savefig(png_path, format='png')
    plt.close()
    
    print(f"  ✅ Fig4 : {pdf_path} + PNG")
    return True


# ============================================================================
# MAIN
# ============================================================================
def main():
    parser = argparse.ArgumentParser(
        description="Generate HQC figures (publication quality)"
    )
    parser.add_argument("--data-dir", required=True,
                       help="Root directory (contains TLS/csv/ and QUIC/csv/)")
    parser.add_argument("--out-dir", default=None,
                       help="Output directory (default: data-dir/plots/)")
    args = parser.parse_args()
    
    out_dir = args.out_dir or os.path.join(args.data_dir, "plots")
    os.makedirs(out_dir, exist_ok=True)
    
    print("\n" + "="*60)
    print("  HQC STUDY — GENERATING FIGURES")
    print("="*60)
    print(f"  Data dir   : {args.data_dir}")
    print(f"  Output dir : {out_dir}")
    print("="*60 + "\n")
    
    print("Loading HQC data...")
    data = load_all(args.data_dir)
    
    n_tls = len(data.get("TLS", {}))
    n_quic = len(data.get("QUIC", {}))
    
    if n_tls == 0 and n_quic == 0:
        print("❌ No data loaded. Check --data-dir")
        return
    
    print(f"\n✅ Loaded: TLS: {n_tls} signatures, QUIC: {n_quic} signatures\n")
    
    print("Generating figures...\n")
    
    fig1_violin_by_level(data, out_dir)
    fig2_heatmap_overhead(data, out_dir)
    fig3_superadditivity(data, out_dir)
    fig4_sig_impact(data, out_dir)
    
    print("\n" + "="*60)
    print("✅ ALL HQC FIGURES GENERATED")
    print(f"   Output: {out_dir}")
    print("\n   Files:")
    print("   - fig1a_level1_hqc_violin.pdf / .png")
    print("   - fig1b_level3_hqc_violin.pdf / .png")
    print("   - fig1c_level5_hqc_violin.pdf / .png")
    print("   - fig2_hqc_heatmap_overhead.pdf / .png")
    print("   - fig3_hqc_superadditivity.pdf / .png")
    print("   - fig4_hqc_sig_impact.pdf / .png")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()
