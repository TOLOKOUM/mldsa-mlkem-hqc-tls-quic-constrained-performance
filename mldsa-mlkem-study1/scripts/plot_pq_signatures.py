#!/usr/bin/env python3
"""
plot_pq_signatures.py
==================================

- TOUTES les figures : sortie PDF + PNG
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
import warnings
warnings.filterwarnings('ignore')

# ============================================================================
# PALETTE UNIFIÉE
# ============================================================================
# Signature classique = ORANGE (partout)
# Signature ML-DSA = BLEU (partout)
COLORS = {
    "classical": "#E69F00",  # ORANGE
    "pq":        "#56B4E9",  # BLEU
}

# Palette divergente professionnelle — PAS DE NOIR
# Rouge = ML-DSA plus lent, Vert = ML-DSA plus rapide
DIVERGING_CMAP = LinearSegmentedColormap.from_list(
    'rd_yl_gn',
    ['#CC6677',  # Rouge foncé (très négatif: ML-DSA plus lent)
     '#DDAA77',  # Ocre (négatif modéré)
     '#EEEEAA',  # Jaune clair (neutre)
     '#88CCAA',  # Vert clair (positif modéré: ML-DSA plus rapide)
     '#44AA77'], # Vert foncé (très positif)
    N=256
)

plt.rcParams.update({
    'font.family': 'serif',
    'font.serif': ['Times New Roman', 'DejaVu Serif'],
    'font.size': 11,
    'axes.titlesize': 11,
    'axes.labelsize': 10,
    'xtick.labelsize': 8,
    'ytick.labelsize': 8,
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
# CONSTANTES
# ============================================================================
NIST_LEVELS = {"ed25519": 1, "mldsa44": 1, "secp384r1": 3, "mldsa65": 3,
               "secp521r1": 5, "mldsa87": 5}

SIG_PAIRS = [
    ("ed25519", "mldsa44", 1, "NIST Level I (128-bit)"),
    ("secp384r1", "mldsa65", 3, "NIST Level III (192-bit)"),
    ("secp521r1", "mldsa87", 5, "NIST Level V (256-bit)"),
]

KEMS_BY_LEVEL = {
    1: ["P-256", "x25519", "p256_mlkem512", "x25519_mlkem512", "mlkem512"],
    3: ["P-384", "x448", "p384_mlkem768", "x448_mlkem768", "mlkem768"],
    5: ["P-521", "p521_mlkem1024", "mlkem1024"],
}

KEM_DISPLAY = {
    "P-256": "P-256", "x25519": "X25519",
    "P-384": "P-384", "x448": "X448", "P-521": "P-521",
    "mlkem512": "ML-KEM-512", "mlkem768": "ML-KEM-768", "mlkem1024": "ML-KEM-1024",
    "p256_mlkem512": "P-256+ML-KEM", "x25519_mlkem512": "X25519+ML-KEM",
    "p384_mlkem768": "P-384+ML-KEM", "x448_mlkem768": "X448+ML-KEM",
    "p521_mlkem1024": "P-521+ML-KEM",
}

KEM_TYPE = {
    "P-256": "classical", "x25519": "classical",
    "P-384": "classical", "x448": "classical", "P-521": "classical",
    "mlkem512": "pq_pure", "mlkem768": "pq_pure", "mlkem1024": "pq_pure",
    "p256_mlkem512": "hybrid", "x25519_mlkem512": "hybrid",
    "p384_mlkem768": "hybrid", "x448_mlkem768": "hybrid",
    "p521_mlkem1024": "hybrid",
}

SIG_CLASSICAL = {"ed25519", "secp384r1", "secp521r1"}
SIG_PQ = {"mldsa44", "mldsa65", "mldsa87"}

# ============================================================================
# CHARGEMENT
# ============================================================================
def load_all(data_dir):
    data = {}
    for proto in ["TLS", "QUIC"]:
        data[proto] = {}
        base_dir = data_dir.rstrip('/')
        for sig in NIST_LEVELS.keys():
            path = os.path.join(base_dir, proto.upper(), "csv",
                                f"{sig}_{proto.lower()}_ideal.csv")
            if not os.path.isfile(path):
                alt_path = os.path.join(base_dir, proto.upper(),
                                       f"{sig}_{proto.lower()}_ideal.csv")
                if os.path.isfile(alt_path):
                    path = alt_path
                else:
                    continue
            try:
                df = pd.read_csv(path)
                data[proto][sig] = {k: df[k].dropna().astype(float).values
                                   for k in df.columns}
            except Exception:
                continue
    return data


# ============================================================================
# FIGURE 1A, 1B, 1C — Violin plots (légende EN HAUT de chaque sous-figure)
# ============================================================================
def fig1_violin_by_level(data, out_dir):
    """Figure 1 : violon plots — légende en haut près de l'axe des ordonnées"""
    
    for sig_c, sig_pq, level, level_title in SIG_PAIRS:
        kems = KEMS_BY_LEVEL[level]
        display_names = [KEM_DISPLAY.get(k, k) for k in kems]
        
        fig, axes = plt.subplots(1, 2, figsize=(11, 5.5))
        
        for col, proto in enumerate(["TLS", "QUIC"]):
            ax = axes[col]
            
            if sig_c not in data[proto] or sig_pq not in data[proto]:
                ax.text(0.5, 0.5, "No data", ha='center', va='center')
                ax.set_title(f"{proto}", fontsize=11, fontweight='bold')
                continue
            
            positions_c, positions_pq = [], []
            vals_c, vals_pq = [], []
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
                x += spacing
            
            if not vals_c:
                continue
            
            # MÊMES COULEURS pour TLS et QUIC
            color_c = COLORS["classical"]  # ORANGE
            color_pq = COLORS["pq"]        # BLEU
            
            # Violin plots
            vp_c = ax.violinplot(vals_c, positions=positions_c,
                                 showmedians=True, widths=0.8)
            vp_pq = ax.violinplot(vals_pq, positions=positions_pq,
                                  showmedians=True, widths=0.8)
            
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
            
            tick_pos = [(p + p2)/2 for p, p2 in zip(positions_c, positions_pq)]
            ax.set_xticks(tick_pos)
            ax.set_xticklabels(display_names, rotation=30, ha='right', fontsize=7)
            ax.set_ylabel("Handshake time (ms)", fontsize=10)
            ax.set_title(f"{proto}", fontsize=11, fontweight='bold')
            ax.grid(True, alpha=0.25, linestyle=':')
            
            # LÉGENDE EN HAUT — placée dans le coin supérieur gauche
            legend_elements = [
                mpatches.Patch(color=color_c, alpha=0.7,
                              label=f"{sig_c} (classical)"),
                mpatches.Patch(color=color_pq, alpha=0.7,
                              label=f"{sig_pq} (ML-DSA)"),
            ]
            ax.legend(handles=legend_elements, loc='upper left',
                     framealpha=0.9, fontsize=8, title="Signature")
        
        # Titre principal
        #fig.suptitle(f"ML-DSA vs Classical Signatures — {level_title}\n"
         #           f"Handshake time distributions (500 runs, ideal conditions)",
          #          fontsize=11, fontweight='bold', y=0.98)
        
        plt.tight_layout(rect=[0, 0, 1, 0.96])
        
        # Sauvegarde PDF + PNG
        level_map = {1: "a", 3: "b", 5: "c"}
        suffix = level_map[level]
        pdf_path = os.path.join(out_dir, f"fig1{suffix}_level{level}_violin.pdf")
        png_path = os.path.join(out_dir, f"fig1{suffix}_level{level}_violin.png")
        
        plt.savefig(pdf_path, format='pdf')
        plt.savefig(png_path, format='png')
        plt.close()
        print(f"✅ Fig1{suffix} (Level {level}) : {pdf_path} + PNG")
    
    return True


# ============================================================================
# FIGURE 2 — Heatmap 
# ============================================================================
def fig2_heatmap_overhead(data, out_dir):
    all_kems = []
    for _, _, level, _ in SIG_PAIRS:
        for kem in KEMS_BY_LEVEL[level]:
            if kem not in all_kems:
                all_kems.append(kem)
    
    display_kems = [KEM_DISPLAY.get(k, k) for k in all_kems]
    
    row_labels = []
    for sig_c, sig_pq, level, _ in SIG_PAIRS:
        row_labels.append(f"NIST L{level}  |  {sig_c} → {sig_pq}")
    
    fig, axes = plt.subplots(1, 2, figsize=(14, 4.5))
    #fig.suptitle("Figure 2 — ML-DSA overhead vs classical signatures (Δ%)\n"
     #           "Green = ML-DSA faster | Red = ML-DSA slower",
      #          fontsize=11, fontweight='bold', y=0.98)
    
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
        
        # Déterminer l'échelle symétrique (valeurs positives ET négatives)
        max_abs = max(abs(np.nanmin(mat)), abs(np.nanmax(mat))) if not np.all(np.isnan(mat)) else 50
        lim = max(50, np.ceil(max_abs / 25) * 25)
        
        im = ax.imshow(mat, cmap=DIVERGING_CMAP, vmin=-lim, vmax=lim, aspect='auto')
        
        ax.set_xticks(range(len(display_kems)))
        ax.set_xticklabels(display_kems, rotation=45, ha='right', fontsize=6.5)
        ax.set_yticks(range(len(row_labels)))
        ax.set_yticklabels(row_labels, fontsize=8)
        ax.set_title(f"{proto}", fontsize=11, fontweight='bold')
        ax.grid(False)
        
        # Ajouter les valeurs numériques
        for ri in range(mat.shape[0]):
            for ci in range(mat.shape[1]):
                val = mat[ri, ci]
                if not np.isnan(val):
                    # Texte blanc si la valeur est proche des extrêmes
                    txt_color = 'white' if abs(val) > lim * 0.6 else '#333333'
                    ax.text(ci, ri, f"{val:+.0f}%", ha='center', va='center',
                           fontsize=7, fontweight='bold', color=txt_color)
        
        # Colorbar avec label clair
        cbar = plt.colorbar(im, ax=ax, shrink=0.8, aspect=30)
        cbar.set_label("Δ% (ML-DSA minus classical)\nNegative: ML-DSA faster | Positive: ML-DSA slower",
                      fontsize=8)
        cbar.ax.tick_params(labelsize=8)
    
    plt.tight_layout()
    
    pdf_path = os.path.join(out_dir, "fig2_heatmap_overhead.pdf")
    png_path = os.path.join(out_dir, "fig2_heatmap_overhead.png")
    plt.savefig(pdf_path, format='pdf')
    plt.savefig(png_path, format='png', dpi=150)
    plt.close()
    print(f"✅ Fig2 heatmap : {pdf_path} + PNG")
    return True

# ============================================================================
# FIGURE 3 — Super-additivité (axes des ordonnées clairs et explicites)
# ============================================================================
def fig3_superadditivity(data, out_dir):
    kem_pairs = {
        1: [("P-256", "mlkem512"), ("x25519", "mlkem512"),
            ("P-256", "p256_mlkem512"), ("x25519", "x25519_mlkem512")],
        3: [("P-384", "mlkem768"), ("x448", "mlkem768"),
            ("P-384", "p384_mlkem768"), ("x448", "x448_mlkem768")],
        5: [("P-521", "mlkem1024"), ("P-521", "p521_mlkem1024")],
    }
    
    fig, axes = plt.subplots(1, 2, figsize=(14, 5.5))
    
    for col, proto in enumerate(["TLS", "QUIC"]):
        ax = axes[col]
        labels, ratios, bar_colors = [], [], []
        
        for sig_c, sig_pq, level, _ in SIG_PAIRS:
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
                
                # Nom CLAIR et EXPLICITE pour l'axe des ordonnées
                proto_sig = "TLS" if proto == "TLS" else "QUIC"
                label = f"{proto_sig}: {sig_c} + {kem_c}\n→ {sig_pq} + {kem_pq}"
                labels.append(label)
                ratios.append(ratio)
                
                if ratio > 1.05:
                    bar_colors.append(COLORS["pq"])      # Bleu = super-additif
                elif ratio < 0.95:
                    bar_colors.append(COLORS["classical"]) # Orange = sub-additif
                else:
                    bar_colors.append("#999999")          # Gris = additif
        
        if not labels:
            ax.text(0.5, 0.5, "No data", ha='center', va='center')
            ax.set_title(f"{proto}", fontsize=11, fontweight='bold')
            continue
        
        y_pos = np.arange(len(labels))
        bars = ax.barh(y_pos, ratios, color=bar_colors, alpha=0.85,
                      edgecolor='white', linewidth=0.8, height=0.7)
        
        # Lignes de référence
        ax.axvline(1.0, color='#333333', lw=1.5, ls='-', alpha=0.7, label='Additive (1.0)')
        ax.axvline(1.05, color=COLORS["pq"], lw=1, ls='--', alpha=0.6, label='Super-additive (1.05)')
        ax.axvline(0.95, color=COLORS["classical"], lw=1, ls='--', alpha=0.6, label='Sub-additive (0.95)')
        
        ax.set_yticks(y_pos)
        ax.set_yticklabels(labels, fontsize=7)
        ax.set_xlabel("Actual overhead / Expected overhead ratio", fontsize=10)
        ax.set_title(f"{proto} — Combined migration", fontsize=11, fontweight='bold')
        ax.grid(True, axis='x', alpha=0.25, linestyle=':')
        
        # Ajouter les valeurs numériques à droite des barres
        for i, (bar, r) in enumerate(zip(bars, ratios)):
            ax.text(r + 0.02, bar.get_y() + bar.get_height()/2,
                   f"{r:.2f}", va='center', fontsize=7)
    
    # Légende en bas de la figure
    legend_elements = [
        mpatches.Patch(color=COLORS["pq"], alpha=0.85, label='Super-additive (>1.05)'),
        mpatches.Patch(color="#999999", alpha=0.85, label='Additive (0.95–1.05)'),
        mpatches.Patch(color=COLORS["classical"], alpha=0.85, label='Sub-additive (<0.95)'),
    ]
    fig.legend(handles=legend_elements, loc='lower center',
              bbox_to_anchor=(0.5, -0.08), ncol=3, fontsize=9,
              frameon=True, fancybox=False, edgecolor='#333333')
    
    #fig.suptitle("Figure 3 — Super-additivity: actual vs expected combined overhead ratio\n"
     #           "Ratio > 1.05 = super-additive | 0.95–1.05 = additive | < 0.95 = sub-additive",
      #          fontsize=10, fontweight='bold', y=0.98)
    
    plt.tight_layout(rect=[0, 0.05, 1, 0.94])
    
    pdf_path = os.path.join(out_dir, "fig3_superadditivity.pdf")
    png_path = os.path.join(out_dir, "fig3_superadditivity.png")
    plt.savefig(pdf_path, format='pdf')
    plt.savefig(png_path, format='png', dpi=150)
    plt.close()
    print(f"✅ Fig3 superadditivity : {pdf_path} + PNG")
    return True


# ============================================================================
# MAIN
# ============================================================================
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--out-dir", default=None)
    args = parser.parse_args()
    
    out_dir = args.out_dir or os.path.join(args.data_dir, "plots")
    os.makedirs(out_dir, exist_ok=True)
    
    print("\n" + "="*60)
    print("GENERATING FIGURES — FINAL VERSION")
    print("="*60)
    print(f"Data dir  : {args.data_dir}")
    print(f"Output dir: {out_dir}")
    print("="*60 + "\n")
    
    data = load_all(args.data_dir)
    print(f"✓ Loaded {sum(len(data[p]) for p in data)} protocol/sig combinations\n")
    
    print("Generating figures...\n")
    
    fig1_violin_by_level(data, out_dir)
    fig2_heatmap_overhead(data, out_dir)
    fig3_superadditivity(data, out_dir)
    
    print("\n" + "="*60)
    print("✅ ALL FIGURES GENERATED (PDF + PNG)")
    print(f"   Output: {out_dir}")
    print("\n   Files:")
    print("   - fig1a_level1_violin.pdf / .png")
    print("   - fig1b_level3_violin.pdf / .png")
    print("   - fig1c_level5_violin.pdf / .png")
    print("   - fig2_heatmap_overhead.pdf / .png")
    print("   - fig3_superadditivity.pdf / .png")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()
