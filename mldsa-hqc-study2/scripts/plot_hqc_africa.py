#!/usr/bin/env python3
"""
plot_hqc_africa_final.py
=========================
Figures pour les conditions réseau africaines — HQC (Phase 6)

Améliorations :
- Figure 6 : découpée en 3 PDF (L1, L3, L5) pour delta evolution
- Figure 7 : découpée en 3 PDF (L1, L3, L5) pour protocole reversal
- Figure 8 : heatmap découpée en 3 PDF (L1, L3, L5) avec chiffres lisibles
- Figure 9 : violon plots en conditions locales (35ms/2%) — 3 PDF
- Figure 10 : résumé par catégorie (1 PDF)

Usage:
    python3 plot_hqc_africa_final.py \\
        --data-dir ~/Documents/TLS-QUIC/mldsa-hqc-study2 \\
        --out-dir  ~/Documents/TLS-QUIC/mldsa-hqc-study2/plots/
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
# PALETTE PROFESSIONNELLE — cohérente avec ML-KEM
# ============================================================================
COLORS = {
    "classical": "#E69F00",  # ORANGE — signature classique
    "pq":        "#56B4E9",  # BLEU — signature ML-DSA
}

HQC_COLORS = {
    "classique":    "#2E75B6",   # Bleu
    "HQC pur":      "#C55A11",   # Orange
    "HQC hybride":  "#BF9000",   # Ocre
}

plt.rcParams.update({
    'font.family': 'serif',
    'font.serif': ['Times New Roman', 'DejaVu Serif'],
    'font.size': 11,
    'axes.titlesize': 11,
    'axes.labelsize': 10,
    'xtick.labelsize': 8,
    'ytick.labelsize': 8,
    'legend.fontsize': 8,
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
SCENARIOS = {
    "ideal":           {"label": "Ideal\n(0 ms / 0%)",       "delay": 0,   "loss": 0},
    "africa_local":    {"label": "Local YDE\n(35 ms / 2%)",  "delay": 35,  "loss": 2},
    "africa_backbone": {"label": "Backbone\n(200 ms / 4%)",  "delay": 200, "loss": 4},
    "africa_degraded": {"label": "Degraded\n(200 ms / 10%)", "delay": 200, "loss": 10},
}
SCEN_ORDER = list(SCENARIOS.keys())
SCEN_LABELS = [SCENARIOS[s]["label"] for s in SCEN_ORDER]

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
    "P-256": "classique", "x25519": "classique",
    "P-384": "classique", "x448": "classique", "P-521": "classique",
    "hqc128": "HQC pur", "hqc192": "HQC pur", "hqc256": "HQC pur",
    "p256_hqc128": "HQC hybride", "x25519_hqc128": "HQC hybride",
    "p384_hqc192": "HQC hybride", "x448_hqc192": "HQC hybride",
    "p521_hqc256": "HQC hybride",
}

KEM_MARKERS = {"classique": "o", "HQC pur": "^", "HQC hybride": "s"}
SIG_PQ = {"mldsa44", "mldsa65", "mldsa87"}
SIG_CLASSICAL = {"ed25519", "secp384r1", "secp521r1"}


# ============================================================================
# CHARGEMENT DES DONNÉES
# ============================================================================
def load_all(data_dir):
    data = {}
    for proto in ["TLS", "QUIC"]:
        data[proto] = {}
        for scen in SCENARIOS:
            data[proto][scen] = {}
            for sig in set([p[0] for p in SIG_PAIRS] + [p[1] for p in SIG_PAIRS]):
                fname = f"{sig}_{proto.lower()}_{scen}.csv"
                path = os.path.join(data_dir, proto.upper(), "csv", fname)
                if not os.path.isfile(path):
                    alt_path = os.path.join(data_dir, proto.upper(), fname)
                    if os.path.isfile(alt_path):
                        path = alt_path
                    else:
                        continue
                try:
                    df = pd.read_csv(path)
                    data[proto][scen][sig] = {
                        kem: df[kem].dropna().astype(float).values
                        for kem in df.columns
                    }
                except Exception:
                    continue
    return data


# ============================================================================
# FIGURE 6 — Delta evolution (un PDF par niveau)
# ============================================================================
def fig6_delta_evolution_by_level(data, out_dir):
    """Figure 6 : 3 PDF (L1, L3, L5) — évolution Δ% par scénario"""
    
    for sig_c, sig_pq, level, level_title in SIG_PAIRS:
        fig, axes = plt.subplots(1, 2, figsize=(11, 5))
        #fig.suptitle(
         #   f"Figure 6 — HQC: ML-DSA overhead evolution — {level_title}\n"
          #  f"Negative Δ% = ML-DSA faster | Positive Δ% = ML-DSA slower",
           # fontsize=10, fontweight='bold', y=0.98
        #)
        
        x_pos = np.arange(len(SCEN_ORDER))
        kems = KEMS_BY_LEVEL[level]
        
        for col, proto in enumerate(["TLS", "QUIC"]):
            ax = axes[col]
            
            ax.axhline(y=0, color='#333333', lw=1.5, ls='--', alpha=0.7)
            ax.axhspan(-200, 0, alpha=0.05, color='#44AA77')
            ax.axhspan(0, 300, alpha=0.05, color='#CC6677')
            
            for kem in kems:
                deltas = []
                for scen in SCEN_ORDER:
                    try:
                        mc = np.mean(data[proto][scen][sig_c][kem])
                        mp = np.mean(data[proto][scen][sig_pq][kem])
                        deltas.append(((mp - mc) / mc) * 100)
                    except KeyError:
                        deltas.append(np.nan)
                
                kt = KEM_TYPE.get(kem, "classique")
                color = HQC_COLORS.get(kt, "#999999")
                marker = KEM_MARKERS.get(kt, "o")
                display_name = KEM_DISPLAY.get(kem, kem)
                
                valid = [(x_pos[i], d) for i, d in enumerate(deltas) if not np.isnan(d)]
                if not valid:
                    continue
                vx, vd = zip(*valid)
                ax.plot(vx, vd, color=color, marker=marker,
                       lw=1.5, ms=5, alpha=0.85, label=display_name)
                ax.annotate(display_name, (vx[-1], vd[-1]), fontsize=6,
                           xytext=(3, 0), textcoords='offset points',
                           color=color)
            
            ax.set_xticks(x_pos)
            ax.set_xticklabels(SCEN_LABELS, fontsize=7)
            ax.set_ylabel("Δ% (ML-DSA vs Classical)", fontsize=9)
            ax.set_xlabel("Network scenario", fontsize=9)
            ax.set_title(f"{proto}", fontsize=10, fontweight='bold')
            ax.grid(True, alpha=0.25, linestyle=':')
            
            for xv in [0.5, 1.5, 2.5]:
                ax.axvline(x=xv, color='gray', lw=0.6, ls=':', alpha=0.5)
            
            legend_elements = [
                mpatches.Patch(color=HQC_COLORS["classique"], label='Classical KEM'),
                mpatches.Patch(color=HQC_COLORS["HQC pur"], label='HQC pure'),
                mpatches.Patch(color=HQC_COLORS["HQC hybride"], label='HQC hybrid'),
            ]
            ax.legend(handles=legend_elements, loc='upper left', fontsize=6, framealpha=0.9)
        
        plt.tight_layout(rect=[0, 0, 1, 0.94])
        
        level_map = {1: "a", 3: "b", 5: "c"}
        suffix = level_map[level]
        pdf_path = os.path.join(out_dir, f"fig6{suffix}_level{level}_hqc_delta_evolution.pdf")
        png_path = pdf_path.replace('.pdf', '.png')
        
        plt.savefig(pdf_path, format='pdf')
        plt.savefig(png_path, format='png')
        plt.close()
        
        print(f"  ✅ Fig6{suffix} (Level {level}) : {pdf_path} + PNG")
    
    return True


# ============================================================================
# FIGURE 7 — TLS vs QUIC reversal (un PDF par niveau)
# ============================================================================
def fig7_tls_quic_reversal_by_level(data, out_dir):
    """Figure 7 : 3 PDF (L1, L3, L5) — renversement TLS vs QUIC"""
    
    for sig_c, sig_pq, level, level_title in SIG_PAIRS:
        fig, axes = plt.subplots(1, 2, figsize=(11, 5))
        #fig.suptitle(
         #   f"Figure 7 — HQC: TLS vs QUIC protocol reversal — {level_title}\n"
          #  f"Positive = TLS slower | Negative = TLS faster",
           # fontsize=10, fontweight='bold', y=0.98
        #)
        
        x_pos = np.arange(len(SCEN_ORDER))
        kems = KEMS_BY_LEVEL[level]
        
        for col, proto_sig in enumerate([sig_c, sig_pq]):
            ax = axes[col]
            sig = proto_sig
            sig_type = "ML-DSA" if sig in SIG_PQ else "Classical"
            
            ax.axhline(y=0, color='#333333', lw=1.5, ls='--', alpha=0.7)
            ax.axhspan(-400, 0, alpha=0.05, color='#44AA77')
            ax.axhspan(0, 600, alpha=0.05, color='#CC6677')
            
            for kem in kems:
                diffs = []
                for scen in SCEN_ORDER:
                    try:
                        mt = np.mean(data["TLS"][scen][sig][kem])
                        mq = np.mean(data["QUIC"][scen][sig][kem])
                        diffs.append(((mt - mq) / mq) * 100)
                    except KeyError:
                        diffs.append(np.nan)
                
                kt = KEM_TYPE.get(kem, "classique")
                color = HQC_COLORS.get(kt, "#999999")
                marker = KEM_MARKERS.get(kt, "o")
                display_name = KEM_DISPLAY.get(kem, kem)
                
                valid = [(x_pos[i], d) for i, d in enumerate(diffs) if not np.isnan(d)]
                if not valid:
                    continue
                vx, vd = zip(*valid)
                ax.plot(vx, vd, color=color, marker=marker,
                       lw=1.5, ms=5, alpha=0.85, label=display_name)
                ax.annotate(display_name, (vx[-1], vd[-1]), fontsize=6,
                           xytext=(3, 0), textcoords='offset points',
                           color=color)
            
            ax.set_xticks(x_pos)
            ax.set_xticklabels(SCEN_LABELS, fontsize=7)
            ax.set_ylabel("(TLS − QUIC) / QUIC × 100 (%)", fontsize=9)
            ax.set_xlabel("Network scenario", fontsize=9)
            ax.set_title(f"Signature: {sig} ({sig_type})", fontsize=10, fontweight='bold')
            ax.grid(True, alpha=0.25, linestyle=':')
            
            for xv in [0.5, 1.5, 2.5]:
                ax.axvline(x=xv, color='gray', lw=0.6, ls=':', alpha=0.5)
            
            legend_elements = [
                mpatches.Patch(color=HQC_COLORS["classique"], label='Classical KEM'),
                mpatches.Patch(color=HQC_COLORS["HQC pur"], label='HQC pure'),
                mpatches.Patch(color=HQC_COLORS["HQC hybride"], label='HQC hybrid'),
                mpatches.Patch(color='#44AA77', alpha=0.3, label='TLS faster'),
                mpatches.Patch(color='#CC6677', alpha=0.3, label='QUIC faster'),
            ]
            ax.legend(handles=legend_elements, loc='upper left', fontsize=6, framealpha=0.9)
        
        plt.tight_layout(rect=[0, 0, 1, 0.94])
        
        level_map = {1: "a", 3: "b", 5: "c"}
        suffix = level_map[level]
        pdf_path = os.path.join(out_dir, f"fig7{suffix}_level{level}_hqc_protocol_reversal.pdf")
        png_path = pdf_path.replace('.pdf', '.png')
        
        plt.savefig(pdf_path, format='pdf')
        plt.savefig(png_path, format='png')
        plt.close()
        
        print(f"  ✅ Fig7{suffix} (Level {level}) : {pdf_path} + PNG")
    
    return True


# ============================================================================
# FIGURE 8 — Deployment heatmap (un PDF par niveau, chiffres lisibles)
# ============================================================================
def fig8_deployment_heatmap_by_level(data, out_dir):
    """Figure 8 : 3 PDF (L1, L3, L5) — heatmap déploiement"""
    
    for sig_c, sig_pq, level, level_title in SIG_PAIRS:
        kems = KEMS_BY_LEVEL[level]
        
        combos = []
        for sig in [sig_c, sig_pq]:
            sig_label = "Classical" if sig in SIG_CLASSICAL else "ML-DSA"
            for kem in kems:
                kem_type = KEM_TYPE.get(kem, "classique")
                display_kem = KEM_DISPLAY.get(kem, kem)
                combos.append({
                    'sig': sig,
                    'kem': kem,
                    'label': f"{sig}\n{display_kem}",
                    'sig_type': sig_label,
                    'kem_type': kem_type
                })
        
        fig, axes = plt.subplots(1, 2, figsize=(14, 8))
        #fig.suptitle(
         #   f"Figure 8 — HQC: Deployment heatmap — {level_title}\n"
          #  f"Mean handshake time (ms) | Red = slow | Yellow = fast",
           # fontsize=10, fontweight='bold', y=0.98
        #)
        
        for col, proto in enumerate(["TLS", "QUIC"]):
            ax = axes[col]
            mat = np.full((len(combos), len(SCEN_ORDER)), np.nan)
            
            for ri, combo in enumerate(combos):
                for ci, scen in enumerate(SCEN_ORDER):
                    try:
                        mat[ri, ci] = np.mean(data[proto][scen][combo['sig']][combo['kem']])
                    except (KeyError, ValueError):
                        pass
            
            mat_log = np.log10(np.where(mat > 0, mat, np.nan))
            vmin = 0
            vmax = np.nanmax(mat_log) if not np.all(np.isnan(mat_log)) else 3
            
            im = ax.imshow(mat_log, cmap='YlOrRd', aspect='auto', vmin=vmin, vmax=vmax)
            
            ax.set_xticks(range(len(SCEN_ORDER)))
            ax.set_xticklabels(SCEN_LABELS, fontsize=7)
            ax.set_yticks(range(len(combos)))
            ax.set_yticklabels([c['label'] for c in combos], fontsize=6)
            ax.set_title(f"{proto}", fontsize=11, fontweight='bold')
            ax.grid(False)
            
            # Ajouter les valeurs numériques
            for ri in range(mat.shape[0]):
                for ci in range(mat.shape[1]):
                    val = mat[ri, ci]
                    if not np.isnan(val):
                        log_val = mat_log[ri, ci] if not np.isnan(mat_log[ri, ci]) else vmin
                        txt_color = 'white' if log_val > (vmin + vmax) * 0.6 else '#222222'
                        if val < 1:
                            text = f"{val:.2f}"
                        elif val < 10:
                            text = f"{val:.1f}"
                        else:
                            text = f"{val:.0f}"
                        ax.text(ci, ri, text, ha='center', va='center',
                               fontsize=8 if val < 100 else 7, fontweight='bold', color=txt_color)
            
            # Séparateur visuel
            mid = len(combos) // 2
            ax.axhline(y=mid - 0.5, color='white', lw=2)
            
            cbar = plt.colorbar(im, ax=ax, shrink=0.7)
            cbar.set_label("log₁₀(ms)", fontsize=8)
            cbar.set_ticks([0, 1, 2, 3])
            cbar.set_ticklabels(['1 ms', '10 ms', '100 ms', '1000 ms'])
            cbar.ax.tick_params(labelsize=7)
        
        plt.tight_layout(rect=[0, 0, 1, 0.94])
        
        level_map = {1: "a", 3: "b", 5: "c"}
        suffix = level_map[level]
        pdf_path = os.path.join(out_dir, f"fig8{suffix}_level{level}_hqc_deployment_heatmap.pdf")
        png_path = pdf_path.replace('.pdf', '.png')
        
        plt.savefig(pdf_path, format='pdf')
        plt.savefig(png_path, format='png')
        plt.close()
        
        print(f"  ✅ Fig8{suffix} (Level {level}) : {pdf_path} + PNG")
    
    return True


# ============================================================================
# FIGURE 9 — Violin plots en conditions locales (35ms/2%) — 3 PDF
# ============================================================================
def fig9_local_yde_violin_plots(data, out_dir):
    """Figure 9 : Violin plots pour conditions locales (35ms/2%)"""
    
    local_scen = "africa_local"
    local_label = "Local YDE (35 ms RTT / 2% loss) — Critical threshold"
    
    for sig_c, sig_pq, level, level_title in SIG_PAIRS:
        kems = KEMS_BY_LEVEL[level]
        display_names = [KEM_DISPLAY.get(kem, kem) for kem in kems]
        
        fig, axes = plt.subplots(1, 2, figsize=(11, 5.5))
        #fig.suptitle(
         #   f"Figure 9 — HQC: Handshake time distributions under local conditions — {level_title}\n"
          #  f"{local_label} (500 runs)",
           # fontsize=10, fontweight='bold', y=0.98
        #)
        
        for col, proto in enumerate(["TLS", "QUIC"]):
            ax = axes[col]
            
            if sig_c not in data[proto].get(local_scen, {}) or \
               sig_pq not in data[proto].get(local_scen, {}):
                ax.text(0.5, 0.5, "No data", ha='center', va='center')
                ax.set_title(f"{proto}", fontsize=10, fontweight='bold')
                continue
            
            positions_c, positions_pq = [], []
            vals_c, vals_pq = [], []
            tick_positions, tick_labels = [], []
            x = 1
            spacing = 3
            
            for kem, disp_name in zip(kems, display_names):
                if kem not in data[proto][local_scen].get(sig_c, {}) or \
                   kem not in data[proto][local_scen].get(sig_pq, {}):
                    continue
                
                arr_c = data[proto][local_scen][sig_c][kem]
                arr_pq = data[proto][local_scen][sig_pq][kem]
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
            
            color_c = COLORS["classical"]
            color_pq = COLORS["pq"]
            
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
            ax.set_ylabel("Handshake time (ms)", fontsize=9)
            ax.set_title(f"{proto}", fontsize=10, fontweight='bold')
            ax.grid(True, alpha=0.25, linestyle=':')
            
            legend_elements = [
                mpatches.Patch(color=color_c, alpha=0.7, label=f"{sig_c} (classical)"),
                mpatches.Patch(color=color_pq, alpha=0.7, label=f"{sig_pq} (ML-DSA)"),
            ]
            ax.legend(handles=legend_elements, loc='upper left', framealpha=0.9, fontsize=8)
        
        plt.tight_layout(rect=[0, 0, 1, 0.94])
        
        level_map = {1: "a", 3: "b", 5: "c"}
        suffix = level_map[level]
        pdf_path = os.path.join(out_dir, f"fig9{suffix}_level{level}_hqc_local_yde_violin.pdf")
        png_path = pdf_path.replace('.pdf', '.png')
        
        plt.savefig(pdf_path, format='pdf')
        plt.savefig(png_path, format='png')
        plt.close()
        
        print(f"  ✅ Fig9{suffix} (Level {level}) : {pdf_path} + PNG")
    
    return True


# ============================================================================
# FIGURE 10 — Category summary (1 PDF)
# ============================================================================
def fig10_category_summary(data, out_dir):
    """Figure 10 : Résumé par catégorie (Classical / HQC pur / HQC hybride)"""
    
    categories_order = ["classique", "HQC pur", "HQC hybride"]
    category_labels = ["Classical KEM", "HQC Pure", "HQC Hybrid"]
    
    sig_classic_map = {1: "ed25519", 3: "secp384r1", 5: "secp521r1"}
    sig_pq_map = {1: "mldsa44", 3: "mldsa65", 5: "mldsa87"}
    
    fig, axes = plt.subplots(2, 4, figsize=(16, 8))
    #fig.suptitle(
     #   "Figure 10 — HQC: Handshake time by category (Signature × KEM type)\n"
      #  "Hatched bars = ML-DSA signature | Solid bars = Classical signature",
       # fontsize=11, fontweight='bold', y=0.98
    #)
    
    for col, scen in enumerate(SCEN_ORDER):
        for row, proto in enumerate(["TLS", "QUIC"]):
            ax = axes[row][col]
            x = np.arange(len(categories_order))
            width = 0.35
            
            means_classic, means_pq = [], []
            
            for cat in categories_order:
                vals_c, vals_pq = [], []
                for lvl in [1, 3, 5]:
                    sig_c = sig_classic_map[lvl]
                    sig_pq = sig_pq_map[lvl]
                    for kem in KEMS_BY_LEVEL[lvl]:
                        if KEM_TYPE.get(kem, "") != cat:
                            continue
                        try:
                            vals_c.append(np.mean(data[proto][scen][sig_c][kem]))
                        except KeyError:
                            pass
                        try:
                            vals_pq.append(np.mean(data[proto][scen][sig_pq][kem]))
                        except KeyError:
                            pass
                means_classic.append(np.mean(vals_c) if vals_c else 0)
                means_pq.append(np.mean(vals_pq) if vals_pq else 0)
            
            colors = [HQC_COLORS[c] for c in categories_order]
            bars_c = ax.bar(x - width/2, means_classic, width,
                           color=colors, alpha=0.85, edgecolor='white')
            bars_pq = ax.bar(x + width/2, means_pq, width,
                            color=colors, alpha=0.55, hatch='//', edgecolor='white')
            
            for bar in list(bars_c) + list(bars_pq):
                h = bar.get_height()
                if h > 0:
                    ax.text(bar.get_x() + bar.get_width()/2, h + 0.5,
                           f"{h:.0f}", ha='center', va='bottom', fontsize=6)
            
            ax.set_xticks(x)
            ax.set_xticklabels(category_labels, fontsize=7)
            ax.set_ylabel("Mean handshake time (ms)", fontsize=8)
            ax.set_title(f"{proto}\n{SCENARIOS[scen]['label']}", fontsize=8, fontweight='bold')
            ax.grid(True, axis='y', alpha=0.25, linestyle=':')
            
            if col == 0 and row == 0:
                ax.legend([bars_c, bars_pq], ['Classical signature', 'ML-DSA signature'],
                         fontsize=7, loc='upper left')
    
    # Légende générale pour les couleurs des barres
    legend_elements = [
        mpatches.Patch(color=HQC_COLORS["classique"], label='Classical KEM'),
        mpatches.Patch(color=HQC_COLORS["HQC pur"], label='HQC Pure'),
        mpatches.Patch(color=HQC_COLORS["HQC hybride"], label='HQC Hybrid'),
    ]
    fig.legend(handles=legend_elements, loc='lower center',
              bbox_to_anchor=(0.5, -0.02), ncol=3, fontsize=8)
    
    plt.tight_layout(rect=[0, 0.02, 1, 0.95])
    
    pdf_path = os.path.join(out_dir, "fig10_hqc_category_summary.pdf")
    png_path = pdf_path.replace('.pdf', '.png')
    plt.savefig(pdf_path, format='pdf')
    plt.savefig(png_path, format='png')
    plt.close()
    
    print(f"  ✅ Fig10 : {pdf_path} + PNG")
    return True


# ============================================================================
# MAIN
# ============================================================================
def main():
    parser = argparse.ArgumentParser(
        description="Generate HQC Africa figures (publication quality)"
    )
    parser.add_argument("--data-dir", required=True,
                       help="Root directory (contains TLS/csv/ and QUIC/csv/)")
    parser.add_argument("--out-dir", default=None,
                       help="Output directory (default: data-dir/plots/)")
    args = parser.parse_args()
    
    out_dir = args.out_dir or os.path.join(args.data_dir, "plots")
    os.makedirs(out_dir, exist_ok=True)
    
    print("\n" + "="*60)
    print("  HQC STUDY — GENERATING AFRICA SCENARIO FIGURES")
    print("="*60)
    print(f"  Data dir   : {args.data_dir}")
    print(f"  Output dir : {out_dir}")
    print("="*60 + "\n")
    
    print("Loading HQC Africa data...")
    data = load_all(args.data_dir)
    
    # Vérification
    n_tls = len(data.get("TLS", {}))
    n_quic = len(data.get("QUIC", {}))
    print(f"✅ TLS scenarios: {n_tls}, QUIC scenarios: {n_quic}\n")
    
    print("Generating figures...\n")
    
    fig6_delta_evolution_by_level(data, out_dir)
    fig7_tls_quic_reversal_by_level(data, out_dir)
    fig8_deployment_heatmap_by_level(data, out_dir)
    fig9_local_yde_violin_plots(data, out_dir)
    fig10_category_summary(data, out_dir)
    
    print("\n" + "="*60)
    print("✅ ALL HQC AFRICA FIGURES GENERATED")
    print(f"   Output: {out_dir}")
    print("\n   Files:")
    print("   Figure 6 (Delta evolution):")
    print("     - fig6a_level1_hqc_delta_evolution.pdf / .png")
    print("     - fig6b_level3_hqc_delta_evolution.pdf / .png")
    print("     - fig6c_level5_hqc_delta_evolution.pdf / .png")
    print("   Figure 7 (Protocol reversal):")
    print("     - fig7a_level1_hqc_protocol_reversal.pdf / .png")
    print("     - fig7b_level3_hqc_protocol_reversal.pdf / .png")
    print("     - fig7c_level5_hqc_protocol_reversal.pdf / .png")
    print("   Figure 8 (Deployment heatmap):")
    print("     - fig8a_level1_hqc_deployment_heatmap.pdf / .png")
    print("     - fig8b_level3_hqc_deployment_heatmap.pdf / .png")
    print("     - fig8c_level5_hqc_deployment_heatmap.pdf / .png")
    print("   Figure 9 (Local YDE violin):")
    print("     - fig9a_level1_hqc_local_yde_violin.pdf / .png")
    print("     - fig9b_level3_hqc_local_yde_violin.pdf / .png")
    print("     - fig9c_level5_hqc_local_yde_violin.pdf / .png")
    print("   Figure 10 (Category summary):")
    print("     - fig10_hqc_category_summary.pdf / .png")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()
