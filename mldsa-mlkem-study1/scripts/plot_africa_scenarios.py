#!/usr/bin/env python3
"""
plot_africa_scenarios.py 
=========================================================
Figures pour conditions réseau africaines avec :
- Figure 6 : découpée par niveau de sécurité (3 PDF)
- Figure 7 : découpée par niveau de sécurité (3 PDF)
- Figure 8 : découpée par niveau de sécurité (3 PDF) avec chiffres lisibles
- Figure 9 : violon plots en conditions dégradées (3 PDF, un par niveau)
"""

import os
import argparse
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

# ============================================================================
# CONFIGURATION PUBLICATION
# ============================================================================
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

NIST_LEVELS = {
    "ed25519": 1, "mldsa44": 1,
    "secp384r1": 3, "mldsa65": 3,
    "secp521r1": 5, "mldsa87": 5,
}

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

KEM_COLORS = {
    "classical": "#2E75B6",  # Bleu
    "hybrid":    "#BF9000",  # Ocre
    "pq_pure":   "#C55A11",  # Orange
}
KEM_MARKERS = {"classical": "o", "hybrid": "s", "pq_pure": "^"}
KEM_TYPE_LABEL = {"classical": "Classical KEM", "hybrid": "Hybrid KEM", "pq_pure": "PQ KEM"}

SIG_PQ = {"mldsa44", "mldsa65", "mldsa87"}
SIG_CLASSICAL = {"ed25519", "secp384r1", "secp521r1"}

# Couleurs signatures (cohérentes avec figures précédentes)
SIG_COLORS = {
    "classical": "#E69F00",  # ORANGE
    "pq": "#56B4E9",         # BLEU
}


# ============================================================================
# CHARGEMENT DES DONNÉES
# ============================================================================
def load_all(data_dir):
    data = {}
    for proto in ["TLS", "QUIC"]:
        data[proto] = {}
        for scen in SCENARIOS:
            data[proto][scen] = {}
            for sig in NIST_LEVELS:
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
# FIGURE 6 — Évolution Δ% (un PDF par niveau de sécurité)
# ============================================================================
def fig6_delta_evolution_by_level(data, out_dir):
    """Figure 6 : 3 PDF (L1, L3, L5) avec évolution du surcoût ML-DSA"""
    
    for sig_c, sig_pq, level, level_title in SIG_PAIRS:
        fig, axes = plt.subplots(1, 2, figsize=(11, 5))
        #fig.suptitle(
         #   f"Figure 6 — ML-DSA overhead evolution — {level_title}\n"
          #  f"Negative Δ% = ML-DSA faster | Positive Δ% = ML-DSA slower",
           # fontsize=11, fontweight='bold', y=0.98
        #)
        
        x_pos = np.arange(len(SCEN_ORDER))
        kems = KEMS_BY_LEVEL[level]
        
        for col, proto in enumerate(["TLS", "QUIC"]):
            ax = axes[col]
            
            ax.axhline(y=0, color='#333333', lw=1.5, ls='--', alpha=0.7)
            ax.axhspan(-200, 0, alpha=0.05, color='#44AA77')   # Vert clair
            ax.axhspan(0, 200, alpha=0.05, color='#CC6677')    # Rouge clair
            
            for kem in kems:
                deltas = []
                for scen in SCEN_ORDER:
                    try:
                        mc = np.mean(data[proto][scen][sig_c][kem])
                        mp = np.mean(data[proto][scen][sig_pq][kem])
                        deltas.append(((mp - mc) / mc) * 100)
                    except KeyError:
                        deltas.append(np.nan)
                
                kt = KEM_TYPE.get(kem, "classical")
                color = KEM_COLORS.get(kt, "#999999")
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
                           color=color, fontweight='medium')
            
            ax.set_xticks(x_pos)
            ax.set_xticklabels(SCEN_LABELS, fontsize=7)
            ax.set_ylabel("Δ% (ML-DSA vs Classical)", fontsize=9)
            ax.set_xlabel("Network scenario", fontsize=9)
            ax.set_title(f"{proto}", fontsize=10, fontweight='bold')
            ax.grid(True, alpha=0.25, linestyle=':')
            
            for xv in [0.5, 1.5, 2.5]:
                ax.axvline(x=xv, color='gray', lw=0.6, ls=':', alpha=0.5)
            
            # Légende
            legend_elements = [
                mpatches.Patch(color=KEM_COLORS["classical"], label='Classical KEM'),
                mpatches.Patch(color=KEM_COLORS["hybrid"], label='Hybrid KEM'),
                mpatches.Patch(color=KEM_COLORS["pq_pure"], label='PQ KEM'),
                plt.Line2D([0], [0], color='#333333', ls='--', label='Δ% = 0 (parity)'),
            ]
            ax.legend(handles=legend_elements, loc='upper left', fontsize=7, framealpha=0.9)
        
        plt.tight_layout(rect=[0, 0, 1, 0.94])
        
        level_map = {1: "a", 3: "b", 5: "c"}
        suffix = level_map[level]
        pdf_path = os.path.join(out_dir, f"fig6{suffix}_level{level}_delta_evolution.pdf")
        png_path = pdf_path.replace('.pdf', '.png')
        
        plt.savefig(pdf_path, format='pdf')
        plt.savefig(png_path, format='png')
        plt.close()
        
        print(f"✅ Fig6{suffix} (Level {level}) : {pdf_path} + PNG")
    
    return True


# ============================================================================
# FIGURE 7 — Renversement TLS vs QUIC 
# ============================================================================
def fig7_tls_quic_reversal_by_level(data, out_dir):
    """Figure 7 : 3 PDF (L1, L3, L5) avec TLS vs QUIC reversal"""
    
    for sig_c, sig_pq, level, level_title in SIG_PAIRS:
        fig, axes = plt.subplots(1, 2, figsize=(11, 5))
        #fig.suptitle(
         #   f"Figure 7 — TLS vs QUIC protocol reversal — {level_title}\n"
          #  f"Positive = TLS slower | Negative = TLS faster (TLS > QUIC)",
           # fontsize=11, fontweight='bold', y=0.98
        #)
        
        x_pos = np.arange(len(SCEN_ORDER))
        kems = KEMS_BY_LEVEL[level]
        
        for col, proto_sig in enumerate([sig_c, sig_pq]):
            ax = axes[col]
            sig = proto_sig
            sig_type = "ML-DSA" if sig in SIG_PQ else "Classical"
            sig_color = SIG_COLORS["pq"] if sig in SIG_PQ else SIG_COLORS["classical"]
            
            ax.axhline(y=0, color='#333333', lw=1.5, ls='--', alpha=0.7)
            ax.axhspan(-600, 0, alpha=0.05, color='#44AA77')   # Vert (TLS meilleur)
            ax.axhspan(0, 600, alpha=0.05, color='#CC6677')    # Rouge (QUIC meilleur)
            
            for kem in kems:
                diffs = []
                for scen in SCEN_ORDER:
                    try:
                        mt = np.mean(data["TLS"][scen][sig][kem])
                        mq = np.mean(data["QUIC"][scen][sig][kem])
                        diffs.append(((mt - mq) / mq) * 100)
                    except KeyError:
                        diffs.append(np.nan)
                
                kt = KEM_TYPE.get(kem, "classical")
                color = KEM_COLORS.get(kt, "#999999")
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
                           color=color, fontweight='medium')
            
            ax.set_xticks(x_pos)
            ax.set_xticklabels(SCEN_LABELS, fontsize=7)
            ax.set_ylabel("(TLS − QUIC) / QUIC × 100 (%)", fontsize=9)
            ax.set_xlabel("Network scenario", fontsize=9)
            ax.set_title(f"Signature: {sig} ({sig_type})", fontsize=10, fontweight='bold')
            ax.grid(True, alpha=0.25, linestyle=':')
            
            for xv in [0.5, 1.5, 2.5]:
                ax.axvline(x=xv, color='gray', lw=0.6, ls=':', alpha=0.5)
            
            # Légende
            legend_elements = [
                mpatches.Patch(color=KEM_COLORS["classical"], label='Classical KEM'),
                mpatches.Patch(color=KEM_COLORS["hybrid"], label='Hybrid KEM'),
                mpatches.Patch(color=KEM_COLORS["pq_pure"], label='PQ KEM'),
                mpatches.Patch(color='#44AA77', alpha=0.3, label='TLS faster (negative)'),
                mpatches.Patch(color='#CC6677', alpha=0.3, label='QUIC faster (positive)'),
            ]
            ax.legend(handles=legend_elements, loc='upper left', fontsize=6, framealpha=0.9)
        
        plt.tight_layout(rect=[0, 0, 1, 0.94])
        
        level_map = {1: "a", 3: "b", 5: "c"}
        suffix = level_map[level]
        pdf_path = os.path.join(out_dir, f"fig7{suffix}_level{level}_protocol_reversal.pdf")
        png_path = pdf_path.replace('.pdf', '.png')
        
        plt.savefig(pdf_path, format='pdf')
        plt.savefig(png_path, format='png')
        plt.close()
        
        print(f"✅ Fig7{suffix} (Level {level}) : {pdf_path} + PNG")
    
    return True


# ============================================================================
# FIGURE 8 — Heatmap déploiement 
# ============================================================================
def fig8_deployment_heatmap_by_level(data, out_dir):
    """Figure 8 : 3 PDF (L1, L3, L5) avec heatmap déploiement lisible"""
    
    for sig_c, sig_pq, level, level_title in SIG_PAIRS:
        kems = KEMS_BY_LEVEL[level]
        
        # Construire les combinaisons pour ce niveau uniquement
        combos = []
        for sig in [sig_c, sig_pq]:
            sig_label = "Classical" if sig in SIG_CLASSICAL else "ML-DSA"
            for kem in kems:
                kem_type = KEM_TYPE.get(kem, "classical")
                kem_label = KEM_TYPE_LABEL.get(kem_type, kem)
                display_kem = KEM_DISPLAY.get(kem, kem)
                combos.append({
                    'sig': sig,
                    'kem': kem,
                    'label': f"{sig}\n({display_kem[:10]})",
                    'sig_type': sig_label,
                    'kem_type': kem_type
                })
        
        fig, axes = plt.subplots(1, 2, figsize=(14, 8))
        #fig.suptitle(
         #   f"Figure 8 — Deployment heatmap — {level_title}\n"
          #  f"Mean handshake time (ms) | Red = slow | Yellow = fast",
           # fontsize=11, fontweight='bold', y=0.98
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
            
            # Échelle logarithmique pour meilleure lisibilité
            mat_log = np.log10(np.where(mat > 0, mat, np.nan))
            vmin = 0  # 1 ms
            vmax = np.nanmax(mat_log) if not np.all(np.isnan(mat_log)) else 3  # 1000 ms
            
            im = ax.imshow(mat_log, cmap='YlOrRd', aspect='auto', vmin=vmin, vmax=vmax)
            
            ax.set_xticks(range(len(SCEN_ORDER)))
            ax.set_xticklabels(SCEN_LABELS, fontsize=7)
            ax.set_yticks(range(len(combos)))
            ax.set_yticklabels([c['label'] for c in combos], fontsize=7)
            ax.set_title(f"{proto}", fontsize=11, fontweight='bold')
            ax.grid(False)
            
            # Ajouter les valeurs numériques (chiffres PLUS GROS et lisibles)
            for ri in range(mat.shape[0]):
                for ci in range(mat.shape[1]):
                    val = mat[ri, ci]
                    if not np.isnan(val):
                        # Déterminer couleur du texte selon fond
                        log_val = mat_log[ri, ci] if not np.isnan(mat_log[ri, ci]) else vmin
                        txt_color = 'white' if log_val > (vmin + vmax) * 0.6 else '#222222'
                        # Format: <1 ms = "X.X ms" | >=1 ms = "XX ms"
                        if val < 1:
                            text = f"{val:.2f}"
                        elif val < 10:
                            text = f"{val:.1f}"
                        else:
                            text = f"{val:.0f}"
                        ax.text(ci, ri, text,
                               ha='center', va='center',
                               fontsize=9 if val < 100 else 7,
                               fontweight='bold', color=txt_color)
            
            # Séparateurs visuels entre types de signatures
            mid = len(combos) // 2
            ax.axhline(y=mid - 0.5, color='white', lw=2)
            
            # Colorbar
            cbar = plt.colorbar(im, ax=ax, shrink=0.7)
            cbar.set_label("log₁₀(ms)", fontsize=8)
            cbar.set_ticks([0, 1, 2, 3])
            cbar.set_ticklabels(['1 ms', '10 ms', '100 ms', '1000 ms'])
            cbar.ax.tick_params(labelsize=7)
        
        plt.tight_layout(rect=[0, 0, 1, 0.94])
        
        level_map = {1: "a", 3: "b", 5: "c"}
        suffix = level_map[level]
        pdf_path = os.path.join(out_dir, f"fig8{suffix}_level{level}_deployment_heatmap.pdf")
        png_path = pdf_path.replace('.pdf', '.png')
        
        plt.savefig(pdf_path, format='pdf')
        plt.savefig(png_path, format='png')
        plt.close()
        
        print(f"✅ Fig8{suffix} (Level {level}) : {pdf_path} + PNG")
    
    return True


# ============================================================================


# ============================================================================
# FIGURE 9 — Violin plots en conditions LOCALES (35ms/2%)
# ============================================================================
def fig9_local_yde_violin_plots(data, out_dir):
    """
    Figure 9 : Violin plots pour conditions réseau LOCALES (35ms/2%)
    C'est le scénario PERTINENT car c'est celui où :
    - Le renversement TLS > QUIC se produit
    - ML-DSA commence à devenir pénalisant
    - C'est le seuil critique de 35 ms RTT identifié dans l'article
    """
    
    local_scen = "africa_local"
    local_label = "Local YDE (35 ms RTT / 2% loss) — Critical threshold scenario"
    
    for sig_c, sig_pq, level, level_title in SIG_PAIRS:
        kems = KEMS_BY_LEVEL[level]
        display_names = [KEM_DISPLAY.get(k, k) for k in kems]
        
        fig, axes = plt.subplots(1, 2, figsize=(11, 5.5))
        #fig.suptitle(
         #   f"Figure 9 — Handshake time distributions under local network conditions — {level_title}\n"
          #  f"{local_label} (500 runs) | At this RTT, the TLS > QUIC reversal occurs",
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
            x = 1
            spacing = 3
            
            for kem, disp_name in zip(kems, display_names):
                if kem not in data[proto][local_scen].get(sig_c, {}) or \
                   kem not in data[proto][local_scen].get(sig_pq, {}):
                    continue
                
                arr_c = data[proto][local_scen][sig_c][kem]
                arr_pq = data[proto][local_scen][sig_pq][kem]
                
                # Élaguer les outliers extrêmes (99e percentile)
                all_vals = np.concatenate([arr_c, arr_pq])
                cap = np.percentile(all_vals, 99)
                vals_c.append(np.clip(arr_c, 0, cap))
                vals_pq.append(np.clip(arr_pq, 0, cap))
                positions_c.append(x)
                positions_pq.append(x + 1)
                x += spacing
            
            if not vals_c:
                continue
            
            # Couleurs cohérentes : ORANGE = classique, BLEU = ML-DSA
            color_c = SIG_COLORS["classical"]  # #E69F00
            color_pq = SIG_COLORS["pq"]         # #56B4E9
            
            # Violin plots
            vp_c = ax.violinplot(vals_c, positions=positions_c,
                                showmedians=True, widths=0.8)
            vp_pq = ax.violinplot(vals_pq, positions=positions_pq,
                                 showmedians=True, widths=0.8)
            
            # Styliser classique (ORANGE)
            for pc in vp_c['bodies']:
                pc.set_facecolor(color_c)
                pc.set_alpha(0.7)
                pc.set_edgecolor('white')
                pc.set_linewidth(0.5)
            for part in ['cmedians', 'cmins', 'cmaxes', 'cbars']:
                if part in vp_c:
                    vp_c[part].set_color(color_c)
                    vp_c[part].set_linewidth(1.2)
            
            # Styliser ML-DSA (BLEU)
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
            ax.set_ylabel("Handshake time (ms)", fontsize=9)
            ax.set_title(f"{proto}", fontsize=10, fontweight='bold')
            ax.grid(True, alpha=0.25, linestyle=':')
            
            # Légende en haut à gauche
            legend_elements = [
                mpatches.Patch(color=color_c, alpha=0.7, label=f"{sig_c} (classical)"),
                mpatches.Patch(color=color_pq, alpha=0.7, label=f"{sig_pq} (ML-DSA)"),
            ]
            ax.legend(handles=legend_elements, loc='upper left', framealpha=0.9, fontsize=8)
            
            # Ajouter une annotation soulignant le renversement (uniquement pour TLS/QUIC)
            if proto == "TLS":
                # Calculer la médiane pour TLS ML-DSA et QUIC ML-DSA pour ce niveau
                try:
                    tls_vals = []
                    quic_vals = []
                    for kem in kems:
                        if kem in data["TLS"][local_scen].get(sig_pq, {}):
                            tls_vals.extend(data["TLS"][local_scen][sig_pq][kem])
                        if kem in data["QUIC"][local_scen].get(sig_pq, {}):
                            quic_vals.extend(data["QUIC"][local_scen][sig_pq][kem])
                    if tls_vals and quic_vals:
                        median_tls = np.median(tls_vals)
                        median_quic = np.median(quic_vals)
                        if median_tls < median_quic:
                            ax.annotate("TLS > QUIC\nreversal",
                                       xy=(0.98, 0.95), xycoords='axes fraction',
                                       ha='right', va='top', fontsize=7,
                                       color='red', fontweight='bold',
                                       bbox=dict(boxstyle="round,pad=0.3",
                                                facecolor='white', alpha=0.8))
                except Exception:
                    pass
        
        plt.tight_layout(rect=[0, 0, 1, 0.94])
        
        level_map = {1: "a", 3: "b", 5: "c"}
        suffix = level_map[level]
        pdf_path = os.path.join(out_dir, f"fig9{suffix}_level{level}_local_yde_violin.pdf")
        png_path = pdf_path.replace('.pdf', '.png')
        
        plt.savefig(pdf_path, format='pdf')
        plt.savefig(png_path, format='png')
        plt.close()
        
        print(f"✅ Fig9{suffix} (Level {level}) : {pdf_path} + PNG")
    
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
    print("GENERATING FIGURES 6-9 — FINAL VERSION")
    print("="*60)
    print(f"Data dir  : {args.data_dir}")
    print(f"Output dir: {out_dir}")
    print("="*60 + "\n")
    
    data = load_all(args.data_dir)
    print(f"✓ Loaded data\n")
    
    print("Generating figures...\n")
    
    fig6_delta_evolution_by_level(data, out_dir)
    fig7_tls_quic_reversal_by_level(data, out_dir)
    fig8_deployment_heatmap_by_level(data, out_dir)
    fig9_local_yde_violin_plots(data, out_dir)
    
    print("\n" + "="*60)
    print("✅ ALL FIGURES GENERATED (PDF + PNG)")
    print(f"   Output: {out_dir}")
    print("\n   Files generated:")
    print("   Figure 6 (Delta evolution):")
    print("     - fig6a_level1_delta_evolution.pdf / .png")
    print("     - fig6b_level3_delta_evolution.pdf / .png")
    print("     - fig6c_level5_delta_evolution.pdf / .png")
    print("   Figure 7 (Protocol reversal):")
    print("     - fig7a_level1_protocol_reversal.pdf / .png")
    print("     - fig7b_level3_protocol_reversal.pdf / .png")
    print("     - fig7c_level5_protocol_reversal.pdf / .png")
    print("   Figure 8 (Deployment heatmap):")
    print("     - fig8a_level1_deployment_heatmap.pdf / .png")
    print("     - fig8b_level3_deployment_heatmap.pdf / .png")
    print("     - fig8c_level5_deployment_heatmap.pdf / .png")
    print("   Figure 9 (Degraded conditions violin):")
    print("     - fig9a_level1_degraded_violin.pdf / .png")
    print("     - fig9b_level3_degraded_violin.pdf / .png")
    print("     - fig9c_level5_degraded_violin.pdf / .png")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()
