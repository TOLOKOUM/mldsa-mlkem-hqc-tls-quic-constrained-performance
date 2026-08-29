"""
plot_handshake_latency.py — Figures de latence de handshake avec tableau de synthèse intégré

Structure de la figure (inspirée de Montenegro et al., Computer Networks 2026, Fig. 3/4/5) :
  (a), (b), ... : panels violon+boxplot, un par sig_alg (classique / post-quantique)
  (c)           : tableau descriptif synthétique (Mean, CV%, Max, [Fail]) par KEM et par panel

Les statistiques du tableau (c) sont calculées à partir des MÊMES tableaux bruts déjà
chargés pour dessiner les violons (pas une deuxième lecture de handshake_report.md), avec
une vérification croisée automatique contre mean_ms de handshake_stats.csv (si la colonne
existe) : un avertissement est émis en console si l'écart relatif dépasse 2 %.
"""

import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib
import matplotlib.pyplot as plt

print(f"[INFO] matplotlib version: {matplotlib.__version__}")

sys.path.insert(0, str(Path(__file__).resolve().parent))
from plot_style import (
    FIGSIZE_SINGLE_COL, KEM_FAMILY_COLORS, KEM_FAMILY_ORDER,
    classify_kem_family, kem_family_legend_handles, style_axes, save_figure,
    SECURITY_LEVEL_ORDER, SCENARIO_SLUGS,
)

PROTOCOL_AUTH_PAIRS = [("tls", "single"), ("tls", "mutual"), ("quic", "single")]

LOG_SCALE = True
YLIM_HEADROOM = 1.2           # marge réduite : plus besoin de place pour les annotations "max"
MEAN_CROSS_CHECK_TOL = 0.02   # tolérance 2% entre mean recalculé et handshake_stats.csv

_KEM_TOKEN_MAP = {
    "p256": "P-256", "p384": "P-384", "p521": "P-521",
    "x25519": "X25519", "x448": "X448",
    "hqc128": "HQC-128", "hqc192": "HQC-192", "hqc256": "HQC-256",
    "mlkem512": "ML-KEM-512", "mlkem768": "ML-KEM-768", "mlkem1024": "ML-KEM-1024",
}


def format_kem_label(kem: str) -> str:
    """Label deux-lignes utilisé sous les violons (compact)."""
    kem_norm = kem.strip()
    if kem_norm in ("P-256", "P-384", "P-521"):
        return kem_norm
    parts = kem_norm.lower().split("_")
    mapped = [_KEM_TOKEN_MAP.get(p, p) for p in parts]
    if len(mapped) > 1:
        return f"{mapped[0]}+\n{mapped[1]}"
    return mapped[0]


def format_kem_label_flat(kem: str) -> str:
    """Label une-ligne utilisé comme libellé de ligne dans le tableau (c)."""
    kem_norm = kem.strip()
    if kem_norm in ("P-256", "P-384", "P-521"):
        return kem_norm
    parts = kem_norm.lower().split("_")
    mapped = [_KEM_TOKEN_MAP.get(p, p) for p in parts]
    return "+".join(mapped)


import re

BLOCK_SUFFIX_RE = re.compile(r"_block(\d+)of(\d+)$")


def raw_csv_paths(root: Path, protocol: str, auth_mode: str, scenario_dir: str,
                   sig_alg: str, kem: str) -> list:
    """Retourne TOUS les fichiers CSV bruts d'une combinaison, tous blocs confondus.

    Depuis le découpage de la campagne en N_BLOCKS (cf. Launcher_pq_mldsa_mlkem_hqc.sh
    et logs_to_csv.py), une combinaison SIG_ALG/KEM produit un fichier CSV PAR BLOC
    (ex: handshake_tls_single_ed25519_P-256_none_block1of4.csv, ..._block2of4.csv, ...)
    et non plus un seul fichier -- raw_csv_path (ancienne version, un seul chemin en
    dur sans suffixe) ne trouvait donc plus rien, ce qui vidait silencieusement
    table_rows et faisait planter table_ax.table() sur une liste vide.

    Un fichier sans suffixe _blockNofM est traité comme bloc unique, pour
    compatibilité avec d'éventuels logs pré-découpage en blocs (même convention
    que parse_block_suffix dans logs_to_csv.py)."""
    base_stem = f"handshake_{protocol}_{auth_mode}_{sig_alg}_{kem}_{scenario_dir}"
    csv_dir = root / "csv"
    if not csv_dir.is_dir():
        return []
    matches = []
    for f in sorted(csv_dir.glob(f"{base_stem}*.csv")):
        suffix = f.stem[len(base_stem):]
        if suffix == "" or BLOCK_SUFFIX_RE.fullmatch(suffix):
            matches.append(f)
    return matches


def load_success_durations(csv_paths, expected_n_blocks: int = None, combo_label: str = ""):
    """Concatène TOUS les blocs d'une combinaison avant de calculer quoi que ce
    soit -- sinon chaque figure ne représenterait qu'un sous-ensemble arbitraire
    (souvent un seul bloc sur 4) des 500 handshakes réellement collectés.

    Avertit explicitement si des blocs manquent sur disque par rapport au nombre
    de blocs déclaré dans les données (colonne n_blocks) -- pour éviter qu'un
    bloc absent (campagne interrompue, fichier non copié, etc.) passe inaperçu
    et fausse silencieusement les figures et le tableau (c)."""
    if not csv_paths:
        return np.array([]), 0, 0, 0
    dfs = [pd.read_csv(p) for p in csv_paths]
    df = pd.concat(dfs, ignore_index=True)
    n_total = len(df)

    n_blocks_seen = df["block_index"].nunique() if "block_index" in df.columns else 1
    n_blocks_declared = int(df["n_blocks"].max()) if "n_blocks" in df.columns and n_total else 1
    if expected_n_blocks is None:
        expected_n_blocks = n_blocks_declared
    if n_blocks_seen < expected_n_blocks:
        print(f"[WARN] {combo_label} : seulement {n_blocks_seen}/{expected_n_blocks} "
              f"bloc(s) trouvé(s) sur disque -- figure/tableau construits sur des "
              f"données PARTIELLES pour cette combinaison.")

    ok = df[df["success"] == 1]
    n_failed = n_total - len(ok)
    return ok["handshake_duration_ms"].to_numpy(dtype=float), n_failed, n_total, n_blocks_seen


def fmt_ms(x):
    """Formatage compact d'une durée en ms (ex: 7771474 -> '7.77M', 322.4 -> '322.4')."""
    if x is None or (isinstance(x, float) and np.isnan(x)):
        return "—"
    ax = abs(x)
    if ax >= 1e6:
        return f"{x/1e6:.2f}M"
    if ax >= 1e3:
        return f"{x/1e3:.2f}k"
    if ax >= 10:
        return f"{x:.1f}"
    return f"{x:.2f}"


def fmt_pct(x):
    if x is None or (isinstance(x, float) and np.isnan(x)):
        return "—"
    return f"{x:.1f}"


def compute_kem_stats(durations: np.ndarray, n_failed: int, n_total: int, n_blocks_seen: int = 1) -> dict:
    """Statistiques descriptives calculées sur les durées de handshake réussies."""
    n = durations.size
    mean = float(np.mean(durations)) if n else float("nan")
    std = float(np.std(durations, ddof=1)) if n > 1 else 0.0
    cv = (std / mean * 100.0) if mean else float("nan")
    if n:
        q1, q3 = np.percentile(durations, [25, 75])
        iqr = q3 - q1
        lower, upper = q1 - 1.5 * iqr, q3 + 1.5 * iqr
        out_pct = float(np.mean((durations < lower) | (durations > upper)) * 100.0)
        max_v = float(durations.max())
    else:
        out_pct, max_v = float("nan"), float("nan")
    return dict(mean=mean, cv=cv, out_pct=out_pct, max=max_v,
                n_failed=int(n_failed), n_total=int(n_total), n_blocks_seen=int(n_blocks_seen))


def build_panel(ax, root, protocol, auth_mode, scenario_dir, sig_alg, level_rows,
                 families_used: set, read_counter: dict):
    """
    Dessine un panel violon+boxplot pour un sig_alg donné et calcule, EN PARALLELE et à
    partir des MEMES fichiers CSV bruts, les statistiques par KEM utilisées ensuite dans
    le tableau (c). Aucune deuxième lecture de handshake_report.md n'est effectuée.

    Retourne (ylim, positions, data, table_rows).
    table_rows : liste ordonnée de dicts {fam, kem, label, stats}.
    """
    entries = []
    for _, r in level_rows.iterrows():
        fam = classify_kem_family(r.kem_class, r.kem)
        entries.append((fam, r))
    entries.sort(key=lambda e: (KEM_FAMILY_ORDER.index(e[0]), e[1].kem))

    data, colors, labels = [], [], []
    table_rows = []

    for fam, r in entries:
        kem = r.kem
        csv_paths = raw_csv_paths(root, protocol, auth_mode, scenario_dir, sig_alg, kem)
        if not csv_paths:
            continue
        ref_n_blocks = getattr(r, "n_blocks_pooled", None)
        expected_n_blocks = int(ref_n_blocks) if ref_n_blocks is not None and not pd.isna(ref_n_blocks) else None
        durations, n_failed, n_total, n_blocks_seen = load_success_durations(
            csv_paths, expected_n_blocks=expected_n_blocks,
            combo_label=f"{sig_alg}/{kem}/{scenario_dir}",
        )
        read_counter["n_files"] += len(csv_paths)
        read_counter["n_rows"] += n_total

        stats = compute_kem_stats(durations, n_failed, n_total, n_blocks_seen)

        # --- Vérification croisée avec handshake_stats.csv (si mean_ms est disponible) ---
        ref_mean = getattr(r, "mean_ms", None)
        if ref_mean is not None and not pd.isna(ref_mean) and ref_mean != 0 and stats["mean"] == stats["mean"]:
            rel_diff = abs(stats["mean"] - ref_mean) / abs(ref_mean)
            if rel_diff > MEAN_CROSS_CHECK_TOL:
                print(f"[WARN] mean_ms diverge de {rel_diff*100:.1f}% pour {sig_alg}/{kem}/{scenario_dir} "
                      f"(recalculé={stats['mean']:.1f} ms, handshake_stats.csv={ref_mean:.1f} ms)")

        table_rows.append(dict(fam=fam, kem=kem, label=format_kem_label_flat(kem), stats=stats))

        if durations.size == 0:
            continue
        data.append(durations)
        colors.append(KEM_FAMILY_COLORS[fam])
        labels.append(format_kem_label(kem))
        families_used.add(fam)

    if not data:
        ax.text(0.5, 0.5, "No data available", ha="center", va="center",
                 transform=ax.transAxes, fontsize=8, color="#999999")
        return None, [], [], table_rows

    positions = list(range(1, len(data) + 1))

    parts = ax.violinplot(data, positions=positions, showmeans=False, showextrema=False, widths=0.7)
    for pc, color in zip(parts["bodies"], colors):
        pc.set_facecolor(color)
        pc.set_edgecolor("none")
        pc.set_alpha(0.75)

    ax.boxplot(
        data, positions=positions, widths=0.12, showfliers=False,
        boxprops=dict(color="black", linewidth=0.6),
        whiskerprops=dict(color="black", linewidth=0.6),
        capprops=dict(color="black", linewidth=0.6),
        medianprops=dict(color="black", linewidth=1.2),
    )

    ax.set_xticks(positions)
    ax.set_xticklabels(labels, rotation=40, ha="right", rotation_mode="anchor", fontsize=7.0)

    upper_whiskers = []
    for arr in data:
        q1, q3 = np.percentile(arr, [25, 75])
        iqr = q3 - q1
        upper_whiskers.append(q3 + 1.5 * iqr)
    panel_top = max(upper_whiskers) * YLIM_HEADROOM
    panel_bottom = max(0.1, min(a.min() for a in data) * 0.85)

    return (panel_bottom, panel_top), positions, data, table_rows


def build_summary_table(table_ax, panel_specs, any_failures: bool):
    """
    panel_specs : liste (sig_alg, fam_label, table_rows), un par panel, dans l'ordre (a),(b)...
    Construit le tableau (c) : lignes = union ordonnée des KEM, colonnes groupées par panel
    avec les métriques Mean(ms) | CV(%) | Max(ms) [| Fail].
    """
    table_ax.axis("off")

    # Union ordonnée des KEM sur tous les panels (même ordre que sur les violons)
    seen = {}
    for _, _, rows in panel_specs:
        for row in rows:
            seen.setdefault(row["kem"], (row["fam"], row["label"]))
    ordered_kems = sorted(seen.keys(), key=lambda k: (KEM_FAMILY_ORDER.index(seen[k][0]), k))

    metrics = ["Mean (ms)", "CV (%)", "Max (ms)"]
    if any_failures:
        metrics.append("Fail")

    col_labels = ["KEM"]
    for sig_alg, _fam_label, _rows in panel_specs:
        for m in metrics:
            col_labels.append(f"{sig_alg}\n{m}")

    cell_text = []
    for kem in ordered_kems:
        _fam, label = seen[kem]
        row_cells = [label]
        for _sig_alg, _fam_label, rows in panel_specs:
            match = next((r for r in rows if r["kem"] == kem), None)
            if match is None:
                row_cells.extend(["—"] * len(metrics))
                continue
            s = match["stats"]
            row_cells.append(fmt_ms(s["mean"]))
            row_cells.append(fmt_pct(s["cv"]))
            row_cells.append(fmt_ms(s["max"]))
            if any_failures:
                row_cells.append(f"{s['n_failed']}/{s['n_total']}" if s["n_failed"] else "0")
        cell_text.append(row_cells)

    n_cols = len(col_labels)
    first_col_w = 0.17
    other_w = (1.0 - first_col_w) / (n_cols - 1)
    col_widths = [first_col_w] + [other_w] * (n_cols - 1)

    tbl = table_ax.table(cellText=cell_text, colLabels=col_labels, cellLoc="center",
                          colWidths=col_widths, loc="center")
    tbl.auto_set_font_size(False)
    tbl.set_fontsize(6.3)
    tbl.scale(1.0, 1.35)

    n_metrics = len(metrics)
    for (row, col), cell in tbl.get_celld().items():
        cell.set_linewidth(0.4)
        cell.set_edgecolor("#BBBBBB")
        if row == 0:
            cell.set_facecolor("#EDEDED")
            cell.set_text_props(weight="bold", fontsize=5.8)
        else:
            if col == 0:
                cell.set_text_props(ha="left")
            else:
                group_idx = (col - 1) // n_metrics
                if group_idx % 2 == 1:
                    cell.set_facecolor("#F7F7F7")

    table_ax.text(0.0, 1.08, "(c)", transform=table_ax.transAxes,
                  fontsize=9, fontweight="bold", va="bottom")
    return tbl


def process_scenario(root: Path, protocol: str, auth_mode: str, scenario_dir: str):
    stats_path = root / "analyse" / "handshake_stats.csv"
    if not stats_path.exists():
        return

    stats = pd.read_csv(stats_path)
    scenario_slug = SCENARIO_SLUGS.get(scenario_dir, scenario_dir)

    panel_letters = "abcdefgh"

    for level in SECURITY_LEVEL_ORDER:
        level_rows = stats[stats["security_level"] == level]
        if level_rows.empty:
            continue

        sig_algs = list(level_rows.sort_values(
            by="sig_family", key=lambda s: s.map({"classique": 0, "pq": 1})
        )["sig_alg"].unique())

        n_panels = len(sig_algs)

        violin_height = FIGSIZE_SINGLE_COL[1] + 0.15
        tick_spacer_height = 0.85   # absorbe les xticklabels roté(e)s sans espace superflu ailleurs
        legend_height = 0.34

        # Dimensionnement du tableau en fonction du nombre de KEM distincts du niveau
        n_kem_rows_estimate = level_rows["kem"].nunique()
        table_height = 0.235 * (n_kem_rows_estimate + 1) + 0.35

        fig_w = FIGSIZE_SINGLE_COL[0] * n_panels * 1.1
        fig_h = violin_height + tick_spacer_height + legend_height + table_height
        fig = plt.figure(figsize=(fig_w, fig_h))

        # 4 lignes : violons | tampon (xticklabels roté(e)s) | légende | tableau (c)
        outer_gs = fig.add_gridspec(
            4, 1,
            height_ratios=[violin_height, tick_spacer_height, legend_height, table_height],
            hspace=0.0,
        )
        top_gs = outer_gs[0].subgridspec(1, n_panels, wspace=0.15)
        axes = [fig.add_subplot(top_gs[0, i]) for i in range(n_panels)]

        families_used = set()
        read_counter = {"n_files": 0, "n_rows": 0}
        panel_results = []   # (ax, ylim, positions, data)
        panel_specs = []     # (sig_alg, fam_label, table_rows)
        any_failures = False

        for idx, (ax, sig_alg) in enumerate(zip(axes, sig_algs)):
            sig_rows = level_rows[level_rows["sig_alg"] == sig_alg]
            sig_family = sig_rows["sig_family"].iloc[0]
            fam_label = "classical" if sig_family == "classique" else "post-quantum"

            ylim, positions, data, table_rows = build_panel(
                ax, root, protocol, auth_mode, scenario_dir, sig_alg, sig_rows,
                families_used, read_counter,
            )
            any_failures = any_failures or any(r["stats"]["n_failed"] for r in table_rows)

            letter = panel_letters[idx]
            ax.text(-0.12, 1.10, f"({letter})", transform=ax.transAxes,
                     fontsize=9, fontweight="bold", va="bottom")
            ax.set_title(f"{sig_alg} ({fam_label})", fontsize=8.0, pad=10)
            style_axes(ax, grid_axis="y")
            panel_results.append((ax, ylim, positions, data))
            panel_specs.append((sig_alg, fam_label, table_rows))

        valid_ylims = [r[1] for r in panel_results if r[1] is not None]
        if valid_ylims:
            global_bottom = min(y[0] for y in valid_ylims)
            global_top = max(y[1] for y in valid_ylims)
            for ax, ylim, positions, data in panel_results:
                if ylim is None:
                    continue
                if LOG_SCALE:
                    ax.set_yscale("log")
                ax.set_ylim(global_bottom, global_top)

        axes[0].set_ylabel(
            "Handshake duration (ms), log scale" if LOG_SCALE else "Handshake duration (ms)",
            fontsize=8.0,
        )

        # Ligne 1 (index 1) volontairement laissée vide : elle absorbe le débordement
        # des xticklabels roté(e)s des panels du dessus, sans créer d'espace visible.

        legend_ax = fig.add_subplot(outer_gs[2])
        legend_ax.axis("off")
        if families_used:
            handles = kem_family_legend_handles(families_used)
            legend_ax.legend(
                handles=handles, loc="center", ncol=min(len(handles), 5),
                frameon=False, fontsize=6.8, handletextpad=0.5, columnspacing=1.2,
                borderaxespad=0.0,
            )

        table_ax = fig.add_subplot(outer_gs[3])
        build_summary_table(table_ax, panel_specs, any_failures)

        fig.subplots_adjust(top=0.92, bottom=0.02, left=0.09, right=0.98)

        out_dir = root / "plots"
        filename_stem = f"handshake_{protocol}_{auth_mode}_{level}_{scenario_slug}"
        print(f"  -> {filename_stem}  [files read: {read_counter['n_files']}, rows read: {read_counter['n_rows']}]")
        save_figure(fig, out_dir, filename_stem)
        plt.close(fig)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--captures-root", default="./captures")
    ap.add_argument("--protocol", choices=["tls", "quic"], default=None)
    ap.add_argument("--auth-mode", choices=["single", "mutual"], default=None)
    args = ap.parse_args()

    captures_root = Path(args.captures_root)
    pairs = PROTOCOL_AUTH_PAIRS
    if args.protocol:
        pairs = [p for p in pairs if p[0] == args.protocol]
    if args.auth_mode:
        pairs = [p for p in pairs if p[1] == args.auth_mode]

    for protocol, auth_mode in pairs:
        base = captures_root / protocol / auth_mode
        if not base.exists():
            continue
        scenario_dirs = sorted(d.name for d in base.iterdir() if d.is_dir())
        for scenario_dir in scenario_dirs:
            print(f"[{protocol}/{auth_mode}/{scenario_dir}]")
            process_scenario(base / scenario_dir, protocol, auth_mode, scenario_dir)


if __name__ == "__main__":
    main()
