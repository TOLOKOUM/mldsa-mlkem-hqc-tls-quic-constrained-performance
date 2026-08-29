"""
plot_resource_usage.py
========================
Génère les figures de consommation de ressources (CPU par handshake, pic
mémoire) à partir de captures/{tls,quic}/{single,mutual}/<scénario>/
resource_usage/resource_usage_*.csv.

USAGE (depuis la racine du dépôt) :
    python3 plot_resource_usage.py
    python3 plot_resource_usage.py --protocol tls --auth-mode single

STRUCTURE (cohérente avec plot_handshake_latency.py) :
    Pour chaque (protocole x mode auth x scénario x niveau de sécurité),
    DEUX figures séparées (unités incompatibles) :
        resource_cpu_{...}.pdf   -- CPU par handshake (ms), échelle log
        resource_mem_{...}.pdf   -- pic mémoire (MB), échelle linéaire
    Chaque figure : 2 panels (signature classique | PQ), comme la latence.
    Barres groupées par rôle (client / serveur) dans chaque config KEM :
    couleur = famille de KEM, hachure = rôle (serveur hachuré, client uni).

SOURCE DES DONNÉES ET AGRÉGATION PAR BLOCS :
    Depuis le passage à la méthodologie en 4 blocs randomisés
    (Launcher_pq_mldsa_mlkem_hqc.sh), resource_usage_*.csv contient EN
    TEMPS NORMAL 4 lignes voulues par combinaison (protocol, auth_mode,
    sig_alg, kem, role) -- une par block_index, chacune déjà moyennée en
    interne sur les n_runs handshakes du bloc. Ce ne sont PAS des doublons.

    Pipeline en deux temps, jamais confondu :
      1. resolve_duplicate_runs(..., key_cols=[...,"block_index"]) ne
         détecte et n'écrase QUE les vrais doublons accidentels -- deux
         lignes qui partagent le MÊME block_index (ex: re-run partiel).
      2. aggregate_resource_blocks(...) combine ensuite statistiquement les
         (jusqu'à 4) blocs restants par combinaison : moyenne inter-blocs +
         IC95% par bootstrap de blocs entiers (mêmes seed/n_resamples que
         le pipeline de latence, cf. plot_style.block_bootstrap_mean_ci).
         Si une combinaison n'a qu'un seul bloc exploitable, l'IC est
         explicitement marqué "non calculable" (ci_method), jamais tu.

    Avant ce passage aux blocs, une seule ligne existait par combinaison ;
    dans ce cas n_blocks_pooled==1 pour toutes les combinaisons et aucun IC
    n'est tracé (comportement inchangé, pas de régression pour d'anciennes
    captures non ré-exécutées).
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
    KEM_FAMILY_COLORS, KEM_FAMILY_ORDER, classify_kem_family, derive_kem_class,
    SECURITY_LEVEL_ORDER, SCENARIO_SLUGS, format_kem_label_flat,
    sorted_kem_rows, style_axes, save_figure, resolve_duplicate_runs,
    kem_family_legend_handles, aggregate_resource_blocks,
)

PROTOCOL_AUTH_PAIRS = [("tls", "single"), ("tls", "mutual"), ("quic", "single")]
ROLE_ORDER = ["client", "server"]
ROLE_HATCH = {"client": "", "server": "///"}
ROLE_LABELS = {"client": "Client", "server": "Server"}

EXPECTED_COLUMNS_LEGACY = ["timestamp", "protocol", "auth_mode", "sig_alg", "kem",
                           "network_profile", "role", "n_runs", "cpu_usec_total",
                           "cpu_usec_per_handshake", "mem_peak_bytes"]

# Structure "post-blocs" (Launcher_pq_mldsa_mlkem_hqc.sh) : 3 colonnes en
# plus à la fin (block_index, n_blocks, seed). Les deux en-têtes sont
# acceptés ; toute autre structure est rejetée explicitement plutôt que de
# laisser pandas mal aligner des colonnes.
EXPECTED_COLUMNS_BLOCKS = EXPECTED_COLUMNS_LEGACY + ["block_index", "n_blocks", "seed"]


def load_resource_csv(csv_path: Path):
    """Charge un CSV resource_usage_*.csv avec vérification de structure
    (détecte le bug de virgule décimale non réparé plutôt que de planter
    obscurément ou de mal aligner des colonnes). Accepte l'ancien format
    (sans block_index/n_blocks/seed) et le nouveau format post-blocs ;
    ajoute block_index=1 pour l'ancien format afin que le reste du pipeline
    (resolve_duplicate_runs + aggregate_resource_blocks) fonctionne
    identiquement dans les deux cas, avec n_blocks_pooled==1 et pas d'IC
    pour les anciennes captures non ré-exécutées."""
    with open(csv_path, newline="") as f:
        first_line = f.readline().strip().split(",")

    if first_line == EXPECTED_COLUMNS_BLOCKS:
        has_blocks = True
    elif first_line == EXPECTED_COLUMNS_LEGACY:
        has_blocks = False
    else:
        print(f"    [ATTENTION] en-tête inattendu dans {csv_path.name}, ignoré : {first_line}")
        return None

    n_expected = len(first_line)

    # Vérifie le nombre de colonnes de chaque ligne avant de laisser pandas
    # deviner -- si une ligne a une colonne de trop, c'est probablement le
    # bug de virgule décimale non réparé (cf. repair_resource_usage_csv.py).
    with open(csv_path, newline="") as f:
        import csv as _csv
        rows = list(_csv.reader(f))
    corrupted = [i for i, r in enumerate(rows[1:], start=2) if len(r) == n_expected + 1]
    if corrupted:
        print(f"    [ATTENTION] {csv_path.name} : {len(corrupted)} ligne(s) semblent avoir "
              f"le bug de virgule décimale (colonne coupée en deux) -- lance d'abord "
              f"`python3 repair_resource_usage_csv.py {csv_path}`. Fichier ignoré pour l'instant.")
        return None

    df = pd.read_csv(csv_path)
    if not has_blocks:
        df["block_index"] = 1
        df["n_blocks"] = 1
        df["seed"] = "NA"
    return df


def draw_grouped_bars(ax, sub_df: pd.DataFrame, value_col: str, unit_scale: float,
                       ci_low_col: str = None, ci_high_col: str = None):
    """Barres groupées (client/serveur) par config KEM, couleur=famille,
    hachure=rôle. Trace des barres d'erreur IC95% si ci_low_col/ci_high_col
    sont fournis et calculables pour la combinaison (cf.
    aggregate_resource_blocks -- "NA" si un seul bloc). Retourne le max de
    valeur+erreur tracée (pour ylim)."""
    sub_df_sorted = sorted_kem_rows(
        sub_df.drop_duplicates(subset=["kem", "kem_class"])[["kem", "kem_class"]]
    )
    kems = sub_df_sorted["kem"].tolist()
    families = sub_df_sorted["kem_family"].tolist()

    x = np.arange(len(kems))
    n_roles = len(ROLE_ORDER)
    width = 0.8 / n_roles
    offsets = np.linspace(-0.4 + width / 2, 0.4 - width / 2, n_roles)

    max_val = 0.0
    for role, offset in zip(ROLE_ORDER, offsets):
        role_df = sub_df[sub_df["role"] == role].set_index("kem")
        values, err_low, err_high = [], [], []
        for kem in kems:
            if kem in role_df.index:
                v = role_df.loc[kem, value_col] * unit_scale
                values.append(v)
                if ci_low_col and ci_high_col:
                    lo, hi = role_df.loc[kem, ci_low_col], role_df.loc[kem, ci_high_col]
                    if lo not in ("NA", None) and hi not in ("NA", None):
                        err_low.append(max(0.0, v - lo * unit_scale))
                        err_high.append(max(0.0, hi * unit_scale - v))
                    else:
                        err_low.append(0.0)
                        err_high.append(0.0)
                else:
                    err_low.append(0.0)
                    err_high.append(0.0)
            else:
                values.append(0.0)
                err_low.append(0.0)
                err_high.append(0.0)
        values = np.array(values)
        colors = [KEM_FAMILY_COLORS[f] for f in families]
        ax.bar(x + offset, values, width=width, color=colors,
               edgecolor="#444444", linewidth=0.4, hatch=ROLE_HATCH[role], zorder=3)
        if ci_low_col and ci_high_col and (any(err_low) or any(err_high)):
            ax.errorbar(x + offset, values, yerr=[err_low, err_high], fmt="none",
                         ecolor="#222222", elinewidth=0.6, capsize=1.5, zorder=4)
        if values.size:
            local_max = values.max() + (max(err_high) if err_high else 0.0)
            max_val = max(max_val, local_max)

    ax.set_xticks(x)
    ax.set_xticklabels([format_kem_label_flat(k) for k in kems],
                        rotation=40, ha="right", rotation_mode="anchor", fontsize=6.3)
    return max_val


def build_metric_figure(root: Path, protocol, auth_mode, scenario_dir, scenario_slug,
                         df: pd.DataFrame, level: str, metric_key: str):
    """metric_key: 'cpu' ou 'mem'."""
    if metric_key == "cpu":
        base_col, unit_scale, ylabel, log_scale = "cpu_usec_per_handshake", 1 / 1000.0, \
            "CPU time per handshake (ms), log scale", True
    else:
        base_col, unit_scale, ylabel, log_scale = "mem_peak_bytes", 1 / (1024 * 1024), \
            "Peak memory (MB)", False

    value_col = f"{base_col}_mean"
    ci_low_col, ci_high_col = f"{base_col}_ci95_low", f"{base_col}_ci95_high"

    level_rows = df[df["security_level"] == level]
    if level_rows.empty:
        return

    sig_algs = list(level_rows.sort_values(
        by="sig_family", key=lambda s: s.map({"classique": 0, "pq": 1})
    )["sig_alg"].unique())
    n_panels = len(sig_algs)

    fig, axes = plt.subplots(1, n_panels, figsize=(3.6 * n_panels, 3.2), sharey=True)
    if n_panels == 1:
        axes = [axes]

    panel_maxes = []
    for ax, sig_alg in zip(axes, sig_algs):
        sig_rows = level_rows[level_rows["sig_alg"] == sig_alg]
        sig_family = sig_rows["sig_family"].iloc[0]
        fam_label = "classical" if sig_family == "classique" else "post-quantum"
        top = draw_grouped_bars(ax, sig_rows, value_col, unit_scale, ci_low_col, ci_high_col)
        panel_maxes.append(top)
        ax.set_title(f"{sig_alg} ({fam_label})", fontsize=9)
        style_axes(ax, grid_axis="y")

    global_top = max(panel_maxes) * (1.3 if log_scale else 1.15) if panel_maxes else 1.0
    for ax in axes:
        if log_scale:
            ax.set_yscale("log")
        ax.set_ylim(None if log_scale else 0, global_top)
    axes[0].set_ylabel(ylabel)

    fam_handles = kem_family_legend_handles(set(
        classify_kem_family(kc, k) for kc, k in zip(level_rows["kem_class"], level_rows["kem"])
    ))
    role_handles = [plt.Rectangle((0, 0), 1, 1, facecolor="white", edgecolor="black",
                                    hatch=ROLE_HATCH[r], label=ROLE_LABELS[r]) for r in ROLE_ORDER]
    fig.legend(handles=fam_handles + role_handles, loc="lower center",
               ncol=min(len(fam_handles) + len(role_handles), 4), frameon=False,
               fontsize=7.0, bbox_to_anchor=(0.5, -0.14))

    fig.tight_layout()

    out_dir = root / "plots"
    filename_stem = f"resource_{metric_key}_{protocol}_{auth_mode}_{level}_{scenario_slug}"
    print(f"  -> {filename_stem}")
    save_figure(fig, out_dir, filename_stem)
    plt.close(fig)


def process_scenario(root: Path, protocol: str, auth_mode: str, scenario_dir: str):
    csv_name = f"resource_usage_{protocol}_{auth_mode}_{scenario_dir}.csv"
    csv_path = root / "resource_usage" / csv_name
    if not csv_path.exists():
        print(f"  [SKIP] {csv_path} introuvable")
        return

    df = load_resource_csv(csv_path)
    if df is None:
        return

    unknown_sig = set(df["sig_alg"].unique())
    from plot_style import SIG_ALG_TO_LEVEL, SIG_ALG_TO_FAMILY
    missing_map = unknown_sig - set(SIG_ALG_TO_LEVEL)
    if missing_map:
        raise ValueError(f"{csv_path} : sig_alg non mappé(s) {missing_map} -- "
                          f"ajoute-les dans SIG_ALG_TO_LEVEL/SIG_ALG_TO_FAMILY (plot_style.py)")

    # Étape 1 : ne dédoublonner QUE les vrais doublons accidentels (même
    # block_index répété pour la même combinaison). Les blocs distincts
    # voulus par la méthodologie ne sont PAS affectés par cette étape.
    n_rows_before = len(df)
    df = resolve_duplicate_runs(
        df, key_cols=["protocol", "auth_mode", "sig_alg", "kem", "role", "block_index"],
        value_cols=["cpu_usec_per_handshake", "mem_peak_bytes"],
    )
    if len(df) != n_rows_before:
        print(f"    [INFO] {n_rows_before - len(df)} ligne(s) éliminée(s) comme doublons "
              f"exacts de block_index (voir détail ci-dessus).")

    # Étape 2 : agrégation statistique des blocs restants (1 à 4 par
    # combinaison) en une ligne par (protocol, auth_mode, sig_alg, kem, role),
    # avec moyenne inter-blocs et IC95% bootstrap de blocs.
    n_combos_before = df[["protocol", "auth_mode", "sig_alg", "kem", "role"]].drop_duplicates().shape[0]
    df = aggregate_resource_blocks(
        df, key_cols=["protocol", "auth_mode", "sig_alg", "kem", "role"],
        value_cols=["cpu_usec_per_handshake", "mem_peak_bytes"],
    )
    n_single_block = int((df["n_blocks_pooled"] == 1).sum())
    print(f"    [INFO] {n_combos_before} combinaison(s) agrégée(s) sur leurs blocs "
          f"({n_single_block} combinaison(s) avec un seul bloc exploitable -- "
          f"pas d'IC bootstrap pour celles-ci).")

    df["security_level"] = df["sig_alg"].map(SIG_ALG_TO_LEVEL)
    df["sig_family"] = df["sig_alg"].map(SIG_ALG_TO_FAMILY)
    if "kem_class" not in df.columns:
        df["kem_class"] = df["kem"].map(derive_kem_class)

    scenario_slug = SCENARIO_SLUGS.get(scenario_dir, scenario_dir.replace(".", "").replace(" ", "_"))

    for level in SECURITY_LEVEL_ORDER:
        for metric_key in ("cpu", "mem"):
            build_metric_figure(root, protocol, auth_mode, scenario_dir, scenario_slug,
                                 df, level, metric_key)


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
