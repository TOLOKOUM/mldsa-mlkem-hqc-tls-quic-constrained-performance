"""
plot_style.py
=============
Module de style centralisé pour les figures de l'étude
"Post-Quantum Cryptography over TLS/QUIC under Constrained Networks".

À placer à la RACINE du dépôt :
    ~/Documents/mldsa-mlkem-hqc-tls-quic-constrained-performance/plot_style.py

Tous les scripts de figure doivent commencer par :
    from plot_style import *

Ce module ne produit aucune figure "métier" lui-même : il ne fait que
définir la palette, la typographie, les conventions de nommage/sauvegarde,
et de petites fonctions utilitaires réutilisées partout. Ça garantit que
TOUTES les figures de l'article ont la même patte visuelle, sans avoir à
redéfinir des couleurs à chaque script.

-----------------------------------------------------------------------
CHOIX DE PALETTE (à valider avant de continuer)
-----------------------------------------------------------------------
La dimension la plus importante scientifiquement dans cette étude est la
comparaison ML-KEM vs HQC (et pur vs hybride). C'est donc CETTE dimension
qui porte la couleur. Le niveau de sécurité (L1/L3/L5) porte la FORME
(marker) dans les figures globales, jamais la couleur, pour ne pas
surcharger le canal couleur. La famille de signature (classique/PQ) est
gérée par des PANELS séparés (facettes), pas par la couleur, pour la
même raison.

Palette choisie : Okabe-Ito (colorblind-safe, standard en publication
scientifique), avec un dégradé de luminosité pur/hybride à l'intérieur
de chaque famille de KEM :

    Classique (baseline ECDH/ECDSA seul)  -> gris neutre   #7F7F7F
    ML-KEM pur                            -> bleu          #0072B2
    ML-KEM hybride (x25519/P-xxx + KEM)   -> bleu clair     #56B4E9
    HQC pur                               -> vermillon     #D55E00
    HQC hybride                           -> orange        #E69F00

Pourquoi ce choix :
  - Bleu = famille ML-KEM, orange/rouge = famille HQC : opposition
    immédiatement lisible même en niveaux de gris (impression N&B).
  - Le gris neutre pour le baseline classique le sort visuellement de la
    comparaison PQ tout en restant présent comme référence.
  - Variante claire = hybride, variante saturée = pur : cohérent dans
    les deux familles, pas besoin d'un 6e code couleur.

Si tu veux une palette différente (ex. imposée par un template Elsevier,
ou pour matcher une figure de Montenegro que tu as en tête), dis-le moi
maintenant : c'est le bon moment, avant qu'elle soit utilisée partout.

-----------------------------------------------------------------------
DIMENSIONS DES FIGURES (Computer Networks / Elsevier)
-----------------------------------------------------------------------
Elsevier double colonne : largeur de texte ~= 7.0-7.5 in (190 mm)
Elsevier simple colonne : largeur ~= 3.3-3.5 in (90 mm)

IMPORTANT : les tailles de police ci-dessous sont calibrées pour un
rendu à taille RÉELLE d'impression (pas de figure géante recompressée).
Une figure "simple colonne" de 3.5 in de large avec du texte à 8-9 pt
reste lisible imprimée à cette taille. C'est plus petit que ce que tu
avais dans tes anciens scripts (LABEL_SIZE=14, TICK_SIZE=20), qui étaient
calibrés pour un affichage écran/poster, pas pour un encart d'article.

-----------------------------------------------------------------------
"""

import statistics
from pathlib import Path
import pandas as pd
import matplotlib as mpl
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.lines as mlines

# =========================================================================
# 1. TYPOGRAPHIE ET RCPARAMS GLOBAUX
# =========================================================================

mpl.rcParams.update({
    "font.family": "sans-serif",
    "font.sans-serif": ["Arial", "Helvetica", "DejaVu Sans"],
    "font.size": 9,
    "axes.titlesize": 9,
    "axes.labelsize": 9,
    "xtick.labelsize": 8,
    "ytick.labelsize": 8,
    "legend.fontsize": 7.5,
    "legend.title_fontsize": 8,
    "axes.linewidth": 0.8,
    "grid.linewidth": 0.5,
    "lines.linewidth": 1.2,
    "lines.markersize": 4.5,
    "figure.dpi": 150,          # rendu écran pendant le dev
    "savefig.dpi": 300,         # export PNG haute résolution
    "pdf.fonttype": 42,         # texte éditable dans le PDF (obligatoire éditeurs)
    "ps.fonttype": 42,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.grid": True,
    "grid.alpha": 0.35,
    "axes.axisbelow": True,
})

# =========================================================================
# 2. TAILLES DE FIGURE STANDARD (en pouces)
# =========================================================================

FIGSIZE_SINGLE_COL = (3.5, 2.7)   # une figure par colonne
FIGSIZE_SINGLE_COL_TALL = (3.5, 3.4)
FIGSIZE_DOUBLE_COL = (7.16, 3.0)  # pleine largeur de page
FIGSIZE_DOUBLE_COL_TALL = (7.16, 4.2)

# =========================================================================
# 3. PALETTE — FAMILLE DE KEM (dimension centrale de l'étude)
# =========================================================================

KEM_FAMILY_COLORS = {
    "classical":     "#7F7F7F",  # gris neutre : baseline ECDH seul
    "mlkem_pure":    "#0072B2",  # bleu : ML-KEM pur
    "mlkem_hybrid":  "#56B4E9",  # bleu clair : ML-KEM hybride
    "hqc_pure":      "#D55E00",  # vermillon : HQC pur
    "hqc_hybrid":    "#E69F00",  # orange : HQC hybride
}

KEM_FAMILY_LABELS = {
    "classical":    "Classical KEX",
    "mlkem_pure":   "ML-KEM (pure)",
    "mlkem_hybrid": "ML-KEM (hybrid)",
    "hqc_pure":     "HQC (pure)",
    "hqc_hybrid":   "HQC (hybrid)",
}

# Ordre d'affichage sur les axes X / dans les légendes : baseline d'abord,
# puis les deux familles ML-KEM regroupées, puis les deux familles HQC
# regroupées. Ce regroupement rend la comparaison ML-KEM vs HQC immédiate
# (bloc contre bloc) plutôt que d'alterner les deux familles.
KEM_FAMILY_ORDER = [
    "classical", "mlkem_pure", "mlkem_hybrid", "hqc_pure", "hqc_hybrid",
]


def classify_kem_family(kem_class: str, kem_name: str) -> str:
    """
    Classe une ligne de handshake_stats.csv / handshake_overhead.csv dans
    une des 5 catégories ci-dessus, à partir des colonnes `kem_class`
    (classique / pq_pur / hybride) et `kem` (ex: 'hqc128', 'x25519_mlkem512').

    Lève ValueError si la classification échoue (mieux vaut planter que
    silencieusement mal classer un point de donnée).
    """
    kem_class = str(kem_class).strip().lower()
    kem_name_l = str(kem_name).strip().lower()

    if kem_class == "classique":
        return "classical"

    has_hqc = "hqc" in kem_name_l
    has_mlkem = "mlkem" in kem_name_l

    if has_hqc and has_mlkem:
        raise ValueError(
            f"Nom de KEM ambigu (contient à la fois 'hqc' et 'mlkem'): {kem_name!r}"
        )

    if kem_class == "pq_pur":
        if has_mlkem:
            return "mlkem_pure"
        if has_hqc:
            return "hqc_pure"
        raise ValueError(f"kem_class='pq_pur' mais KEM non reconnu: {kem_name!r}")

    if kem_class == "hybride":
        if has_mlkem:
            return "mlkem_hybrid"
        if has_hqc:
            return "hqc_hybrid"
        raise ValueError(f"kem_class='hybride' mais KEM non reconnu: {kem_name!r}")

    raise ValueError(f"kem_class inconnu: {kem_class!r} (attendu: classique/pq_pur/hybride)")


# =========================================================================
# 4. NIVEAU DE SÉCURITÉ — FORME, PAS COULEUR
# =========================================================================

SECURITY_LEVEL_ORDER = ["L1", "L3", "L5"]
SECURITY_LEVEL_MARKERS = {"L1": "o", "L3": "s", "L5": "^"}
SECURITY_LEVEL_LABELS = {"L1": "L1 (128-bit)", "L3": "L3 (192-bit)", "L5": "L5 (256-bit)"}

# =========================================================================
# 5. PROTOCOLE — STYLE DE TRAIT, PAS COULEUR
# =========================================================================

PROTOCOL_LINESTYLES = {"tls": "-", "quic": "--"}
PROTOCOL_LABELS = {"tls": "TLS 1.3", "quic": "QUIC"}

AUTH_MODE_LABELS = {"single": "Server-auth", "mutual": "Mutual-auth"}

SIG_FAMILY_LABELS = {"classique": "Classical signature", "pq": "PQ signature"}

# Mapping fixe sig_alg -> niveau de sécurité / famille. Invariant sur tout le
# dépôt (confirmé sur handshake_stats.csv : chaque sig_alg n'existe qu'à UN
# seul niveau). Utile pour les fichiers qui n'ont pas de colonne
# security_level/sig_family explicite (ex: traffic_size_summary.csv).
SIG_ALG_TO_LEVEL = {
    "ed25519": "L1", "mldsa44": "L1",
    "secp384r1": "L3", "mldsa65": "L3",
    "secp521r1": "L5", "mldsa87": "L5",
}
SIG_ALG_TO_FAMILY = {
    "ed25519": "classique", "secp384r1": "classique", "secp521r1": "classique",
    "mldsa44": "pq", "mldsa65": "pq", "mldsa87": "pq",
}

# =========================================================================
# 6. SCÉNARIOS RÉSEAU — mapping dossier -> label scientifique
# =========================================================================
# IMPORTANT : recalibré sur les mesures terrain de Yaoundé (cf. mémoire
# projet) -- MTN -> Modéré: delay=62.51ms, loss=1.3% ;
#             Orange -> Dégradé: delay=83.52ms, loss=1.5833%.
# Les noms de dossier ci-dessous DOIVENT correspondre exactement aux
# dossiers réels sous captures/{tls,quic}/{single,mutual}/ -- toute
# incohérence ici fait échouer silencieusement (avec juste un [SKIP] en
# console, facile à manquer) les scripts qui itèrent sur SCENARIO_ORDER
# (ex: plot_global_network_sensitivity.py).

SCENARIO_ORDER = [
    "none",
    "simple_loss1.3_delay62.51ms",
    "simple_loss1.5833_delay83.52ms",
    "stable",
    "unstable",
]

SCENARIO_LABELS = {
    "none": "Ideal",
    "simple_loss1.3_delay62.51ms": "Moderate (MTN 4G)",
    "simple_loss1.5833_delay83.52ms": "Degraded (Orange 4G)",
    "stable": "GE-Stable",
    "unstable": "GE-Unstable",
}

# Nom court utilisé dans les noms de fichiers (pas d'espaces/accents/parenthèses)
SCENARIO_SLUGS = {
    "none": "ideal",
    "simple_loss1.3_delay62.51ms": "moderate",
    "simple_loss1.5833_delay83.52ms": "degraded",
    "stable": "ge_stable",
    "unstable": "ge_unstable",
}


# =========================================================================
# 6bis. LABEL DE CONFIGURATION KEM — partagé entre tous les scripts
# =========================================================================
# Identique à la logique validée dans plot_handshake_latency.py (version
# adoptée) ; dupliqué ici volontairement plutôt que d'importer depuis ce
# script pour ne jamais risquer de modifier son comportement verrouillé.
# Tout NOUVEAU script doit importer format_kem_label / format_kem_label_flat
# depuis CE module plutôt que de les redéfinir localement.

_KEM_TOKEN_MAP = {
    "p256": "P-256", "p384": "P-384", "p521": "P-521",
    "x25519": "X25519", "x448": "X448",
    "hqc128": "HQC-128", "hqc192": "HQC-192", "hqc256": "HQC-256",
    "mlkem512": "ML-KEM-512", "mlkem768": "ML-KEM-768", "mlkem1024": "ML-KEM-1024",
}


def format_kem_label(kem: str) -> str:
    """Label deux-lignes compact, pour les ticks d'axe X (ex: 'P-256+\\nHQC-128')."""
    kem_norm = kem.strip()
    if kem_norm in ("P-256", "P-384", "P-521"):
        return kem_norm
    parts = kem_norm.lower().split("_")
    mapped = [_KEM_TOKEN_MAP.get(p, p) for p in parts]
    if len(mapped) > 1:
        return f"{mapped[0]}+\n{mapped[1]}"
    return mapped[0]


def format_kem_label_flat(kem: str) -> str:
    """Label une-ligne (ex: 'P-256+HQC-128'), pour les labels de ligne de tableau."""
    kem_norm = kem.strip()
    if kem_norm in ("P-256", "P-384", "P-521"):
        return kem_norm
    parts = kem_norm.lower().split("_")
    mapped = [_KEM_TOKEN_MAP.get(p, p) for p in parts]
    return "+".join(mapped)


def derive_kem_class(kem: str) -> str:
    """
    Dérive kem_class ('classique'/'pq_pur'/'hybride') depuis le seul nom du
    KEM, pour les CSV qui n'ont pas cette colonne pré-calculée (ex:
    resource_usage_*.csv, contrairement à handshake_stats.csv). Logique
    identique à classify_kem() dans parse_traffic_size.py -- à garder
    synchronisée si l'une des deux change.
    """
    k = kem.lower().replace("-", "")
    is_pq = any(tag in k for tag in ("mlkem", "hqc"))
    is_classical_component = any(tag in k for tag in ("p256", "p384", "p521", "x25519", "x448"))
    if is_pq and is_classical_component:
        return "hybride"
    if is_pq:
        return "pq_pur"
    return "classique"


def sorted_kem_rows(df):
    """
    Trie un DataFrame (doit avoir les colonnes 'kem_class' et 'kem') selon
    l'ordre canonique KEM_FAMILY_ORDER puis alphabétique, et ajoute une
    colonne 'kem_family'. Lève la même ValueError que classify_kem_family
    si une ligne est mal formée -- ne masque jamais un problème de données.
    """
    df = df.copy()
    df["kem_family"] = [
        classify_kem_family(kc, k) for kc, k in zip(df["kem_class"], df["kem"])
    ]
    df["_fam_order"] = df["kem_family"].map(KEM_FAMILY_ORDER.index)
    df = df.sort_values(by=["_fam_order", "kem"]).drop(columns=["_fam_order"])
    return df.reset_index(drop=True)


# =========================================================================
# 6ter. PALETTE — COMPOSANTS DE TRAFIC DE HANDSHAKE (taille, pas latence)
# =========================================================================
# Volontairement DIFFÉRENTE de KEM_FAMILY_COLORS (bleu/orange) : ici on
# empile par TYPE DE MESSAGE, pas par famille de KEM, donc réutiliser la
# même palette créerait une fausse association visuelle entre les deux
# types de figures. Dégradé séquentiel violet (ColorBrewer "Purples",
# standard et sûr) : l'ordre chronologique du handshake se lit directement
# dans le dégradé clair -> foncé.

TRAFFIC_COMPONENT_ORDER = [
    "ClientHello", "ServerHello", "EncryptedExtensions", "CertificateRequest",
    "Certificate", "CertificateVerify", "Finished", "NewSessionTicket",
]

TRAFFIC_COMPONENT_COLORS = {
    "ClientHello":          "#efedf5",
    "ServerHello":          "#dadaeb",
    "EncryptedExtensions":  "#bcbddc",
    "CertificateRequest":   "#9e9ac8",
    "Certificate":          "#807dba",
    "CertificateVerify":    "#6a51a3",
    "Finished":             "#54278f",
    "NewSessionTicket":     "#3f007d",
}

TRAFFIC_RESIDUAL_STYLE = dict(facecolor="white", edgecolor="#888888", hatch="//", linewidth=0.5)
TRAFFIC_RESIDUAL_LABEL = "Other / transport overhead"


def available_traffic_components(df, columns_suffix="_bytes"):
    """
    Retourne, dans l'ordre chronologique TRAFFIC_COMPONENT_ORDER, uniquement
    les composants dont la colonne existe dans df ET contient au moins une
    valeur non-NA (ex: 'CertificateRequest' est exclu tant qu'aucune capture
    mutual-auth n'existe, mais réapparaît automatiquement dès qu'il y en a).
    """
    available = []
    for comp in TRAFFIC_COMPONENT_ORDER:
        col = f"{comp}{columns_suffix}"
        if col in df.columns and df[col].notna().any():
            available.append(comp)
    return available


def fmt_kb(n_bytes, base=1024):
    """Formatage compact d'une taille en KB pour annotation sur figure."""
    kb = n_bytes / base
    if kb >= 100:
        return f"{kb:.0f}"
    if kb >= 10:
        return f"{kb:.1f}"
    return f"{kb:.2f}"


def resolve_duplicate_runs(df, key_cols, timestamp_col="timestamp", value_cols=None):
    """
    Certains CSV de ce dépôt contiennent plusieurs mesures pour la même
    combinaison (ex: resource_usage_*.csv après un re-run partiel). Règle
    adoptée : on garde la ligne au timestamp le PLUS RÉCENT par combinaison
    de key_cols, et on imprime un rapport transparent des combinaisons
    affectées (jamais un dédoublonnage silencieux).

    IMPORTANT (cf. aggregate_resource_blocks ci-dessous) : depuis le passage
    à la méthodologie en blocs randomisés, resource_usage_*.csv contient
    normalement PLUSIEURS lignes voulues par combinaison (une par
    block_index) -- ce ne sont PAS des doublons à écraser. Pour ces
    fichiers, `key_cols` DOIT inclure "block_index" ici, afin que cette
    fonction ne traite comme "doublon" que deux lignes partageant le MÊME
    block_index (un vrai re-run accidentel). L'agrégation statistique des
    blocs entre eux se fait ensuite, séparément, via
    aggregate_resource_blocks.

    df           : DataFrame avec une colonne timestamp (parseable par pandas)
    key_cols     : liste de colonnes identifiant une combinaison unique
    value_cols   : colonnes numériques à comparer entre versions pour le
                   rapport d'écart (si None, toutes les colonnes numériques)
    Retourne le DataFrame dédoublonné (une ligne par combinaison de key_cols).
    """
    df = df.copy()
    df["_ts_parsed"] = pd.to_datetime(df[timestamp_col])
    dup_mask = df.duplicated(subset=key_cols, keep=False)
    n_dup_combos = df.loc[dup_mask, key_cols].drop_duplicates().shape[0]

    if n_dup_combos > 0:
        if value_cols is None:
            value_cols = df.select_dtypes(include="number").columns.tolist()
        print(f"    [ATTENTION] {n_dup_combos} combinaison(s) avec plusieurs mesures "
              f"({timestamp_col} différents) -- la ligne au timestamp le plus récent "
              f"est conservée pour chacune :")
        for keys, group in df.loc[dup_mask].groupby(key_cols):
            group_sorted = group.sort_values("_ts_parsed")
            oldest, newest = group_sorted.iloc[0], group_sorted.iloc[-1]
            diffs = []
            for vc in value_cols:
                if vc in group.columns and oldest[vc] != 0:
                    rel = 100 * (newest[vc] - oldest[vc]) / oldest[vc]
                    if abs(rel) > 1:
                        diffs.append(f"{vc}: {rel:+.0f}%")
            key_str = keys if isinstance(keys, str) else "/".join(map(str, keys))
            print(f"      {key_str} -- {len(group)} mesures, "
                  f"écart le plus récent vs le plus ancien: {', '.join(diffs) if diffs else 'négligeable'}")

    df = df.sort_values("_ts_parsed").drop_duplicates(subset=key_cols, keep="last")
    return df.drop(columns=["_ts_parsed"]).reset_index(drop=True)


def block_bootstrap_mean_ci(block_values, n_resamples=5000, seed=12345):
    """
    IC95% de la moyenne par bootstrap de BLOCS ENTIERS (rééchantillonnage
    avec remise de blocs, jamais d'observations individuelles à l'intérieur
    d'un bloc). Reçoit directement une liste de valeurs DÉJÀ AGRÉGÉES PAR
    BLOC (ex: cpu_usec_per_handshake moyen sur les n_runs d'un bloc) --
    contrairement à block_bootstrap_ci() dans analyze_handshake_performance.py
    qui rééchantillonne des durées de handshake individuelles à l'intérieur
    de chaque bloc rééchantillonné (les logs de latence ont l'observation
    individuelle disponible, pas resource_usage_*.csv qui ne stocke qu'une
    moyenne par bloc).

    Même graine et même nombre de resamples (seed=12345, n_resamples=5000)
    que le reste du pipeline statistique, pour rester cohérent.

    Retourne None si moins de 2 blocs (bootstrap non défini avec un seul
    bloc -- le résultat doit alors être signalé comme "IC non calculable",
    jamais silencieusement omis).
    """
    import random
    block_values = [v for v in block_values if v is not None]
    if len(block_values) < 2:
        return None
    rng = random.Random(seed)
    means = sorted(
        statistics.mean(rng.choice(block_values) for _ in range(len(block_values)))
        for _ in range(n_resamples)
    )

    def pct(p):
        k = (len(means) - 1) * (p / 100)
        f, c = int(k), min(int(k) + 1, len(means) - 1)
        if f == c:
            return means[f]
        return means[f] + (means[c] - means[f]) * (k - f)

    return (round(pct(2.5), 3), round(pct(97.5), 3))


def aggregate_resource_blocks(df, key_cols, value_cols, block_col="block_index"):
    """
    Agrège les lignes-blocs de resource_usage_*.csv (une ligne par
    block_index pour une même combinaison de key_cols, chacune déjà moyennée
    en interne sur les n_runs handshakes du bloc) en UNE ligne par
    combinaison, avec moyenne inter-blocs et IC95% par bootstrap de blocs
    (cf. block_bootstrap_mean_ci).

    À utiliser TOUJOURS APRÈS resolve_duplicate_runs(key_cols + [block_col]),
    qui doit avoir déjà éliminé les vrais doublons accidentels au même
    block_index. Ici, les lignes multiples par combinaison de key_cols sont
    les blocs VOULUS de la méthodologie -- elles sont combinées
    statistiquement, jamais écrasées ni moyennées en ignorant leur
    appartenance à des blocs distincts.

    Pour chaque colonne de value_cols, ajoute au DataFrame retourné :
        {value_col}_mean       -- moyenne des moyennes de bloc
        {value_col}_ci95_low   -- borne basse IC95% bootstrap de blocs (ou "NA")
        {value_col}_ci95_high  -- borne haute IC95% bootstrap de blocs (ou "NA")
        {value_col}_ci_method  -- "bootstrap_blocs" ou message explicite si
                                   IC non calculable (1 seul bloc)
    Ajoute aussi "n_blocks_pooled" (nombre de block_index distincts vus pour
    la combinaison).
    """
    rows = []
    for keys, group in df.groupby(key_cols):
        key_vals = keys if isinstance(keys, tuple) else (keys,)
        row = dict(zip(key_cols, key_vals))
        n_blocks = group[block_col].nunique()
        row["n_blocks_pooled"] = n_blocks
        for vc in value_cols:
            block_means = group.groupby(block_col)[vc].mean().tolist()
            row[f"{vc}_mean"] = statistics.mean(block_means) if block_means else None
            ci = block_bootstrap_mean_ci(block_means) if n_blocks > 1 else None
            if ci is not None:
                row[f"{vc}_ci95_low"], row[f"{vc}_ci95_high"] = ci
                row[f"{vc}_ci_method"] = "bootstrap_blocs"
            else:
                row[f"{vc}_ci95_low"], row[f"{vc}_ci95_high"] = "NA", "NA"
                row[f"{vc}_ci_method"] = "normale_naive (1 seul bloc -- IC non calculable ici)"
        rows.append(row)
    return pd.DataFrame(rows)


# =========================================================================
# 7. SAUVEGARDE STANDARDISÉE (PDF vectoriel + PNG haute résolution)
# =========================================================================

def save_figure(fig, output_dir, filename_stem: str, dpi: int = 300):
    """
    Sauvegarde une figure en PDF (vectoriel, pour soumission à la revue)
    ET en PNG haute résolution (pour relecture/brouillon/PowerPoint).

    - output_dir : dossier 'plots/' du scénario concerné (créé s'il n'existe pas)
    - filename_stem : nom de fichier SANS extension, explicite et intuitif
      (ex: "handshake_L1_tls_single_ideal")

    Ne met AUCUN titre dans la figure elle-même (le titre/la légende de
    figure doit être dans le texte LaTeX de l'article, pas incrusté dans
    le PDF) -- ceci est une convention, pas une contrainte technique : si
    un script ajoute un ax.set_title(), c'est un choix explicite à faire
    au cas par cas, pas la norme par défaut.

    Retourne (chemin_pdf, chemin_png).
    """
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    pdf_path = out_dir / f"{filename_stem}.pdf"
    png_path = out_dir / f"{filename_stem}.png"

    fig.savefig(pdf_path, bbox_inches="tight")
    fig.savefig(png_path, bbox_inches="tight", dpi=dpi)

    print(f"[OK] {pdf_path}")
    print(f"[OK] {png_path}")
    return pdf_path, png_path


def style_axes(ax, grid_axis="y"):
    """Nettoyage standard des axes : pas de spines haut/droite, grille légère."""
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.grid(True, axis=grid_axis, alpha=0.35, linewidth=0.5)
    ax.set_axisbelow(True)
    return ax


def kem_family_legend_handles(families=None):
    """
    Construit les handles de légende (patches colorés) pour les familles
    de KEM utilisées dans une figure, dans l'ordre canonique KEM_FAMILY_ORDER.

    `families` : sous-ensemble optionnel de KEM_FAMILY_ORDER à inclure
                  (si None, inclut les 5 familles).
    """
    fams = families if families is not None else KEM_FAMILY_ORDER
    fams_ordered = [f for f in KEM_FAMILY_ORDER if f in fams]
    return [
        mpatches.Patch(color=KEM_FAMILY_COLORS[f], label=KEM_FAMILY_LABELS[f])
        for f in fams_ordered
    ]


def security_level_legend_handles(levels=None):
    """Handles de légende pour les marqueurs de niveau de sécurité (figures globales)."""
    lvls = levels if levels is not None else SECURITY_LEVEL_ORDER
    lvls_ordered = [l for l in SECURITY_LEVEL_ORDER if l in lvls]
    return [
        mlines.Line2D([], [], color="black", marker=SECURITY_LEVEL_MARKERS[l],
                      linestyle="None", label=SECURITY_LEVEL_LABELS[l])
        for l in lvls_ordered
    ]


# =========================================================================
# 8. AUTO-TEST : génère une planche de vérification de la palette
# =========================================================================

if __name__ == "__main__":
    import numpy as np

    fig, axes = plt.subplots(1, 2, figsize=FIGSIZE_DOUBLE_COL)

    # Panel 1 : swatches de couleur avec labels
    ax = axes[0]
    for i, fam in enumerate(KEM_FAMILY_ORDER):
        ax.barh(i, 1, color=KEM_FAMILY_COLORS[fam])
        ax.text(1.05, i, KEM_FAMILY_LABELS[fam], va="center", fontsize=8)
    ax.set_yticks([])
    ax.set_xticks([])
    ax.set_xlim(0, 2.6)
    ax.set_title("KEM family palette", fontsize=9)
    for spine in ax.spines.values():
        spine.set_visible(False)

    # Panel 2 : démo d'un mini graphique combinant couleur (famille) et
    # marker (niveau de sécurité), pour vérifier la lisibilité combinée
    ax = axes[1]
    rng = np.random.default_rng(0)
    for lvl in SECURITY_LEVEL_ORDER:
        for fam in KEM_FAMILY_ORDER:
            x = SECURITY_LEVEL_ORDER.index(lvl) + rng.uniform(-0.1, 0.1)
            y = rng.uniform(0, 1) + KEM_FAMILY_ORDER.index(fam)
            ax.plot(x, y, marker=SECURITY_LEVEL_MARKERS[lvl],
                     color=KEM_FAMILY_COLORS[fam], linestyle="None")
    ax.set_xticks(range(len(SECURITY_LEVEL_ORDER)))
    ax.set_xticklabels(SECURITY_LEVEL_ORDER)
    ax.set_title("Color = KEM family, marker = security level", fontsize=9)
    style_axes(ax)

    fig.tight_layout()
    save_figure(fig, "./_style_test", "palette_check")

    # Test de classify_kem_family sur des cas réels de tes CSV
    test_cases = [
        ("classique", "P-256", "classical"),
        ("classique", "x25519", "classical"),
        ("pq_pur", "hqc128", "hqc_pure"),
        ("pq_pur", "mlkem512", "mlkem_pure"),
        ("hybride", "p256_hqc128", "hqc_hybrid"),
        ("hybride", "x25519_mlkem512", "mlkem_hybrid"),
        ("hybride", "p384_hqc192", "hqc_hybrid"),
        ("hybride", "p521_mlkem1024", "mlkem_hybrid"),
    ]
    print("\n--- Vérification classify_kem_family() sur cas réels ---")
    all_ok = True
    for kem_class, kem_name, expected in test_cases:
        result = classify_kem_family(kem_class, kem_name)
        status = "OK" if result == expected else "FAIL"
        if result != expected:
            all_ok = False
        print(f"[{status}] classify_kem_family({kem_class!r}, {kem_name!r}) "
              f"= {result!r} (attendu: {expected!r})")
    print("\nTOUT EST OK." if all_ok else "\n!!! DES TESTS ONT ÉCHOUÉ !!!")
