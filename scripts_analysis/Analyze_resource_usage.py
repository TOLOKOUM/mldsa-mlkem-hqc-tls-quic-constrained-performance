#!/usr/bin/env python3
"""
analyze_resource_usage.py — Agrège resource_usage.csv (produit par
Launcher_unified.sh / Launcher_pq_mldsa_mlkem_hqc.sh) en un tableau
comparatif CPU/mémoire par combinaison SIG_ALG/KEM, avec calcul du
surcoût relatif PQ vs classique.

USAGE:
    python3 analyze_resource_usage.py --input ~/captures/resource_usage/resource_usage.csv \
                                       --out-dir results_resources/
    python3 analyze_resource_usage.py --input-dir ~/captures --out-dir results_resources/

LIMITE MÉTHODOLOGIQUE (reprise du launcher, à documenter dans l'article) :
    Les mesures CPU/mémoire portent sur le conteneur entier (harnais de test
    perftestClientTlsQuic.sh / perftestServerTlsQuic.sh inclus), pas
    uniquement sur les opérations cryptographiques isolées. Le surcoût
    relatif PQ-vs-classique reste néanmoins valide car ce biais de mesure
    est constant à travers toutes les combinaisons.

AGRÉGATION PAR BLOCS (méthodologie post-refonte, 4 blocs randomisés) :
    Depuis le passage à Launcher_pq_mldsa_mlkem_hqc.sh en 4 blocs, chaque
    combinaison (protocol, auth_mode, sig_alg, kem, role) apparaît en
    PLUSIEURS lignes (une par block_index), chacune déjà moyennée en
    interne sur les n_runs handshakes du bloc (typiquement 125). Le
    pipeline ci-dessous agrège D'ABORD par combinaison individuelle sur ses
    blocs (moyenne + IC95% bootstrap de blocs), et SEULEMENT ENSUITE
    regroupe ces moyennes-de-combo par (protocol, role, kem_class) pour le
    tableau récapitulatif -- jamais l'inverse. Faire l'inverse (moyenner
    directement les lignes-blocs brutes par classe) mélangerait le bruit
    intra-combo (bloc à bloc) avec la vraie variance inter-combo (P-256 vs
    X25519 par ex.), et sur-pondérerait les combinaisons ayant plus de
    blocs exploitables que d'autres.

    Pour d'anciennes captures à un seul run par combinaison (pas de colonne
    block_index, ou une seule valeur de block_index), le comportement se
    réduit naturellement au cas à 1 bloc : moyenne = la valeur unique, IC
    marqué explicitement "NA (1 seul bloc)" plutôt que silencieusement omis.
"""

import argparse
import csv
import random
import re
import statistics
from pathlib import Path
from collections import defaultdict

_RESOURCE_FILENAME_RE = re.compile(r"^resource_usage_(tls|quic)_(single|mutual)_(.+)\.csv$")


def classify_kem(kem: str) -> str:
    """Classe un KEM en classique / hybride / PQ pur, pour regroupement.
    Normalise la casse et les tirets car les noms hybrides utilisent
    'p256_mlkem512' (minuscule, sans tiret) alors que le KEM classique pur
    s'appelle 'P-256' (majuscule, avec tiret) dans le launcher."""
    k = kem.lower().replace("-", "")
    is_pq = any(tag in k for tag in ("mlkem", "hqc"))
    is_classical_component = any(tag in k for tag in ("p256", "p384", "p521", "x25519", "x448"))
    if is_pq and is_classical_component:
        return "hybride"
    if is_pq:
        return "pq_pur"
    return "classique"


def load_rows(path: Path, scenario_override: str = None):
    """Charge un CSV resource_usage_*.csv. Si scenario_override est fourni
    (dérivé du NOM DU FICHIER par load_rows_multi, jamais de la colonne
    interne), il remplace la valeur de network_profile lue dans le CSV et
    sert de source de vérité -- cf. _check_network_profile_sanity : le
    champ network_profile écrit par le pipeline de capture s'est avéré
    parfois tronqué/générique (ex: 'simple' pour deux scénarios de perte
    distincts, 'simple_loss1.3_delay62.51ms' ET 'simple_loss1.5833_delay83.52ms'
    tous les deux réduits à 'simple'), ce qui fusionnerait silencieusement
    deux conditions réseau différentes si on lui faisait confiance."""
    rows = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for r in reader:
            if r["cpu_usec_per_handshake"] in ("NA", "", None) and r["mem_peak_bytes"] in ("NA", "", None):
                continue
            rows.append(r)
    _check_network_profile_sanity(path, rows, scenario_override)
    if scenario_override is not None:
        for r in rows:
            r["network_profile"] = scenario_override
    return rows


def _check_network_profile_sanity(path: Path, rows, scenario_override: str = None):
    """Garde-fou : un bug déjà rencontré sur traffic_size_summary.csv faisait
    que la colonne network_profile contenait la valeur du protocole
    ('tls'/'quic') au lieu du scénario réseau réel. Un second bug, distinct,
    a été trouvé ici : network_profile tronqué en 'simple' pour DEUX
    scénarios de perte différents (perd la distinction Modéré/Dégradé). Les
    deux sont signalés fort -- network_profile ne doit jamais être fusionné
    en silence."""
    if not rows:
        return
    seen = {r.get("network_profile") for r in rows}
    if seen & {"tls", "quic"}:
        print(f"    [ATTENTION GRAVE] {path.name} : la colonne network_profile contient "
              f"{seen & {'tls', 'quic'}} -- ça ressemble au bug déjà vu sur "
              f"traffic_size_summary.csv (network_profile pollué par la valeur du "
              f"protocole). Vérifie le générateur de ce CSV avant de faire confiance "
              f"à l'agrégation par scénario réseau.")
    elif not (seen - {None, "NA", ""}):
        print(f"    [ATTENTION] {path.name} : colonne network_profile vide/absente sur "
              f"toutes les lignes -- l'agrégation par combo ne pourra pas distinguer les "
              f"scénarios réseau pour ce fichier.")
    if scenario_override is not None and seen - {scenario_override}:
        print(f"    [ATTENTION GRAVE] {path.name} : la colonne network_profile du CSV "
              f"contient {seen} au lieu du scénario attendu d'après le nom de fichier/dossier "
              f"({scenario_override!r}) -- valeur du CSV IGNORÉE et remplacée par "
              f"{scenario_override!r} pour toutes les lignes de ce fichier. Ce champ est "
              f"donc non fiable dans le pipeline de capture -- à corriger à la source si "
              f"d'autres scripts en dépendent directement.")


def scenario_from_filename(path: Path):
    """Dérive (protocol, auth_mode, scenario) du nom de fichier
    resource_usage_{protocol}_{auth_mode}_{scenario}.csv -- source de
    vérité pour network_profile, cf. load_rows. Retourne None si le nom ne
    correspond pas à ce motif (cas du fallback legacy 'resource_usage.csv'
    plat, où on ne peut pas déduire le scénario du nom de fichier et où
    on doit alors faire confiance -- prudemment -- à la colonne interne)."""
    m = _RESOURCE_FILENAME_RE.match(path.name)
    if not m:
        return None
    return m.group(3)


def load_rows_multi(paths):
    """Charge et concatène plusieurs resource_usage_*.csv (structure éclatée
    par protocole/auth_mode/network_profile depuis Launcher_pq_mldsa_mlkem_hqc.sh).
    Pour chaque fichier dont le nom suit le motif standard, le scénario réseau
    est dérivé du NOM DE FICHIER (source fiable) et remplace la colonne
    network_profile interne du CSV, qui s'est avérée non fiable (cf.
    _check_network_profile_sanity). Chaque ligne garde ses propres colonnes
    protocol/auth_mode, donc l'agrégation en aval (par protocole/rôle/classe
    KEM/scénario) reste correcte même en mélangeant des fichiers de
    scénarios différents."""
    rows = []
    for p in paths:
        scenario = scenario_from_filename(p)
        rows.extend(load_rows(p, scenario_override=scenario))
    return rows


def to_float(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def block_bootstrap_ci_simple(block_means, n_resamples=5000, seed=12345):
    """IC95% de la moyenne par bootstrap de BLOCS ENTIERS. Reçoit une liste
    de valeurs déjà agrégées PAR BLOC (une moyenne par block_index) --
    même principe et mêmes paramètres (seed=12345, 5000 resamples) que
    block_bootstrap_ci dans analyze_handshake_performance.py et
    block_bootstrap_mean_ci dans plot_style.py, pour rester cohérent sur
    tout le pipeline statistique. Retourne None si moins de 2 blocs."""
    if len(block_means) < 2:
        return None
    rng = random.Random(seed)
    means = sorted(
        statistics.mean(rng.choice(block_means) for _ in range(len(block_means)))
        for _ in range(n_resamples)
    )

    def pct(p):
        k = (len(means) - 1) * (p / 100)
        f, c = int(k), min(int(k) + 1, len(means) - 1)
        return means[f] if f == c else means[f] + (means[c] - means[f]) * (k - f)

    return (pct(2.5), pct(97.5))


def aggregate_by_combo(rows):
    """Agrège les lignes-blocs (une par block_index, ou une seule ligne pour
    les anciennes captures sans colonne block_index) en une ligne par
    combinaison (protocol, auth_mode, network_profile, sig_alg, kem, role),
    avec moyenne inter-blocs et IC95% bootstrap de blocs -- AVANT tout
    regroupement par classe KEM (cf. aggregate() ci-dessous).

    CRITIQUE : network_profile DOIT faire partie de la clé. Avec
    --input-dir, les 5 scénarios réseau (none/loss1.3/loss1.5833/stable/
    unstable) sont chargés depuis des fichiers séparés dont chacun a ses
    propres block_index 1..4. Sans network_profile dans la clé, un
    block_index=1 du scénario "none" serait confondu avec le block_index=1
    du scénario "stable" -- ce ne sont PAS des blocs de la même expérience,
    et les mélanger pollue l'IC bootstrap avec l'effet du réseau au lieu du
    seul bruit intra-combo."""
    groups = defaultdict(lambda: {"cpu": defaultdict(list), "mem": defaultdict(list)})
    for r in rows:
        key = (r["protocol"], r["auth_mode"], r.get("network_profile", "NA"),
               r["sig_alg"], r["kem"], r["role"])
        block = r.get("block_index", "1") or "1"
        cpu = to_float(r["cpu_usec_per_handshake"])
        mem = to_float(r["mem_peak_bytes"])
        if cpu is not None:
            groups[key]["cpu"][block].append(cpu)
        if mem is not None:
            groups[key]["mem"][block].append(mem)

    combo_rows = []
    for (protocol, auth_mode, network_profile, sig_alg, kem, role), vals in sorted(groups.items()):
        row = {
            "protocol": protocol, "auth_mode": auth_mode, "network_profile": network_profile,
            "sig_alg": sig_alg, "kem": kem, "kem_class": classify_kem(kem), "role": role,
        }
        for metric, unit_div, mean_key, ci_key, n_key in (
            ("cpu", 1000.0, "cpu_ms_per_handshake_mean", "cpu_ms_ci95", "n_blocks_cpu"),
            ("mem", 1024 * 1024.0, "mem_peak_MiB_mean", "mem_MiB_ci95", "n_blocks_mem"),
        ):
            # Une valeur par block_index (moyenne du bloc, déjà agrégée en
            # amont sur ses n_runs handshakes -- ou valeur unique si un seul
            # run existe pour ce block_index, ce qui est le cas normal).
            block_means = [statistics.mean(v) for v in vals[metric].values() if v]
            row[n_key] = len(block_means)
            if block_means:
                row[mean_key] = round(statistics.mean(block_means) / unit_div, 3)
                ci = block_bootstrap_ci_simple(block_means) if len(block_means) > 1 else None
                if ci is not None:
                    row[ci_key] = f"[{ci[0] / unit_div:.3f}, {ci[1] / unit_div:.3f}]"
                    row[f"{ci_key}_method"] = "bootstrap_blocs"
                else:
                    row[ci_key] = "NA (1 seul bloc)"
                    row[f"{ci_key}_method"] = "normale_naive (1 seul bloc -- IC non calculable ici)"
            else:
                row[mean_key], row[ci_key], row[f"{ci_key}_method"] = "NA", "NA", "NA"
        combo_rows.append(row)
    return combo_rows


def aggregate(combo_rows):
    """Regroupe par (protocol, network_profile, role, kem_class) à PARTIR
    DES MOYENNES PAR COMBO déjà calculées par aggregate_by_combo -- jamais
    à partir des lignes-blocs brutes (cf. note méthodologique en tête de
    fichier). network_profile reste une dimension du regroupement : le
    surcoût CPU/mémoire PQ-vs-classique peut légitimement différer entre
    Ideal et un scénario avec pertes (retransmissions QUIC notamment), donc
    on ne l'efface pas en moyennant across scenarios."""
    groups = defaultdict(lambda: {"cpu": [], "mem": []})
    for r in combo_rows:
        key = (r["protocol"], r["network_profile"], r["role"], r["kem_class"])
        if r["cpu_ms_per_handshake_mean"] != "NA":
            groups[key]["cpu"].append(r["cpu_ms_per_handshake_mean"])
        if r["mem_peak_MiB_mean"] != "NA":
            groups[key]["mem"].append(r["mem_peak_MiB_mean"])

    summary = []
    for (protocol, network_profile, role, kem_class), vals in sorted(groups.items()):
        cpu_vals, mem_vals = vals["cpu"], vals["mem"]
        summary.append({
            "protocol": protocol,
            "network_profile": network_profile,
            "role": role,
            "kem_class": kem_class,
            "n_combinations": max(len(cpu_vals), len(mem_vals)),
            "cpu_ms_per_handshake_mean": round(statistics.mean(cpu_vals), 3) if cpu_vals else "NA",
            "mem_peak_MiB_mean": round(statistics.mean(mem_vals), 2) if mem_vals else "NA",
        })
    return summary


def compute_overhead(summary):
    """Calcule le surcoût relatif (%) de chaque classe vs le baseline
    classique, par protocole, PAR SCÉNARIO RÉSEAU et par rôle (baseline
    calculé séparément pour chaque network_profile -- ne compare jamais un
    scénario dégradé à un baseline mesuré sous un autre scénario)."""
    baseline = {}
    for row in summary:
        if row["kem_class"] == "classique" and row["cpu_ms_per_handshake_mean"] != "NA":
            baseline[(row["protocol"], row["network_profile"], row["role"])] = row["cpu_ms_per_handshake_mean"]

    overhead_rows = []
    for row in summary:
        base = baseline.get((row["protocol"], row["network_profile"], row["role"]))
        if base and row["cpu_ms_per_handshake_mean"] != "NA" and base > 0:
            pct = round((row["cpu_ms_per_handshake_mean"] - base) / base * 100, 1)
        else:
            pct = "NA"
        overhead_rows.append({**row, "cpu_overhead_pct_vs_classique": pct})
    return overhead_rows


def write_csv(path, rows):
    if not rows:
        return
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def write_report(path, overhead_rows, n_raw_rows, n_combos, n_single_block_combos):
    lines = ["# Annexe méthodologique — Consommation CPU/mémoire des handshakes\n"]
    lines.append(f"**Lignes brutes agrégées : {n_raw_rows}**  \n")
    lines.append(f"**Combinaisons distinctes (protocol/auth_mode/network_profile/sig_alg/kem/role) : "
                  f"{n_combos}**  \n")
    lines.append(f"**Dont combinaisons avec un seul bloc exploitable (pas d'IC bootstrap) : "
                  f"{n_single_block_combos}**\n")
    lines.append("| Protocole | Scénario réseau | Rôle | Classe KEM | N combinaisons | "
                  "CPU moyen/handshake (ms) | Surcoût CPU vs classique (%) | Pic mémoire moyen (MiB) |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for r in overhead_rows:
        lines.append(f"| {r['protocol']} | {r['network_profile']} | {r['role']} | {r['kem_class']} | "
                      f"{r['n_combinations']} | {r['cpu_ms_per_handshake_mean']} | "
                      f"{r['cpu_overhead_pct_vs_classique']} | {r['mem_peak_MiB_mean']} |")

    lines.append("\n## Note méthodologique (à inclure telle quelle dans l'article)\n")
    lines.append("Les mesures CPU proviennent des compteurs cgroup (`cpu.stat`/`cpuacct.usage`) "
                  "du conteneur, capturés en delta entre le début et la fin de chaque batch de "
                  "handshakes, puis divisés par le nombre de handshakes. Le pic mémoire provient de "
                  "`memory.peak` (cgroup v2) ou `memory.max_usage_in_bytes` (cgroup v1). Ces mesures "
                  "portent sur le conteneur entier, harnais de test inclus, et non sur les seules "
                  "opérations cryptographiques ; ce biais constant à travers toutes les combinaisons "
                  "ne remet pas en cause la comparaison relative classique/hybride/PQ pur.\n\n"
                  "Chaque combinaison a été mesurée sur 4 blocs randomisés indépendants (méthodologie "
                  "identique à celle des mesures de latence) ; les valeurs moyennes ci-dessus sont la "
                  "moyenne des moyennes de bloc, avec IC95% par bootstrap de blocs entiers (5000 "
                  "resamples, seed 12345) rapporté au niveau de chaque combinaison individuelle dans "
                  "resource_by_combo.csv. Pour les combinaisons ne disposant que d'un seul bloc "
                  "exploitable, l'IC bootstrap n'est pas calculable et n'est pas rapporté (cf. colonne "
                  "cpu_ms_ci95_method / mem_MiB_ci95_method).")

    Path(path).write_text("\n".join(lines))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", type=Path,
                     help="Chemin vers un unique resource_usage*.csv (rétrocompatibilité)")
    ap.add_argument("--input-dir", type=Path,
                     help="Dossier racine (ex: captures/) sous lequel chercher récursivement "
                          "tous les resource_usage_*.csv (structure éclatée par "
                          "protocole/auth_mode/network_profile)")
    ap.add_argument("--out-dir", default="results_resources", type=Path)
    args = ap.parse_args()

    if not args.input and not args.input_dir:
        print("ERREUR: fournir --input <fichier.csv> OU --input-dir <dossier racine captures/>")
        return

    args.out_dir.mkdir(parents=True, exist_ok=True)

    if args.input_dir:
        if not args.input_dir.exists():
            print(f"ERREUR: dossier introuvable: {args.input_dir}")
            return
        csv_paths = sorted(args.input_dir.rglob("resource_usage_*.csv"))
        # Rétrocompatibilité : ancien format non-éclaté, un seul fichier nommé
        # exactement "resource_usage.csv" quelque part dans l'arborescence.
        csv_paths += sorted(args.input_dir.rglob("resource_usage.csv"))
        if not csv_paths:
            print(f"ERREUR: aucun resource_usage*.csv trouvé sous {args.input_dir}")
            return
        print(f"{len(csv_paths)} fichier(s) resource_usage trouvé(s) sous {args.input_dir} :")
        for p in csv_paths:
            print(f"  - {p}")
        rows = load_rows_multi(csv_paths)
    else:
        if not args.input.exists():
            print(f"ERREUR: fichier introuvable: {args.input}")
            return
        rows = load_rows(args.input, scenario_override=scenario_from_filename(args.input))

    print(f"Lignes exploitables (CPU ou mémoire non-NA) : {len(rows)}")
    if not rows:
        print("Aucune donnée exploitable — vérifiez que le launcher a bien pu lire les cgroups "
              "(certains environnements Docker restreignent l'accès à /sys/fs/cgroup depuis un "
              "conteneur ; voir la limite documentée dans le script).")
        return

    combo_rows = aggregate_by_combo(rows)
    n_single_block_combos = sum(
        1 for r in combo_rows
        if r["n_blocks_cpu"] <= 1 and r["n_blocks_mem"] <= 1
    )
    write_csv(args.out_dir / "resource_by_combo.csv", combo_rows)

    summary = aggregate(combo_rows)
    overhead = compute_overhead(summary)

    write_csv(args.out_dir / "resource_summary.csv", overhead)
    write_report(args.out_dir / "rapport_ressources.md", overhead, len(rows),
                 len(combo_rows), n_single_block_combos)

    print(f"\nTerminé. Fichiers écrits dans {args.out_dir}/:")
    print("  - resource_by_combo.csv   (une ligne par combinaison INCLUANT le scénario réseau, "
          "agrégée sur ses 4 blocs, avec IC)")
    print("  - resource_summary.csv    (agrégat par classe KEM/protocole/scénario réseau/rôle)")
    print("  - rapport_ressources.md")
    if n_single_block_combos:
        print(f"\n[ATTENTION] {n_single_block_combos} combinaison(s) (protocol/auth_mode/"
              f"network_profile/sig_alg/kem/role) n'ont qu'un seul bloc exploitable -- pas "
              f"d'IC bootstrap pour elles, voir resource_by_combo.csv.")


if __name__ == "__main__":
    main()
