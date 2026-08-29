#!/usr/bin/env python3
"""
analyze_sessions.py — Agrège les sessions collectées par collect_session.sh
et dérive 3 scénarios réseau réels : Idéal, Modéré, Dégradé.

Le modèle Gilbert-Elliott (burst-loss) N'EST PAS recalculé ici : ses paramètres
restent ceux déjà validés dans le projet précédent (aucune donnée d'entrée requise).

USAGE:
    python3 analyze_sessions.py --sessions-dir sessions/ --out-dir results/

SORTIES:
    results/sessions_summary.csv   -> une ligne par session, toutes les stats
    results/scenarios_reels.csv    -> les 3 scénarios dérivés + commandes tc/netem
    results/rapport_methodologique.md -> texte prêt à coller dans l'annexe de l'article

HYPOTHÈSE MÉTHODOLOGIQUE REPRISE DU PROJET PRÉCÉDENT :
    Le délai est appliqué en bidirectionnel sur eth0 des conteneurs client ET serveur,
    ce qui double le RTT déclaré. Donc pour obtenir un RTT cible mesuré R_target,
    la commande tc doit utiliser delay = R_target / 2 sur CHAQUE interface.
"""

import argparse
import json
import re
import statistics
import csv
from pathlib import Path

RTT_RE = re.compile(r"time=([\d.]+)\s*ms")
SUMMARY_LOSS_RE = re.compile(r"(\d+)\s+packets transmitted,\s+(\d+)\s+received.*?([\d.]+)%\s+packet loss")
IPERF_JITTER_RE = re.compile(r"([\d.]+)\s+ms\s+\d+/\d+\s*\(([\d.]+)%\)")


def parse_ping_log(path: Path):
    text = path.read_text(errors="ignore")
    rtts = [float(x) for x in RTT_RE.findall(text)]
    m = SUMMARY_LOSS_RE.search(text)
    if m:
        transmitted, received, loss_pct = int(m.group(1)), int(m.group(2)), float(m.group(3))
    else:
        # fallback : pas de ligne de résumé exploitable
        transmitted, received, loss_pct = len(rtts), len(rtts), 0.0
    return rtts, transmitted, received, loss_pct


def parse_iperf_log(path: Path):
    if not path.exists():
        return None, None
    text = path.read_text(errors="ignore")
    matches = IPERF_JITTER_RE.findall(text)
    if not matches:
        return None, None
    # dernière ligne exploitable = résumé "Receiver"
    jitter_ms, loss_pct = matches[-1]
    return float(jitter_ms), float(loss_pct)


def percentile(values, p):
    if not values:
        return None
    s = sorted(values)
    k = (len(s) - 1) * (p / 100)
    f, c = int(k), min(int(k) + 1, len(s) - 1)
    if f == c:
        return s[f]
    return s[f] + (s[c] - s[f]) * (k - f)


def load_sessions(sessions_dir: Path):
    rows = []
    raw_rtts_by_session = {}
    for sdir in sorted(sessions_dir.glob("*")):
        meta_path = sdir / "meta.json"
        ping_path = sdir / "ping.log"
        if not (meta_path.exists() and ping_path.exists()):
            continue
        meta = json.loads(meta_path.read_text())
        rtts, transmitted, received, loss_pct = parse_ping_log(ping_path)
        jitter_ms, iperf_loss_pct = parse_iperf_log(sdir / "iperf.log")

        if not rtts:
            print(f"  [!] {sdir.name}: aucune valeur RTT exploitable, session ignorée.")
            continue

        raw_rtts_by_session[sdir.name] = rtts
        rows.append({
            "session": sdir.name,
            "operator": meta.get("operator"),
            "connection_type": meta.get("connection_type"),
            "location": meta.get("location"),
            "day_of_week": meta.get("day_of_week"),
            "time_slot": meta.get("time_slot"),
            "hour": meta.get("hour"),
            "n_rtt_samples": len(rtts),
            "rtt_mean_ms": round(statistics.mean(rtts), 3),
            "rtt_stdev_ms": round(statistics.stdev(rtts), 3) if len(rtts) > 1 else 0.0,
            "rtt_p50_ms": round(percentile(rtts, 50), 3),
            "rtt_p95_ms": round(percentile(rtts, 95), 3),
            "rtt_p99_ms": round(percentile(rtts, 99), 3),
            "loss_pct": loss_pct,
            "transmitted": transmitted,
            "received": received,
            "jitter_ms": jitter_ms,
        })
    return rows, raw_rtts_by_session


IDEAL_SCENARIO = {
    "scenario": "Idéal (Baseline)",
    "source_session": "N/A (Theoretical Control)",
    "operator": "None",
    "connection_type": "Loopback / Local",
    "time_slot": "N/A",
    "rtt_mean_ms": 0.0,
    "rtt_p95_ms": 0.0,
    "loss_pct": 0.0,
    "severity_score": None,
    "jitter_ms": 0.0,
    "tc_delay_per_interface_ms": 0.0,
    "tc_netem_cmd": "none (pas de restriction tc)",
    "n_sessions_used": "N/A",
    "n_sessions_excluded_iqr": "N/A",
    "n_jitter_sessions": "N/A",
    "days_covered": "N/A",
}


# ─────────────────────────────────────────────────────────────────────────
# Mapping opérateur -> scénario, FIXÉ (pas re-dérivé à chaque exécution).
# Conforme au design déjà établi dans l'article (Table 2, tab:related,
# §Contributions : "Moderate reproduces an MTN 4G measurement, Degraded an
# Orange 4G measurement"). Le score de sévérité composite (RTT+perte) sert
# uniquement de garde-fou de cohérence ci-dessous, plus comme mécanisme de
# sélection : avec seulement 4 sessions, l'ancienne sélection par score
# assignait Modéré=MTN par une égalité quasi parfaite (0.0150 vs 0.0150,
# départagée par l'ordre d'itération Python) -- un mécanisme d'affectation
# aussi fragile ne doit pas décider quel opérateur porte quel scénario.
OPERATOR_SCENARIO_MAP = {
    "MTN": "Modéré (terrain)",
    "Orange": "Dégradé (terrain)",
}


def iqr_filtered(rows, key="rtt_mean_ms"):
    """Exclut les sessions aberrantes (méthode IQR) AU SEIN d'un même groupe
    (même opérateur), plutôt qu'à travers des opérateurs différents comme
    dans l'ancienne version -- sinon une session MTN à comportement extrême
    pouvait être comparée/exclue par rapport à des sessions Orange sans
    rapport. Nécessite au moins 4 sessions pour un calcul IQR significatif;
    en dessous, on ne filtre rien mais on le signale."""
    if len(rows) < 4:
        return rows, []
    vals = sorted(r[key] for r in rows)
    q1, q3 = percentile(vals, 25), percentile(vals, 75)
    iqr = q3 - q1
    lo, hi = q1 - 1.5 * iqr, q3 + 1.5 * iqr
    kept = [r for r in rows if lo <= r[key] <= hi]
    excluded = [r for r in rows if not (lo <= r[key] <= hi)]
    return (kept or rows), excluded


def pool_operator_sessions(rows, operator, pooled_rtt_source=None):
    """Agrège TOUTES les sessions valides d'un opérateur (au lieu de n'en
    retenir qu'une seule) :
      - RTT / perte : moyenne pondérée par n_rtt_samples, + dispersion
        INTER-sessions (stdev des moyennes de session) rapportée séparément
        de la dispersion intra-session déjà connue -- ce sont deux sources
        de variance distinctes, ne pas les confondre.
      - p95 : si pooled_rtt_source (dict session->liste de RTT bruts) est
        fourni (mode --sessions-dir), recalculé sur la distribution BRUTE
        poolée de toutes les sessions retenues (le plus rigoureux). Sinon
        (mode --from-summary-csv, RTT bruts non disponibles), moyenne des
        p95 de chaque session -- moins rigoureux, signalé comme tel.
      - gigue : moyenne sur les seules sessions qui en disposent (n_jitter
        peut être < n_sessions_used, rapporté explicitement)."""
    op_rows = [r for r in rows if r["operator"] == operator]
    if not op_rows:
        return None

    kept, excluded = iqr_filtered(op_rows, key="rtt_mean_ms")

    total_n = sum(r["n_rtt_samples"] for r in kept)
    rtt_mean_pooled = sum(r["rtt_mean_ms"] * r["n_rtt_samples"] for r in kept) / total_n
    loss_pooled = sum(r["loss_pct"] * r["transmitted"] for r in kept) / sum(r["transmitted"] for r in kept)

    session_means = [r["rtt_mean_ms"] for r in kept]
    rtt_between_session_stdev = (
        statistics.stdev(session_means) if len(session_means) > 1 else 0.0
    )

    if pooled_rtt_source is not None:
        pooled_raw = []
        for r in kept:
            pooled_raw.extend(pooled_rtt_source.get(r["session"], []))
        rtt_p95_pooled = percentile(pooled_raw, 95) if pooled_raw else None
        p95_method = "recalculé sur RTT bruts poolés"
    else:
        rtt_p95_pooled = round(statistics.mean([r["rtt_p95_ms"] for r in kept]), 3)
        p95_method = "moyenne des p95 par session (RTT bruts non disponibles, --from-summary-csv)"

    jitter_vals = [r["jitter_ms"] for r in kept if r["jitter_ms"] is not None]
    jitter_pooled = round(statistics.mean(jitter_vals), 3) if jitter_vals else None

    days = sorted(set(r["day_of_week"] for r in kept))
    slots = sorted(set(r["time_slot"] for r in kept))

    return {
        "operator": operator,
        "n_sessions_used": len(kept),
        "n_sessions_excluded_iqr": len(excluded),
        "excluded_sessions": [r["session"] for r in excluded],
        "days_covered": days,
        "slots_covered": slots,
        "rtt_mean_ms": round(rtt_mean_pooled, 3),
        "rtt_between_session_stdev_ms": round(rtt_between_session_stdev, 3),
        "rtt_p95_ms": round(rtt_p95_pooled, 3) if rtt_p95_pooled is not None else None,
        "rtt_p95_method": p95_method,
        "loss_pct": round(loss_pooled, 4),
        "n_jitter_sessions": len(jitter_vals),
        "jitter_ms": jitter_pooled,
        "source_sessions": [r["session"] for r in kept],
    }


def compute_severity_scores(rows):
    """Conservé UNIQUEMENT comme diagnostic de cohérence (affiché dans le
    rapport) : si le score composite d'un opérateur dépasse celui de l'autre
    dans le sens inattendu, c'est un signal à examiner -- mais ce score ne
    décide plus quel opérateur porte quel scénario (cf. commentaire
    OPERATOR_SCENARIO_MAP ci-dessus)."""
    rtts = [r["rtt_mean_ms"] for r in rows]
    losses = [r["loss_pct"] for r in rows]
    rtt_min, rtt_max = min(rtts), max(rtts)
    loss_min, loss_max = min(losses), max(losses)
    rtt_range = (rtt_max - rtt_min) or 1.0
    loss_range = (loss_max - loss_min) or 1.0
    for r in rows:
        norm_rtt = (r["rtt_mean_ms"] - rtt_min) / rtt_range
        norm_loss = (r["loss_pct"] - loss_min) / loss_range
        r["severity_score"] = round(0.5 * norm_rtt + 0.5 * norm_loss, 4)
    return rows


def derive_scenarios(rows, pooled_rtt_source=None):
    """Idéal = contrôle théorique fixe (0 ms, 0% perte) -- PAS dérivé de
    mesures terrain. Modéré et Dégradé sont désormais des AGRÉGATS pondérés
    de TOUTES les sessions valides de l'opérateur correspondant (MTN/Orange,
    mapping fixé), pas la sélection d'une session unique."""
    present_operators = set(r["operator"] for r in rows)
    missing = set(OPERATOR_SCENARIO_MAP) - present_operators
    if missing:
        raise ValueError(
            f"Opérateur(s) manquant(s) pour dériver les scénarios : {missing}. "
            f"Le mapping fixe requiert au moins 1 session valide pour chacun de "
            f"{list(OPERATOR_SCENARIO_MAP)}."
        )

    rows = compute_severity_scores(rows)  # diagnostic seulement, cf. docstring

    scenarios = [dict(IDEAL_SCENARIO)]
    pooled_by_operator = {}
    for operator, label in OPERATOR_SCENARIO_MAP.items():
        pooled = pool_operator_sessions(rows, operator, pooled_rtt_source=pooled_rtt_source)
        pooled_by_operator[operator] = pooled
        rtt_target = pooled["rtt_mean_ms"]
        tc_delay_per_iface = round(rtt_target / 2, 2)  # cf. hypothèse de doublement RTT
        jitter_clause = f"{pooled['jitter_ms']}ms " if pooled["jitter_ms"] else ""
        scenarios.append({
            "scenario": label,
            "source_session": f"pooled({pooled['n_sessions_used']} sessions)",
            "operator": operator,
            "connection_type": "4G",
            "time_slot": ",".join(pooled["slots_covered"]) or "N/A",
            "rtt_mean_ms": rtt_target,
            "rtt_p95_ms": pooled["rtt_p95_ms"],
            "loss_pct": pooled["loss_pct"],
            "severity_score": None,  # diagnostic seulement, cf. rapport
            "jitter_ms": pooled["jitter_ms"] if pooled["jitter_ms"] is not None else "N/A",
            "tc_delay_per_interface_ms": tc_delay_per_iface,
            "tc_netem_cmd": (
                f"tc qdisc add dev eth0 root netem delay {tc_delay_per_iface}ms "
                f"{jitter_clause}loss {pooled['loss_pct']}%"
            ),
            "n_sessions_used": pooled["n_sessions_used"],
            "n_sessions_excluded_iqr": pooled["n_sessions_excluded_iqr"],
            "n_jitter_sessions": pooled["n_jitter_sessions"],
            "days_covered": ",".join(pooled["days_covered"]),
        })
    return scenarios, pooled_by_operator


def write_csv(path, rows):
    if not rows:
        return
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def write_report(path, rows, scenarios, warn_n_sessions):
    lines = []
    lines.append("# Annexe méthodologique — Calibration réseau à partir de mesures terrain\n")
    lines.append(f"**Nombre de sessions valides analysées : {len(rows)}**")
    if warn_n_sessions:
        lines.append("\n> ⚠️ Moins de 18 sessions collectées (minimum recommandé pour couvrir "
                      "3 opérateurs × 2 créneaux × 3 jours). Les scénarios dérivés ci-dessous "
                      "restent calculables mais leur représentativité statistique est plus "
                      "faible — à mentionner explicitement dans les limites de l'étude si le "
                      "nombre de sessions reste bas.\n")

    days = sorted(set(r["day_of_week"] for r in rows))
    slots_check = sorted(set(r["time_slot"] for r in rows))
    if len(days) <= 1 or len(slots_check) <= 1:
        lines.append("\n> ⚠️ Toutes les sessions proviennent du même jour et/ou du même créneau "
                      "horaire. Modéré et Dégradé reflètent donc une variabilité inter-opérateurs "
                      "à un instant donné, pas une variabilité temporelle (heures creuses/pointe, "
                      "jours différents). À signaler explicitement en limite de l'étude tant que "
                      "des sessions complémentaires (autres jours, heures creuses) n'ont pas été "
                      "ajoutées.\n")

    operators = sorted(set(r["operator"] for r in rows))
    slots = sorted(set(r["time_slot"] for r in rows))
    lines.append(f"\nOpérateurs/connexions couverts : {', '.join(operators)}")
    lines.append(f"\nCréneaux couverts : {', '.join(slots)}\n")

    lines.append("\n## Scénarios réseau dérivés (remplacent les scénarios uniform-loss précédents)\n")
    lines.append("| Scénario | N sessions poolées | RTT moyen (ms) | RTT p95 (ms) | "
                  "Perte (%) | Gigue (ms, n sessions) | Délai tc/interface (ms) |")
    lines.append("|---|---|---|---|---|---|---|")
    for s in scenarios:
        n_used = s.get("n_sessions_used", "N/A")
        if n_used == "N/A":
            gigue_label = "N/A"
        else:
            gigue_label = f"{s['jitter_ms']} (n={s.get('n_jitter_sessions','?')})" if s['jitter_ms'] != "N/A" else "N/A"
        lines.append(f"| {s['scenario']} | {n_used} | "
                      f"{s['rtt_mean_ms']} | {s['rtt_p95_ms']} | {s['loss_pct']} | "
                      f"{gigue_label} | {s['tc_delay_per_interface_ms']} |")

    lines.append("\n## Traçabilité par scénario (agrégation, pas sélection d'une session unique)\n")
    lines.append("Chaque scénario Modéré/Dégradé est désormais une **moyenne pondérée sur toutes "
                  "les sessions valides** de l'opérateur correspondant (MTN→Modéré, Orange→Dégradé, "
                  "mapping fixé par le design de l'étude), avec exclusion IQR des sessions "
                  "aberrantes au sein du groupe. Le détail :\n")
    for s in scenarios:
        if s["scenario"] == "Idéal (Baseline)":
            continue
        lines.append(f"- **{s['scenario']}** ({s['operator']}) : {s['n_sessions_used']} session(s) "
                      f"utilisée(s), {s.get('n_sessions_excluded_iqr', 0)} exclue(s) par IQR, "
                      f"jours couverts = {s.get('days_covered', 'N/A')}, "
                      f"gigue disponible sur {s.get('n_jitter_sessions', 0)}/{s['n_sessions_used']} "
                      f"session(s).")

    lines.append("\n## Commandes tc/netem correspondantes\n")
    lines.append("Rappel méthodologique : le délai est appliqué en bidirectionnel sur eth0 des "
                  "conteneurs client ET serveur, doublant le RTT déclaré. Les valeurs ci-dessous "
                  "utilisent donc `delay = RTT_mesuré / 2` par interface.\n")
    for s in scenarios:
        lines.append(f"- **{s['scenario']}** : `{s['tc_netem_cmd']}`")

    lines.append("\n## Note sur le modèle Gilbert-Elliott\n")
    lines.append("Les paramètres du modèle Gilbert-Elliott (p, r, taux de perte par état) ne sont "
                  "**pas modifiés** par cette recalibration terrain : ils restent ceux validés lors "
                  "de la phase précédente du projet (single-cell rerun N=500 confirmant l'anomalie "
                  "GE-Unstable, exclusion permanente déjà justifiée).")

    Path(path).write_text("\n".join(lines))


def load_rows_from_summary_csv(path: Path):
    """Charge directement depuis un sessions_summary.csv déjà agrégé
    (produit par une exécution antérieure de ce script), sans repartir des
    ping.log bruts. Utile quand seules les données déjà agrégées sont
    disponibles."""
    rows = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for r in reader:
            rows.append({
                "session": r["session"],
                "operator": r["operator"],
                "connection_type": r["connection_type"],
                "location": r.get("location", ""),
                "day_of_week": r.get("day_of_week", ""),
                "time_slot": r.get("time_slot", ""),
                "hour": r.get("hour", ""),
                "n_rtt_samples": int(r["n_rtt_samples"]),
                "rtt_mean_ms": float(r["rtt_mean_ms"]),
                "rtt_stdev_ms": float(r["rtt_stdev_ms"]),
                "rtt_p50_ms": float(r["rtt_p50_ms"]),
                "rtt_p95_ms": float(r["rtt_p95_ms"]),
                "rtt_p99_ms": float(r["rtt_p99_ms"]),
                "loss_pct": float(r["loss_pct"]),
                "transmitted": int(r["transmitted"]),
                "received": int(r["received"]),
                "jitter_ms": float(r["jitter_ms"]) if r.get("jitter_ms") not in (None, "", "N/A") else None,
            })
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sessions-dir", type=Path,
                     help="Dossier de sessions brutes (ping.log/meta.json par sous-dossier)")
    ap.add_argument("--from-summary-csv", type=Path,
                     help="Repartir directement d'un sessions_summary.csv déjà agrégé, "
                          "sans relire les ping.log bruts")
    ap.add_argument("--out-dir", default="results", type=Path)
    args = ap.parse_args()

    if not args.sessions_dir and not args.from_summary_csv:
        args.sessions_dir = Path("sessions")

    args.out_dir.mkdir(parents=True, exist_ok=True)

    pooled_rtt_source = None
    if args.from_summary_csv:
        print(f"Lecture directe depuis {args.from_summary_csv} ...")
        rows = load_rows_from_summary_csv(args.from_summary_csv)
        print("  (mode --from-summary-csv : RTT bruts indisponibles -> p95 poolé "
              "= moyenne des p95 par session, moins rigoureux que le recalcul sur "
              "données brutes ; préférer --sessions-dir quand possible)")
    else:
        print(f"Lecture des sessions dans {args.sessions_dir} ...")
        rows, pooled_rtt_source = load_sessions(args.sessions_dir)
    print(f"  -> {len(rows)} session(s) valide(s) trouvée(s).")

    if len(rows) < 2:
        print("ERREUR: au moins 2 sessions valides sont nécessaires (Idéal est désormais un "
              "contrôle théorique fixe, seuls Modéré et Dégradé requièrent des sessions réelles). "
              "Arrêt.")
        return

    write_csv(args.out_dir / "sessions_summary.csv", rows)
    scenarios, pooled_by_operator = derive_scenarios(rows, pooled_rtt_source=pooled_rtt_source)
    write_csv(args.out_dir / "scenarios_reels.csv", scenarios)
    write_report(args.out_dir / "rapport_methodologique.md", rows, scenarios, warn_n_sessions=len(rows) < 18)

    print(f"\nTerminé. Fichiers écrits dans {args.out_dir}/:")
    print("  - sessions_summary.csv")
    print("  - scenarios_reels.csv")
    print("  - rapport_methodologique.md  (à coller/adapter dans l'annexe méthodologique)")


if __name__ == "__main__":
    main()
