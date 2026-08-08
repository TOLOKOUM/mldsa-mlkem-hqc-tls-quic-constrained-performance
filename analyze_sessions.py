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
    return rows


IDEAL_SCENARIO = {
    "scenario": "Idéal (Baseline)",
    "source_session": "N/A (Theoretical Control)",
    "operator": "None",
    "connection_type": "Loopback / Local",
    "time_slot": "N/A",
    "rtt_mean_ms": 0.0,
    "rtt_p95_ms": 0.0,
    "loss_pct": 0.0,
    "severity_score": 0.0,
    "jitter_ms": 0.0,
    "tc_delay_per_interface_ms": 0.0,
    "tc_netem_cmd": "none (pas de restriction tc)",
}


def compute_severity_scores(rows):
    """Score composite = 0.5 * RTT_normalisé + 0.5 * perte_normalisée (min-max
    sur l'échantillon). Remplace le tri par perte seule, qui produisait une
    inversion (Modéré avec un RTT plus élevé que Dégradé) car RTT et perte
    ne sont pas corrélés dans les mesures terrain réelles."""
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


def derive_scenarios(rows):
    """Idéal = contrôle théorique fixe (0 ms, 0% perte) — PAS dérivé de mesures
    terrain, sur décision explicite : ce scénario sert de référence de calcul
    pure, indépendante de toute variabilité d'échantillonnage.
    Modéré et Dégradé restent dérivés de sessions RÉELLEMENT OBSERVÉES
    (aucune valeur synthétique), sur la base d'un score de sévérité composite
    (RTT + perte, poids égal), en écartant les extrêmes non représentatifs
    (méthode IQR) pour le dégradé."""
    if len(rows) < 2:
        raise ValueError("Il faut au moins 2 sessions valides pour distinguer Modéré et Dégradé "
                          "(Idéal est désormais un contrôle théorique fixe, pas une session).")

    rows = compute_severity_scores(rows)
    by_severity = sorted(rows, key=lambda r: (r["severity_score"], r["rtt_mean_ms"]))
    scores = [r["severity_score"] for r in by_severity]

    if len(rows) == 2:
        # Avec seulement 2 sessions, l'attribution est directe : la moins
        # sévère est Modéré, l'autre est Dégradé. Pas assez de points pour
        # une estimation de médiane/percentile robuste — à noter comme limite.
        modere, degrade = by_severity[0], by_severity[1]
    else:
        median_score = percentile(scores, 50)
        modere = min(by_severity, key=lambda r: abs(r["severity_score"] - median_score))

        q1, q3 = percentile(scores, 25), percentile(scores, 75)
        iqr = q3 - q1
        outlier_threshold = q3 + 1.5 * iqr
        non_outliers = [r for r in by_severity if r["severity_score"] <= outlier_threshold] or by_severity

        p90_score = percentile([r["severity_score"] for r in non_outliers], 90)
        worse_than_median = [r for r in non_outliers if r["severity_score"] > modere["severity_score"]]
        pool = worse_than_median or non_outliers
        degrade = min(pool, key=lambda r: abs(r["severity_score"] - p90_score))

    scenarios = [dict(IDEAL_SCENARIO)]
    for label, r in [("Modéré (terrain)", modere), ("Dégradé (terrain)", degrade)]:
        rtt_target = r["rtt_mean_ms"]
        tc_delay_per_iface = round(rtt_target / 2, 2)  # cf. hypothèse de doublement RTT
        scenarios.append({
            "scenario": label,
            "source_session": r["session"],
            "operator": r["operator"],
            "connection_type": r["connection_type"],
            "time_slot": r["time_slot"],
            "rtt_mean_ms": rtt_target,
            "rtt_p95_ms": r["rtt_p95_ms"],
            "loss_pct": r["loss_pct"],
            "severity_score": r["severity_score"],
            "jitter_ms": r["jitter_ms"] if r["jitter_ms"] is not None else "N/A",
            "tc_delay_per_interface_ms": tc_delay_per_iface,
            "tc_netem_cmd": (
                f"tc qdisc add dev eth0 root netem delay {tc_delay_per_iface}ms "
                f"{(str(r['jitter_ms']) + 'ms ') if r['jitter_ms'] else ''}loss {r['loss_pct']}%"
            ),
        })
    return scenarios


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
    lines.append("| Scénario | Session source | Opérateur | RTT moyen (ms) | RTT p95 (ms) | "
                  "Perte (%) | Gigue (ms) | Délai tc/interface (ms) |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for s in scenarios:
        lines.append(f"| {s['scenario']} | {s['source_session']} | {s['operator']} | "
                      f"{s['rtt_mean_ms']} | {s['rtt_p95_ms']} | {s['loss_pct']} | "
                      f"{s['jitter_ms']} | {s['tc_delay_per_interface_ms']} |")

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

    if args.from_summary_csv:
        print(f"Lecture directe depuis {args.from_summary_csv} ...")
        rows = load_rows_from_summary_csv(args.from_summary_csv)
    else:
        print(f"Lecture des sessions dans {args.sessions_dir} ...")
        rows = load_sessions(args.sessions_dir)
    print(f"  -> {len(rows)} session(s) valide(s) trouvée(s).")

    if len(rows) < 2:
        print("ERREUR: au moins 2 sessions valides sont nécessaires (Idéal est désormais un "
              "contrôle théorique fixe, seuls Modéré et Dégradé requièrent des sessions réelles). "
              "Arrêt.")
        return

    write_csv(args.out_dir / "sessions_summary.csv", rows)
    scenarios = derive_scenarios(rows)
    write_csv(args.out_dir / "scenarios_reels.csv", scenarios)
    write_report(args.out_dir / "rapport_methodologique.md", rows, scenarios, warn_n_sessions=len(rows) < 18)

    print(f"\nTerminé. Fichiers écrits dans {args.out_dir}/:")
    print("  - sessions_summary.csv")
    print("  - scenarios_reels.csv")
    print("  - rapport_methodologique.md  (à coller/adapter dans l'annexe méthodologique)")


if __name__ == "__main__":
    main()
