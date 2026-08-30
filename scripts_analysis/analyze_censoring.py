#!/usr/bin/env python3
"""
analyze_censoring.py — Répond à l'objection "informative censoring" (F-05) :
au lieu d'exclure silencieusement les échecs des statistiques de latence,
calcule pour chaque combinaison (protocole/auth/réseau/config) :
  1. Le taux de succès avec un IC95% binomial exact (Clopper-Pearson).
  2. Un RMST (Restricted Mean Survival Time) à une deadline commune T
     choisie en analyse : tout run dont la durée dépasse T, ou qui a
     échoué, est traité comme "non complété avant T" et contribue T à
     la moyenne tronquée -- pas besoin que le harnais ait imposé cette
     deadline au moment de la capture, c'est une réanalyse de durées
     déjà enregistrées.
  3. Un "coût composite par tentative" = moyenne sur TOUTES les
     tentatives (succès ET échecs comptés à T), par opposition à la
     moyenne conditionnelle au succès seul déjà rapportée ailleurs dans
     le papier.

Ne fait AUCUNE nouvelle mesure : relit uniquement les CSV par bloc déjà
audités (même schéma que audit_measurement_totals_v2.py :
execution,mode,handshake_duration_ms,success,block_index,n_blocks).

USAGE:
    python3 analyze_censoring.py --root captures/ --deadline-ms 5000 --out censoring_report.csv
"""

import argparse
import csv
import math
import os
import statistics
from collections import defaultdict

# --- Reprise de la logique validee dans audit_measurement_totals_v2.py ---
L1_SIGS = ["ed25519", "mldsa44"]
L1_KEMS = ["P-256", "x25519", "p256_hqc128", "x25519_hqc128",
           "p256_mlkem512", "x25519_mlkem512", "hqc128", "mlkem512"]
L3_SIGS = ["secp384r1", "mldsa65"]
L3_KEMS = ["P-384", "x448", "p384_hqc192", "x448_hqc192",
           "p384_mlkem768", "x448_mlkem768", "hqc192", "mlkem768"]
L5_SIGS = ["secp521r1", "mldsa87"]
L5_KEMS = ["P-521", "p521_hqc256", "p521_mlkem1024", "hqc256", "mlkem1024"]

ALL_CONFIGS = []
for sig in L1_SIGS:
    for kem in L1_KEMS:
        ALL_CONFIGS.append(("L1", sig, kem))
for sig in L3_SIGS:
    for kem in L3_KEMS:
        ALL_CONFIGS.append(("L3", sig, kem))
for sig in L5_SIGS:
    for kem in L5_KEMS:
        ALL_CONFIGS.append(("L5", sig, kem))
assert len(ALL_CONFIGS) == 42

NETWORKS = ["none", "simple_loss1.3_delay62.51ms", "simple_loss1.5833_delay83.52ms", "stable", "unstable"]
PROTO_AUTH = [("tls", "single"), ("tls", "mutual"), ("quic", "single")]
N_BLOCKS = 4
PURE_CLASSICAL_KEMS = {"P-256", "P-384", "P-521"}


def sig_kem_to_filename_tokens(sig, kem):
    sig_token = sig.lower()
    kem_token = kem if kem in PURE_CLASSICAL_KEMS else kem.lower()
    return sig_token, kem_token


def expected_filepath(root, protocol, auth_mode, sig, kem, network, block_i):
    sig_l, kem_l = sig_kem_to_filename_tokens(sig, kem)
    fname = f"handshake_{protocol}_{auth_mode}_{sig_l}_{kem_l}_{network}_block{block_i}of{N_BLOCKS}.csv"
    return os.path.join(root, protocol, auth_mode, network, "csv", fname)


def clopper_pearson_ci(successes, n, alpha=0.05):
    """IC95% binomial exact (Clopper-Pearson), sans dependance scipy.
    Utilise la relation Beta <-> incomplete beta via une approximation
    par bissection sur la fonction de repartition binomiale."""
    if n == 0:
        return (0.0, 1.0)

    def binom_cdf(k, n, p):
        # P(X <= k) pour X ~ Binomial(n, p), somme directe (n <= 500 ici, ok)
        s = 0.0
        for i in range(0, k + 1):
            s += math.comb(n, i) * (p ** i) * ((1 - p) ** (n - i))
        return s

    def find_p_for_cdf(k, n, target, lo=0.0, hi=1.0, iters=60):
        for _ in range(iters):
            mid = (lo + hi) / 2
            if binom_cdf(k, n, mid) > target:
                lo = mid
            else:
                hi = mid
        return (lo + hi) / 2

    if successes == 0:
        low = 0.0
    else:
        low = find_p_for_cdf(successes - 1, n, 1 - alpha / 2)
    if successes == n:
        high = 1.0
    else:
        high = find_p_for_cdf(successes, n, alpha / 2)
    return (round(low, 4), round(high, 4))


def read_block_rows(fpath):
    """Retourne liste de (success:bool, duration_ms:float|None)."""
    rows = []
    with open(fpath, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            success = str(row.get("success", "")).strip() == "1"
            dur = row.get("handshake_duration_ms", "")
            try:
                dur_val = float(dur) if dur not in (None, "", "NaN", "nan") else None
            except ValueError:
                dur_val = None
            rows.append((success, dur_val))
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--deadline-ms", type=float, required=True,
                     help="Deadline commune T (ms) pour le RMST -- choisir une valeur "
                          "couvrant la quasi-totalite des succes sous Ideal/Moderate/Degraded "
                          "(ex: 5000ms), documentee dans le papier comme choix d'analyse.")
    ap.add_argument("--out", default="censoring_report.csv")
    args = ap.parse_args()
    T = args.deadline_ms

    results = []
    for protocol, auth_mode in PROTO_AUTH:
        for network in NETWORKS:
            for level, sig, kem in ALL_CONFIGS:
                all_rows = []
                for block_i in range(1, N_BLOCKS + 1):
                    fpath = expected_filepath(args.root, protocol, auth_mode, sig, kem, network, block_i)
                    if not os.path.isfile(fpath):
                        continue
                    all_rows.extend(read_block_rows(fpath))

                if not all_rows:
                    continue

                n = len(all_rows)
                n_success = sum(1 for s, _ in all_rows if s)
                success_rate = n_success / n
                ci_low, ci_high = clopper_pearson_ci(n_success, n)

                # RMST a deadline T : chaque run contribue min(duration, T) si succes et duration<=T,
                # sinon T (echec OU succes tardif au-dela de T traite comme censure a T)
                contributions = []
                for success, dur in all_rows:
                    if success and dur is not None and dur <= T:
                        contributions.append(dur)
                    else:
                        contributions.append(T)  # echec ou succes tardif -> censure a T
                rmst = statistics.mean(contributions)

                # Comparaison : moyenne conditionnelle au succes SEUL (ce que le papier rapporte deja)
                succ_durations = [d for s, d in all_rows if s and d is not None]
                conditional_mean = statistics.mean(succ_durations) if succ_durations else None

                results.append({
                    "protocol": protocol, "auth_mode": auth_mode, "network": network,
                    "level": level, "sig": sig, "kem": kem,
                    "n_attempts": n, "n_success": n_success,
                    "success_rate": round(success_rate, 4),
                    "success_rate_ci95_low": ci_low, "success_rate_ci95_high": ci_high,
                    "conditional_mean_ms": round(conditional_mean, 3) if conditional_mean else "NA",
                    "rmst_at_deadline_ms": round(rmst, 3),
                    "deadline_ms": T,
                    "rmst_minus_conditional_mean": (
                        round(rmst - conditional_mean, 3) if conditional_mean else "NA"
                    ),
                })

    if not results:
        print("[!] Aucun resultat -- verifie --root.")
        return

    with open(args.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        w.writeheader()
        w.writerows(results)

    # Resume : ou la moyenne conditionnelle sous-estime le plus le vrai cout (RMST)
    gaps = [(r["rmst_minus_conditional_mean"], r) for r in results
            if r["rmst_minus_conditional_mean"] != "NA"]
    gaps.sort(key=lambda x: -x[0])

    print(f"=== CENSORING REPORT (deadline T={T} ms) ===")
    print(f"{len(results)} combinaisons analysees -> {args.out}")
    print("\nTop 10 des ecarts RMST - moyenne_conditionnelle (ou l'exclusion des echecs")
    print("sous-estime le plus le vrai cout par tentative) :")
    for gap, r in gaps[:10]:
        print(f"  {r['protocol']:5s} {r['auth_mode']:6s} {r['network']:32s} "
              f"{r['sig']:12s} {r['kem']:16s} succ={r['success_rate']*100:5.1f}%  "
              f"cond_mean={r['conditional_mean_ms']:>9}  RMST={r['rmst_at_deadline_ms']:>9}  "
              f"gap=+{gap:.1f} ms")


if __name__ == "__main__":
    main()
