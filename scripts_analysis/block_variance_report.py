#!/usr/bin/env python3
"""
block_variance_report.py

Objectif : repondre objectivement, a partir des CSV par bloc DEJA
VALIDES par audit_measurement_totals_v2.py, a trois questions :
  1. Variance inter-bloc vs intra-bloc par configuration (ICC-like ratio).
  2. Autocorrelation lag-1 intra-bloc (meme methodologie que la revue
     externe sur l'ancienne campagne sequentielle : proportion de series
     avec |rho_1| > 0.1 et > 0.5).
  3. Etalement temporel reel des 4 blocs (via les dates de modification
     des fichiers, en l'absence de colonne timestamp dans les CSV).

Ne fait AUCUNE nouvelle mesure : relit uniquement captures/ existant.
Reutilise la meme logique de construction de noms de fichiers que
audit_measurement_totals_v2.py (deja validee).

USAGE:
    python3 block_variance_report.py --root captures/ --out block_variance.csv
"""

import argparse
import csv
import os
import statistics
import sys
from collections import defaultdict

# --- Reprise exacte de la logique validee dans audit_measurement_totals_v2.py ---
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


def lag1_autocorr(values):
    """Autocorrelation lag-1 simple (Pearson entre x[t] et x[t+1])."""
    n = len(values)
    if n < 3:
        return None
    mean = sum(values) / n
    num = sum((values[i] - mean) * (values[i + 1] - mean) for i in range(n - 1))
    den = sum((v - mean) ** 2 for v in values)
    if den == 0:
        return None
    return num / den


def read_block_success_durations(fpath):
    """Retourne la liste ordonnee des handshake_duration_ms pour les runs
    reussis (success==1), dans l'ordre d'execution d'origine."""
    rows = []
    with open(fpath, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if str(row.get("success", "")).strip() == "1":
                try:
                    rows.append((int(row["execution"]), float(row["handshake_duration_ms"])))
                except (ValueError, KeyError):
                    continue
    rows.sort(key=lambda r: r[0])
    return [v for _, v in rows]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--out", default="block_variance.csv")
    args = ap.parse_args()

    results = []
    n_configs_processed = 0
    n_configs_skipped = 0
    mtime_samples = []

    for protocol, auth_mode in PROTO_AUTH:
        for network in NETWORKS:
            for level, sig, kem in ALL_CONFIGS:
                block_means = []
                block_vars = []
                block_ac1 = []
                block_files_found = 0

                for block_i in range(1, N_BLOCKS + 1):
                    fpath = expected_filepath(args.root, protocol, auth_mode, sig, kem, network, block_i)
                    if not os.path.isfile(fpath):
                        continue
                    block_files_found += 1
                    mtime_samples.append((fpath, os.path.getmtime(fpath)))

                    vals = read_block_success_durations(fpath)
                    if len(vals) < 3:
                        continue
                    block_means.append(statistics.mean(vals))
                    block_vars.append(statistics.pvariance(vals))
                    ac1 = lag1_autocorr(vals)
                    if ac1 is not None:
                        block_ac1.append(ac1)

                if block_files_found < 4 or len(block_means) < 2:
                    n_configs_skipped += 1
                    continue

                inter_block_var = statistics.variance(block_means)  # sample variance, n-1=3
                intra_block_var = statistics.mean(block_vars)
                ratio = inter_block_var / intra_block_var if intra_block_var > 0 else float("nan")
                mean_ac1 = statistics.mean(block_ac1) if block_ac1 else None
                max_abs_ac1 = max((abs(a) for a in block_ac1), default=None)

                results.append({
                    "protocol": protocol, "auth_mode": auth_mode, "network": network,
                    "level": level, "sig": sig, "kem": kem,
                    "inter_block_var": inter_block_var, "intra_block_var": intra_block_var,
                    "inter_over_intra_ratio": ratio,
                    "mean_lag1_autocorr": mean_ac1, "max_abs_lag1_autocorr": max_abs_ac1,
                })
                n_configs_processed += 1

    with open(args.out, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "protocol", "auth_mode", "network", "level", "sig", "kem",
            "inter_block_var", "intra_block_var", "inter_over_intra_ratio",
            "mean_lag1_autocorr", "max_abs_lag1_autocorr",
        ])
        writer.writeheader()
        for r in results:
            writer.writerow(r)

    # --- Resume global ---
    ratios = [r["inter_over_intra_ratio"] for r in results if r["inter_over_intra_ratio"] == r["inter_over_intra_ratio"]]
    max_ac1s = [r["max_abs_lag1_autocorr"] for r in results if r["max_abs_lag1_autocorr"] is not None]

    print("=== BLOCK VARIANCE SUMMARY ===")
    print(f"Configurations traitees (4/4 blocs presents) : {n_configs_processed}")
    print(f"Configurations ignorees (bloc(s) manquant(s)) : {n_configs_skipped}")
    if ratios:
        ratios_sorted = sorted(ratios)
        n = len(ratios_sorted)
        print(f"\nRatio variance inter-bloc / intra-bloc (n={n}):")
        print(f"  median = {ratios_sorted[n // 2]:.4f}")
        print(f"  mean   = {sum(ratios_sorted) / n:.4f}")
        print(f"  min    = {ratios_sorted[0]:.4f}")
        print(f"  max    = {ratios_sorted[-1]:.4f}")
    if max_ac1s:
        n = len(max_ac1s)
        above_01 = sum(1 for a in max_ac1s if a > 0.1)
        above_05 = sum(1 for a in max_ac1s if a > 0.5)
        print(f"\nAutocorrelation lag-1 intra-bloc (max sur les 4 blocs, n={n} series):")
        print(f"  |rho_1| > 0.1 : {above_01}/{n} ({100*above_01/n:.1f}%)")
        print(f"  |rho_1| > 0.5 : {above_05}/{n} ({100*above_05/n:.1f}%)")

    # Etalement temporel : pour UNE config, ecart entre mtime du bloc 1 et du bloc 4
    if mtime_samples:
        import datetime
        mtime_samples.sort(key=lambda x: x[1])
        first_file, first_t = mtime_samples[0]
        last_file, last_t = mtime_samples[-1]
        span_hours = (last_t - first_t) / 3600
        print(f"\nEtalement temporel global (mtime du premier vs dernier fichier de bloc trouve):")
        print(f"  premier : {datetime.datetime.fromtimestamp(first_t)} ({first_file})")
        print(f"  dernier : {datetime.datetime.fromtimestamp(last_t)} ({last_file})")
        print(f"  duree totale de la campagne (approx.) : {span_hours:.1f} heures")

    print(f"\nRapport detaille : {args.out}")


if __name__ == "__main__":
    main()
