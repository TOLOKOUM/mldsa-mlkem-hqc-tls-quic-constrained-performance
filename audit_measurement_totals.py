#!/usr/bin/env python3
"""
audit_measurement_totals_v2.py

Objectif : fermer mathematiquement l'audit du nombre total de mesures,
en s'appuyant sur :
  (a) la liste EXACTE des 42 configurations signature x KEM telle que
      publiee dans Table~configs_ultra_compact du manuscrit ;
  (b) le vrai schema des CSV par bloc, confirme sur le terrain :
        execution,mode,handshake_duration_ms,success,block_index,n_blocks
  (c) une construction explicite du nom de fichier attendu pour chacune
      des 42 x 5 x {tls-single, tls-mutual, quic-single} x 4 blocs = 2520
      combinaisons, plutot qu'un parsing fragile du nom de fichier.

Ne fait AUCUNE nouvelle mesure : relit uniquement captures/ existant.

USAGE:
    python3 audit_measurement_totals_v2.py --root captures/ --out audit_v2_report.csv

A VERIFIER AVANT DE LANCER (cf. commandes ls demandees) :
  - NETWORKS : noms exacts des sous-dossiers reseau (none/moderate/degraded/stable/unstable
    devine a partir de deux exemples confirmes : "none" et "unstable")
"""

import argparse
import csv
import os
import sys
from collections import defaultdict

# ---------------------------------------------------------------------------
# 1) Les 42 configurations, telles que publiees dans Table configs_ultra_compact
# ---------------------------------------------------------------------------
# Niveau L1 : 8 KEM x 2 signatures = 16
L1_SIGS = ["ed25519", "mldsa44"]
L1_KEMS = [
    "P-256", "x25519",
    "p256_hqc128", "x25519_hqc128",
    "p256_mlkem512", "x25519_mlkem512",
    "hqc128", "mlkem512",
]

# Niveau L3 : 8 KEM x 2 signatures = 16
L3_SIGS = ["secp384r1", "mldsa65"]
L3_KEMS = [
    "P-384", "x448",
    "p384_hqc192", "x448_hqc192",
    "p384_mlkem768", "x448_mlkem768",
    "hqc192", "mlkem768",
]

# Niveau L5 : 5 KEM x 2 signatures = 10
L5_SIGS = ["secp521r1", "mldsa87"]
L5_KEMS = [
    "P-521",
    "p521_hqc256", "p521_mlkem1024",
    "hqc256", "mlkem1024",
]

ALL_CONFIGS = []  # list of (level, sig, kem)
for sig in L1_SIGS:
    for kem in L1_KEMS:
        ALL_CONFIGS.append(("L1", sig, kem))
for sig in L3_SIGS:
    for kem in L3_KEMS:
        ALL_CONFIGS.append(("L3", sig, kem))
for sig in L5_SIGS:
    for kem in L5_KEMS:
        ALL_CONFIGS.append(("L5", sig, kem))

assert len(ALL_CONFIGS) == 42, f"Attendu 42 configs, obtenu {len(ALL_CONFIGS)}"

# ---------------------------------------------------------------------------
# 2) Reseaux et modes d'authentification
# ---------------------------------------------------------------------------
# Confirme via `ls captures/tls/single/` (identique pour tls/mutual et quic/single) :
#   none | simple_loss1.3_delay62.51ms | simple_loss1.5833_delay83.52ms | stable | unstable
NETWORKS = [
    "none",
    "simple_loss1.3_delay62.51ms",       # Moderate (MTN 4G, 62.51 ms / 1.3%)
    "simple_loss1.5833_delay83.52ms",    # Degraded (Orange 4G, 83.52 ms / 1.5833%)
    "stable",                            # GE-Stable
    "unstable",                          # GE-Unstable
]

# Mapping lisible pour les rapports texte (utilise plus bas dans le CSV de sortie)
NETWORK_LABELS = {
    "none": "Ideal",
    "simple_loss1.3_delay62.51ms": "Moderate",
    "simple_loss1.5833_delay83.52ms": "Degraded",
    "stable": "GE-Stable",
    "unstable": "GE-Unstable",
}

# (protocol, auth_mode) valides -- QUIC mutual n'existe pas (limitation MsQuic documentee)
PROTO_AUTH = [
    ("tls", "single"),
    ("tls", "mutual"),
    ("quic", "single"),
]

N_BLOCKS = 4


# KEM "classique pur" tels qu'ecrits dans Table configs_ultra_compact -- ce sont
# les SEULS tokens qui gardent leur casse et leur tiret d'origine dans les noms
# de fichiers reels (confirme par `ls captures/quic/single/unstable/csv/ | grep
# secp521r1` : le fichier existe sous "..._P-521_..." et non "..._p521_...").
# Tous les autres tokens (signature, KEM hybrides, KEM PQ purs) sont en minuscules.
PURE_CLASSICAL_KEMS = {"P-256", "P-384", "P-521"}


def sig_kem_to_filename_tokens(sig, kem):
    sig_token = sig.lower()
    if kem in PURE_CLASSICAL_KEMS:
        kem_token = kem  # casse et tiret preserves tels quels
    else:
        kem_token = kem.lower()
    return sig_token, kem_token


def expected_filepath(root, protocol, auth_mode, sig, kem, network, block_i):
    sig_l, kem_l = sig_kem_to_filename_tokens(sig, kem)
    fname = f"handshake_{protocol}_{auth_mode}_{sig_l}_{kem_l}_{network}_block{block_i}of{N_BLOCKS}.csv"
    return os.path.join(root, protocol, auth_mode, network, "csv", fname)


def read_block_file(fpath):
    """Lit un fichier de bloc reel et retourne (attempted, success, failure,
    nan_success_mismatch)."""
    attempted = 0
    success = 0
    mismatch = 0
    with open(fpath, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            attempted += 1
            succ_flag = str(row.get("success", "")).strip()
            dur = row.get("handshake_duration_ms", "")
            dur_is_missing = (dur is None or str(dur).strip() == "" or str(dur).strip().lower() == "nan")

            is_success = succ_flag in ("1", "true", "True")
            if is_success:
                success += 1

            # Coherence check: success==1 mais duree manquante, ou success==0 mais duree presente
            if is_success and dur_is_missing:
                mismatch += 1
            if (not is_success) and (not dur_is_missing):
                mismatch += 1

    failure = attempted - success
    return attempted, success, failure, mismatch


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--out", default="audit_v2_report.csv")
    args = ap.parse_args()

    missing_files = []
    mismatch_files = []

    # Agregation par (protocol, auth_mode, network, level, sig, kem)
    agg = defaultdict(lambda: {"attempted": 0, "success": 0, "failure": 0, "blocks_found": 0})
    total_attempted = total_success = total_failure = 0
    total_expected_files = 0
    total_found_files = 0

    for protocol, auth_mode in PROTO_AUTH:
        for network in NETWORKS:
            for level, sig, kem in ALL_CONFIGS:
                for block_i in range(1, N_BLOCKS + 1):
                    total_expected_files += 1
                    fpath = expected_filepath(args.root, protocol, auth_mode, sig, kem, network, block_i)
                    if not os.path.isfile(fpath):
                        missing_files.append(fpath)
                        continue
                    total_found_files += 1
                    try:
                        attempted, success, failure, mismatch = read_block_file(fpath)
                    except Exception as e:
                        print(f"[WARN] Erreur de lecture {fpath}: {e}", file=sys.stderr)
                        continue

                    if mismatch > 0:
                        mismatch_files.append((fpath, mismatch))

                    key = (protocol, auth_mode, network, level, sig, kem)
                    agg[key]["attempted"] += attempted
                    agg[key]["success"] += success
                    agg[key]["failure"] += failure
                    agg[key]["blocks_found"] += 1

                    total_attempted += attempted
                    total_success += success
                    total_failure += failure

    # Ecriture du rapport detaille
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["protocol", "auth_mode", "network", "network_label", "level", "sig", "kem",
                          "blocks_found_of_4", "attempted", "success", "failure"])
        for (protocol, auth_mode, network, level, sig, kem), c in sorted(agg.items()):
            writer.writerow([protocol, auth_mode, network, NETWORK_LABELS.get(network, network), level, sig, kem,
                              c["blocks_found"], c["attempted"], c["success"], c["failure"]])
        writer.writerow([])
        writer.writerow(["TOTAL", "", "", "", "", "", "", total_attempted, total_success, total_failure])

    print("=== AUDIT SUMMARY (v2, base sur les 42 configs officielles) ===")
    print(f"Fichiers de bloc attendus (42x5x3x4)     : {total_expected_files}")
    print(f"Fichiers de bloc trouves                 : {total_found_files}")
    print(f"Fichiers de bloc MANQUANTS               : {len(missing_files)}")
    for m in missing_files:
        print(f"    [MISSING] {m}")
    print()
    print(f"Total handshakes attempted (somme lignes) : {total_attempted}")
    print(f"Total handshakes success                  : {total_success}")
    print(f"Total handshakes failure                  : {total_failure}")
    print(f"Total attendu si complet (2520 x 125)      : {total_expected_files * 125}")
    print()
    if mismatch_files:
        print(f"[WARN] {len(mismatch_files)} fichiers ont une incoherence success/duration_ms :")
        for fp, n in mismatch_files[:20]:
            print(f"    [MISMATCH x{n}] {fp}")
    else:
        print("Aucune incoherence success/duration_ms detectee : les deux colonnes s'accordent partout.")

    print()
    print(f"Rapport detaille ecrit dans : {args.out}")


if __name__ == "__main__":
    main()
