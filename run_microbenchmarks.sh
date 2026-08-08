#!/usr/bin/env bash
#
# run_microbenchmarks.sh — Microbenchmarks crypto complets : signatures ET KEM,
# classique ET post-quantique, dans un seul run reproductible.
#
# Complète microbench_result.txt (qui ne couvrait que les signatures) avec les
# opérations KEM (encaps/decaps) manquantes pour ML-KEM et HQC.
#
# NOTE MÉTHODOLOGIQUE : ceci mesure le coût de l'opération cryptographique
# ISOLÉE (keygen/sign/verify/encaps/decaps), pas le handshake TLS/QUIC complet.
# C'est complémentaire, pas redondant, avec les mesures CPU/mémoire du
# Launcher_unified.sh (qui capturent le conteneur entier pendant un handshake
# réel). Les KEM hybrides (p256_mlkem512, etc.) ne sont pas benchmarkés isolément
# ici : leur coût est approximativement composable (classique + PQ), et leur
# coût réel en contexte de handshake est déjà capturé par le launcher principal.
#
# USAGE:
#   ./run_microbenchmarks.sh [out_dir] [seconds_per_op]
#
# PRÉREQUIS : openssl avec oqsprovider chargé (même environnement que vos
# conteneurs Docker — lancez ce script DANS le conteneur, ou sur un système
# où oqsprovider.cnf est configuré).

set -uo pipefail

OUT_DIR="${1:-microbench_results}"
SECONDS_PER_OP="${2:-10}"
mkdir -p "$OUT_DIR"
TS=$(date +%Y%m%d_%H%M%S)
RAW="$OUT_DIR/microbench_raw_$TS.txt"

echo "== Microbenchmarks cryptographiques — $(date) ==" | tee "$RAW"
echo "Durée par opération : ${SECONDS_PER_OP}s" | tee -a "$RAW"

run_block() {
    local title="$1"; shift
    echo "" | tee -a "$RAW"
    echo "### $title ###" | tee -a "$RAW"
    if ! "$@" 2>&1 | tee -a "$RAW"; then
        echo "[!] Échec pour: $* — voir message ci-dessus. Script poursuivi." | tee -a "$RAW"
    fi
}

echo ""
echo "[1/4] Signatures classiques (ECDSA/EdDSA)..."
run_block "Signatures classiques" \
    openssl speed -seconds "$SECONDS_PER_OP" ecdsap384 ecdsap521 ed25519

echo ""
echo "[2/4] Signatures post-quantiques (ML-DSA, via oqsprovider)..."
run_block "Signatures ML-DSA" \
    openssl speed -provider oqsprovider -provider default -seconds "$SECONDS_PER_OP" mldsa44 mldsa65 mldsa87

echo ""
echo "[3/4] KEM classiques (ECDH — baseline pour comparaison)..."
run_block "KEM classiques (ECDH)" \
    openssl speed -seconds "$SECONDS_PER_OP" ecdhx25519 ecdhx448 ecdhp256 ecdhp384 ecdhp521

echo ""
echo "[4/4] KEM post-quantiques (ML-KEM + HQC — détection automatique des noms disponibles)..."
AVAILABLE_KEMS=$(openssl list -kem-algorithms -provider oqsprovider -provider default 2>/dev/null \
    | grep -Eio '\b(mlkem[0-9]+|hqc[0-9]+)\b' | tr 'A-Z' 'a-z' | sort -u | tr '\n' ' ')
if [[ -z "$AVAILABLE_KEMS" ]]; then
    echo "[!] Aucun KEM PQ détecté via 'openssl list -kem-algorithms'. Vérifiez que" | tee -a "$RAW"
    echo "    oqsprovider est bien chargé (openssl.cnf) dans cet environnement." | tee -a "$RAW"
else
    echo "  KEMs PQ détectés : $AVAILABLE_KEMS"
    # shellcheck disable=SC2086
    run_block "KEM post-quantiques (ML-KEM, HQC)" \
        openssl speed -provider oqsprovider -provider default -seconds "$SECONDS_PER_OP" $AVAILABLE_KEMS
fi

echo ""
echo "=================================================="
echo " Résultats bruts : $RAW"
echo " Ensuite : python3 parse_microbench.py --input $RAW --out-dir $OUT_DIR"
echo "=================================================="
