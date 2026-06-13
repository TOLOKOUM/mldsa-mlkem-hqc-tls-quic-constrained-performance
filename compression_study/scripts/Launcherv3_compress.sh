#!/bin/bash
set -euo pipefail

###############################################################################
#  Launcherv3_compress.sh  — version corrigée
#  Certificate Compression (RFC 8879) — with vs without
#
#  Corrections apportées :
#    1. Check zlib au démarrage (diagnostic clair)
#    2. Bug PUMBA_PIDS[@] vide avec set -u → corrigé
#    3. Résultats organisés par paire : results/<RUN>/<SIG>_<KEM>/nocompress|compressed/
#    4. Cleanup robuste avec trap (Ctrl+C, erreurs)
#    5. Ordre des paires fixé via tableau ordonné (pas de hashmap)
#    6. Wait serveur avant de lancer le client (évite les échecs au démarrage)
#    7. Métadonnées enrichies (zlib_available, cert_sizes)
#    8. Re-application netem sur stable/unstable après restart serveur
#    9. CORRECTION: Utilisation de start_server() pour récupérer l'IP correctement
#
#  Usage: ./Launcherv3_compress.sh [tls|quic] [none|simple|stable|unstable] [loss-percent] [delay-ms]
###############################################################################

PROTOCOL="${1:-tls}"
NETWORK_PROFILE="${2:-none}"
LOSS_PERC="${3:-0}"
DELAY_MS="${4:-0}"

USAGE="Usage: $0 [tls|quic] [none|simple|stable|unstable] [loss-percent] [delay-ms]"

NETIF="eth0"
IMAGE="uma-tls-quic-pq-34"
OQS_SERVER="servidor"
OQS_CLIENT="cliente"
RUNS_PER_CONDITION=500

RESULTS_HOST_DIR="/home/tolokoum/Documents/TLS-QUIC/compression_study/results"
SCRIPTS_DIR="/home/tolokoum/Documents/TLS-QUIC/0-docker/scripts"

###############################################################################
#  Validation des arguments
###############################################################################
if [[ "$PROTOCOL" != "tls" && "$PROTOCOL" != "quic" ]]; then
    echo "ERROR: Invalid protocol '$PROTOCOL'"; echo "$USAGE"; exit 1
fi
if [[ "$NETWORK_PROFILE" != "none" && "$NETWORK_PROFILE" != "simple" \
   && "$NETWORK_PROFILE" != "stable" && "$NETWORK_PROFILE" != "unstable" ]]; then
    echo "ERROR: Invalid network profile '$NETWORK_PROFILE'"; echo "$USAGE"; exit 1
fi
if ! [[ "$LOSS_PERC" =~ ^[0-9]+$ ]] || (( LOSS_PERC < 0 || LOSS_PERC > 100 )); then
    echo "ERROR: Invalid loss-percent '$LOSS_PERC'"; echo "$USAGE"; exit 1
fi
if ! [[ "$DELAY_MS" =~ ^[0-9]+$ ]]; then
    echo "ERROR: Invalid delay-ms '$DELAY_MS'"; echo "$USAGE"; exit 1
fi

###############################################################################
#  Configuration
###############################################################################
USE_TLS="$([[ "$PROTOCOL" == "tls" ]] && echo true || echo false)"

# Paires ordonnées : SIG_ALG:KEM_ALG
# (tableau ordonné pour reproductibilité — pas de hashmap non déterministe)
PAIR_KEYS=("mldsa44" "mldsa65" "mldsa87" "mldsa65")
PAIR_KEMS=("mlkem512" "mlkem768" "mlkem1024" "hqc192")
# Labels uniques pour les dossiers (distinguer les deux mldsa65)
PAIR_LABELS=("mldsa44_mlkem512" "mldsa65_mlkem768" "mldsa87_mlkem1024" "mldsa65_hqc192")

STABLE_GEMODEL=(10 50 70 10)
UNSTABLE_GEMODEL=(20 40 90 20)
PUMBA_PIDS=()

mkdir -p "$RESULTS_HOST_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RUN_ID="${PROTOCOL}_${NETWORK_PROFILE}_l${LOSS_PERC}_d${DELAY_MS}_${TIMESTAMP}"
RESULTS_RUN_DIR="${RESULTS_HOST_DIR}/${RUN_ID}"
mkdir -p "$RESULTS_RUN_DIR"

###############################################################################
#  Diagnostic zlib (informatif, non bloquant)
###############################################################################
echo ""
echo "================================================================================"
echo "  DIAGNOSTIC: Checking RFC 8879 compression support in Docker image..."
echo "================================================================================"

ZLIB_AVAILABLE="false"
if docker run --rm "$IMAGE" /opt/oqssa/bin/openssl version -f 2>/dev/null | grep -qi "zlib"; then
    ZLIB_AVAILABLE="true"
    echo "  ✅ zlib detected → RFC 8879 certificate compression IS available"
else
    echo "  ⚠️  zlib NOT detected in OpenSSL build flags"
    echo "  → The 'compressed' phase will use default OpenSSL behavior"
    echo "  → Flags -no_tx_cert_comp / -no_rx_cert_comp are still applied for 'nocompress'"
    echo "  → Results will show handshake latency diff with/without those flags"
fi
echo ""

###############################################################################
#  Fonctions utilitaires
###############################################################################

cleanup() {
    echo ""
    echo "[CLEANUP] Stopping containers and network..."
    docker kill "$OQS_SERVER" &>/dev/null || true
    docker kill "$OQS_CLIENT" &>/dev/null || true
    sleep 1
    docker container prune -f &>/dev/null || true
    docker volume rm cert &>/dev/null || true
    docker network rm localNet &>/dev/null || true
    # Tuer les processus pumba s'il y en a
    if [[ ${#PUMBA_PIDS[@]} -gt 0 ]]; then
        for pid in "${PUMBA_PIDS[@]}"; do
            kill -9 "$pid" &>/dev/null || true
        done
    fi
    echo "[CLEANUP] Done."
}

# Trap pour nettoyage sur Ctrl+C ou erreur
trap cleanup EXIT INT TERM

wait_for_server_ip() {
    local container_name="$1"
    local label="$2"
    local server_ip=""
    for attempt in $(seq 1 30); do
        server_ip=$(docker inspect \
            -f '{{ (index .NetworkSettings.Networks "localNet").IPAddress }}' \
            "$container_name" 2>/dev/null || true)
        if [[ "$server_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "$server_ip"
            return 0
        fi
        echo "  [SERVER] $label: Waiting for IP ($attempt/30)..." >&2
        sleep 1
    done
    echo "  [ERROR] $label: Could not get valid server IP. Got: '$server_ip'" >&2
    return 1
}

apply_network_conditions() {
    local container_name="$1"
    case "$NETWORK_PROFILE" in
        simple)
            if [[ "$LOSS_PERC" != "0" || "$DELAY_MS" != "0" ]]; then
                sleep 1
                docker exec "$container_name" tc qdisc add dev "$NETIF" root netem \
                    delay "${DELAY_MS}ms" loss "${LOSS_PERC}%" 2>/dev/null || true
                echo "  [NETWORK] Applied: delay=${DELAY_MS}ms loss=${LOSS_PERC}%"
            fi
            ;;
        stable|unstable)
            local args=("${STABLE_GEMODEL[@]}")
            [[ "$NETWORK_PROFILE" == "unstable" ]] && args=("${UNSTABLE_GEMODEL[@]}")
            if command -v pumba &>/dev/null; then
                /usr/local/bin/pumba netem \
                    --duration 2h \
                    --interface "$NETIF" \
                    loss-gemodel \
                    --pg "${args[0]}" --pb "${args[1]}" \
                    --one-h "${args[2]}" --one-k "${args[3]}" \
                    "$container_name" &
                PUMBA_PIDS+=($!)
                echo "  [NETWORK] Pumba started (PID: ${PUMBA_PIDS[-1]})"
            else
                echo "  [WARN] pumba not installed, GE model not applied"
            fi
            ;;
        none)
            : # pas de conditions réseau
            ;;
    esac
}

start_server() {
    local sig_alg="$1"
    local kem="$2"
    local compress="$3"

    docker rm -f "$OQS_SERVER" &>/dev/null || true

    docker run \
        --cap-add=NET_ADMIN \
        --name "$OQS_SERVER" \
        --network localNet \
        -v cert:/cert \
        -e TC_DELAY=0ms \
        -e TC_LOSS=0% \
        -e CERT_PATH=/cert/ \
        -e KEM_ALG="$kem" \
        -e SIG_ALG="$sig_alg" \
        -e USE_TLS="$USE_TLS" \
        -e COMPRESS_CERT="$compress" \
        -d "$IMAGE" perftestServerCompress.sh

    local server_ip
    server_ip=$(wait_for_server_ip "$OQS_SERVER" "start_server")
    echo "$server_ip"
}

run_single_test() {
    local sig_alg="$1"
    local kem="$2"
    local compress="$3"
    local compress_label="$4"
    local results_subdir="$5"
    local server_ip="$6"

    echo ""
    echo "  ── Phase: $compress_label ($RUNS_PER_CONDITION runs) ────────────────────"
    mkdir -p "$results_subdir"

    docker rm -f "$OQS_CLIENT" &>/dev/null || true

    GLOBAL_START=$(date +%s%3N)

    docker run \
        --cap-add=NET_ADMIN \
        --network localNet \
        --name "$OQS_CLIENT" \
        -v cert:/cert \
        -v "${results_subdir}:/results" \
        -v "${SCRIPTS_DIR}/perftestClientCompress.sh:/opt/oqssa/bin/perftestClientCompress.sh:ro" \
        -e DOCKER_HOST="$server_ip" \
        -e TC_DELAY=0ms \
        -e TC_LOSS=0% \
        -e CERT_PATH=/cert/ \
        -e KEM_ALG="$kem" \
        -e SIG_ALG="$sig_alg" \
        -e USE_TLS="$USE_TLS" \
        -e NUM_RUNS="$RUNS_PER_CONDITION" \
        -e MUTUAL=false \
        -e COMPRESS_CERT="$compress" \
        -e CLIENT_ID="$([[ "$compress" == "true" ]] && echo 2 || echo 1)" \
        -e RESULTS_DIR=/results \
        "$IMAGE" ./perftestClientCompress.sh

    GLOBAL_END=$(date +%s%3N)
    TOTAL_TIME=$((GLOBAL_END - GLOBAL_START))
    echo "  [CLIENT] Finished in $((TOTAL_TIME / 1000))s"

    # Sauvegarder les logs du container client
    docker logs "$OQS_CLIENT" 2>&1 \
        > "${results_subdir}/log_${sig_alg}_${kem}_${compress_label}.log" || true

    docker rm -f "$OQS_CLIENT" &>/dev/null || true
}

###############################################################################
#  Affichage du plan de test
###############################################################################
echo ""
echo "================================================================================"
echo "  CERTIFICATE COMPRESSION TEST — RFC 8879"
echo "  Protocol : $PROTOCOL"
echo "  Profile  : $NETWORK_PROFILE  loss=${LOSS_PERC}%  delay=${DELAY_MS}ms"
echo "  Runs/cond: $RUNS_PER_CONDITION"
echo "  zlib     : $ZLIB_AVAILABLE"
echo "  Results  : $RESULTS_RUN_DIR"
echo "================================================================================"

###############################################################################
#  Préparation réseau Docker
###############################################################################
echo ""
echo "[INIT] Setting up Docker network and volumes..."
cleanup

docker network create localNet
docker volume create cert

echo "[INIT] Ready."

###############################################################################
#  Boucle principale sur les paires
###############################################################################
PAIR_COUNT=${#PAIR_KEYS[@]}

for idx in $(seq 0 $((PAIR_COUNT - 1))); do
    SIG_ALG="${PAIR_KEYS[$idx]}"
    KEM="${PAIR_KEMS[$idx]}"
    PAIR_LABEL="${PAIR_LABELS[$idx]}"

    echo ""
    echo "================================================================================"
    echo "  Pair $((idx+1))/$PAIR_COUNT : $SIG_ALG + $KEM"
    echo "================================================================================"

    # ── Dossiers de résultats spécifiques à cette paire ─────────────
    PAIR_DIR="${RESULTS_RUN_DIR}/${PAIR_LABEL}"
    NOCOMPRESS_DIR="${PAIR_DIR}/nocompress"
    COMPRESSED_DIR="${PAIR_DIR}/compressed"
    mkdir -p "$NOCOMPRESS_DIR" "$COMPRESSED_DIR"

    # ── Générer les certificats ──────────────────────────────────────
    echo " ==> Generating certificates for $SIG_ALG..."
    docker volume rm cert &>/dev/null || true
    docker volume create cert
    docker run --rm \
        -v cert:/cert \
        -e CERT_PATH=/cert/ \
        -e SIG_ALG="$SIG_ALG" \
        -i "$IMAGE" doCert.sh

    # ── Mesurer la taille du certificat ─────────────────────────────
    CERT_SIZE=$(docker run --rm -v cert:/cert "$IMAGE" \
        sh -c 'wc -c < /cert/server.crt 2>/dev/null || echo 0')
    echo "  [INFO] server.crt size: ${CERT_SIZE} bytes"

    # ════════════════════════════════════════════════════════════════
    #  PHASE 1 — NOCOMPRESS
    # ════════════════════════════════════════════════════════════════
    echo ""
    echo "  ── [PHASE 1] Starting server with COMPRESS_CERT=false ──────────"
    SERVER_IP=$(start_server "$SIG_ALG" "$KEM" "false")
    echo "  [SERVER] IP = $SERVER_IP"

    apply_network_conditions "$OQS_SERVER"
    sleep 2  # laisser openssl s_server accepter les connexions

    run_single_test "$SIG_ALG" "$KEM" "false" "nocompress" "$NOCOMPRESS_DIR" "$SERVER_IP"

    # ════════════════════════════════════════════════════════════════
    #  PHASE 2 — COMPRESSED
    #  On redémarre le serveur avec COMPRESS_CERT=true
    # ════════════════════════════════════════════════════════════════
    echo ""
    echo "  ── [PHASE 2] Restarting server with COMPRESS_CERT=true ─────────"

    docker kill "$OQS_SERVER" &>/dev/null || true
    docker rm -f "$OQS_SERVER" &>/dev/null || true

    # Tuer les pumba de la phase précédente avant de relancer
    if [[ ${#PUMBA_PIDS[@]} -gt 0 ]]; then
        for pid in "${PUMBA_PIDS[@]}"; do
            kill -9 "$pid" &>/dev/null || true
        done
        PUMBA_PIDS=()
    fi

    SERVER_IP=$(start_server "$SIG_ALG" "$KEM" "true")
    echo "  [SERVER] IP = $SERVER_IP"

    apply_network_conditions "$OQS_SERVER"
    sleep 2

    run_single_test "$SIG_ALG" "$KEM" "true" "compressed" "$COMPRESSED_DIR" "$SERVER_IP"

    # ── Tuer pumba après la phase compressed ────────────────────────
    if [[ ${#PUMBA_PIDS[@]} -gt 0 ]]; then
        for pid in "${PUMBA_PIDS[@]}"; do
            kill -9 "$pid" &>/dev/null || true
        done
        PUMBA_PIDS=()
    fi

    # ── Métadonnées ─────────────────────────────────────────────────
    META_FILE="${PAIR_DIR}/metadata.txt"
    cat > "$META_FILE" <<EOF
protocol=$PROTOCOL
sig_alg=$SIG_ALG
kem_alg=$KEM
pair_label=$PAIR_LABEL
runs_per_condition=$RUNS_PER_CONDITION
network_profile=$NETWORK_PROFILE
loss_percent=$LOSS_PERC
delay_ms=$DELAY_MS
timestamp=$TIMESTAMP
zlib_available=$ZLIB_AVAILABLE
cert_size_bytes=$CERT_SIZE
approach=certificate_compression_rfc8879
note=$([ "$ZLIB_AVAILABLE" = "false" ] && echo "zlib absent: compressed phase uses default OpenSSL behavior" || echo "RFC 8879 active in compressed phase")
EOF

    docker kill "$OQS_SERVER" &>/dev/null || true
    docker rm -f "$OQS_SERVER" &>/dev/null || true

    echo "  ✅ Pair done: $SIG_ALG × $KEM → $PAIR_DIR"
done

###############################################################################
#  Résumé final
###############################################################################
echo ""
echo "================================================================================"
echo "  ALL PAIRS COMPLETED"
echo "  Results : $RESULTS_RUN_DIR"
echo "  zlib    : $ZLIB_AVAILABLE"
echo ""
echo "  Structure:"
for label in "${PAIR_LABELS[@]}"; do
    echo "    $RESULTS_RUN_DIR/$label/{nocompress,compressed}/*.csv"
done
echo ""
echo "  Quick analysis:"
echo "    for f in \$(find $RESULTS_RUN_DIR -name '*.csv'); do"
echo "      echo \"\$f\"; awk -F',' 'NR>1&&\$3==1{s+=\$2;n++}END{printf \"  avg=%.1fms n=%d\\n\",s/n,n}' \"\$f\"; done"
echo "================================================================================"
