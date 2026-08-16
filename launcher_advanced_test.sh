#!/bin/bash
set -euo pipefail

###############################################################################
#  launcher_advanced_test.sh
#
#  Regroupe deux familles de tests avancés post-quantiques TLS/QUIC :
#    - concurrent load  : N clients simultanés, RUNS_PER_CLIENT handshakes/client
#    - session resumption : phase 1 (N full) -> phase 2 (N resumed), approche
#                            "batch séparés" (littérature)
#
#  IMPORTANT — Scénario réseau :
#    Ce launcher ne tourne QU'EN CONDITION IDEALE (network_profile=none).
#    Décision actée pour le projet : les scénarios Moderate/Degraded (simple)
#    et GE-Stable/GE-Unstable ont été volontairement exclus des tests de
#    charge concurrente et de session resumption, à cause d'artefacts de
#    warm-up et de limites d'outillage constatées lors des essais
#    préliminaires (cf. note de transparence prévue en §7 de l'article).
#    Si un jour ces scénarios doivent être réintégrés, il faudra d'abord
#    revalider empiriquement le comportement warm-up sous perte/latence
#    avant de lever cette restriction — ne pas la contourner en douce.
#
#  Authentification : single uniquement (MUTUAL=false). L'auth mutuelle QUIC
#  est connue pour ne pas être appliquée correctement dans cette stack —
#  hors scope pour ces deux tests.
#
#  Usage:
#    ./launcher_advanced_test.sh [concurrent|resumption|both] [tls|quic|both] [num_clients]
#
#  Exemples:
#    ./launcher_advanced_test.sh concurrent tls 20
#    ./launcher_advanced_test.sh resumption quic
#    ./launcher_advanced_test.sh both both 50
###############################################################################

TEST_TYPE=${1:-both}
PROTO_ARG=${2:-both}
NUM_CLIENTS=${3:-20}

USAGE="Usage: $0 [concurrent|resumption|both] [tls|quic|both] [num_clients]"

###############################################################################
#  Validation des arguments
###############################################################################
if [[ "$TEST_TYPE" != "concurrent" && "$TEST_TYPE" != "resumption" && "$TEST_TYPE" != "both" ]]; then
    echo "Invalid test type: must be 'concurrent', 'resumption' or 'both'."
    echo "$USAGE"; exit 1
fi

if [[ "$PROTO_ARG" != "tls" && "$PROTO_ARG" != "quic" && "$PROTO_ARG" != "both" ]]; then
    echo "Invalid protocol: must be 'tls', 'quic' or 'both'."
    echo "$USAGE"; exit 1
fi

if ! [[ "$NUM_CLIENTS" =~ ^[0-9]+$ ]] || (( NUM_CLIENTS < 1 )); then
    echo "Invalid num_clients: must be a positive integer."
    echo "$USAGE"; exit 1
fi

if [[ "$PROTO_ARG" == "both" ]]; then
    PROTOCOLS=("tls" "quic")
else
    PROTOCOLS=("$PROTO_ARG")
fi

###############################################################################
#  Configuration fixe
###############################################################################
IMAGE=uma-tls-quic-pq-34
OQS_SERVER="servidor"
OQS_CLIENT_PREFIX="cliente"
NETWORK_PROFILE="none"     # figé volontairement — voir bandeau ci-dessus

RUNS_PER_CLIENT=500        # concurrent load : handshakes par client
RUNS_PER_PHASE=500         # resumption : handshakes par phase (full / resumed)

# Concurrent : une seule paire, fixée par le protocole précédent (Prof)
CONCURRENT_SIG="mldsa65"
CONCURRENT_KEM="mlkem768"

# Resumption : deux paires (set minimal validé)
declare -A RESUMPTION_PAIRS
RESUMPTION_PAIRS=(
    ["mldsa65"]="mlkem768"
    ["mldsa87"]="hqc256"
)

PROJECT_DIR="${HOME}/Documents/mldsa-mlkem-hqc-tls-quic-constrained-performance"
CAPTURES_DIR="${PROJECT_DIR}/captures"

###############################################################################
#  Pré-vols
###############################################################################
if ! command -v docker >/dev/null 2>&1; then
    echo "[FATAL] docker introuvable dans le PATH."; exit 1
fi

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "[FATAL] Image docker '$IMAGE' introuvable. Build-la avant de relancer."
    exit 1
fi

###############################################################################
#  Fonctions utilitaires
###############################################################################

# Nettoyage léger : containers uniquement (safe à appeler entre chaque combo)
reset_containers() {
    docker rm -f "$OQS_SERVER" &>/dev/null || true
    for ((c=1; c<=NUM_CLIENTS; c++)); do
        docker rm -f "${OQS_CLIENT_PREFIX}${c}" &>/dev/null || true
    done
}

# Nettoyage complet : containers + réseau + volume (appelé au début et à la fin)
full_cleanup() {
    echo "[CLEAN] Full cleanup (containers, network, volume)..."
    docker kill "$OQS_SERVER" &>/dev/null || true
    for ((c=1; c<=NUM_CLIENTS; c++)); do
        docker kill "${OQS_CLIENT_PREFIX}${c}" &>/dev/null || true
    done
    reset_containers
    sleep 1
    docker container prune -f >/dev/null || true
    docker volume rm cert &>/dev/null || true
    docker network rm localNet &>/dev/null || true
    sleep 1
}

ensure_network_and_volume() {
    if ! docker network inspect localNet >/dev/null 2>&1; then
        docker network create localNet >/dev/null
        echo "[NET] Network localNet created."
    fi
    if ! docker volume inspect cert >/dev/null 2>&1; then
        docker volume create cert >/dev/null
        echo "[VOL] Volume cert created."
    fi
}

# Vérifie si un run concurrent est déjà complet (idempotence, cf. pattern
# already_done() du launcher principal patché)
already_done_concurrent() {
    local csv_dir=$1 sig_alg=$2 kem=$3
    local c f lines
    for ((c=1; c<=NUM_CLIENTS; c++)); do
        f="${csv_dir}/client_${c}_${sig_alg}_${kem}.csv"
        [[ -f "$f" ]] || return 1
        lines=$(wc -l < "$f")
        [[ "$lines" -ge $((RUNS_PER_CLIENT + 1)) ]] || return 1
    done
    return 0
}

# Vérifie si un run resumption est déjà complet
already_done_resumption() {
    local csv_dir=$1 sig_alg=$2 kem=$3
    local f="${csv_dir}/resumption_1_${sig_alg}_${kem}.csv"
    local lines
    [[ -f "$f" ]] || return 1
    lines=$(wc -l < "$f")
    [[ "$lines" -ge $((RUNS_PER_PHASE * 2 + 1)) ]] || return 1
    return 0
}

###############################################################################
#  Concurrent load test
###############################################################################
run_concurrent_test() {
    local protocol=$1
    local use_tls
    use_tls=$([[ "$protocol" == "tls" ]] && echo true || echo false)

    local test_dir="${CAPTURES_DIR}/${protocol}/single/${NETWORK_PROFILE}/concurrent_load"
    local csv_dir="${test_dir}/csv"
    local log_dir="${test_dir}/handshake_logs"
    mkdir -p "$csv_dir" "$log_dir"

    echo "=============================================================================="
    echo "  CONCURRENT LOAD TEST — $(echo "$protocol" | tr '[:lower:]' '[:upper:]') — Ideal scenario"
    echo "  Clients: $NUM_CLIENTS  |  Runs/client: $RUNS_PER_CLIENT  |  Sig/KEM: ${CONCURRENT_SIG}/${CONCURRENT_KEM}"
    echo "=============================================================================="

    if already_done_concurrent "$csv_dir" "$CONCURRENT_SIG" "$CONCURRENT_KEM"; then
        echo "[SKIP] Concurrent ${protocol} déjà complet (${NUM_CLIENTS} clients x ${RUNS_PER_CLIENT} runs) → $csv_dir"
        return 0
    fi

    reset_containers

    echo " ==> Creating certificates (${CONCURRENT_SIG})..."
    docker run --rm -v cert:/cert -e CERT_PATH=/cert/ -e SIG_ALG="$CONCURRENT_SIG" -i "$IMAGE" doCert.sh

    echo "[SERVER] Starting server (Ideal, no impairment)..."
    docker run --cap-add=NET_ADMIN \
        --name "$OQS_SERVER" \
        --network localNet \
        -v cert:/cert \
        -e TC_DELAY=0ms -e TC_LOSS=0% \
        -e CERT_PATH=/cert/ \
        -e KEM_ALG="$CONCURRENT_KEM" -e SIG_ALG="$CONCURRENT_SIG" \
        -e USE_TLS="$use_tls" -e MUTUAL=false \
        -d "$IMAGE" perftestServerTlsQuic.sh

    sleep 3
    local server_ip
    server_ip=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$OQS_SERVER")
    echo "[SERVER] IP: $server_ip"
    sleep 1

    echo "[CLIENTS] Launching $NUM_CLIENTS clients simultaneously..."
    local global_start global_end total_time
    global_start=$(date +%s%3N)

    CLIENT_IDS=()
    for ((c=1; c<=NUM_CLIENTS; c++)); do
        local client_name="${OQS_CLIENT_PREFIX}${c}"
        docker run --cap-add=NET_ADMIN \
            --network localNet \
            --name "$client_name" \
            -v cert:/cert \
            -v "${csv_dir}:/results" \
            -e DOCKER_HOST="$server_ip" \
            -e TC_DELAY=0ms -e TC_LOSS=0% \
            -e CERT_PATH=/cert/ \
            -e KEM_ALG="$CONCURRENT_KEM" -e SIG_ALG="$CONCURRENT_SIG" \
            -e USE_TLS="$use_tls" \
            -e NUM_RUNS="$RUNS_PER_CLIENT" \
            -e MUTUAL=false \
            -e CLIENT_ID="$c" \
            -e RESULTS_DIR=/results \
            -d "$IMAGE" ./perftestClientConcurrent.sh
        CLIENT_IDS+=("$client_name")
    done

    echo "[CLIENTS] All $NUM_CLIENTS clients launched. Waiting for completion..."
    for client_name in "${CLIENT_IDS[@]}"; do
        docker wait "$client_name" > /dev/null
    done
    global_end=$(date +%s%3N)
    total_time=$((global_end - global_start))
    echo "[CLIENTS] All clients finished in ${total_time} ms"

    local ts log_file meta_file
    ts=$(date +%Y%m%d_%H%M%S)
    log_file="${log_dir}/concurrent_${protocol}_${CONCURRENT_SIG}_${CONCURRENT_KEM}_${ts}.log"
    for client_name in "${CLIENT_IDS[@]}"; do
        echo "--- ${client_name} ---" >> "$log_file"
        docker logs "$client_name" >> "$log_file" 2>&1 || true
    done

    meta_file="${log_dir}/metadata_concurrent_${CONCURRENT_SIG}_${CONCURRENT_KEM}_${ts}.txt"
    cat > "$meta_file" <<EOF
protocol=$protocol
sig_alg=$CONCURRENT_SIG
kem_alg=$CONCURRENT_KEM
num_clients=$NUM_CLIENTS
runs_per_client=$RUNS_PER_CLIENT
total_handshakes=$((NUM_CLIENTS * RUNS_PER_CLIENT))
network_profile=$NETWORK_PROFILE
mutual=false
total_time_ms=$total_time
timestamp=$ts
EOF

    for client_name in "${CLIENT_IDS[@]}"; do
        docker rm -f "$client_name" &>/dev/null || true
    done
    docker kill "$OQS_SERVER" &>/dev/null || true
    docker rm -f "$OQS_SERVER" &>/dev/null || true

    echo "[OK] Concurrent ${protocol} ${CONCURRENT_SIG}/${CONCURRENT_KEM} → $csv_dir"
}

###############################################################################
#  Session resumption test (batch séparés)
###############################################################################
run_resumption_test() {
    local protocol=$1
    local use_tls
    use_tls=$([[ "$protocol" == "tls" ]] && echo true || echo false)

    local test_dir="${CAPTURES_DIR}/${protocol}/single/${NETWORK_PROFILE}/session_resumption"
    local csv_dir="${test_dir}/csv"
    local log_dir="${test_dir}/handshake_logs"
    mkdir -p "$csv_dir" "$log_dir"

    echo "=============================================================================="
    echo "  SESSION RESUMPTION TEST — $(echo "$protocol" | tr '[:lower:]' '[:upper:]') — Ideal scenario"
    echo "=============================================================================="

    if [[ "$protocol" == "quic" ]]; then
        echo "[WARN] QUIC resumption via quics_connection est connue non fonctionnelle"
        echo "       (-sess_out: accepté silencieusement, rien n'est écrit). On exécute"
        echo "       quand même pour la traçabilité — attends-toi à resumed ≈ full."
    fi

    for sig_alg in "${!RESUMPTION_PAIRS[@]}"; do
        local kem="${RESUMPTION_PAIRS[$sig_alg]}"

        echo "------------------------------------------------------------------------------"
        echo "  Pair: ${sig_alg} / ${kem}"
        echo "------------------------------------------------------------------------------"

        if already_done_resumption "$csv_dir" "$sig_alg" "$kem"; then
            echo "[SKIP] Resumption ${protocol} ${sig_alg}/${kem} déjà complet → $csv_dir"
            continue
        fi

        reset_containers

        echo " ==> Creating certificates (${sig_alg})..."
        docker run --rm -v cert:/cert -e CERT_PATH=/cert/ -e SIG_ALG="$sig_alg" -i "$IMAGE" doCert.sh

        echo "[SERVER] Starting server..."
        docker run --cap-add=NET_ADMIN \
            --name "$OQS_SERVER" \
            --network localNet \
            -v cert:/cert \
            -e TC_DELAY=0ms -e TC_LOSS=0% \
            -e CERT_PATH=/cert/ \
            -e KEM_ALG="$kem" -e SIG_ALG="$sig_alg" \
            -e USE_TLS="$use_tls" -e MUTUAL=false \
            -d "$IMAGE" perftestServerTlsQuic.sh

        sleep 3
        local server_ip
        server_ip=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$OQS_SERVER")
        echo "[SERVER] IP: $server_ip"
        sleep 1

        echo "[CLIENT] Running batch (phase1 full -> phase2 resumed)..."
        local global_start global_end total_time
        global_start=$(date +%s%3N)

        docker run --cap-add=NET_ADMIN \
            --network localNet \
            --name "${OQS_CLIENT_PREFIX}1" \
            -v cert:/cert \
            -v "${csv_dir}:/results" \
            -e DOCKER_HOST="$server_ip" \
            -e TC_DELAY=0ms -e TC_LOSS=0% \
            -e CERT_PATH=/cert/ \
            -e KEM_ALG="$kem" -e SIG_ALG="$sig_alg" \
            -e USE_TLS="$use_tls" \
            -e NUM_RUNS="$RUNS_PER_PHASE" \
            -e MUTUAL=false \
            -e CLIENT_ID=1 \
            -e RESULTS_DIR=/results \
            "$IMAGE" ./perftestClientResumption.sh

        global_end=$(date +%s%3N)
        total_time=$((global_end - global_start))
        echo "[CLIENT] Done in ${total_time} ms"

        local ts log_file meta_file
        ts=$(date +%Y%m%d_%H%M%S)
        log_file="${log_dir}/resumption_${protocol}_${sig_alg}_${kem}_${ts}.log"
        docker logs "${OQS_CLIENT_PREFIX}1" >> "$log_file" 2>&1 || true

        meta_file="${log_dir}/metadata_resumption_${sig_alg}_${kem}_${ts}.txt"
        cat > "$meta_file" <<EOF
protocol=$protocol
sig_alg=$sig_alg
kem_alg=$kem
runs_per_phase=$RUNS_PER_PHASE
total_runs=$((RUNS_PER_PHASE * 2))
approach=batch_separe
network_profile=$NETWORK_PROFILE
mutual=false
total_time_ms=$total_time
timestamp=$ts
EOF

        docker rm -f "${OQS_CLIENT_PREFIX}1" &>/dev/null || true
        docker kill "$OQS_SERVER" &>/dev/null || true
        docker rm -f "$OQS_SERVER" &>/dev/null || true

        echo "[OK] Resumption ${protocol} ${sig_alg}/${kem} → $csv_dir"
    done
}

###############################################################################
#  MAIN
###############################################################################
trap 'echo "[TRAP] Interrupted — cleaning up..."; full_cleanup; exit 130' INT TERM

echo "=============================================================================="
echo "  ADVANCED TEST LAUNCHER"
echo "  Test type(s):     $TEST_TYPE"
echo "  Protocol(s):      ${PROTOCOLS[*]}"
echo "  Network profile:  $NETWORK_PROFILE (fixé — Ideal uniquement, cf. bandeau)"
echo "  Auth:              single (MUTUAL=false)"
[[ "$TEST_TYPE" != "resumption" ]] && echo "  Num clients:      $NUM_CLIENTS"
echo "=============================================================================="

full_cleanup
ensure_network_and_volume

for protocol in "${PROTOCOLS[@]}"; do
    if [[ "$TEST_TYPE" == "concurrent" || "$TEST_TYPE" == "both" ]]; then
        run_concurrent_test "$protocol"
    fi
    if [[ "$TEST_TYPE" == "resumption" || "$TEST_TYPE" == "both" ]]; then
        run_resumption_test "$protocol"
    fi
done

full_cleanup

echo ""
echo "=============================================================================="
echo "  ADVANCED TESTS COMPLETED"
echo "  Results under: ${CAPTURES_DIR}/{tls,quic}/single/none/{concurrent_load,session_resumption}/"
echo "=============================================================================="
