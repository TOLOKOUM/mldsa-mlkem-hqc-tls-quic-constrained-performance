#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Ajustement des chemins vers le dossier 0-docker/scripts/ ──
SCRIPTS_DIR="$SCRIPT_DIR/0-docker/scripts"
CONCURRENT_SCRIPT="$SCRIPTS_DIR/perftestClientConcurrent.sh"
RESUMPTION_SCRIPT="$SCRIPTS_DIR/perftestClientResumption.sh"

NETWORK_SCENARIO="${1:-}"

if [[ "$NETWORK_SCENARIO" != "ideal" && "$NETWORK_SCENARIO" != "modere" && "$NETWORK_SCENARIO" != "degrade" ]]; then
    echo "Usage: $0 <ideal|modere|degrade>"
    exit 1
fi

case "$NETWORK_SCENARIO" in
    ideal)
        MAIN_PROFILE="none"; MAIN_LOSS=0; MAIN_DELAY=0ms ;;
    modere)
        MAIN_PROFILE="simple"; MAIN_LOSS=0.3%; MAIN_DELAY=30.02ms ;;
    degrade)
        MAIN_PROFILE="simple"; MAIN_LOSS=0.2%; MAIN_DELAY=65.15ms ;;
esac

###############################################################################
# 0. BUILD DES IMAGES DOCKER (oqs-client, oqs-server, oqs-do-cert)
###############################################################################
# NOTE : ce bloc suppose que docker-compose-localhost.yaml définit un contexte
# de build pour chacune de ces trois images, avec exactement ces noms
# (services "oqs-client", "oqs-server", "oqs-do-cert" ou équivalent via
# "image:"). Si "docker images | grep oqs" ne montre toujours rien après ce
# build, il faut ajuster les noms ci-dessous pour correspondre au compose file.
echo "== [BUILD] Construction des images Docker (oqs-client, oqs-server, oqs-do-cert) =="
if ! docker compose -f docker-compose-localhost.yaml build; then
    echo "[ERREUR FATALE] Le build des images Docker a échoué. Abandon de la campagne."
    echo "Vérifiez 'docker compose -f docker-compose-localhost.yaml build' manuellement pour voir l'erreur complète."
    exit 1
fi
if ! docker images --format '{{.Repository}}' | grep -q '^oqs-client$'; then
    echo "[ERREUR FATALE] L'image 'oqs-client' n'existe toujours pas après le build. Abandon."
    echo "Le nom de l'image dans docker-compose-localhost.yaml ne correspond probablement pas à 'oqs-client'."
    exit 1
fi
echo "== [BUILD] OK — images disponibles localement =="
docker images | grep oqs

ADVANCED_ROOT_DIR="$SCRIPT_DIR/captures_advanced"
RUN_TS="$(date +%Y%m%d_%H%M%S)"

LOG_DIR="$ADVANCED_ROOT_DIR/orchestration_logs/${RUN_TS}_${NETWORK_SCENARIO}"
OUT_CONCURRENT_DIR="$ADVANCED_ROOT_DIR/concurrent/${NETWORK_SCENARIO}"
OUT_RESUMPTION_DIR="$ADVANCED_ROOT_DIR/resumption/${NETWORK_SCENARIO}"

mkdir -p "$LOG_DIR" "$OUT_CONCURRENT_DIR" "$OUT_RESUMPTION_DIR"

SUMMARY_FILE="$LOG_DIR/summary.txt"
: > "$SUMMARY_FILE"
log() { echo "$1" | tee -a "$SUMMARY_FILE"; }

RESULTS=()

chmod +x "$CONCURRENT_SCRIPT" "$RESUMPTION_SCRIPT" 2>/dev/null || true

# ── Initialisation de l'environnement Docker ─────────────
start_docker_server() {
    local sig_alg="$1"
    echo "  [Docker] Initialisation de l'infrastructure et génération des certificats ($sig_alg)..."
    docker compose -f docker-compose-localhost.yaml down --volumes --remove-orphans >/dev/null 2>&1 || true
    docker network create localNet >/dev/null 2>&1 || true
    docker volume create cert >/dev/null 2>&1 || true

    # Génération des certificats
    if ! docker run --rm -v cert:/cert -e SIG_ALG="$sig_alg" oqs-do-cert > "$LOG_DIR/docert_${sig_alg}.log" 2>&1; then
        echo "  [ATTENTION] Génération des certificats en échec pour $sig_alg — voir $LOG_DIR/docert_${sig_alg}.log"
    fi

    # Démarrage du serveur
    if ! docker run -d --name servidor --network localNet -v cert:/cert -p 4433:4433 -e SIG_ALG="$sig_alg" oqs-server > "$LOG_DIR/server_start_${sig_alg}.log" 2>&1; then
        echo "  [ATTENTION] Démarrage du conteneur serveur en échec pour $sig_alg — voir $LOG_DIR/server_start_${sig_alg}.log"
    fi
    sleep 2
    if ! docker ps --format '{{.Names}}' | grep -q '^servidor$'; then
        echo "  [ATTENTION] Le conteneur 'servidor' n'est pas en cours d'exécution après démarrage."
        echo "  --- docker logs servidor ---"
        docker logs servidor 2>&1 | tail -n 30 || true
    fi
}

stop_docker_server() {
    docker stop servidor >/dev/null 2>&1 || true
    docker rm servidor >/dev/null 2>&1 || true
}

run_step() {
    local label="$1"; shift
    local safe_name
    safe_name=$(echo "$label" | tr ' /()' '____' | tr -s '_')
    log ""
    log "=================================================="
    log " ÉTAPE : $label"
    log " Commande : $*"
    log " Début : $(date '+%H:%M:%S')"
    log "=================================================="
    if "$@" 2>&1 | tee -a "$LOG_DIR/${safe_name}.log"; then
        log "  [OK-SHELL] $label terminé avec succès."
        RESULTS+=("$label:0")
    else
        log "  [ATTENTION] $label a rencontré un problème."
        RESULTS+=("$label:1")
    fi
    log " Fin : $(date '+%H:%M:%S')"
}

log "== Campagne de tests avancés — scénario: $NETWORK_SCENARIO — $(date) =="

###############################################################################
# 1. TESTS DE CHARGE CONCURRENTE
###############################################################################
run_concurrent_test() {
    local use_tls="$1" sig_alg="$2" kem_alg="$3" conc="$4" waves="$5"
    local proto="quic"; [ "$use_tls" = "true" ] && proto="tls"
    
    start_docker_server "$sig_alg"
    
    log "  -> Exécution test concurrence $proto $sig_alg + $kem_alg (C=$conc, W=$waves)..."
    USE_TLS="$use_tls" SIG_ALG="$sig_alg" KEM_ALG="$kem_alg" \
    CONCURRENCY="$conc" WAVES="$waves" TC_DELAY="$MAIN_DELAY" TC_LOSS="$MAIN_LOSS" \
    "$CONCURRENT_SCRIPT"
    
    stop_docker_server
    
    local summary_file="/tmp/concurrent_summary_${proto}_${sig_alg}_${kem_alg}_c${conc}.csv"
    if [ -f "$summary_file" ]; then
        mv "$summary_file" "$OUT_CONCURRENT_DIR/"
        log "  [OK] Fichier de résultats généré : $OUT_CONCURRENT_DIR/$(basename "$summary_file")"
    else
        log "  [ERREUR] Le fichier $summary_file n'a pas été produit."
        return 1
    fi
}

run_step "Concurrence TLS ML-KEM-512" run_concurrent_test "true" "mldsa44" "mlkem512" 5 10
run_step "Concurrence TLS HQC-128"     run_concurrent_test "true" "mldsa44" "hqc128"   5 10
run_step "Concurrence QUIC ML-KEM-512" run_concurrent_test "false" "mldsa44" "mlkem512" 5 10

###############################################################################
# 2. TESTS DE REPRISE DE SESSION
###############################################################################
run_resumption_test() {
    local use_tls="$1" sig_alg="$2" kem_alg="$3" waves="$4"
    local proto="quic"; [ "$use_tls" = "true" ] && proto="tls"

    start_docker_server "$sig_alg"

    log "  -> Exécution test resumption $proto $sig_alg + $kem_alg (W=$waves)..."
    USE_TLS="$use_tls" SIG_ALG="$sig_alg" KEM_ALG="$kem_alg" \
    WAVES="$waves" TC_DELAY="$MAIN_DELAY" TC_LOSS="$MAIN_LOSS" \
    "$RESUMPTION_SCRIPT"

    stop_docker_server

    local summary_file="/tmp/resumption_summary_${proto}_${sig_alg}_${kem_alg}.csv"
    if [ -f "$summary_file" ]; then
        mv "$summary_file" "$OUT_RESUMPTION_DIR/"
        log "  [OK] Fichier de résultats généré : $OUT_RESUMPTION_DIR/$(basename "$summary_file")"
    else
        log "  [ERREUR] Le fichier $summary_file n'a pas été produit."
        return 1
    fi
}

run_step "Resumption TLS ML-KEM-512" run_resumption_test "true" "mldsa44" "mlkem512" 20
run_step "Resumption TLS HQC-128"     run_resumption_test "true" "mldsa44" "hqc128"   20

###############################################################################
# 3. RÉCAPITULATIF
###############################################################################
log ""
log "=================================================="
log " RÉCAPITULATIF FINAL"
log "=================================================="
for r in "${RESULTS[@]}"; do
    label="${r%%:*}"; code="${r##*:}"
    [[ "$code" == "0" ]] && log "  [OK]    $label" || log "  [ÉCHEC] $label"
done
