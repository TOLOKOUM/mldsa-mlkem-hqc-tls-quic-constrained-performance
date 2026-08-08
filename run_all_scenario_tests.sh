#!/usr/bin/env bash
set -uo pipefail
#
# run_all_scenario_tests.sh — Généralisation de run_all_ideal_tests.sh :
# lance sweep + charge concurrente + resumption + validation pour N'IMPORTE
# QUEL scénario réseau (ideal / modere / degrade), pas juste idéal.
#
# Usage: ./run_all_scenario_tests.sh <ideal|modere|degrade> [waves_concurrent] [waves_resumption]
#   Défauts : waves_concurrent=20, waves_resumption=50
#
# Combos représentatifs (charge concurrente / resumption) : 6, un par niveau
# de sécurité NIST × famille PQ pure. Auth = single uniquement (mutual TLS
# et QUIC mutual restent hors de cette campagne automatique — QUIC mutual :
# authentification non fiable, cf. diagnostic précédent).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

MAIN_LAUNCHER="./Launcher_pq_mldsa_mlkem_hqc.sh"
ADV_LAUNCHER="./Launcher_advanced_tests.sh"

NETWORK_SCENARIO="${1:-}"
WAVES_CONCURRENT="${2:-20}"
WAVES_RESUMPTION="${3:-50}"

if [[ "$NETWORK_SCENARIO" != "ideal" && "$NETWORK_SCENARIO" != "modere" && "$NETWORK_SCENARIO" != "degrade" ]]; then
    echo "Usage: $0 <ideal|modere|degrade> [waves_concurrent] [waves_resumption]"
    exit 1
fi

# ── Traduction scénario -> paramètres du launcher principal ────────────────
# (Launcher_advanced_tests.sh accepte directement ideal/modere/degrade, pas
# besoin de traduction pour lui — seul le launcher principal a besoin des
# valeurs brutes loss/delay et du mot-clé "simple"/"none".)
case "$NETWORK_SCENARIO" in
    ideal)
        MAIN_PROFILE="none"; MAIN_LOSS=0; MAIN_DELAY=0 ;;
    modere)
        MAIN_PROFILE="simple"; MAIN_LOSS=0.3; MAIN_DELAY=30.02 ;;
    degrade)
        MAIN_PROFILE="simple"; MAIN_LOSS=0.2; MAIN_DELAY=65.15 ;;
esac

REPR_COMBOS=(
    "mldsa44 mlkem512"
    "mldsa65 mlkem768"
    "mldsa87 mlkem1024"
    "mldsa44 hqc128"
    "mldsa65 hqc192"
    "mldsa87 hqc256"
)

RUN_TS="$(date +%Y%m%d_%H%M%S)"
LOG_DIR="$SCRIPT_DIR/captures/orchestration_logs/${RUN_TS}_${NETWORK_SCENARIO}"
mkdir -p "$LOG_DIR"
SUMMARY_FILE="$LOG_DIR/summary.txt"

: > "$SUMMARY_FILE"
log() { echo "$1" | tee -a "$SUMMARY_FILE"; }

RESULTS=()

for f in "$MAIN_LAUNCHER" "$ADV_LAUNCHER"; do
    if [[ ! -f "$f" ]]; then
        log "[ERREUR FATALE] $f introuvable dans $SCRIPT_DIR. Arrêt."
        exit 1
    fi
    chmod +x "$f" 2>/dev/null || true
done

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
        log "  [OK-SHELL] $label terminé sans erreur shell (exit 0)."
        RESULTS+=("$label:0")
    else
        log "  [ATTENTION] $label a retourné un code d'erreur shell — voir $LOG_DIR/${safe_name}.log"
        RESULTS+=("$label:1")
    fi
    log " Fin : $(date '+%H:%M:%S')"
}

log "== Campagne de tests — scénario: $NETWORK_SCENARIO — $(date) =="
log "Launcher principal : profile=$MAIN_PROFILE loss=$MAIN_LOSS delay=$MAIN_DELAY"
log "Waves concurrent=$WAVES_CONCURRENT | Waves resumption=$WAVES_RESUMPTION"
log "Combos représentatifs :"
for combo in "${REPR_COMBOS[@]}"; do log "  - $combo"; done

###############################################################################
# 1. SWEEP PRINCIPAL
###############################################################################
run_step "Sweep TLS single ($NETWORK_SCENARIO)"  "$MAIN_LAUNCHER" both tls  single nocapture "$MAIN_PROFILE" "$MAIN_LOSS" "$MAIN_DELAY"
run_step "Sweep TLS mutual ($NETWORK_SCENARIO)"  "$MAIN_LAUNCHER" both tls  mutual nocapture "$MAIN_PROFILE" "$MAIN_LOSS" "$MAIN_DELAY"
run_step "Sweep QUIC single ($NETWORK_SCENARIO)" "$MAIN_LAUNCHER" both quic single nocapture "$MAIN_PROFILE" "$MAIN_LOSS" "$MAIN_DELAY"

log ""
log "[INFO] QUIC mutual volontairement EXCLU — authentification non fiable"
log "       dans cette pile (confirmé empiriquement)."

###############################################################################
# 2. CHARGE CONCURRENTE
###############################################################################
for combo in "${REPR_COMBOS[@]}"; do
    read -r SIG KEM <<< "$combo"
    run_step "Concurrent TLS $NETWORK_SCENARIO ($SIG/$KEM)"  "$ADV_LAUNCHER" concurrent tls  single "$SIG" "$KEM" "$NETWORK_SCENARIO" "1,5,10,20,50" "$WAVES_CONCURRENT"
    run_step "Concurrent QUIC $NETWORK_SCENARIO ($SIG/$KEM)" "$ADV_LAUNCHER" concurrent quic single "$SIG" "$KEM" "$NETWORK_SCENARIO" "1,5,10,20,50" "$WAVES_CONCURRENT"
done

###############################################################################
# 3. SESSION RESUMPTION
###############################################################################
for combo in "${REPR_COMBOS[@]}"; do
    read -r SIG KEM <<< "$combo"
    run_step "Resumption TLS $NETWORK_SCENARIO ($SIG/$KEM)"  "$ADV_LAUNCHER" resumption tls  single "$SIG" "$KEM" "$NETWORK_SCENARIO" "$WAVES_RESUMPTION" false
    run_step "Resumption QUIC $NETWORK_SCENARIO ($SIG/$KEM)" "$ADV_LAUNCHER" resumption quic single "$SIG" "$KEM" "$NETWORK_SCENARIO" "$WAVES_RESUMPTION" false
done

###############################################################################
# 4. VALIDATION
###############################################################################
log ""
log "=================================================="
log " VALIDATION DES DONNÉES PRODUITES"
log "=================================================="

VALIDATION_OK=true

validate_handshake_logs() {
    local protocol="$1" auth_mode="$2"
    local dir="$SCRIPT_DIR/captures/$protocol/$auth_mode/${MAIN_PROFILE_LABEL}/handshake_logs"
    log ""
    log "--- Logs de handshake : $protocol/$auth_mode ($dir) ---"
    if [[ ! -d "$dir" ]] || [[ -z "$(ls -A "$dir" 2>/dev/null)" ]]; then
        log "  [ÉCHEC VALIDATION] Aucun log trouvé dans $dir."
        VALIDATION_OK=false
        return
    fi
    local n_files
    n_files=$(find "$dir" -name "handshake_*.log" | wc -l)
    log "  $n_files fichier(s) de log trouvé(s) (42 attendus)."
    if [[ "$n_files" -lt 42 ]]; then
        log "  [ATTENTION] Moins de 42 fichiers — au moins une combinaison a échoué."
        VALIDATION_OK=false
    fi

    python3 parse_handshake_logs.py --input-dir "$dir" --out-dir "$LOG_DIR/validation_${protocol}_${auth_mode}" \
        2>&1 | tee -a "$SUMMARY_FILE"

    local stats_csv="$LOG_DIR/validation_${protocol}_${auth_mode}/handshake_stats.csv"
    if [[ -f "$stats_csv" ]]; then
        local n_bad
        n_bad=$(LC_ALL=C awk -F, 'NR>1 && $10<95 {c++} END{print c+0}' "$stats_csv")
        if [[ "$n_bad" -gt 0 ]]; then
            log "  [ATTENTION] $n_bad combinaison(s) sous 95% de succès — voir $stats_csv."
            VALIDATION_OK=false
        else
            log "  [OK] Tous les taux de succès sont >= 95%."
        fi
    fi
}

# NETWORK_PROFILE_LABEL exact tel qu'écrit par le launcher principal (avec
# loss/delay intégrés pour "simple") — recalculé ici à l'identique pour
# retrouver les bons dossiers.
if [[ "$NETWORK_SCENARIO" == "ideal" ]]; then
    MAIN_PROFILE_LABEL="none"
else
    MAIN_PROFILE_LABEL="simple_loss${MAIN_LOSS}_delay${MAIN_DELAY}ms"
fi

validate_handshake_logs "tls" "single"
validate_handshake_logs "tls" "mutual"
validate_handshake_logs "quic" "single"

validate_resource_usage() {
    local protocol="$1" auth_mode="$2"
    local csv="$SCRIPT_DIR/captures/$protocol/$auth_mode/${MAIN_PROFILE_LABEL}/resource_usage/resource_usage_${protocol}_${auth_mode}_${MAIN_PROFILE_LABEL}.csv"
    log ""
    log "--- CPU/mémoire : $protocol/$auth_mode ---"
    if [[ ! -f "$csv" ]]; then
        log "  [ÉCHEC VALIDATION] $csv introuvable."
        VALIDATION_OK=false
        return
    fi
    local n_rows
    n_rows=$(($(wc -l < "$csv") - 1))
    log "  $n_rows ligne(s) dans $csv."
    [[ "$n_rows" -eq 0 ]] && { log "  [ÉCHEC VALIDATION] Fichier vide."; VALIDATION_OK=false; } || log "  [OK]"
}

validate_resource_usage "tls" "single"
validate_resource_usage "tls" "mutual"
validate_resource_usage "quic" "single"

validate_advanced() {
    local kind="$1" glob="$2" expected="$3"
    local dir="$SCRIPT_DIR/captures/advanced_tests"
    log ""
    log "--- $kind ---"
    local n_files
    n_files=$(find "$dir" -name "$glob" 2>/dev/null | wc -l)
    log "  $n_files fichier(s) trouvé(s) ($glob), $expected attendu(s)."
    if [[ "$n_files" -eq 0 ]]; then
        log "  [ÉCHEC VALIDATION] Aucun fichier."
        VALIDATION_OK=false
    elif [[ "$n_files" -lt "$expected" ]]; then
        log "  [ATTENTION] Moins de fichiers que prévu — au moins un combo a échoué."
        VALIDATION_OK=false
    else
        log "  [OK]"
    fi
}

validate_advanced "Charge concurrente TLS" "concurrent_summary_tls_*_${NETWORK_SCENARIO}_c*.csv" 30
validate_advanced "Charge concurrente QUIC" "concurrent_summary_quic_*_${NETWORK_SCENARIO}_c*.csv" 30
validate_advanced "Resumption TLS" "resumption_summary_tls_*_${NETWORK_SCENARIO}.csv" 6
validate_advanced "Resumption QUIC" "resumption_summary_quic_*_${NETWORK_SCENARIO}.csv" 6

###############################################################################
# 5. RÉCAPITULATIF
###############################################################################
log ""
log "=================================================="
log " RÉCAPITULATIF FINAL — scénario: $NETWORK_SCENARIO"
log "=================================================="
for r in "${RESULTS[@]}"; do
    label="${r%%:*}"; code="${r##*:}"
    [[ "$code" == "0" ]] && log "  [OK-SHELL]    $label" || log "  [ERREUR-SHELL] $label"
done

log ""
if $VALIDATION_OK; then
    log "✅ VALIDATION GLOBALE : les données produites semblent réelles et plausibles."
else
    log "⚠️  VALIDATION GLOBALE : au moins un point d'attention détecté ci-dessus."
fi

log ""
log "Rapport complet : $SUMMARY_FILE"
log "Logs détaillés par étape : $LOG_DIR/"
