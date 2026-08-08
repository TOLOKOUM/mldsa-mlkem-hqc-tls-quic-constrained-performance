#!/usr/bin/env bash
set -uo pipefail
#
# run_all_ideal_tests.sh — Lance TOUS les tests en conditions idéales
# (sweep principal + charge concurrente + resumption) et VALIDE
# automatiquement que les données produites sont réelles et plausibles.
#
# Ne s'arrête pas au premier échec (pas de "set -e") : on veut un rapport
# complet de ce qui a marché et ce qui n'a pas marché, pas un arrêt sec.
#
# Usage: ./run_all_ideal_tests.sh [waves_concurrent] [waves_resumption]
#   Par défaut : 20 / 50 (comme avant). Réduire pour un test rapide avant de
#   lancer la campagne complète, ex: ./run_all_ideal_tests.sh 3 5
#
# Charge concurrente et resumption tournent maintenant sur 6 combos
# REPRÉSENTATIFS (un par niveau de sécurité × famille), pas un seul —
# cohérent avec PLAN_DE_RUNS.md. Auth = single uniquement pour l'instant ;
# mutual (TLS) et QUIC mutual restent hors de cette campagne automatique
# (QUIC mutual : authentification non fiable, cf. diagnostic précédent —
# TLS mutual : pas encore inclus, à ajouter séparément si besoin).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

MAIN_LAUNCHER="./Launcher_pq_mldsa_mlkem_hqc.sh"
ADV_LAUNCHER="./Launcher_advanced_tests.sh"

WAVES_CONCURRENT="${1:-20}"
WAVES_RESUMPTION="${2:-50}"

# Combos représentatifs : un par niveau de sécurité NIST × famille PQ pure
# (pas de variantes hybrides ici — le sweep principal couvre déjà toute la
# matrice ; charge concurrente/resumption visent le comportement du serveur
# sous charge/reprise, pas l'exhaustivité algorithmique).
REPR_COMBOS=(
    "mldsa44 mlkem512"
    "mldsa65 mlkem768"
    "mldsa87 mlkem1024"
    "mldsa44 hqc128"
    "mldsa65 hqc192"
    "mldsa87 hqc256"
)

RUN_TS="$(date +%Y%m%d_%H%M%S)"
LOG_DIR="$SCRIPT_DIR/captures/orchestration_logs/$RUN_TS"
mkdir -p "$LOG_DIR"
SUMMARY_FILE="$LOG_DIR/summary.txt"

: > "$SUMMARY_FILE"
log() { echo "$1" | tee -a "$SUMMARY_FILE"; }

RESULTS=()   # "label:0|1" — 0=ok, 1=échec shell, on affine avec la validation ensuite

# Vérifications préalables : les deux launchers existent et sont exécutables
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

log "== Campagne de tests IDÉAL — $(date) =="
log "Waves concurrent=$WAVES_CONCURRENT | Waves resumption=$WAVES_RESUMPTION"
log "Combos représentatifs (charge concurrente / resumption) :"
for combo in "${REPR_COMBOS[@]}"; do log "  - $combo"; done

###############################################################################
# 1. SWEEP PRINCIPAL — toutes les combinaisons SIG/KEM, conditions idéales
###############################################################################
run_step "Sweep TLS single"  "$MAIN_LAUNCHER" both tls  single nocapture none 0 0
run_step "Sweep TLS mutual"  "$MAIN_LAUNCHER" both tls  mutual nocapture none 0 0
run_step "Sweep QUIC single" "$MAIN_LAUNCHER" both quic single nocapture none 0 0

log ""
log "[INFO] QUIC mutual volontairement EXCLU de cette campagne — authentification"
log "       non appliquée de façon fiable dans cette pile (confirmé empiriquement,"
log "       cf. diagnostic précédent). Lancez-le séparément si besoin, en marquant"
log "       les résultats comme non représentatifs d'une auth réelle."

###############################################################################
# 2. CHARGE CONCURRENTE — 6 combos représentatifs, TLS et QUIC
###############################################################################
for combo in "${REPR_COMBOS[@]}"; do
    read -r SIG KEM <<< "$combo"
    run_step "Concurrent TLS ideal ($SIG/$KEM)"  "$ADV_LAUNCHER" concurrent tls  single "$SIG" "$KEM" ideal "1,5,10,20,50" "$WAVES_CONCURRENT"
    run_step "Concurrent QUIC ideal ($SIG/$KEM)" "$ADV_LAUNCHER" concurrent quic single "$SIG" "$KEM" ideal "1,5,10,20,50" "$WAVES_CONCURRENT"
done

###############################################################################
# 3. SESSION RESUMPTION — 6 combos représentatifs, TLS et QUIC
###############################################################################
for combo in "${REPR_COMBOS[@]}"; do
    read -r SIG KEM <<< "$combo"
    run_step "Resumption TLS ideal ($SIG/$KEM)"  "$ADV_LAUNCHER" resumption tls  single "$SIG" "$KEM" ideal "$WAVES_RESUMPTION" false
    run_step "Resumption QUIC ideal ($SIG/$KEM)" "$ADV_LAUNCHER" resumption quic single "$SIG" "$KEM" ideal "$WAVES_RESUMPTION" false
done

###############################################################################
# 4. VALIDATION — les données sont-elles RÉELLEMENT là et plausibles ?
#    C'est la partie qui répond à "je veux me rassurer que ça se passe bien".
###############################################################################
log ""
log "=================================================="
log " VALIDATION DES DONNÉES PRODUITES"
log "=================================================="

VALIDATION_OK=true

validate_handshake_logs() {
    local protocol="$1" auth_mode="$2"
    local dir="$SCRIPT_DIR/captures/$protocol/$auth_mode/none/handshake_logs"
    log ""
    log "--- Logs de handshake : $protocol/$auth_mode ($dir) ---"
    if [[ ! -d "$dir" ]] || [[ -z "$(ls -A "$dir" 2>/dev/null)" ]]; then
        log "  [ÉCHEC VALIDATION] Aucun log trouvé dans $dir — le sweep n'a probablement pas tourné."
        VALIDATION_OK=false
        return
    fi
    local n_files
    n_files=$(find "$dir" -name "handshake_*.log" | wc -l)
    log "  $n_files fichier(s) de log trouvé(s)."

    python3 parse_handshake_logs.py --input-dir "$dir" --out-dir "$LOG_DIR/validation_${protocol}_${auth_mode}" \
        2>&1 | tee -a "$SUMMARY_FILE"

    local stats_csv="$LOG_DIR/validation_${protocol}_${auth_mode}/handshake_stats.csv"
    if [[ ! -f "$stats_csv" ]]; then
        log "  [ÉCHEC VALIDATION] handshake_stats.csv non généré — logs illisibles."
        VALIDATION_OK=false
        return
    fi

    # Combien de combinaisons ont un taux de succès < 95% ? (seuil arbitraire mais
    # raisonnable — quelques échecs isolés en idéal sont anormaux)
    local n_bad
    n_bad=$(LC_ALL=C awk -F, 'NR>1 && $10<95 {c++} END{print c+0}' "$stats_csv")
    local n_total_combos
    n_total_combos=$(($(wc -l < "$stats_csv") - 1))
    log "  $n_total_combos combinaison(s) analysée(s), $n_bad avec un taux de succès < 95%."
    if [[ "$n_bad" -gt 0 ]]; then
        log "  [ATTENTION] Voir $stats_csv — combinaisons avec échecs à investiguer avant de"
        log "              considérer cette campagne comme un baseline propre."
        VALIDATION_OK=false
    else
        log "  [OK] Tous les taux de succès sont >= 95%."
    fi
}

validate_handshake_logs "tls" "single"
validate_handshake_logs "tls" "mutual"
validate_handshake_logs "quic" "single"

validate_resource_usage() {
    local protocol="$1" auth_mode="$2"
    local csv="$SCRIPT_DIR/captures/$protocol/$auth_mode/none/resource_usage/resource_usage_${protocol}_${auth_mode}_none.csv"
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
    if [[ "$n_rows" -eq 0 ]]; then
        log "  [ÉCHEC VALIDATION] Fichier présent mais vide."
        VALIDATION_OK=false
    else
        log "  [OK]"
    fi
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
    log "  $n_files fichier(s) trouvé(s) ($glob dans $dir), $expected attendu(s)."
    if [[ "$n_files" -eq 0 ]]; then
        log "  [ÉCHEC VALIDATION] Aucun fichier — l'étape a probablement échoué avant la copie des résultats."
        VALIDATION_OK=false
    elif [[ "$n_files" -lt "$expected" ]]; then
        log "  [ATTENTION] Moins de fichiers que prévu — au moins un combo a probablement échoué"
        log "              silencieusement (le script continue même en cas d'erreur shell isolée)."
        VALIDATION_OK=false
    else
        log "  [OK]"
    fi
}

# 6 combos × 5 niveaux de concurrence = 30 fichiers attendus par protocole
# 6 combos × 1 fichier = 6 fichiers attendus par protocole (resumption)
validate_advanced "Charge concurrente TLS" "concurrent_summary_tls_*_ideal_c*.csv" 30
validate_advanced "Charge concurrente QUIC" "concurrent_summary_quic_*_ideal_c*.csv" 30
validate_advanced "Resumption TLS" "resumption_summary_tls_*_ideal.csv" 6
validate_advanced "Resumption QUIC" "resumption_summary_quic_*_ideal.csv" 6

###############################################################################
# 5. RÉCAPITULATIF FINAL
###############################################################################
log ""
log "=================================================="
log " RÉCAPITULATIF FINAL"
log "=================================================="
for r in "${RESULTS[@]}"; do
    label="${r%%:*}"
    code="${r##*:}"
    if [[ "$code" == "0" ]]; then
        log "  [OK-SHELL]    $label"
    else
        log "  [ERREUR-SHELL] $label"
    fi
done

log ""
if $VALIDATION_OK; then
    log "✅ VALIDATION GLOBALE : les données produites semblent réelles et plausibles."
    log "   Vous pouvez avancer avec confiance sur les scénarios Modéré/Dégradé."
else
    log "⚠️  VALIDATION GLOBALE : au moins un point d'attention détecté ci-dessus."
    log "   Ne lancez pas Modéré/Dégradé avant d'avoir compris et corrigé ces points —"
    log "   relancer sur une base bancale ne ferait que multiplier le problème."
fi

log ""
log "Rapport complet : $SUMMARY_FILE"
log "Logs détaillés par étape : $LOG_DIR/"
