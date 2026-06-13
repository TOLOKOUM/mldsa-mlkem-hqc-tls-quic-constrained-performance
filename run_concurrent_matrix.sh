#!/bin/bash
# ============================================================================
# run_concurrent_matrix.sh
# Exécute la matrice complète des tests de charge concurrente
#
# Matrice:
#   Protocoles : TLS, QUIC
#   Clients    : 10, 50, 100
#   Scénarios  : Ideal (0ms/0%), Local YDE (35ms/2%), Degraded (200ms/10%)
#
# Total : 2 × 3 × 3 = 18 runs
#
# Usage: ./run_concurrent_matrix.sh [--dry-run] [--resume] [--start-from N]
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LAUNCHER="${SCRIPT_DIR}/Launcherv3_mlkem_concurrent.sh"
DRY_RUN=false
RESUME=false
START_FROM=1

# Emplacement unique des résultats - CORRIGÉ pour ton utilisateur
RESULTS_DIR="/home/tolokoum/Documents/TLS-QUIC/mldsa-mlkem-study1/result_concurrent"

# Créer le dossier s'il n'existe pas
mkdir -p "$RESULTS_DIR"

# Matrice de tests
PROTOCOLS=("tls" "quic")
CLIENTS=(10 50 100)
SCENARIOS=(
    "none 0 0:Ideal (0ms, 0%)"
    "simple 2 35:Local YDE (35ms, 2%)"
    "simple 10 200:Degraded (200ms, 10%)"
)

# Traitement des arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=true; shift ;;
        --resume) RESUME=true; shift ;;
        --start-from) START_FROM="$2"; shift 2 ;;
        *) shift ;;
    esac
done

# Calculer le nombre total de runs
TOTAL_RUNS=$((${#PROTOCOLS[@]} * ${#CLIENTS[@]} * ${#SCENARIOS[@]}))
echo "=============================================================================="
echo "  CONCURRENT TEST MATRIX"
echo "=============================================================================="
echo "  Total runs:     $TOTAL_RUNS"
echo "  Results dir:    $RESULTS_DIR"
echo "  Protocols:      ${PROTOCOLS[*]}"
echo "  Clients:        ${CLIENTS[*]}"
echo "  Scenarios:"
for SCENARIO_DEF in "${SCENARIOS[@]}"; do
    SCENARIO_ARGS="${SCENARIO_DEF%%:*}"
    SCENARIO_LABEL="${SCENARIO_DEF##*:}"
    echo "    - $SCENARIO_LABEL ($SCENARIO_ARGS)"
done
echo "=============================================================================="
echo ""

RUN_NUM=0
for PROTO in "${PROTOCOLS[@]}"; do
    for N in "${CLIENTS[@]}"; do
        for SCENARIO_DEF in "${SCENARIOS[@]}"; do
            RUN_NUM=$((RUN_NUM + 1))

            # Parser le scénario
            SCENARIO_ARGS="${SCENARIO_DEF%%:*}"
            SCENARIO_LABEL="${SCENARIO_DEF##*:}"
            read -r PROFILE LOSS DELAY <<< "$SCENARIO_ARGS"

            # Vérifier si on doit skipper (--start-from)
            if (( RUN_NUM < START_FROM )); then
                echo "[SKIP] Run $RUN_NUM/$TOTAL_RUNS: $PROTO | $N clients | $SCENARIO_LABEL"
                continue
            fi

            # Vérifier si déjà fait (--resume)
            if $RESUME; then
                PATTERN="${PROTO}_c${N}_${PROFILE}_l${LOSS}_d${DELAY}_*"
                if ls "$RESULTS_DIR"/$PATTERN >/dev/null 2>&1; then
                    echo "[SKIP] Run $RUN_NUM/$TOTAL_RUNS: $PROTO | $N clients | $SCENARIO_LABEL (déjà fait)"
                    continue
                fi
            fi

            echo ""
            echo "=============================================================================="
            echo "  RUN $RUN_NUM/$TOTAL_RUNS"
            echo "  Protocol:      $PROTO"
            echo "  Clients:       $N"
            echo "  Scenario:      $SCENARIO_LABEL"
            echo "  Profile:       $PROFILE | Loss: $LOSS% | Delay: ${DELAY}ms"
            echo "=============================================================================="

            if $DRY_RUN; then
                echo "[DRY-RUN] $LAUNCHER $PROTO $N $PROFILE $LOSS $DELAY"
            else
                "$LAUNCHER" "$PROTO" "$N" "$PROFILE" "$LOSS" "$DELAY"
                echo "[DONE] Run $RUN_NUM/$TOTAL_RUNS completed."
            fi
        done
    done
done

echo ""
echo "=============================================================================="
echo "  ALL RUNS COMPLETED"
echo "=============================================================================="
echo "  Results stored in: $RESULTS_DIR"
echo ""
echo "  To analyze individual runs:"
echo "    python3 ${SCRIPT_DIR}/analyse_concurrent.py $RESULTS_DIR/<run_dir> --plots"
echo ""
echo "  To compare all runs:"
echo "    python3 ${SCRIPT_DIR}/compare_concurrent.py $RESULTS_DIR/"
echo "=============================================================================="
