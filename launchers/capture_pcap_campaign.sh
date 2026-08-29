#!/usr/bin/env bash
###############################################################################
# capture_pcap_campaign.sh — génère et exécute les commandes de
# capture_pcap_demo.sh pour :
#   42 paires SIG_ALG/KEM (mêmes listes que Launcher_pq_mldsa_mlkem_hqc.sh)
#   × 2 protocoles (tls, quic), AUTH SINGLE UNIQUEMENT (pas de mutual)
#   × 3 scénarios réseau : Idéal, Modéré (terrain), Dégradé (terrain)
#     (PAS de GE-Stable/GE-Unstable ici -- exclus par choix)
#   = 42 × 2 × 3 = 252 captures au total.
#
# Usage:
#   ./capture_pcap_campaign.sh [--dry-run] [--scenarios ideal,modere,degrade]
#
#   --dry-run              : affiche les commandes sans les exécuter
#   --scenarios LISTE       : limite aux scénarios listés (par défaut: les 3
#                              ci-dessus). Valeurs possibles: ideal,modere,degrade
#                              (ge-stable/ge-unstable retirés du set par défaut,
#                              utilisables seulement si explicitement demandés)
#
# ⚠️ À LIRE AVANT DE LANCER SANS --dry-run :
#   252 captures, chacune avec démarrage/arrêt de 2 conteneurs + génération
#   de certs, représentent plusieurs HEURES d'exécution (estimation grossière :
#   20-30s par capture → ~1.5 à 2h pour la totalité). Non-interactif donc
#   lançable sans surveillance (tmux/nohup), mais vérifie d'abord avec
#   --dry-run que la liste te convient.
###############################################################################
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CAPTURE_SCRIPT="$SCRIPT_DIR/capture_pcap_demo.sh"

DRY_RUN=false
SCENARIO_FILTER="ideal,modere,degrade"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=true; shift ;;
        --scenarios) SCENARIO_FILTER="$2"; shift 2 ;;
        *) echo "Argument inconnu: $1"; exit 1 ;;
    esac
done

if [[ ! -x "$CAPTURE_SCRIPT" ]]; then
    echo "❌ $CAPTURE_SCRIPT introuvable ou non exécutable (chmod +x d'abord)."
    exit 1
fi

###############################################################################
#  Mêmes listes SIG_ALG/KEM que Launcher_pq_mldsa_mlkem_hqc.sh (KEM_FAMILY=both)
###############################################################################

SUPPORTED_SIG_ALGS=("ed25519" "secp384r1" "secp521r1" "mldsa44" "mldsa65" "mldsa87")

CLASSICAL_L1=("P-256" "x25519")
CLASSICAL_L3=("P-384" "x448")
CLASSICAL_L5=("P-521")

MLKEM_L1=("p256_mlkem512" "x25519_mlkem512" "mlkem512")
MLKEM_L3=("p384_mlkem768" "x448_mlkem768" "mlkem768")
MLKEM_L5=("p521_mlkem1024" "mlkem1024")

HQC_L1=("hqc128" "p256_hqc128" "x25519_hqc128")
HQC_L3=("hqc192" "p384_hqc192" "x448_hqc192")
HQC_L5=("hqc256" "p521_hqc256")

KEMS_L1=("${CLASSICAL_L1[@]}" "${MLKEM_L1[@]}" "${HQC_L1[@]}")
KEMS_L3=("${CLASSICAL_L3[@]}" "${MLKEM_L3[@]}" "${HQC_L3[@]}")
KEMS_L5=("${CLASSICAL_L5[@]}" "${MLKEM_L5[@]}" "${HQC_L5[@]}")

###############################################################################
#  Scénarios réseau (label, profil, loss%, delay-ms)
###############################################################################

declare -A SCENARIOS
SCENARIOS[ideal]="none|0|0"
SCENARIOS[modere]="simple|1.3|62.51"
SCENARIOS[degrade]="simple|1.5833|83.52"
SCENARIOS[ge-stable]="stable|0|0"
SCENARIOS[ge-unstable]="unstable|0|0"

IFS=',' read -ra SELECTED_SCENARIOS <<< "$SCENARIO_FILTER"
for s in "${SELECTED_SCENARIOS[@]}"; do
    if [[ -z "${SCENARIOS[$s]+x}" ]]; then
        echo "❌ Scénario inconnu: '$s' (valides: ${!SCENARIOS[*]})"
        exit 1
    fi
done

###############################################################################
#  Construction de la liste à plat (SIG_ALG, KEM) — identique au launcher
###############################################################################

PAIRS=()
for SIG_ALG in "${SUPPORTED_SIG_ALGS[@]}"; do
    if [ "$SIG_ALG" = "ed25519" ] || [ "$SIG_ALG" = "mldsa44" ]; then
        KEMS_FOR_SIG=("${KEMS_L1[@]}")
    elif [ "$SIG_ALG" = "secp384r1" ] || [ "$SIG_ALG" = "mldsa65" ]; then
        KEMS_FOR_SIG=("${KEMS_L3[@]}")
    elif [ "$SIG_ALG" = "secp521r1" ] || [ "$SIG_ALG" = "mldsa87" ]; then
        KEMS_FOR_SIG=("${KEMS_L5[@]}")
    fi
    for KEM in "${KEMS_FOR_SIG[@]}"; do
        PAIRS+=("${SIG_ALG}|${KEM}")
    done
done

echo "Paires SIG_ALG/KEM: ${#PAIRS[@]} (attendu: 42)"
echo "Scénarios sélectionnés: ${SELECTED_SCENARIOS[*]}"

# single uniquement (tls + quic) -- pas de mutual, sur demande explicite
PROTO_AUTH_COMBOS=("tls|single" "quic|single")

TOTAL=$(( ${#PAIRS[@]} * ${#PROTO_AUTH_COMBOS[@]} * ${#SELECTED_SCENARIOS[@]} ))
echo "Total de captures à exécuter: $TOTAL"
echo ""

if [[ "$DRY_RUN" == "true" ]]; then
    echo "── MODE --dry-run : affichage seul, rien n'est exécuté ──"
fi

###############################################################################
#  Exécution
###############################################################################

i=0
FAILED=()
for scenario_name in "${SELECTED_SCENARIOS[@]}"; do
    IFS='|' read -r PROFILE LOSS DELAY <<< "${SCENARIOS[$scenario_name]}"
    for pa in "${PROTO_AUTH_COMBOS[@]}"; do
        IFS='|' read -r PROTOCOL AUTH_MODE <<< "$pa"
        for PAIR in "${PAIRS[@]}"; do
            IFS='|' read -r SIG_ALG KEM <<< "$PAIR"
            i=$((i+1))
            CMD=("$CAPTURE_SCRIPT" "$PROTOCOL" "$SIG_ALG" "$KEM" "$AUTH_MODE" "$PROFILE" "$LOSS" "$DELAY")
            echo "[$i/$TOTAL] (${scenario_name}) ${CMD[*]}"
            if [[ "$DRY_RUN" != "true" ]]; then
                if ! "${CMD[@]}"; then
                    echo "   ⚠️  ÉCHEC sur cette combinaison — on continue avec la suivante."
                    FAILED+=("${scenario_name}|${PROTOCOL}|${AUTH_MODE}|${SIG_ALG}|${KEM}")
                fi
            fi
        done
    done
done

echo ""
echo "=================================================="
echo " Terminé : $i/$TOTAL combinaisons traitées."
if [[ "$DRY_RUN" != "true" && ${#FAILED[@]} -gt 0 ]]; then
    echo " ⚠️  ${#FAILED[@]} échec(s) :"
    for f in "${FAILED[@]}"; do echo "   - $f"; done
fi
echo "=================================================="
