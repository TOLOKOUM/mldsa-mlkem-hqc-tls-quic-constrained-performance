#!/usr/bin/env bash
# run_S3_measure.sh -- campagne S3 : 20 blocs par bras, bras entrelaces (bloc K traitement puis temoin si K impair ; temoin puis traitement si K pair).
# Usage : seuil_S3/run_S3_measure.sh [K_debut K_fin]   (defaut 1 20).  Relancer la meme commande reprend ce qui manque (jamais --force).
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"; cd "$REPO"
K0=${1:-1}; K1=${2:-20}
declare -A IMG=( [PAD1]=uma-tls-quic-pq-34-v3c-pad1450 [PAD0]=uma-tls-quic-pq-34-v3c )
declare -A SEED=( [PAD1]=20261119 [PAD0]=20261120 )
for K in $(seq "$K0" "$K1"); do
  if (( K % 2 )); then ORDER="PAD1 PAD0"; else ORDER="PAD0 PAD1"; fi
  for A in $ORDER; do
    export CAPTURES_ROOT="$PWD/captures_S3_$A"
    IMAGE="${IMG[$A]}" ./run_campaign_ext.sh --plan "seuil_S3/plans_S3_$A/plan_S2_all.csv" --master-seed "${SEED[$A]}" \
        --state-dir "$PWD/campaign_state_S3_$A" --no-sentinels --block "$K" --max-blocks-per-day 20 \
        2>&1 | tee -a "audit_S3/mesure_${A}.log" | tail -3
    [ "${PIPESTATUS[0]}" -eq 0 ] || { echo "ARRET : bloc $K, bras $A en echec (relancer la meme commande)"; exit 1; }
  done
  echo "=== bloc $K termine pour les deux bras : $(date -Iseconds)"
done
