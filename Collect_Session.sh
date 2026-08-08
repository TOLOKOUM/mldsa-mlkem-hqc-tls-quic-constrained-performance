#!/usr/bin/env bash
#
# collect_session.sh — Collecte terrain unique (RTT, perte, gigue) pour calibration
#                        des scénarios réseau réels (idéal + 2 scénarios dégradés).
#
# Le modèle Gilbert-Elliott (burst-loss) N'EST PAS concerné par ce script :
# ses paramètres restent ceux déjà validés dans le projet précédent.
#
# USAGE:
#   ./collect_session.sh --operator MTN --conn 4G --location "Pulytechnique" \
#                         --target 8.8.8.8 [--iperf-server IP] [--count 1000]
#
# Chaque exécution crée un dossier sessions/<timestamp>_<operateur>_<conn>/
# contenant : ping.log, iperf.log (optionnel), meta.json
#
# PRÉREQUIS : ping, awk, date, (optionnel) iperf3
# Aucun droit root requis pour ce script (la conversion en tc/netem se fait plus tard,
# elle nécessitera root sur les machines d'expérimentation, pas ici).

set -euo pipefail

OPERATOR=""
CONN=""
LOCATION=""
TARGET="1.1.1.1"
IPERF_SERVER=""
COUNT=1000
INTERVAL=0.1
NOTE=""

usage() {
  echo "Usage: $0 --operator <nom> --conn <4G|WiFi|ADSL|3G> --location <lieu> [--target IP] [--iperf-server IP] [--count N] [--note \"texte\"]"
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --operator) OPERATOR="$2"; shift 2;;
    --conn) CONN="$2"; shift 2;;
    --location) LOCATION="$2"; shift 2;;
    --target) TARGET="$2"; shift 2;;
    --iperf-server) IPERF_SERVER="$2"; shift 2;;
    --count) COUNT="$2"; shift 2;;
    --interval) INTERVAL="$2"; shift 2;;
    --note) NOTE="$2"; shift 2;;
    -h|--help) usage;;
    *) echo "Option inconnue: $1"; usage;;
  esac
done

[[ -z "$OPERATOR" || -z "$CONN" || -z "$LOCATION" ]] && { echo "ERREUR: --operator, --conn et --location sont obligatoires."; usage; }

command -v ping >/dev/null 2>&1 || { echo "ERREUR: ping introuvable."; exit 1; }

TS=$(date +%Y%m%d_%H%M%S)
DAY_OF_WEEK=$(date +%A)
HOUR=$(date +%H)
SLOT="creuse"
if [[ "$HOUR" -ge 12 && "$HOUR" -lt 14 ]] || [[ "$HOUR" -ge 19 && "$HOUR" -lt 22 ]]; then
  SLOT="pointe"
fi

SESSION_DIR="sessions/${TS}_${OPERATOR}_${CONN}"
mkdir -p "$SESSION_DIR"

echo "=================================================================="
echo " Session de collecte réseau — $(date)"
echo " Opérateur : $OPERATOR | Connexion : $CONN | Lieu : $LOCATION"
echo " Créneau   : $SLOT (heure=$HOUR) | Jour : $DAY_OF_WEEK"
echo " Dossier   : $SESSION_DIR"
echo "=================================================================="

# --- 1. Capture RTT + perte (ping horodaté par icmp_seq, avec timestamps -D) ---
echo "[1/2] Capture ping ($COUNT paquets, intervalle ${INTERVAL}s, cible $TARGET)..."
PING_LOG="$SESSION_DIR/ping.log"
if ping -D -i "$INTERVAL" -c "$COUNT" "$TARGET" > "$PING_LOG" 2>&1; then
  echo "      -> OK ($PING_LOG)"
else
  echo "      -> ping terminé avec code non-zéro (normal si pertes en fin de séquence) : $PING_LOG conservé."
fi

# --- 2. Capture gigue / bande passante (optionnelle, nécessite un serveur iperf3 dédié) ---
IPERF_LOG=""
if [[ -n "$IPERF_SERVER" ]]; then
  if command -v iperf3 >/dev/null 2>&1; then
    echo "[2/2] Capture jitter/bande passante UDP via iperf3 vers $IPERF_SERVER (60s)..."
    IPERF_LOG="$SESSION_DIR/iperf.log"
    iperf3 -u -c "$IPERF_SERVER" -t 60 -b 1M -i 5 > "$IPERF_LOG" 2>&1 || echo "      -> iperf3 a échoué, voir $IPERF_LOG"
  else
    echo "[2/2] iperf3 non installé sur cette machine — étape sautée."
  fi
else
  echo "[2/2] Pas de --iperf-server fourni — capture jitter sautée (RTT/perte restent valides sans elle)."
fi

# --- 3. Métadonnées de session (traçabilité obligatoire pour l'annexe méthodologique) ---
cat > "$SESSION_DIR/meta.json" <<EOF
{
  "timestamp": "$TS",
  "operator": "$OPERATOR",
  "connection_type": "$CONN",
  "location": "$LOCATION",
  "target": "$TARGET",
  "day_of_week": "$DAY_OF_WEEK",
  "hour": "$HOUR",
  "time_slot": "$SLOT",
  "ping_count": $COUNT,
  "ping_interval_s": $INTERVAL,
  "iperf_server": "${IPERF_SERVER:-null}",
  "note": "$NOTE"
}
EOF

echo "------------------------------------------------------------------"
echo " Session terminée."
echo "------------------------------------------------------------------"
