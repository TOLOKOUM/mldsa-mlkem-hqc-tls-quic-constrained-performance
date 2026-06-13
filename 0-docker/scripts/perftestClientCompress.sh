#!/bin/sh
set -e

# -------------------------------------------------------------------
# perftestClientCompress.sh  — version corrigée
# Client TLS/QUIC avec/sans compression certificat + capture pcap
#
# IMPORTANT — Résultat du diagnostic :
#   OpenSSL OQS compilé SANS zlib → RFC 8879 non disponible.
#   - Phase "compressed"  : aucun flag de compression → comportement défaut
#   - Phase "nocompress"  : -no_rx_cert_comp pour forcer refus compression
#   Les deux phases mesurent le handshake PQ TLS/QUIC de manière comparable.
#   Le CSV inclut une colonne "compress_negotiated" pour vérifier si
#   la compression a bien été (ou non) négociée dans la session.
#
# CSV produit : run_id, duration_ms, success, compress_negotiated
# -------------------------------------------------------------------

# ── Valeurs par défaut ──────────────────────────────────────────────
TC_DELAY="${TC_DELAY:-0ms}"
TC_LOSS="${TC_LOSS:-0%}"
DOCKER_HOST="${DOCKER_HOST:-localhost}"
USE_TLS="${USE_TLS:-true}"
NUM_RUNS="${NUM_RUNS:-500}"
CERT_PATH="${CERT_PATH:-/cert}"
MUTUAL="${MUTUAL:-false}"
COMPRESS_CERT="${COMPRESS_CERT:-false}"
CLIENT_ID="${CLIENT_ID:-0}"
RESULTS_DIR="${RESULTS_DIR:-/results}"
KEM_ALG="${KEM_ALG:-mlkem512}"
SIG_ALG="${SIG_ALG:-mldsa44}"

NETEM_IF="eth0"
CAPTURE_IF="eth0"

# ── Nettoyer DOCKER_HOST (enlever les caractères indésirables) ──────
# Extrait uniquement l'IP (ex: 172.18.0.2) depuis une chaîne comme "ID\n172.18.0.2"
CLEAN_HOST=$(echo "$DOCKER_HOST" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)
if [ -n "$CLEAN_HOST" ]; then
    DOCKER_HOST="$CLEAN_HOST"
fi

# ── Appliquer netem ─────────────────────────────────────────────────
echo "[client-$CLIENT_ID] Applying netem on $NETEM_IF (delay=$TC_DELAY loss=$TC_LOSS)..."
tc qdisc add dev "$NETEM_IF" root netem delay "$TC_DELAY" loss "$TC_LOSS" 2>/dev/null || true

# ── Label pour CSV et noms de fichiers ─────────────────────────────
COMPRESS_LABEL="nocompress"
if [ "$COMPRESS_CERT" = "true" ]; then
    COMPRESS_LABEL="compressed"
fi

echo "[client-$CLIENT_ID] =========================================================="
echo "[client-$CLIENT_ID] SIG_ALG   = $SIG_ALG"
echo "[client-$CLIENT_ID] KEM_ALG   = $KEM_ALG"
echo "[client-$CLIENT_ID] PROTOCOL  = $([ "$USE_TLS" = "true" ] && echo TLS || echo QUIC)"
echo "[client-$CLIENT_ID] COMPRESS  = $COMPRESS_LABEL"
echo "[client-$CLIENT_ID] SERVER    = $DOCKER_HOST:4433"
echo "[client-$CLIENT_ID] RUNS      = $NUM_RUNS"
echo "[client-$CLIENT_ID] =========================================================="

# ── Fix openssl.cnf : supprimer la ligne DEFAULT_GROUPS qui cause
#    des erreurs SSL_CONF_cmd dans certaines versions OQS ────────────
CNF_FILE="/opt/oqssa/ssl/openssl.cnf"
if [ -f "$CNF_FILE" ]; then
    sed -i 's/^DEFAULT_GROUPS/#DEFAULT_GROUPS/' "$CNF_FILE" 2>/dev/null || true
fi
# On exporte aussi la variable pour que OQS Provider l'utilise
export DEFAULT_GROUPS="$KEM_ALG"

# ── Créer le répertoire de résultats ────────────────────────────────
mkdir -p "$RESULTS_DIR"

# ── Fichiers de sortie ──────────────────────────────────────────────
CSV_FILE="${RESULTS_DIR}/compress_${CLIENT_ID}_${SIG_ALG}_${KEM_ALG}_${COMPRESS_LABEL}.csv"
PCAP_FILE="${RESULTS_DIR}/capture_${CLIENT_ID}_${SIG_ALG}_${KEM_ALG}_${COMPRESS_LABEL}.pcap"
LOG_FILE="${RESULTS_DIR}/client_${CLIENT_ID}_${SIG_ALG}_${KEM_ALG}_${COMPRESS_LABEL}.log"

# CSV header : 4 colonnes
echo "run_id,duration_ms,success,compress_negotiated" > "$CSV_FILE"

# ── Démarrer la capture réseau ──────────────────────────────────────
TCPDUMP_PID=""
if command -v tcpdump >/dev/null 2>&1; then
    echo "[client-$CLIENT_ID] Starting tcpdump on $CAPTURE_IF..."
    tcpdump -i "$CAPTURE_IF" -w "$PCAP_FILE" -s 0 \
        "host $DOCKER_HOST and port 4433" 2>/dev/null &
    TCPDUMP_PID=$!
    sleep 1
else
    echo "[client-$CLIENT_ID] tcpdump not available — skipping packet capture"
fi

# ── Attendre que le serveur soit prêt (max 30 tentatives) ───────────
echo "[client-$CLIENT_ID] Waiting for server at $DOCKER_HOST:4433..."
READY=0
for attempt in $(seq 1 30); do
    # Vérifier si le port est ouvert avec nc (netcat) ou timeout openssl
    if command -v nc >/dev/null 2>&1; then
        if nc -z "$DOCKER_HOST" 4433 2>/dev/null; then
            READY=1
            echo "[client-$CLIENT_ID] Server ready (attempt $attempt)"
            break
        fi
    else
        # Fallback: tentative de connexion rapide avec openssl
        if timeout 2 /opt/oqssa/bin/openssl s_client -connect "$DOCKER_HOST:4433" \
            -tls1_3 -CAfile "$CERT_PATH/CA.crt" -groups "$KEM_ALG" </dev/null \
            2>&1 | grep -q "Verify return code: 0"; then
            READY=1
            echo "[client-$CLIENT_ID] Server ready (attempt $attempt)"
            break
        fi
    fi
    echo "[client-$CLIENT_ID] Attempt $attempt/30 — server not ready yet..."
    sleep 1
done

if [ "$READY" = "0" ]; then
    echo "[client-$CLIENT_ID] ERROR: Server not reachable after 30 attempts. Aborting."
    # Arrêter tcpdump avant de quitter
    if [ -n "$TCPDUMP_PID" ]; then
        kill "$TCPDUMP_PID" 2>/dev/null || true
    fi
    exit 1
fi

# ── Boucle principale des mesures ───────────────────────────────────
i=1
while [ "$i" -le "$NUM_RUNS" ]; do

    START_TIME=$(date +%s%3N)

    if [ "$USE_TLS" = "true" ]; then

        # Choisir le flag de compression côté client
        if [ "$COMPRESS_CERT" = "true" ]; then
            # Phase compressed : comportement par défaut (pas de flag)
            # OpenSSL accepte la compression si le serveur la propose
            COMPRESS_FLAG=""
        else
            # Phase nocompress : forcer le refus de compression
            COMPRESS_FLAG="-no_rx_cert_comp"
        fi

        OUTPUT=$(timeout 8 /opt/oqssa/bin/openssl s_client \
            -connect "$DOCKER_HOST:4433" \
            -tls1_3 \
            -CAfile "$CERT_PATH/CA.crt" \
            -groups "$KEM_ALG" \
            -verify 1 \
            ${COMPRESS_FLAG} \
            </dev/null 2>&1)

    else
        # ── Mode QUIC ──────────────────────────────────────────────
        if [ "$MUTUAL" = "true" ]; then
            OUTPUT=$(quics_connection \
                -groups:"$KEM_ALG" \
                -target:"$DOCKER_HOST" \
                -CAfile:"$CERT_PATH/CA.crt" \
                -cert "$CERT_PATH/user.crt" \
                -key  "$CERT_PATH/user.key" 2>&1)
        else
            OUTPUT=$(quics_connection \
                -groups:"$KEM_ALG" \
                -target:"$DOCKER_HOST" \
                -CAfile:"$CERT_PATH/CA.crt" 2>&1)
        fi
    fi

    END_TIME=$(date +%s%3N)
    DURATION=$((END_TIME - START_TIME))

    # ── Détection du succès ─────────────────────────────────────────
    SUCCESS=1
    if echo "$OUTPUT" | grep -q "Verify return code: 0"; then
        SUCCESS=1
    elif echo "$OUTPUT" | grep -qi "error\|alert\|handshake.failure\|connection.refused\|timeout"; then
        SUCCESS=0
    fi

    # ── Détection de la compression négociée ───────────────────────
    # OpenSSL affiche "Cert Compression" ou "cert_compression" si RFC 8879 actif
    COMP_NEG=0
    if echo "$OUTPUT" | grep -qi "cert.compress\|cert_compress\|compress.*cert"; then
        COMP_NEG=1
    fi

    echo "$i,$DURATION,$SUCCESS,$COMP_NEG" >> "$CSV_FILE"

    # Log des erreurs uniquement (pour ne pas alourdir)
    if [ "$SUCCESS" = "0" ]; then
        echo "[client-$CLIENT_ID] run $i FAILED (${DURATION}ms)" >> "$LOG_FILE"
        echo "$OUTPUT" >> "$LOG_FILE"
        echo "---" >> "$LOG_FILE"
    fi

    i=$((i + 1))
done

# ── Arrêter la capture ──────────────────────────────────────────────
if [ -n "$TCPDUMP_PID" ]; then
    echo "[client-$CLIENT_ID] Stopping tcpdump..."
    sleep 1
    kill "$TCPDUMP_PID" 2>/dev/null || true
    wait "$TCPDUMP_PID" 2>/dev/null || true
fi

# ── Résumé final ────────────────────────────────────────────────────
TOTAL=$(awk -F',' 'NR>1 {count++} END {print count+0}' "$CSV_FILE")
SUCCESS_COUNT=$(awk -F',' 'NR>1 && $3==1 {s++} END {print s+0}' "$CSV_FILE")
COMP_COUNT=$(awk -F',' 'NR>1 && $4==1 {c++} END {print c+0}' "$CSV_FILE")
AVG_MS=$(awk -F',' 'NR>1 && $3==1 {sum+=$2; n++} END {if(n>0) printf "%.2f", sum/n; else print "N/A"}' "$CSV_FILE")

echo "[client-$CLIENT_ID] =========================================================="
echo "[client-$CLIENT_ID] DONE: $SUCCESS_COUNT/$TOTAL successful handshakes"
echo "[client-$CLIENT_ID] Compression negotiated: $COMP_COUNT/$TOTAL runs"
echo "[client-$CLIENT_ID] Average latency (success): ${AVG_MS} ms"
echo "[client-$CLIENT_ID] CSV  : $CSV_FILE"
echo "[client-$CLIENT_ID] PCAP : $PCAP_FILE"
echo "[client-$CLIENT_ID] LOG  : $LOG_FILE"
echo "[client-$CLIENT_ID] =========================================================="
