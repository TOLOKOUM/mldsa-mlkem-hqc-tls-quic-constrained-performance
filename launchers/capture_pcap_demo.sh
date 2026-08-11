#!/usr/bin/env bash
set -uo pipefail
#
# capture_pcap_demo.sh — Capture pcap + fichier de clés SSL/TLS de LA MÊME
# connexion, prêts à ouvrir/déchiffrer ensemble dans Wireshark.
#
# TLS : utilise openssl s_client standard (PAS s_connection custom) avec son
# option officielle -keylogfile, documentée et stable — pas besoin de deviner
# si le binaire custom la supporte.
# QUIC : utilise quics_connection avec SSLKEYLOGFILE (méthode déjà confirmée
# dans perftestClientTlsQuic.sh).
#
# Usage: ./capture_pcap_demo.sh [tls|quic] [SIG_ALG] [KEM_ALG]

PROTOCOL="${1:-tls}"
SIG_ALG="${2:-mldsa65}"
KEM_ALG="${3:-p384_mlkem768}"
IMAGE=uma-tls-quic-pq-34
OQS_SERVER="servidor"
OQS_CLIENT="cliente"
USE_TLS=$([[ "$PROTOCOL" == "tls" ]] && echo true || echo false)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PCAP_DIR="$SCRIPT_DIR/captures/pcap_demo"
mkdir -p "$PCAP_DIR"
TS="$(date +%Y%m%d_%H%M%S)"
BASE_NAME="capture_${PROTOCOL}_${SIG_ALG}_${KEM_ALG}_${TS}"
PCAP_NAME="${BASE_NAME}.pcap"
KEYLOG_NAME="${BASE_NAME}_sslkeys.log"

cleaning() {
    docker kill $OQS_SERVER $OQS_CLIENT &>/dev/null || true
    docker rm -f $OQS_SERVER $OQS_CLIENT &>/dev/null || true
    docker container prune -f >/dev/null 2>&1 || true
    docker volume rm cert &>/dev/null || true
    docker network rm localNet &>/dev/null || true
}
trap cleaning EXIT

cleaning
docker network create localNet >/dev/null 2>&1 || true
docker volume create cert >/dev/null 2>&1 || true

echo "==> Certs..."
docker run --rm -v cert:/cert -e CERT_PATH=/cert/ -e SIG_ALG=$SIG_ALG -i "$IMAGE" doCert.sh >/dev/null

echo "==> Démarrage serveur ($PROTOCOL, single)..."
docker run --cap-add=NET_ADMIN --name $OQS_SERVER --network localNet -v cert:/cert \
    -e TC_DELAY=0ms -e TC_LOSS=0% -e CERT_PATH=/cert/ -e KEM_ALG=$KEM_ALG -e DEFAULT_GROUPS=$KEM_ALG \
    -e SIG_ALG=$SIG_ALG -e USE_TLS=$USE_TLS -e MUTUAL=false -d $IMAGE perftestServerTlsQuic.sh >/dev/null
sleep 3
IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $OQS_SERVER)
echo "    Server IP: $IP"

docker create --cap-add=NET_ADMIN --network localNet --name $OQS_CLIENT -v cert:/cert \
    -e DOCKER_HOST="$IP" -e CERT_PATH=/cert/ -e KEM_ALG=$KEM_ALG -e DEFAULT_GROUPS=$KEM_ALG \
    -e SIG_ALG=$SIG_ALG -e USE_TLS=$USE_TLS "$IMAGE" sleep infinity >/dev/null
docker start $OQS_CLIENT >/dev/null
sleep 1

echo "==> Démarrage de tcpdump dans le conteneur client (capture eth0, en arrière-plan)..."
docker exec -d $OQS_CLIENT sh -c "tcpdump -i eth0 -w /tmp/capture.pcap 2>/tmp/tcpdump.log"
sleep 1   # laisser tcpdump s'attacher avant la connexion

echo "==> Connexion de test (avec export des clés de session)..."
if [ "$USE_TLS" = "true" ]; then
    docker exec $OQS_CLIENT sh -c \
        "{ sleep 0.3; printf 'Q\n'; } | openssl s_client -connect \$DOCKER_HOST:4433 -tls1_3 \
            -groups \$KEM_ALG -CAfile \$CERT_PATH/CA.crt -keylogfile /tmp/sslkeys.log -state 2>&1"
else
    docker exec $OQS_CLIENT sh -c \
        "export SSLKEYLOGFILE=/tmp/sslkeys.log; \
         quics_connection -groups:\$KEM_ALG -target:\$DOCKER_HOST -CAfile:\$CERT_PATH/CA.crt"
fi

sleep 1
echo "==> Arrêt de tcpdump..."
docker exec $OQS_CLIENT sh -c "pkill tcpdump" || true
sleep 1

echo "==> Récupération du .pcap et du fichier de clés sur l'hôte..."
docker cp "$OQS_CLIENT:/tmp/capture.pcap" "$PCAP_DIR/$PCAP_NAME"
if docker exec $OQS_CLIENT sh -c "[ -s /tmp/sslkeys.log ]"; then
    docker cp "$OQS_CLIENT:/tmp/sslkeys.log" "$PCAP_DIR/$KEYLOG_NAME"
    KEYLOG_OK=true
else
    echo "  [!] Aucune clé exportée (fichier vide ou absent) — le pcap restera chiffré dans Wireshark."
    KEYLOG_OK=false
fi

echo ""
echo "=================================================="
echo " Capture : $PCAP_DIR/$PCAP_NAME"
if [ "$KEYLOG_OK" = "true" ]; then
    echo " Clés    : $PCAP_DIR/$KEYLOG_NAME"
    echo ""
    echo " Pour déchiffrer dans Wireshark :"
    echo "   1. Fichier > Ouvrir > $PCAP_NAME"
    echo "   2. Édition > Préférences > Protocols > TLS >"
    echo "      (Pre)-Master-Secret log filename > sélectionne $KEYLOG_NAME"
fi
echo "=================================================="
