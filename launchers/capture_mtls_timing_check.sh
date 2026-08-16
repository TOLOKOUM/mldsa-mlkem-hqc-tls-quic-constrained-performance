#!/usr/bin/env bash
set -uo pipefail
#
# capture_mtls_timing_check.sh — Capture single ET mutual pour une seule
# configuration (mldsa44+P-256, L1, réseau idéal) afin de localiser, via les
# timestamps de paquets, où se situe le surcoût mTLS x14 documenté en §5.6 :
# côté client (avant envoi), sur le réseau (gap entre paquets), ou côté
# serveur (avant réponse). Dérivé de capture_one() dans
# launchers/capture_traffic_matrix.sh — ne modifie ni ce script ni
# captures/traffic_size/.
#
# Usage: ./capture_mtls_timing_check.sh

IMAGE=uma-tls-quic-pq-34
OQS_SERVER="servidor"
OQS_CLIENT="cliente"
SIG_ALG="mldsa44"
KEM="P-256"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="$SCRIPT_DIR/captures/mtls_timing_check"
mkdir -p "$OUT_DIR"

cleaning() {
    docker kill $OQS_SERVER $OQS_CLIENT &>/dev/null || true
    docker rm -f $OQS_SERVER $OQS_CLIENT &>/dev/null || true
}

capture_one() {
    local auth_mode="$1"
    local mutual_auth=false
    [[ "$auth_mode" == "mutual" ]] && mutual_auth=true
    local base_name="tls_${auth_mode}_${SIG_ALG}_${KEM}"
    local pcap_path="$OUT_DIR/${base_name}.pcap"

    cleaning
    docker run --cap-add=NET_ADMIN --name $OQS_SERVER --network localNet -v cert:/cert \
        -e TC_DELAY=0ms -e TC_LOSS=0% -e CERT_PATH=/cert/ -e KEM_ALG=$KEM -e DEFAULT_GROUPS=$KEM \
        -e SIG_ALG=$SIG_ALG -e USE_TLS=true -e MUTUAL=$mutual_auth \
        -d $IMAGE perftestServerTlsQuic.sh >/dev/null 2>&1
    sleep 3
    local ip
    ip=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $OQS_SERVER 2>/dev/null)
    if [ -z "$ip" ]; then
        echo "    [!] Serveur non démarré — combo sautée."
        return 1
    fi

    docker create --cap-add=NET_ADMIN --network localNet --name $OQS_CLIENT -v cert:/cert \
        -e DOCKER_HOST="$ip" -e CERT_PATH=/cert/ -e KEM_ALG=$KEM -e DEFAULT_GROUPS=$KEM \
        -e SIG_ALG=$SIG_ALG -e USE_TLS=true "$IMAGE" sleep infinity >/dev/null 2>&1
    docker start $OQS_CLIENT >/dev/null 2>&1
    sleep 1

    # -tt : timestamp haute résolution par paquet (nécessaire pour localiser
    # le surcoût). Capturé côté client pour voir la vue "temps client".
    docker exec -d $OQS_CLIENT sh -c "tcpdump -i eth0 -tt -w /tmp/capture.pcap 2>/tmp/tcpdump.log"
    sleep 1

    local conn_ok=true
    if [ "$auth_mode" = "mutual" ]; then
        docker exec $OQS_CLIENT sh -c \
            "{ sleep 0.3; printf 'Q\n'; } | openssl s_connection -connect \$DOCKER_HOST:4433 -new -verify 1 \
                -CAfile \$CERT_PATH/CA.crt -cert \$CERT_PATH/user.crt -key \$CERT_PATH/user.key" \
            > "$OUT_DIR/${base_name}_stdout.log" 2>&1 || conn_ok=false
    else
        docker exec $OQS_CLIENT sh -c \
            "{ sleep 0.3; printf 'Q\n'; } | openssl s_connection -connect \$DOCKER_HOST:4433 -new -verify 1 \
                -CAfile \$CERT_PATH/CA.crt" \
            > "$OUT_DIR/${base_name}_stdout.log" 2>&1 || conn_ok=false
    fi

    sleep 1
    docker exec $OQS_CLIENT sh -c "pkill tcpdump" >/dev/null 2>&1 || true
    sleep 1

    docker cp "$OQS_CLIENT:/tmp/capture.pcap" "$pcap_path" >/dev/null 2>&1
    # Pas de keylog : on lit les métadonnées TLS non déchiffrées
    # (tls.record.content_type / tls.record.length), suffisantes pour
    # localiser un écart de timing sans avoir besoin du contenu en clair.

    if [ "$conn_ok" = "true" ] && [ -s "$pcap_path" ]; then
        echo "    OK -> $pcap_path"
        return 0
    else
        echo "    ECHEC (voir $OUT_DIR/${base_name}_stdout.log)"
        return 1
    fi
}

echo "*************************************"
echo " Capture timing single vs mutual — ${SIG_ALG}/${KEM}, L1, ideal"
echo " Sortie : $OUT_DIR/"
echo "*************************************"

cleaning
docker network inspect localNet >/dev/null 2>&1 || docker network create localNet >/dev/null
docker volume inspect cert >/dev/null 2>&1 || docker volume create cert >/dev/null
docker run --rm -v cert:/cert -e CERT_PATH=/cert/ -e SIG_ALG=$SIG_ALG -i "$IMAGE" doCert.sh >/dev/null 2>&1

echo ""
echo "=== single ==="
capture_one "single"
echo ""
echo "=== mutual ==="
capture_one "mutual"

cleaning
docker volume rm cert &>/dev/null || true
docker network rm localNet &>/dev/null || true

echo ""
echo "*************************************"
echo " Terminé. Prochaine étape, pour chaque pcap :"
echo "   tshark -r $OUT_DIR/tls_single_${SIG_ALG}_${KEM}.pcap \\"
echo "     -Y tls -T fields -e frame.number -e frame.time_relative -e frame.len \\"
echo "     -e tls.record.content_type -e tls.record.length -e tcp.srcport"
echo "   (idem en remplaçant single par mutual)"
echo "*************************************"
