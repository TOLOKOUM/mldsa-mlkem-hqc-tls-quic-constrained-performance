#!/usr/bin/env bash
set -uo pipefail
#
# capture_traffic_matrix.sh — Capture pcap + clés de session pour UNE connexion
# par combinaison SIG_ALG/KEM (toute la matrice, comme Launcher_pq_mldsa_mlkem_hqc.sh
# KEM_FAMILY=both), pour ensuite extraire la métrique "taille du trafic" via
# parse_traffic_size.py. Une seule connexion par combo (pas 500) : on ne
# cherche pas de distribution statistique, juste la taille des messages
# handshake, qui est déterministe pour une combinaison SIG_ALG/KEM donnée.
#
# Usage: ./capture_traffic_matrix.sh [tls|quic|both] [single|mutual]
#   Par défaut : both (tls+quic), single

PROTOCOLS_ARG="${1:-both}"
AUTH_MODE="${2:-single}"
IMAGE=uma-tls-quic-pq-34
OQS_SERVER="servidor"
OQS_CLIENT="cliente"
MUTUAL_AUTHENTICATION=false
[[ "$AUTH_MODE" == "mutual" ]] && MUTUAL_AUTHENTICATION=true

if [[ "$PROTOCOLS_ARG" == "both" ]]; then
    PROTOCOLS=("tls" "quic")
else
    PROTOCOLS=("$PROTOCOLS_ARG")
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_ROOT="$SCRIPT_DIR/captures/traffic_size"

# ── Mêmes listes que Launcher_pq_mldsa_mlkem_hqc.sh, KEM_FAMILY=both ──────────
SUPPORTED_SIG_ALGS=("ed25519" "secp384r1" "secp521r1" "mldsa44" "mldsa65" "mldsa87")
CLASSICAL_L1=("P-256" "x25519"); CLASSICAL_L3=("P-384" "x448"); CLASSICAL_L5=("P-521")
MLKEM_L1=("p256_mlkem512" "x25519_mlkem512" "mlkem512")
MLKEM_L3=("p384_mlkem768" "x448_mlkem768" "mlkem768")
MLKEM_L5=("p521_mlkem1024" "mlkem1024")
HQC_L1=("hqc128" "p256_hqc128" "x25519_hqc128")
HQC_L3=("hqc192" "p384_hqc192" "x448_hqc192")
HQC_L5=("hqc256" "p521_hqc256")
KEMS_L1=("${CLASSICAL_L1[@]}" "${MLKEM_L1[@]}" "${HQC_L1[@]}")
KEMS_L3=("${CLASSICAL_L3[@]}" "${MLKEM_L3[@]}" "${HQC_L3[@]}")
KEMS_L5=("${CLASSICAL_L5[@]}" "${MLKEM_L5[@]}" "${HQC_L5[@]}")

cleaning() {
    docker kill $OQS_SERVER $OQS_CLIENT &>/dev/null || true
    docker rm -f $OQS_SERVER $OQS_CLIENT &>/dev/null || true
}

n_ok=0
n_fail=0
FAILED_COMBOS=()

capture_one() {
    local protocol="$1" sig_alg="$2" kem="$3"
    local use_tls=$([[ "$protocol" == "tls" ]] && echo true || echo false)
    local out_dir="$OUT_ROOT/$protocol"
    mkdir -p "$out_dir"
    local base_name="${protocol}_${AUTH_MODE}_${sig_alg}_${kem}"
    local pcap_path="$out_dir/${base_name}.pcap"
    local keylog_path="$out_dir/${base_name}_sslkeys.log"

    cleaning
    docker run --cap-add=NET_ADMIN --name $OQS_SERVER --network localNet -v cert:/cert \
        -e TC_DELAY=0ms -e TC_LOSS=0% -e CERT_PATH=/cert/ -e KEM_ALG=$kem -e DEFAULT_GROUPS=$kem \
        -e SIG_ALG=$sig_alg -e USE_TLS=$use_tls -e MUTUAL=$MUTUAL_AUTHENTICATION \
        -d $IMAGE perftestServerTlsQuic.sh >/dev/null 2>&1
    sleep 3
    local ip
    ip=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $OQS_SERVER 2>/dev/null)
    if [ -z "$ip" ]; then
        echo "    [!] Serveur non démarré (SIG_ALG=$sig_alg KEM=$kem) — combo sautée."
        return 1
    fi

    docker create --cap-add=NET_ADMIN --network localNet --name $OQS_CLIENT -v cert:/cert \
        -e DOCKER_HOST="$ip" -e CERT_PATH=/cert/ -e KEM_ALG=$kem -e DEFAULT_GROUPS=$kem \
        -e SIG_ALG=$sig_alg -e USE_TLS=$use_tls "$IMAGE" sleep infinity >/dev/null 2>&1
    docker start $OQS_CLIENT >/dev/null 2>&1
    sleep 1

    docker exec -d $OQS_CLIENT sh -c "tcpdump -i eth0 -w /tmp/capture.pcap 2>/tmp/tcpdump.log"
    sleep 1

    local conn_ok=true
    if [ "$use_tls" = "true" ]; then
        if [ "$AUTH_MODE" = "mutual" ]; then
            docker exec $OQS_CLIENT sh -c \
                "{ sleep 0.3; printf 'Q\n'; } | openssl s_client -connect \$DOCKER_HOST:4433 -tls1_3 \
                    -groups \$KEM_ALG -CAfile \$CERT_PATH/CA.crt -cert \$CERT_PATH/user.crt -key \$CERT_PATH/user.key \
                    -keylogfile /tmp/sslkeys.log" >/dev/null 2>&1 || conn_ok=false
        else
            docker exec $OQS_CLIENT sh -c \
                "{ sleep 0.3; printf 'Q\n'; } | openssl s_client -connect \$DOCKER_HOST:4433 -tls1_3 \
                    -groups \$KEM_ALG -CAfile \$CERT_PATH/CA.crt -keylogfile /tmp/sslkeys.log" >/dev/null 2>&1 || conn_ok=false
        fi
    else
        docker exec $OQS_CLIENT sh -c \
            "export SSLKEYLOGFILE=/tmp/sslkeys.log; \
             quics_connection -groups:\$KEM_ALG -target:\$DOCKER_HOST -CAfile:\$CERT_PATH/CA.crt" >/dev/null 2>&1 || conn_ok=false
    fi

    sleep 1
    docker exec $OQS_CLIENT sh -c "pkill tcpdump" >/dev/null 2>&1 || true
    sleep 1

    docker cp "$OQS_CLIENT:/tmp/capture.pcap" "$pcap_path" >/dev/null 2>&1
    if docker exec $OQS_CLIENT sh -c "[ -s /tmp/sslkeys.log ]" 2>/dev/null; then
        docker cp "$OQS_CLIENT:/tmp/sslkeys.log" "$keylog_path" >/dev/null 2>&1
    fi

    if [ "$conn_ok" = "true" ] && [ -s "$pcap_path" ]; then
        return 0
    else
        return 1
    fi
}

echo "*************************************"
echo " Capture matrice trafic — protocoles: ${PROTOCOLS[*]} | auth: $AUTH_MODE"
echo " Sortie : $OUT_ROOT/<protocol>/"
echo "*************************************"

cleaning
docker network inspect localNet >/dev/null 2>&1 || docker network create localNet >/dev/null
docker volume inspect cert >/dev/null 2>&1 || docker volume create cert >/dev/null

for PROTOCOL in "${PROTOCOLS[@]}"; do
    for SIG_ALG in "${SUPPORTED_SIG_ALGS[@]}"; do
        case "$SIG_ALG" in
            ed25519|mldsa44) KEMS=("${KEMS_L1[@]}") ;;
            secp384r1|mldsa65) KEMS=("${KEMS_L3[@]}") ;;
            secp521r1|mldsa87) KEMS=("${KEMS_L5[@]}") ;;
        esac

        echo ""
        echo "==> [$PROTOCOL] Certs pour SIG_ALG=$SIG_ALG"
        docker run --rm -v cert:/cert -e CERT_PATH=/cert/ -e SIG_ALG=$SIG_ALG -i "$IMAGE" doCert.sh >/dev/null 2>&1

        for KEM in "${KEMS[@]}"; do
            printf "    [%s] %-10s / %-20s ... " "$PROTOCOL" "$SIG_ALG" "$KEM"
            if capture_one "$PROTOCOL" "$SIG_ALG" "$KEM"; then
                echo "OK"
                n_ok=$((n_ok + 1))
            else
                echo "ÉCHEC"
                n_fail=$((n_fail + 1))
                FAILED_COMBOS+=("$PROTOCOL/$SIG_ALG/$KEM")
            fi
        done
    done
done

cleaning
docker volume rm cert &>/dev/null || true
docker network rm localNet &>/dev/null || true

echo ""
echo "*************************************"
echo " Terminé : $n_ok réussies, $n_fail échouées"
if [ "$n_fail" -gt 0 ]; then
    echo " Combos en échec :"
    for c in "${FAILED_COMBOS[@]}"; do echo "   - $c"; done
fi
echo " Fichiers dans : $OUT_ROOT/"
echo " Prochaine étape : python3 parse_traffic_size.py --input-dir $OUT_ROOT --out-dir results_traffic_size"
echo "*************************************"
