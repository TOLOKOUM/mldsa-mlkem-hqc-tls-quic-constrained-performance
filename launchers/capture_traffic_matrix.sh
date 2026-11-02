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
# HARMONISATION AVEC LA CAMPAGNE (critique 4 de l'AE, TDSC-2026-09-3862) :
#   TLS  : openssl s_connection -new -verify 1 ... -www /payload.bin (comme
#          perftestClientTlsQuic.sh ; ce n'est PLUS openssl s_client + "Q") =>
#          meme echange applicatif de 100 octets que QUIC, meme fermeture (RST).
#          Cles : -keylogfile du SERVEUR (s_connection n'en a pas).
#   QUIC : quics_connection (100 octets), cles via SSLKEYLOGFILE cote client.
#   Environnement noyau identique au Launcher : MTU, offloads coupes, sysctl TCP
#   d'isolation, tcpdump filtre "port 4433" (+ -U), serveur -num_tickets 0.
#   Une connexion n'est comptee que si elle satisfait le critere de succes
#   COMMUN de la campagne (App-ready numerique ET App-bytes = 100).
#   Fichier d'audit par combo : <base>.meta.txt (conditions + sortie du client).
#
# Usage: ./capture_traffic_matrix.sh [tls|quic|both] [single|mutual]
#   Par défaut : both (tls+quic), single
#   Variables : MTU (1500), OFFLOAD_OFF (1), TCP_ISOLATE (1), HANDSHAKE_TIMEOUT_S (150)

PROTOCOLS_ARG="${1:-both}"
AUTH_MODE="${2:-single}"
IMAGE=uma-tls-quic-pq-34
OQS_SERVER="servidor"
OQS_CLIENT="cliente"
MUTUAL_AUTHENTICATION=false
[[ "$AUTH_MODE" == "mutual" ]] && MUTUAL_AUTHENTICATION=true
NETIF="eth0"
MTU="${MTU:-1500}"
OFFLOAD_OFF="${OFFLOAD_OFF:-1}"
TCP_ISOLATE="${TCP_ISOLATE:-1}"
HANDSHAKE_TIMEOUT_S="${HANDSHAKE_TIMEOUT_S:-150}"

[[ "$AUTH_MODE" == "single" || "$AUTH_MODE" == "mutual" ]] || { echo "auth: single|mutual"; exit 1; }
[[ "$PROTOCOLS_ARG" == "tls" || "$PROTOCOLS_ARG" == "quic" || "$PROTOCOLS_ARG" == "both" ]] || { echo "protocole: tls|quic|both"; exit 1; }
if [[ "$AUTH_MODE" == "mutual" && "$PROTOCOLS_ARG" == "quic" ]]; then
    echo "QUIC + mutual non supporte (limitation MsQuic documentee) : utilisez 'tls' avec 'mutual'."
    exit 1
fi
if [[ "$AUTH_MODE" == "mutual" && "$PROTOCOLS_ARG" == "both" ]]; then
    echo "[i] QUIC + mutual non supporte (MsQuic) : seul TLS est capture en mode mutual."
    PROTOCOLS_ARG="tls"
fi
[[ "$MTU" =~ ^[0-9]+$ ]] && (( MTU >= 576 && MTU <= 9000 )) || { echo "Invalid MTU: entier entre 576 et 9000."; exit 1; }
for _v in OFFLOAD_OFF TCP_ISOLATE; do
    [[ "${!_v}" == "0" || "${!_v}" == "1" ]] || { echo "Invalid $_v: 0 ou 1."; exit 1; }
done
[[ "$HANDSHAKE_TIMEOUT_S" =~ ^[0-9]+$ ]] && (( HANDSHAKE_TIMEOUT_S >= 1 )) || { echo "Invalid HANDSHAKE_TIMEOUT_S: entier >= 1."; exit 1; }
if [[ "$TCP_ISOLATE" == "1" ]]; then
    TCP_SYSCTLS=(--sysctl net.ipv4.tcp_no_metrics_save=1 --sysctl net.ipv4.tcp_syn_retries=8)
else
    TCP_SYSCTLS=()
fi

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

# ── Aides (equivalents de celles du Launcher) : renvoient 1 au lieu de quitter,
#    pour qu'une combo en echec n'interrompe pas toute la matrice. ────────────
prep_container() {   # container
    local c="$1" nm sr
    docker exec "$c" ip link set dev "$NETIF" mtu "$MTU" >/dev/null 2>&1 || { echo "MTU: echec sur $c" >&2; return 1; }
    docker exec "$c" ip link show dev "$NETIF" 2>/dev/null | grep -q "mtu ${MTU} " || { echo "MTU=$MTU non confirme sur $c" >&2; return 1; }
    if [[ "$OFFLOAD_OFF" == "1" ]]; then
        docker exec "$c" sh -c 'command -v ethtool >/dev/null 2>&1' || { echo "ethtool absent de l'image sur $c" >&2; return 1; }
        docker exec "$c" ethtool -K "$NETIF" tso off gso off gro off >/dev/null 2>&1 || { echo "offloads: echec sur $c" >&2; return 1; }
        # Offloads UDP (MsQuic = UDP_SEGMENT) : sinon super-trames > MTU dans le pcap QUIC.
        local f
        for f in tx-udp-segmentation rx-udp-gro-forwarding rx-gro-list; do
            docker exec "$c" ethtool -K "$NETIF" "$f" off >/dev/null 2>&1 || true
        done
        if docker exec "$c" ethtool -k "$NETIF" 2>/dev/null \
             | grep -E '^(tcp-segmentation-offload|generic-segmentation-offload|generic-receive-offload|tx-udp-segmentation|rx-udp-gro-forwarding|rx-gro-list):' | grep ': on' | grep -v '\[fixed\]' | grep -q .; then
            echo "offload encore actif sur $c" >&2; return 1
        fi
    fi
    if [[ "$TCP_ISOLATE" == "1" ]]; then
        nm=$(docker exec "$c" cat /proc/sys/net/ipv4/tcp_no_metrics_save 2>/dev/null | tr -d '\r\n' || true)
        sr=$(docker exec "$c" cat /proc/sys/net/ipv4/tcp_syn_retries 2>/dev/null | tr -d '\r\n' || true)
        [[ "$nm" == "1" && "$sr" == "8" ]] || { echo "isolation TCP non active sur $c (nm='$nm' sr='$sr')" >&2; return 1; }
    fi
    return 0
}

capture_one() {
    local protocol="$1" sig_alg="$2" kem="$3"
    local use_tls=$([[ "$protocol" == "tls" ]] && echo true || echo false)
    local out_dir="$OUT_ROOT/$protocol"
    mkdir -p "$out_dir"
    local base_name="${protocol}_${AUTH_MODE}_${sig_alg}_${kem}"
    local pcap_path="$out_dir/${base_name}.pcap"
    local keylog_path="$out_dir/${base_name}_sslkeys.log"
    local meta_path="$out_dir/${base_name}.meta.txt"
    local srv_keylog="/tmp/sslkeys_server_${sig_alg}_${kem}.log"
    rm -f "$pcap_path" "$keylog_path" "$meta_path"

    cleaning
    # TLS : SSL_DIR=/tmp => s_server ecrit son keylog dans $srv_keylog.
    local srv_ssl_env=()
    [[ "$use_tls" == "true" ]] && srv_ssl_env=(-e SSL_DIR=/tmp)
    docker run --cap-add=NET_ADMIN --name $OQS_SERVER --network localNet -v cert:/cert \
        ${TCP_SYSCTLS[@]+"${TCP_SYSCTLS[@]}"} \
        -e TC_DELAY=0ms -e TC_LOSS=0% -e CERT_PATH=/cert/ -e KEM_ALG=$kem -e DEFAULT_GROUPS=$kem \
        -e SIG_ALG=$sig_alg -e USE_TLS=$use_tls -e MUTUAL=$MUTUAL_AUTHENTICATION \
        ${srv_ssl_env[@]+"${srv_ssl_env[@]}"} \
        -d $IMAGE perftestServerTlsQuic.sh >/dev/null 2>&1
    sleep 3
    local ip
    ip=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $OQS_SERVER 2>/dev/null)
    if [ -z "$ip" ]; then
        echo "    [!] Serveur non démarré (SIG_ALG=$sig_alg KEM=$kem) — combo sautée."
        return 1
    fi
    prep_container $OQS_SERVER || return 1

    docker create --cap-add=NET_ADMIN --network localNet --name $OQS_CLIENT -v cert:/cert \
        ${TCP_SYSCTLS[@]+"${TCP_SYSCTLS[@]}"} \
        -e DOCKER_HOST="$ip" -e CERT_PATH=/cert/ -e KEM_ALG=$kem -e DEFAULT_GROUPS=$kem \
        -e SIG_ALG=$sig_alg -e USE_TLS=$use_tls "$IMAGE" sleep infinity >/dev/null 2>&1
    docker start $OQS_CLIENT >/dev/null 2>&1
    sleep 1
    prep_container $OQS_CLIENT || return 1

    docker exec -d $OQS_CLIENT sh -c "env -u LD_LIBRARY_PATH tcpdump -i $NETIF -U -n -w /tmp/capture.pcap 'port 4433' 2>/tmp/tcpdump.log"
    local ready=false w
    for w in $(seq 1 50); do
        if docker exec $OQS_CLIENT sh -c "grep -q 'listening on' /tmp/tcpdump.log" 2>/dev/null; then ready=true; break; fi
        sleep 0.1
    done
    if [ "$ready" != "true" ]; then echo "    [!] tcpdump n'a pas demarre — combo sautee."; return 1; fi
    sleep 0.3

    local conn_out="" conn_rc=0
    if [ "$use_tls" = "true" ]; then
        local cert_args=""
        [ "$AUTH_MODE" = "mutual" ] && cert_args="-cert \$CERT_PATH/user.crt -key \$CERT_PATH/user.key"
        conn_out=$(docker exec $OQS_CLIENT sh -c \
            "timeout ${HANDSHAKE_TIMEOUT_S}s openssl s_connection -connect \$DOCKER_HOST:4433 -new -verify 1 \
                -CAfile \$CERT_PATH/CA.crt $cert_args -www /payload.bin 2>&1") || conn_rc=$?
    else
        conn_out=$(docker exec $OQS_CLIENT sh -c \
            "export SSLKEYLOGFILE=/tmp/sslkeys.log; \
             timeout ${HANDSHAKE_TIMEOUT_S}s quics_connection -groups:\$KEM_ALG -target:\$DOCKER_HOST -CAfile:\$CERT_PATH/CA.crt 2>&1") || conn_rc=$?
    fi

    # Critere de succes COMMUN (celui de la campagne).
    local hs_ms app_ms app_bytes conn_ok=true
    hs_ms=$(sed -n 's/^Handshake duration: \([0-9][0-9.]*\) ms.*/\1/p' <<< "$conn_out" | head -1)
    app_ms=$(sed -n 's/^App-ready duration: \([0-9][0-9.]*\) ms.*/\1/p' <<< "$conn_out" | head -1)
    app_bytes=$(sed -n 's/^App-bytes: \([0-9][0-9]*\)[[:space:]]*$/\1/p' <<< "$conn_out" | head -1)
    if [[ "$conn_rc" -ne 0 || -z "$app_ms" || "$app_bytes" != "100" ]]; then conn_ok=false; fi

    sleep 1   # derniers paquets (ACK final, RST / CONNECTION_CLOSE)
    docker exec $OQS_CLIENT sh -c "pkill -TERM tcpdump" >/dev/null 2>&1 || true
    for w in $(seq 1 50); do
        if docker exec $OQS_CLIENT sh -c "grep -q 'packets captured' /tmp/tcpdump.log" 2>/dev/null; then break; fi
        sleep 0.1
    done
    local summary dropped
    summary=$(docker exec $OQS_CLIENT sh -c "grep -E 'packets (captured|received by filter|dropped by kernel)' /tmp/tcpdump.log" 2>/dev/null || true)
    dropped=$(sed -n 's/^\([0-9][0-9]*\) packets dropped by kernel.*/\1/p' <<< "$summary" | head -1)
    local cap_ok=true
    if [[ -z "$dropped" || "$dropped" != "0" ]]; then cap_ok=false; fi
    # Trames > MTU+14 = super-trames GSO/GRO encore actives => capture non fiable.
    local oversize
    oversize=$(docker exec $OQS_CLIENT sh -c "env -u LD_LIBRARY_PATH tcpdump -nn -r /tmp/capture.pcap 'greater $((MTU + 15))' 2>/dev/null | wc -l" 2>/dev/null | tr -d '\r\n' || true)
    if ! [[ "$oversize" =~ ^[0-9]+$ ]] || [[ "$oversize" != "0" ]]; then cap_ok=false; fi

    docker cp "$OQS_CLIENT:/tmp/capture.pcap" "$pcap_path" >/dev/null 2>&1
    local keylog_ok=false
    if [ "$use_tls" = "true" ]; then
        if docker exec $OQS_SERVER sh -c "[ -s $srv_keylog ]" 2>/dev/null; then
            docker cp "$OQS_SERVER:$srv_keylog" "$keylog_path" >/dev/null 2>&1 && keylog_ok=true
        fi
    else
        if docker exec $OQS_CLIENT sh -c "[ -s /tmp/sslkeys.log ]" 2>/dev/null; then
            docker cp "$OQS_CLIENT:/tmp/sslkeys.log" "$keylog_path" >/dev/null 2>&1 && keylog_ok=true
        fi
    fi

    {
        echo "protocol=$protocol auth=$AUTH_MODE sig=$sig_alg kem=$kem"
        echo "mtu=$MTU offload_off=$OFFLOAD_OFF tcp_isolate=$TCP_ISOLATE handshake_timeout_s=$HANDSHAKE_TIMEOUT_S"
        echo "server_ip=$ip conn_ok=$conn_ok capture_ok=$cap_ok keylog_ok=$keylog_ok client_rc=$conn_rc"
        echo "handshake_ms=${hs_ms:-NaN} app_ready_ms=${app_ms:-NaN} app_bytes=${app_bytes:-NA} tcpdump_dropped_by_kernel=${dropped:-NA} oversize_frames=${oversize:-NA}"
        echo "--- sortie du client ---"
        echo "$conn_out"
    } > "$meta_path"

    if [ "$conn_ok" = "true" ] && [ "$cap_ok" = "true" ] && [ -s "$pcap_path" ]; then
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
