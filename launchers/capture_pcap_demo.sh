#!/usr/bin/env bash
###############################################################################
# capture_pcap_demo.sh — Capture pcap + fichier de clés SSL/TLS de LA MÊME
# connexion, prêts à ouvrir/déchiffrer ensemble dans Wireshark.
#
# NON-INTERACTIF (contrairement au mode capture/captureKey du launcher
# principal) : utilise tcpdump directement dans le conteneur au lieu
# d'ouvrir une session Wireshark GUI -- peut donc être bouclé sur plusieurs
# combinaisons sans surveillance.
#
# HARMONISATION AVEC LA CAMPAGNE (critique 4 de l'AE, TDSC-2026-09-3862) :
# la capture reproduit EXACTEMENT la connexion mesurée par la campagne, pour que
# "taille du trafic" et "latence" décrivent la MEME opération :
#   TLS   : openssl s_connection -new -verify 1 ... -www /payload.bin
#           (échange applicatif de 100 octets, fermeture RST via SO_LINGER=0,
#           comme perftestClientTlsQuic.sh ; ce n'est PLUS openssl s_client).
#           Clés : -keylogfile du SERVEUR (s_server), seul côté qui l'expose
#           (s_connection n'a pas d'option de keylog) -> déchiffrement
#           complet possible dans Wireshark.
#   QUIC  : quics_connection (100 octets applicatifs) avec SSLKEYLOGFILE.
# Environnement noyau identique au Launcher : MTU, offloads TSO/GSO/GRO coupés
# (sinon le pcap montre des super-trames, pas des paquets), sysctl TCP
# d'isolation, tcpdump filtré "port 4433", serveur sans tickets (-num_tickets 0).
#
# Variables d'environnement : MTU (1500), OFFLOAD_OFF (1), TCP_ISOLATE (1),
#   HANDSHAKE_TIMEOUT_S (150, identique à la campagne).
#
# Usage:
#   ./capture_pcap_demo.sh [tls|quic] [SIG_ALG] [KEM_ALG] [single|mutual] \
#       [none|simple|delay-only|loss-only|stable|unstable] [loss-percent] [delay-ms]
#
# Exemples:
#   ./capture_pcap_demo.sh tls mldsa65 p384_mlkem768 single none
#   ./capture_pcap_demo.sh tls mldsa65 p384_mlkem768 mutual simple 1.3 62.51
#   ./capture_pcap_demo.sh quic mldsa44 mlkem512 single unstable
#
# NB QUIC + mutual : non supporté (limitation MsQuic documentée) -- refusé
# explicitement plus bas, comme dans le launcher principal.
#
# ARBORESCENCE DE SORTIE — un profil réseau = un dossier, jamais mélangés :
#   captures/pcap_demo/<profil_label>/<protocol>/<auth_mode>/*.pcap|*.log
###############################################################################
set -euo pipefail

PROTOCOL="${1:-tls}"
SIG_ALG="${2:-mldsa65}"
KEM_ALG="${3:-p384_mlkem768}"
AUTH_MODE="${4:-single}"
NETWORK_PROFILE="${5:-none}"
LOSS_PERC="${6:-0}"
DELAY_MS="${7:-0}"

MTU="${MTU:-1500}"
OFFLOAD_OFF="${OFFLOAD_OFF:-1}"
TCP_ISOLATE="${TCP_ISOLATE:-1}"
HANDSHAKE_TIMEOUT_S="${HANDSHAKE_TIMEOUT_S:-150}"

IMAGE=uma-tls-quic-pq-34
OQS_SERVER="servidor"
OQS_CLIENT="cliente"
NETIF="eth0"

USAGE="Usage: $0 [tls|quic] [SIG_ALG] [KEM_ALG] [single|mutual] [none|simple|delay-only|loss-only|stable|unstable] [loss-percent] [delay-ms]"

###############################################################################
#  Validation des paramètres (mêmes règles que Launcher_pq_mldsa_mlkem_hqc.sh)
###############################################################################

if [[ "$PROTOCOL" != "tls" && "$PROTOCOL" != "quic" ]]; then
    echo "Invalid protocol: must be 'tls' or 'quic'."
    echo "$USAGE"
    exit 1
fi

if [[ "$AUTH_MODE" != "mutual" && "$AUTH_MODE" != "single" ]]; then
    echo "Invalid auth mode: must be 'mutual' or 'single'."
    echo "$USAGE"
    exit 1
fi

if [[ "$PROTOCOL" == "quic" && "$AUTH_MODE" == "mutual" ]]; then
    echo "❌ QUIC + mutual non supporté (limitation MsQuic documentée -- cf. mémoire du projet)."
    echo "   Utilise 'single' pour QUIC, ou 'tls' pour tester le mode mutual."
    exit 1
fi

if [[ "$NETWORK_PROFILE" != "none" && "$NETWORK_PROFILE" != "simple" && \
      "$NETWORK_PROFILE" != "delay-only" && "$NETWORK_PROFILE" != "loss-only" && \
      "$NETWORK_PROFILE" != "stable" && "$NETWORK_PROFILE" != "unstable" ]]; then
    echo "Invalid network profile: must be 'none', 'simple', 'delay-only', 'loss-only', 'stable', or 'unstable'."
    echo "$USAGE"
    exit 1
fi

if ! [[ "$LOSS_PERC" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
    echo "Invalid loss-percent: must be a non-negative number (decimals allowed)."
    echo "$USAGE"
    exit 1
fi
LOSS_PERC_VALID=$(LC_ALL=C awk -v v="$LOSS_PERC" 'BEGIN{print (v>=0 && v<=100) ? "1":"0"}')
if [[ "$LOSS_PERC_VALID" != "1" ]]; then
    echo "Invalid loss-percent: must be between 0 and 100."
    echo "$USAGE"
    exit 1
fi

if ! [[ "$DELAY_MS" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
    echo "Invalid delay-ms: must be a non-negative number (decimals allowed)."
    echo "$USAGE"
    exit 1
fi
if ! [[ "$MTU" =~ ^[0-9]+$ ]] || (( MTU < 576 || MTU > 9000 )); then
    echo "Invalid MTU: entier entre 576 et 9000."
    exit 1
fi
for _v in OFFLOAD_OFF TCP_ISOLATE; do
    if [[ "${!_v}" != "0" && "${!_v}" != "1" ]]; then echo "Invalid $_v: 0 ou 1."; exit 1; fi
done
if ! [[ "$HANDSHAKE_TIMEOUT_S" =~ ^[0-9]+$ ]] || (( HANDSHAKE_TIMEOUT_S < 1 )); then
    echo "Invalid HANDSHAKE_TIMEOUT_S: entier >= 1."
    exit 1
fi
# Meme isolation TCP que Launcher_pq_mldsa_mlkem_hqc.sh (pas de cache tcp_metrics,
# abandon du connect() gouverne par le seul timeout externe).
if [[ "$TCP_ISOLATE" == "1" ]]; then
    TCP_SYSCTLS=(--sysctl net.ipv4.tcp_no_metrics_save=1 --sysctl net.ipv4.tcp_syn_retries=8)
else
    TCP_SYSCTLS=()
fi

# ── Label de dossier par profil réseau (jamais mélangés) ───────────────────
case "$NETWORK_PROFILE" in
    none)        NETWORK_PROFILE_LABEL="none" ;;
    simple)      NETWORK_PROFILE_LABEL="simple_loss${LOSS_PERC}_delay${DELAY_MS}ms" ;;
    delay-only)  NETWORK_PROFILE_LABEL="delayonly_delay${DELAY_MS}ms" ;;
    loss-only)   NETWORK_PROFILE_LABEL="lossonly_loss${LOSS_PERC}" ;;
    stable)      NETWORK_PROFILE_LABEL="stable" ;;
    unstable)    NETWORK_PROFILE_LABEL="unstable" ;;
esac

USE_TLS=$([[ "$PROTOCOL" == "tls" ]] && echo true || echo false)
MUTUAL_AUTHENTICATION=$([[ "$AUTH_MODE" == "mutual" ]] && echo true || echo false)

# ── Perfiles GE-model (mêmes valeurs que le launcher principal) ────────────
STABLE_GEMODEL=(10 50 70 10)    # pg10 pb50 h70 k10
UNSTABLE_GEMODEL=(20 40 90 20)  # pg20 pb40 h90 k20

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Arborescence de sortie : un dossier par profil réseau, jamais mélangé ──
PCAP_DIR="$SCRIPT_DIR/captures/pcap_demo/$NETWORK_PROFILE_LABEL/$PROTOCOL/$AUTH_MODE"
mkdir -p "$PCAP_DIR"

TS="$(date +%Y%m%d_%H%M%S)"
BASE_NAME="capture_${PROTOCOL}_${AUTH_MODE}_${SIG_ALG}_${KEM_ALG}_${NETWORK_PROFILE_LABEL}_${TS}"
PCAP_NAME="${BASE_NAME}.pcap"
KEYLOG_NAME="${BASE_NAME}_sslkeys.log"
META_NAME="${BASE_NAME}.meta.txt"     # (suffixe .txt : ne pas etre pris pour un keylog par un glob *.log)

echo "*************************************"
echo "  Protocol:        $PROTOCOL"
echo "  Auth Mode:        $AUTH_MODE"
echo "  SIG_ALG:          $SIG_ALG"
echo "  KEM_ALG:          $KEM_ALG"
echo "  Network Profile:  $NETWORK_PROFILE_LABEL"
echo "  Output dir:       $PCAP_DIR"
echo "*************************************"

###############################################################################
#  Nettoyage
###############################################################################

cleaning() {
    for pid in "${PUMBA_PID:-}"; do
        [[ -n "${pid:-}" ]] && kill -9 "$pid" &>/dev/null || true
    done
    docker kill $OQS_SERVER $OQS_CLIENT &>/dev/null || true
    docker rm -f $OQS_SERVER $OQS_CLIENT &>/dev/null || true
    docker container prune -f >/dev/null 2>&1 || true
    docker volume rm cert &>/dev/null || true
    docker network rm localNet &>/dev/null || true
}
trap cleaning EXIT

# ── Aides communes (equivalents de celles du Launcher) ─────────────────────
die() { echo "❌ ERREUR FATALE: $*" >&2; exit 1; }

set_mtu() {   # container
    docker exec "$1" ip link set dev "$NETIF" mtu "$MTU" || die "impossible de fixer MTU=$MTU sur $1."
    docker exec "$1" ip link show dev "$NETIF" | grep -q "mtu ${MTU} " || die "MTU=$MTU non confirme sur $1."
}

set_offloads() {   # container
    [[ "$OFFLOAD_OFF" == "1" ]] || return 0
    docker exec "$1" sh -c 'command -v ethtool >/dev/null 2>&1' || die "ethtool absent de l'image (reconstruire l'image) sur $1."
    docker exec "$1" ethtool -K "$NETIF" tso off gso off gro off >/dev/null 2>&1 || die "impossible de desactiver TSO/GSO/GRO sur $1."
    # Offloads UDP (MsQuic = UDP_SEGMENT) : sans eux le pcap QUIC contient des
    # super-trames > MTU. Tentes un par un (un nom inconnu ne doit pas bloquer les autres).
    for _f in tx-udp-segmentation rx-udp-gro-forwarding rx-gro-list; do
        docker exec "$1" ethtool -K "$NETIF" "$_f" off >/dev/null 2>&1 || true
    done
    if docker exec "$1" ethtool -k "$NETIF" 2>/dev/null \
         | grep -E '^(tcp-segmentation-offload|generic-segmentation-offload|generic-receive-offload|tx-udp-segmentation|rx-udp-gro-forwarding|rx-gro-list):' | grep ': on' | grep -v '\[fixed\]' | grep -q .; then
        die "offload encore actif sur $1 apres desactivation."
    fi
}

check_tcp_isolation() {   # container
    [[ "$TCP_ISOLATE" == "1" ]] || return 0
    local nm sr
    nm=$(docker exec "$1" cat /proc/sys/net/ipv4/tcp_no_metrics_save 2>/dev/null | tr -d '\r\n' || true)
    sr=$(docker exec "$1" cat /proc/sys/net/ipv4/tcp_syn_retries 2>/dev/null | tr -d '\r\n' || true)
    [[ "$nm" == "1" && "$sr" == "8" ]] || die "isolation TCP non active sur $1 (no_metrics_save='$nm', syn_retries='$sr')."
}

# netem FATAL si non applique (l'ancienne version avalait l'erreur avec '|| true'
# et produisait silencieusement une capture en reseau ideal).
apply_netem() {   # container netem-args...
    local c="$1"; shift
    docker exec "$c" tc qdisc add dev "$NETIF" root netem "$@" || die "tc netem a echoue sur $c ($*)."
    docker exec "$c" tc qdisc show dev "$NETIF" | grep -q netem || die "regle netem non visible sur $c."
}

cleaning
docker network create localNet >/dev/null 2>&1 || true
docker volume create cert >/dev/null 2>&1 || true

###############################################################################
#  Pré-téléchargement de l'image helper pumba (stable/unstable uniquement)
#  -- même logique de miroir local que le launcher principal, pour éviter
#  de dépendre du réseau externe à chaque appel.
###############################################################################

if [[ "$NETWORK_PROFILE" == "stable" || "$NETWORK_PROFILE" == "unstable" ]]; then
    LOCAL_MIRROR="localhost:5000/pumba-alpine-nettools:latest"
    echo "Vérification de l'image helper pumba dans le miroir local ($LOCAL_MIRROR)..."
    if docker pull "$LOCAL_MIRROR" >/dev/null 2>&1; then
        echo "  ↳ Déjà disponible localement."
    else
        echo "  ↳ Absente du miroir local — récupération depuis ghcr.io..."
        pumba_image_ok=false
        for pull_attempt in 1 2 3 4 5; do
            if docker pull ghcr.io/alexei-led/pumba-alpine-nettools:latest; then
                pumba_image_ok=true
                break
            fi
            echo "   ↳ Échec (tentative $pull_attempt/5), nouvel essai dans 5s..."
            sleep 5
        done
        if ! $pumba_image_ok; then
            echo "ERREUR FATALE: impossible de télécharger l'image helper pumba."
            exit 1
        fi
        docker tag ghcr.io/alexei-led/pumba-alpine-nettools:latest "$LOCAL_MIRROR" 2>/dev/null || true
        docker push "$LOCAL_MIRROR" 2>/dev/null \
            || echo "  ↳ [!] Push vers le miroir local échoué (voir README pour la mise en place)."
    fi
fi

###############################################################################
#  Certs
###############################################################################

echo "==> Certs..."
docker run --rm -v cert:/cert -e CERT_PATH=/cert/ -e SIG_ALG=$SIG_ALG -i "$IMAGE" doCert.sh >/dev/null

###############################################################################
#  Serveur
###############################################################################

echo "==> Démarrage serveur ($PROTOCOL, $AUTH_MODE)..."
# TLS : SSL_DIR=/tmp => perftestServerTlsQuic.sh ajoute "-keylogfile
# /tmp/sslkeys_server_<SIG>_<KEM>.log" a s_server (cles recuperees plus bas).
SRV_SSL_ENV=()
[[ "$PROTOCOL" == "tls" ]] && SRV_SSL_ENV=(-e SSL_DIR=/tmp)
SRV_KEYLOG="/tmp/sslkeys_server_${SIG_ALG}_${KEM_ALG}.log"
docker run --cap-add=NET_ADMIN --name $OQS_SERVER --network localNet -v cert:/cert \
    ${TCP_SYSCTLS[@]+"${TCP_SYSCTLS[@]}"} \
    -e TC_DELAY=0ms -e TC_LOSS=0% -e CERT_PATH=/cert/ -e KEM_ALG=$KEM_ALG -e DEFAULT_GROUPS=$KEM_ALG \
    -e SIG_ALG=$SIG_ALG -e USE_TLS=$USE_TLS -e MUTUAL=$MUTUAL_AUTHENTICATION \
    ${SRV_SSL_ENV[@]+"${SRV_SSL_ENV[@]}"} \
    -d $IMAGE perftestServerTlsQuic.sh >/dev/null
sleep 3

IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $OQS_SERVER)
if [[ -z "$IP" ]]; then
    echo "❌ ERREUR : impossible de récupérer l'IP du serveur — le conteneur a-t-il démarré ?"
    echo "--- docker logs $OQS_SERVER ---"
    docker logs $OQS_SERVER 2>&1 | tail -30
    exit 1
fi
echo "    Server IP: $IP"

if ! docker ps --filter "name=^${OQS_SERVER}$" --filter "status=running" -q | grep -q .; then
    echo "❌ ERREUR : le conteneur serveur s'est arrêté après le démarrage."
    docker logs $OQS_SERVER 2>&1 | tail -30
    exit 1
fi

set_mtu "$OQS_SERVER"
set_offloads "$OQS_SERVER"
check_tcp_isolation "$OQS_SERVER"

###############################################################################
#  NETWORK IMPAIRMENTS (serveur) — mêmes profils que le launcher principal
###############################################################################

case "$NETWORK_PROFILE" in
    simple)
        if [[ "$LOSS_PERC" != "0" || "$DELAY_MS" != "0" ]]; then
            echo "   ↳ tc netem serveur: delay=${DELAY_MS}ms loss=${LOSS_PERC}%"
            apply_netem $OQS_SERVER delay ${DELAY_MS}ms loss ${LOSS_PERC}%
        fi
        ;;
    delay-only)
        if [[ "$DELAY_MS" != "0" ]]; then
            echo "   ↳ tc netem serveur: delay=${DELAY_MS}ms loss=0% (delay-only)"
            apply_netem $OQS_SERVER delay ${DELAY_MS}ms
        fi
        ;;
    loss-only)
        if [[ "$LOSS_PERC" != "0" ]]; then
            echo "   ↳ tc netem serveur: loss=${LOSS_PERC}% delay=0ms (loss-only)"
            apply_netem $OQS_SERVER loss ${LOSS_PERC}%
        fi
        ;;
    stable|unstable)
        args=("${STABLE_GEMODEL[@]}")
        [[ "$NETWORK_PROFILE" == "unstable" ]] && args=("${UNSTABLE_GEMODEL[@]}")
        echo "   ↳ Applying ${NETWORK_PROFILE} network profile (loss-gemodel pg${args[0]} pb${args[1]} h${args[2]} k${args[3]})"
        /usr/local/bin/pumba netem --duration 5m --interface $NETIF \
            --tc-image localhost:5000/pumba-alpine-nettools:latest \
            loss-gemodel --pg "${args[0]}" --pb "${args[1]}" \
            --one-h "${args[2]}" --one-k "${args[3]}" "$OQS_SERVER" &
        PUMBA_PID=$!

        # ── Vérification bloquante : la règle est-elle RÉELLEMENT là ? ──
        gemodel_applied=false
        for attempt in $(seq 1 15); do
            sleep 2
            if docker exec "$OQS_SERVER" tc -s qdisc show dev "$NETIF" 2>/dev/null | grep -qi "gemodel"; then
                gemodel_applied=true
                break
            fi
            if ! kill -0 "$PUMBA_PID" 2>/dev/null; then
                echo "   ↳ Le process pumba (PID $PUMBA_PID) s'est terminé sans que la règle soit visible."
                break
            fi
            echo "   ↳ Règle gemodel pas encore visible (tentative $attempt/15)..."
        done
        if ! $gemodel_applied; then
            echo "❌ ERREUR FATALE: la règle loss-gemodel n'a pas pu être confirmée sur $OQS_SERVER après 30s."
            exit 1
        fi
        echo "   ↳ Règle gemodel confirmée active sur $OQS_SERVER."
        ;;
esac

###############################################################################
#  Client
###############################################################################

docker create --cap-add=NET_ADMIN --network localNet --name $OQS_CLIENT -v cert:/cert \
    ${TCP_SYSCTLS[@]+"${TCP_SYSCTLS[@]}"} \
    -e DOCKER_HOST="$IP" -e CERT_PATH=/cert/ -e KEM_ALG=$KEM_ALG -e DEFAULT_GROUPS=$KEM_ALG \
    -e SIG_ALG=$SIG_ALG -e USE_TLS=$USE_TLS "$IMAGE" sleep infinity >/dev/null
docker start $OQS_CLIENT >/dev/null
sleep 1

set_mtu "$OQS_CLIENT"
set_offloads "$OQS_CLIENT"
check_tcp_isolation "$OQS_CLIENT"

case "$NETWORK_PROFILE" in
    simple|delay-only)
        if [[ "$DELAY_MS" != "0" ]]; then
            echo "   ↳ tc netem client: delay=${DELAY_MS}ms"
            apply_netem $OQS_CLIENT delay ${DELAY_MS}ms
        fi
        ;;
esac

echo "==> Démarrage de tcpdump dans le conteneur client (capture $NETIF, filtre port 4433)..."
docker exec -d $OQS_CLIENT sh -c "env -u LD_LIBRARY_PATH tcpdump -i $NETIF -U -n -w /tmp/capture.pcap 'port 4433' 2>/tmp/tcpdump.log"
# Pret = tcpdump a ecrit "listening on" (comme perftestClientTlsQuic.sh), pas un simple sleep.
tcpdump_ready=false
for _w in $(seq 1 50); do
    if docker exec $OQS_CLIENT sh -c "grep -q 'listening on' /tmp/tcpdump.log" 2>/dev/null; then tcpdump_ready=true; break; fi
    sleep 0.1
done
$tcpdump_ready || die "tcpdump n'a pas demarre dans le conteneur client."
sleep 0.3

###############################################################################
#  Connexion de test — IDENTIQUE a celle mesuree par la campagne
###############################################################################

echo "==> Connexion de test (meme client que la campagne, timeout ${HANDSHAKE_TIMEOUT_S}s)..."
CONN_OK=true
CONN_RC=0
if [ "$USE_TLS" = "true" ]; then
    if [ "$MUTUAL_AUTHENTICATION" = "true" ]; then
        CLIENT_CERT_ARGS="-cert \$CERT_PATH/user.crt -key \$CERT_PATH/user.key"
    else
        CLIENT_CERT_ARGS=""
    fi
    CONN_OUTPUT=$(docker exec $OQS_CLIENT sh -c \
        "timeout ${HANDSHAKE_TIMEOUT_S}s openssl s_connection -connect \$DOCKER_HOST:4433 -new -verify 1 \
            -CAfile \$CERT_PATH/CA.crt $CLIENT_CERT_ARGS -www /payload.bin 2>&1") || CONN_RC=$?
else
    CONN_OUTPUT=$(docker exec $OQS_CLIENT sh -c \
        "export SSLKEYLOGFILE=/tmp/sslkeys.log; \
         timeout ${HANDSHAKE_TIMEOUT_S}s quics_connection -groups:\$KEM_ALG -target:\$DOCKER_HOST -CAfile:\$CERT_PATH/CA.crt 2>&1") || CONN_RC=$?
fi
echo "$CONN_OUTPUT"

# Critere de succes COMMUN TLS/QUIC (celui de la campagne) : App-ready numerique
# ET 100 octets de corps recus. "NaN" => echec.
HS_MS=$(sed -n 's/^Handshake duration: \([0-9][0-9.]*\) ms.*/\1/p' <<< "$CONN_OUTPUT" | head -1)
APP_MS=$(sed -n 's/^App-ready duration: \([0-9][0-9.]*\) ms.*/\1/p' <<< "$CONN_OUTPUT" | head -1)
APP_BYTES=$(sed -n 's/^App-bytes: \([0-9][0-9]*\)[[:space:]]*$/\1/p' <<< "$CONN_OUTPUT" | head -1)
if [[ "$CONN_RC" -ne 0 || -z "$APP_MS" || "$APP_BYTES" != "100" ]]; then
    echo "⚠️  Connexion NON conforme (rc=$CONN_RC, App-ready='${APP_MS:-NaN}', App-bytes='${APP_BYTES:-?}') -- pcap inexploitable pour la taille du trafic."
    CONN_OK=false
fi

sleep 1   # laisse sortir les derniers paquets (ACK final, RST / CONNECTION_CLOSE)
echo "==> Arrêt de tcpdump..."
docker exec $OQS_CLIENT sh -c "pkill -TERM tcpdump" || true
for _w in $(seq 1 50); do
    if docker exec $OQS_CLIENT sh -c "grep -q 'packets captured' /tmp/tcpdump.log" 2>/dev/null; then break; fi
    sleep 0.1
done
TCPDUMP_SUMMARY=$(docker exec $OQS_CLIENT sh -c "grep -E 'packets (captured|received by filter|dropped by kernel)' /tmp/tcpdump.log" 2>/dev/null || true)
echo "$TCPDUMP_SUMMARY"
KERNEL_DROPPED=$(sed -n 's/^\([0-9][0-9]*\) packets dropped by kernel.*/\1/p' <<< "$TCPDUMP_SUMMARY" | head -1)
if [[ -z "$KERNEL_DROPPED" || "$KERNEL_DROPPED" != "0" ]]; then
    echo "⚠️  tcpdump : paquets perdus par le noyau ('${KERNEL_DROPPED:-bilan absent}') -- capture non fiable."
    CONN_OK=false
fi
# Trames plus grandes que MTU + 14 (en-tete Ethernet) = super-trames GSO/GRO encore
# actives (typiquement UDP GSO de MsQuic) : la capture ne montre plus des paquets.
# "greater N" : longueur >= N, donc MTU+15 => strictement > MTU+14.
OVERSIZE=$(docker exec $OQS_CLIENT sh -c "env -u LD_LIBRARY_PATH tcpdump -nn -r /tmp/capture.pcap 'greater $((MTU + 15))' 2>/dev/null | wc -l" 2>/dev/null | tr -d '\r\n' || true)
if ! [[ "$OVERSIZE" =~ ^[0-9]+$ ]] || [[ "$OVERSIZE" != "0" ]]; then
    echo "⚠️  ${OVERSIZE:-?} trame(s) > MTU+14 dans le pcap : offloads (GSO/GRO) encore actifs -- capture non fiable."
    CONN_OK=false
fi

###############################################################################
#  Récupération des artefacts
###############################################################################

echo "==> Récupération du .pcap et du fichier de clés sur l'hôte..."
docker cp "$OQS_CLIENT:/tmp/capture.pcap" "$PCAP_DIR/$PCAP_NAME"
KEYLOG_OK=false
if [ "$USE_TLS" = "true" ]; then
    # TLS : cles cote SERVEUR (s_server -keylogfile), cf. en-tete.
    if docker exec $OQS_SERVER sh -c "[ -s $SRV_KEYLOG ]" 2>/dev/null; then
        docker cp "$OQS_SERVER:$SRV_KEYLOG" "$PCAP_DIR/$KEYLOG_NAME" && KEYLOG_OK=true
    fi
else
    # QUIC : cles cote CLIENT (SSLKEYLOGFILE).
    if docker exec $OQS_CLIENT sh -c "[ -s /tmp/sslkeys.log ]" 2>/dev/null; then
        docker cp "$OQS_CLIENT:/tmp/sslkeys.log" "$PCAP_DIR/$KEYLOG_NAME" && KEYLOG_OK=true
    fi
fi
[[ "$KEYLOG_OK" == "true" ]] || echo "  [!] Aucune clé exportée (fichier vide ou absent) — le pcap restera chiffré dans Wireshark."

# Meta d'audit : conditions exactes de la capture + sortie du client.
{
    echo "protocol=$PROTOCOL auth=$AUTH_MODE sig=$SIG_ALG kem=$KEM_ALG"
    echo "network_profile=$NETWORK_PROFILE_LABEL loss_pct=$LOSS_PERC delay_ms_per_interface=$DELAY_MS"
    echo "mtu=$MTU offload_off=$OFFLOAD_OFF tcp_isolate=$TCP_ISOLATE handshake_timeout_s=$HANDSHAKE_TIMEOUT_S"
    echo "server_ip=$IP conn_ok=$CONN_OK handshake_ms=${HS_MS:-NaN} app_ready_ms=${APP_MS:-NaN} app_bytes=${APP_BYTES:-NA}"
    echo "tcpdump_dropped_by_kernel=${KERNEL_DROPPED:-NA} oversize_frames=${OVERSIZE:-NA} keylog_ok=$KEYLOG_OK"
    echo "--- sortie du client ---"
    echo "$CONN_OUTPUT"
} > "$PCAP_DIR/$META_NAME"

echo ""
echo "=================================================="
if [[ "$CONN_OK" == "true" ]]; then
    echo " ✅ Connexion confirmée réussie."
else
    echo " ⚠️  Connexion NON confirmée -- pcap/log probablement inexploitables."
fi
echo " Profil réseau : $NETWORK_PROFILE_LABEL"
echo " Capture : $PCAP_DIR/$PCAP_NAME"
echo " Meta    : $PCAP_DIR/$META_NAME"
if [ "$KEYLOG_OK" = "true" ]; then
    echo " Clés    : $PCAP_DIR/$KEYLOG_NAME"
    echo ""
    echo " Pour déchiffrer dans Wireshark :"
    echo "   1. Fichier > Ouvrir > $PCAP_NAME"
    echo "   2. Édition > Préférences > Protocols > TLS >"
    echo "      (Pre)-Master-Secret log filename > sélectionne $KEYLOG_NAME"
fi
echo "=================================================="

[[ "$CONN_OK" == "true" ]] || exit 1
