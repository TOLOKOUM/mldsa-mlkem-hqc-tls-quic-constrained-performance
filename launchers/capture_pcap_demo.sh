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
# TLS   : openssl s_client standard (-keylogfile officiel, documenté, stable).
# QUIC  : quics_connection avec SSLKEYLOGFILE (méthode confirmée dans
#         perftestClientTlsQuic.sh).
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
docker run --cap-add=NET_ADMIN --name $OQS_SERVER --network localNet -v cert:/cert \
    -e TC_DELAY=0ms -e TC_LOSS=0% -e CERT_PATH=/cert/ -e KEM_ALG=$KEM_ALG -e DEFAULT_GROUPS=$KEM_ALG \
    -e SIG_ALG=$SIG_ALG -e USE_TLS=$USE_TLS -e MUTUAL=$MUTUAL_AUTHENTICATION \
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

###############################################################################
#  NETWORK IMPAIRMENTS (serveur) — mêmes profils que le launcher principal
###############################################################################

case "$NETWORK_PROFILE" in
    simple)
        if [[ "$LOSS_PERC" != "0" || "$DELAY_MS" != "0" ]]; then
            echo "   ↳ tc netem serveur: delay=${DELAY_MS}ms loss=${LOSS_PERC}%"
            docker exec $OQS_SERVER tc qdisc add dev $NETIF root netem \
                delay ${DELAY_MS}ms loss ${LOSS_PERC}% || true
        fi
        ;;
    delay-only)
        if [[ "$DELAY_MS" != "0" ]]; then
            echo "   ↳ tc netem serveur: delay=${DELAY_MS}ms loss=0% (delay-only)"
            docker exec $OQS_SERVER tc qdisc add dev $NETIF root netem \
                delay ${DELAY_MS}ms || true
        fi
        ;;
    loss-only)
        if [[ "$LOSS_PERC" != "0" ]]; then
            echo "   ↳ tc netem serveur: loss=${LOSS_PERC}% delay=0ms (loss-only)"
            docker exec $OQS_SERVER tc qdisc add dev $NETIF root netem \
                loss ${LOSS_PERC}% || true
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
    -e DOCKER_HOST="$IP" -e CERT_PATH=/cert/ -e KEM_ALG=$KEM_ALG -e DEFAULT_GROUPS=$KEM_ALG \
    -e SIG_ALG=$SIG_ALG -e USE_TLS=$USE_TLS "$IMAGE" sleep infinity >/dev/null
docker start $OQS_CLIENT >/dev/null
sleep 1

case "$NETWORK_PROFILE" in
    simple|delay-only)
        if [[ "$DELAY_MS" != "0" ]]; then
            echo "   ↳ tc netem client: delay=${DELAY_MS}ms"
            docker exec $OQS_CLIENT tc qdisc add dev $NETIF root netem \
                delay ${DELAY_MS}ms || true
        fi
        ;;
esac

echo "==> Démarrage de tcpdump dans le conteneur client (capture $NETIF, en arrière-plan)..."
docker exec -d $OQS_CLIENT sh -c "tcpdump -i $NETIF -w /tmp/capture.pcap 2>/tmp/tcpdump.log"
sleep 1   # laisser tcpdump s'attacher avant la connexion

###############################################################################
#  Connexion de test (avec export des clés de session)
###############################################################################

echo "==> Connexion de test..."
CONN_OK=true
if [ "$USE_TLS" = "true" ]; then
    if [ "$MUTUAL_AUTHENTICATION" = "true" ]; then
        # NB: noms de fichiers cert/clé client supposés d'après la sortie de
        # doCert.sh ("subject=CN=user") -- vérifie qu'ils correspondent
        # réellement à ta convention (adapte CLIENT_CERT/CLIENT_KEY sinon).
        CLIENT_CERT_ARGS="-cert \$CERT_PATH/user.crt -key \$CERT_PATH/user.key"
    else
        CLIENT_CERT_ARGS=""
    fi
    CONN_OUTPUT=$(docker exec $OQS_CLIENT sh -c \
        "{ sleep 0.3; printf 'Q\n'; } | openssl s_client -connect \$DOCKER_HOST:4433 -tls1_3 \
            -groups \$KEM_ALG -CAfile \$CERT_PATH/CA.crt $CLIENT_CERT_ARGS \
            -keylogfile /tmp/sslkeys.log -state 2>&1") || CONN_OK=false
    echo "$CONN_OUTPUT"
    if [[ "$CONN_OK" != "true" ]] || ! grep -q "Verify return code: 0" <<< "$CONN_OUTPUT"; then
        echo "⚠️  Le handshake TLS ne semble pas avoir abouti proprement (pas de "
        echo "    'Verify return code: 0' dans la sortie) -- vérifie le pcap/log avant de t'y fier."
        CONN_OK=false
    fi
else
    CONN_OUTPUT=$(docker exec $OQS_CLIENT sh -c \
        "export SSLKEYLOGFILE=/tmp/sslkeys.log; \
         quics_connection -groups:\$KEM_ALG -target:\$DOCKER_HOST -CAfile:\$CERT_PATH/CA.crt 2>&1") || CONN_OK=false
    echo "$CONN_OUTPUT"
    if [[ "$CONN_OK" != "true" ]] || grep -qi "error\|fail" <<< "$CONN_OUTPUT"; then
        echo "⚠️  La connexion QUIC ne semble pas avoir abouti proprement -- vérifie le pcap/log avant de t'y fier."
        CONN_OK=false
    fi
fi

sleep 1
echo "==> Arrêt de tcpdump..."
docker exec $OQS_CLIENT sh -c "pkill tcpdump" || true
sleep 1

###############################################################################
#  Récupération des artefacts
###############################################################################

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
if [[ "$CONN_OK" == "true" ]]; then
    echo " ✅ Connexion confirmée réussie."
else
    echo " ⚠️  Connexion NON confirmée -- pcap/log probablement inexploitables."
fi
echo " Profil réseau : $NETWORK_PROFILE_LABEL"
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

[[ "$CONN_OK" == "true" ]] || exit 1
