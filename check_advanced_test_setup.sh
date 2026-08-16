#!/bin/bash
set -uo pipefail
# (pas de -e ici : on veut collecter TOUS les échecs avant de sortir, pas
#  s'arrêter au premier)

###############################################################################
#  check_advanced_test_setup.sh
#
#  Smoke-test à lancer AVANT launcher_advanced_test.sh pour vérifier que
#  tout le pipeline (image docker, binaires, scripts, réseau, certs,
#  handshakes concurrent + resumption) fonctionne, sur un volume minimal
#  (2 clients x 2 runs), en TLS et QUIC.
#
#  IMPORTANT: n'écrit jamais dans captures/ — tout se passe dans un
#  répertoire temporaire sous /tmp, supprimé à la fin (sauf --keep).
#
#  Usage:
#    ./check_advanced_test_setup.sh [tls|quic|both] [--keep]
#
#  Code de sortie: 0 si tout est OK, 1 si au moins un check a échoué.
###############################################################################

PROTO_ARG=${1:-both}
KEEP=false
[[ "${2:-}" == "--keep" ]] && KEEP=true

if [[ "$PROTO_ARG" == "both" ]]; then
    PROTOCOLS=("tls" "quic")
elif [[ "$PROTO_ARG" == "tls" || "$PROTO_ARG" == "quic" ]]; then
    PROTOCOLS=("$PROTO_ARG")
else
    echo "Usage: $0 [tls|quic|both] [--keep]"; exit 1
fi

IMAGE=uma-tls-quic-pq-34
OQS_SERVER="smoke_servidor"
OQS_CLIENT_PREFIX="smoke_cliente"
SMOKE_NET="smokeNet"
SMOKE_VOL="smokeCert"

SMOKE_CLIENTS=2
SMOKE_RUNS=2

SMOKE_DIR="/tmp/advanced_test_smoketest_$$"
mkdir -p "$SMOKE_DIR"

FAILURES=0

ok()   { echo "  [OK]   $1"; }
fail() { echo "  [FAIL] $1"; FAILURES=$((FAILURES + 1)); }
info() { echo "  [..]   $1"; }

###############################################################################
#  Cleanup (toujours exécuté, même en cas d'échec)
###############################################################################
cleanup() {
    docker kill "$OQS_SERVER" &>/dev/null || true
    for ((c=1; c<=SMOKE_CLIENTS; c++)); do
        docker kill "${OQS_CLIENT_PREFIX}${c}" &>/dev/null || true
    done
    docker rm -f "$OQS_SERVER" &>/dev/null || true
    for ((c=1; c<=SMOKE_CLIENTS; c++)); do
        docker rm -f "${OQS_CLIENT_PREFIX}${c}" &>/dev/null || true
    done
    docker volume rm "$SMOKE_VOL" &>/dev/null || true
    docker network rm "$SMOKE_NET" &>/dev/null || true

    if [[ "$KEEP" == "true" ]]; then
        echo ""
        echo "  (--keep) Résultats du smoke-test conservés dans: $SMOKE_DIR"
    else
        rm -rf "$SMOKE_DIR"
    fi
}
trap cleanup EXIT INT TERM

###############################################################################
#  1. Pré-vols : docker, image, binaires attendus dans l'image
###############################################################################
echo "=============================================================================="
echo "  STEP 1 — Pré-vols (docker, image, binaires, scripts)"
echo "=============================================================================="

if command -v docker >/dev/null 2>&1; then
    ok "docker présent dans le PATH"
else
    fail "docker introuvable — impossible de continuer"
    exit 1
fi

if docker image inspect "$IMAGE" >/dev/null 2>&1; then
    ok "image '$IMAGE' présente"
else
    fail "image '$IMAGE' introuvable — build-la avant de relancer"
    exit 1
fi

info "Vérification des scripts/binaires embarqués dans l'image..."
REQUIRED_ITEMS="doCert.sh perftestServerTlsQuic.sh perftestClientConcurrent.sh perftestClientResumption.sh"
for item in $REQUIRED_ITEMS; do
    if docker run --rm "$IMAGE" sh -c "command -v $item >/dev/null 2>&1 || test -f ./$item || test -f /usr/local/bin/$item"; then
        ok "présent dans l'image: $item"
    else
        fail "MANQUANT dans l'image: $item — copie-le dans le build context et rebuild avant de lancer les vrais tests"
    fi
done

REQUIRED_BINARIES="quics_connection openssl tc"
for bin in $REQUIRED_BINARIES; do
    if docker run --rm "$IMAGE" sh -c "command -v $bin >/dev/null 2>&1"; then
        ok "binaire disponible: $bin"
    else
        fail "binaire MANQUANT dans l'image: $bin"
    fi
done

###############################################################################
#  2. Réseau + volume + certificats
###############################################################################
echo ""
echo "=============================================================================="
echo "  STEP 2 — Réseau, volume, certificats"
echo "=============================================================================="

docker network rm "$SMOKE_NET" &>/dev/null || true
docker volume rm "$SMOKE_VOL" &>/dev/null || true

if docker network create "$SMOKE_NET" >/dev/null 2>&1; then
    ok "réseau '$SMOKE_NET' créé"
else
    fail "impossible de créer le réseau '$SMOKE_NET'"
fi

if docker volume create "$SMOKE_VOL" >/dev/null 2>&1; then
    ok "volume '$SMOKE_VOL' créé"
else
    fail "impossible de créer le volume '$SMOKE_VOL'"
fi

if docker run --rm -v "$SMOKE_VOL":/cert -e CERT_PATH=/cert/ -e SIG_ALG=mldsa65 -i "$IMAGE" doCert.sh >/dev/null 2>&1; then
    ok "génération de certificats (mldsa65) OK"
else
    fail "échec génération de certificats (mldsa65)"
fi

###############################################################################
#  3. Boucle par protocole : serveur + mini concurrent + mini resumption
###############################################################################
for protocol in "${PROTOCOLS[@]}"; do
    echo ""
    echo "=============================================================================="
    echo "  STEP 3 — $(echo "$protocol" | tr '[:lower:]' '[:upper:]') : serveur, concurrent mini-run, resumption mini-run"
    echo "=============================================================================="

    USE_TLS=$([[ "$protocol" == "tls" ]] && echo true || echo false)
    SIG_ALG="mldsa65"
    KEM="mlkem768"

    docker rm -f "$OQS_SERVER" &>/dev/null || true

    info "Démarrage du serveur ($protocol)..."
    if docker run --cap-add=NET_ADMIN \
        --name "$OQS_SERVER" \
        --network "$SMOKE_NET" \
        -v "$SMOKE_VOL":/cert \
        -e TC_DELAY=0ms -e TC_LOSS=0% \
        -e CERT_PATH=/cert/ \
        -e KEM_ALG=$KEM -e SIG_ALG=$SIG_ALG \
        -e USE_TLS=$USE_TLS -e MUTUAL=false \
        -d "$IMAGE" perftestServerTlsQuic.sh >/dev/null 2>&1; then
        ok "serveur $protocol démarré"
    else
        fail "échec démarrage serveur $protocol — abandon des checks $protocol"
        continue
    fi

    sleep 3
    SERVER_IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$OQS_SERVER" 2>/dev/null || true)
    if [[ -n "$SERVER_IP" ]]; then
        ok "IP serveur obtenue: $SERVER_IP"
    else
        fail "impossible d'obtenir l'IP du serveur $protocol — abandon des checks $protocol"
        docker rm -f "$OQS_SERVER" &>/dev/null || true
        continue
    fi
    sleep 1

    # --- Mini concurrent load (2 clients x 2 runs) ---------------------------
    CONCURRENT_DIR="${SMOKE_DIR}/${protocol}/concurrent"
    mkdir -p "$CONCURRENT_DIR"
    info "Mini concurrent load: ${SMOKE_CLIENTS} clients x ${SMOKE_RUNS} runs..."

    CLIENT_IDS=()
    for ((c=1; c<=SMOKE_CLIENTS; c++)); do
        CLIENT_NAME="${OQS_CLIENT_PREFIX}${c}"
        docker rm -f "$CLIENT_NAME" &>/dev/null || true
        docker run --cap-add=NET_ADMIN \
            --network "$SMOKE_NET" \
            --name "$CLIENT_NAME" \
            -v "$SMOKE_VOL":/cert \
            -v "${CONCURRENT_DIR}:/results" \
            -e DOCKER_HOST="$SERVER_IP" \
            -e TC_DELAY=0ms -e TC_LOSS=0% \
            -e CERT_PATH=/cert/ \
            -e KEM_ALG=$KEM -e SIG_ALG=$SIG_ALG \
            -e USE_TLS=$USE_TLS \
            -e NUM_RUNS=$SMOKE_RUNS \
            -e MUTUAL=false \
            -e CLIENT_ID=$c \
            -e RESULTS_DIR=/results \
            -d "$IMAGE" ./perftestClientConcurrent.sh >/dev/null 2>&1
        CLIENT_IDS+=("$CLIENT_NAME")
    done

    for CLIENT_NAME in "${CLIENT_IDS[@]}"; do
        docker wait "$CLIENT_NAME" >/dev/null 2>&1 || true
    done

    ALL_CSV_OK=true
    for ((c=1; c<=SMOKE_CLIENTS; c++)); do
        f="${CONCURRENT_DIR}/client_${c}_${SIG_ALG}_${KEM}.csv"
        if [[ -f "$f" ]]; then
            lines=$(wc -l < "$f")
            if [[ "$lines" -eq $((SMOKE_RUNS + 1)) ]]; then
                ok "CSV concurrent client $c: $lines lignes (attendu $((SMOKE_RUNS + 1)))"
            else
                fail "CSV concurrent client $c: $lines lignes (attendu $((SMOKE_RUNS + 1))) — $f"
                ALL_CSV_OK=false
            fi
        else
            fail "CSV concurrent client $c introuvable: $f"
            ALL_CSV_OK=false
        fi
    done

    if $ALL_CSV_OK; then
        info "Contenu échantillon (client 1):"
        cat "${CONCURRENT_DIR}/client_1_${SIG_ALG}_${KEM}.csv" | sed 's/^/         /'
        if grep -qi "nan" "${CONCURRENT_DIR}/client_1_${SIG_ALG}_${KEM}.csv"; then
            fail "présence de 'NaN' non filtré dans le CSV concurrent — vérifier parse_result()"
        fi
    fi

    for CLIENT_NAME in "${CLIENT_IDS[@]}"; do
        docker rm -f "$CLIENT_NAME" &>/dev/null || true
    done

    # --- Mini session resumption (2 runs/phase) ------------------------------
    RESUMPTION_DIR="${SMOKE_DIR}/${protocol}/resumption"
    mkdir -p "$RESUMPTION_DIR"
    info "Mini resumption: ${SMOKE_RUNS} runs/phase..."

    CLIENT_NAME="${OQS_CLIENT_PREFIX}1"
    docker rm -f "$CLIENT_NAME" &>/dev/null || true
    docker run --cap-add=NET_ADMIN \
        --network "$SMOKE_NET" \
        --name "$CLIENT_NAME" \
        -v "$SMOKE_VOL":/cert \
        -v "${RESUMPTION_DIR}:/results" \
        -e DOCKER_HOST="$SERVER_IP" \
        -e TC_DELAY=0ms -e TC_LOSS=0% \
        -e CERT_PATH=/cert/ \
        -e KEM_ALG=$KEM -e SIG_ALG=$SIG_ALG \
        -e USE_TLS=$USE_TLS \
        -e NUM_RUNS=$SMOKE_RUNS \
        -e MUTUAL=false \
        -e CLIENT_ID=1 \
        -e RESULTS_DIR=/results \
        "$IMAGE" ./perftestClientResumption.sh >/dev/null 2>&1

    RES_CSV="${RESUMPTION_DIR}/resumption_1_${SIG_ALG}_${KEM}.csv"
    if [[ -f "$RES_CSV" ]]; then
        lines=$(wc -l < "$RES_CSV")
        expected=$((SMOKE_RUNS * 2 + 1))
        if [[ "$lines" -eq "$expected" ]]; then
            ok "CSV resumption: $lines lignes (attendu $expected)"
        else
            fail "CSV resumption: $lines lignes (attendu $expected) — $RES_CSV"
        fi

        if grep -q "full" "$RES_CSV" && grep -q "resumed" "$RES_CSV"; then
            ok "CSV resumption contient bien 'full' et 'resumed'"
        else
            fail "CSV resumption ne contient pas les deux types full/resumed"
        fi

        info "Contenu:"
        cat "$RES_CSV" | sed 's/^/         /'

        if grep -qi "nan" "$RES_CSV"; then
            fail "présence de 'NaN' non filtré dans le CSV resumption — vérifier parse_result()"
        fi

        if [[ "$protocol" == "quic" ]]; then
            echo "  [i]    Rappel: QUIC resumption est connue non fonctionnelle dans notre stack"
            echo "         (durées resumed ≈ full attendues — ce n'est pas un bug de ce script)."
        fi
    else
        fail "CSV resumption introuvable: $RES_CSV"
    fi

    docker rm -f "$CLIENT_NAME" &>/dev/null || true
    docker kill "$OQS_SERVER" &>/dev/null || true
    docker rm -f "$OQS_SERVER" &>/dev/null || true
done

###############################################################################
#  Résumé
###############################################################################
echo ""
echo "=============================================================================="
if [[ "$FAILURES" -eq 0 ]]; then
    echo "  RÉSULTAT: TOUT EST OK ($FAILURES échec) — prêt pour launcher_advanced_test.sh"
    echo "=============================================================================="
    exit 0
else
    echo "  RÉSULTAT: $FAILURES CHECK(S) EN ÉCHEC — corriger avant de lancer la vraie campagne"
    echo "=============================================================================="
    exit 1
fi
