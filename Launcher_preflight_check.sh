#!/usr/bin/env bash
set -uo pipefail
#
# Launcher_preflight_check.sh — Vérifie EMPIRIQUEMENT, en une seule exécution,
# tous les points d'incertitude liés au code source de s_connection/
# quics_connection identifiés avant de lancer charge concurrente et
# session resumption :
#
#   1. -sess_out/-sess_in sont-ils supportés (TLS et QUIC) ?
#   2. -verifyCAfile (QUIC mutual) fonctionne-t-il vraiment ?
#   3. Les binaires retournent-ils un exit code non-nul en cas d'échec réel ?
#   4. -cert/-key fonctionnent-ils en mode mutual ?
#
# Ne modifie ni ne dépend d'aucun autre script. Résultat : un rapport texte
# clair, PASS/FAIL/INCONNU pour chaque point, sans avoir à lire de code source.
#
# Usage: ./Launcher_preflight_check.sh [tls|quic|both]

PROTO_ARG=${1:-both}
IMAGE=uma-tls-quic-pq-34
OQS_SERVER="servidor"
OQS_CLIENT="cliente"
SIG_ALG="mldsa44"
KEM_ALG="mlkem512"
REPORT="/tmp/preflight_report_$(date +%Y%m%d_%H%M%S).txt"

log() { echo "$1" | tee -a "$REPORT"; }

cleaning() {
    docker kill $OQS_SERVER &>/dev/null || true
    docker kill $OQS_CLIENT &>/dev/null || true
    sleep 1
    docker container prune -f >/dev/null 2>&1 || true
    docker volume rm cert &>/dev/null || true
    docker network rm localNet &>/dev/null || true
    sleep 1
}

setup() {
    cleaning
    docker network create localNet >/dev/null 2>&1 || true
    docker volume create cert >/dev/null 2>&1 || true
    docker run --rm -v cert:/cert -e CERT_PATH=/cert/ -e SIG_ALG=$SIG_ALG -i "$IMAGE" doCert.sh >/dev/null
}

start_server() {
    local use_tls="$1" mutual="$2"
    docker rm -f $OQS_SERVER $OQS_CLIENT 2>/dev/null || true
    docker run --cap-add=NET_ADMIN --name $OQS_SERVER --network localNet -v cert:/cert \
        -e TC_DELAY=0ms -e TC_LOSS=0% -e CERT_PATH=/cert/ -e KEM_ALG=$KEM_ALG -e SIG_ALG=$SIG_ALG \
        -e USE_TLS="$use_tls" -e MUTUAL="$mutual" -d $IMAGE perftestServerTlsQuic.sh >/dev/null
    sleep 3
    IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $OQS_SERVER)
    docker create --cap-add=NET_ADMIN --network localNet --name $OQS_CLIENT -v cert:/cert \
        -e DOCKER_HOST="$IP" -e TC_DELAY=0ms -e TC_LOSS=0% -e CERT_PATH=/cert/ -e KEM_ALG=$KEM_ALG \
        -e DEFAULT_GROUPS=$KEM_ALG \
        -e SIG_ALG=$SIG_ALG -e USE_TLS="$use_tls" -e MUTUAL="$mutual" "$IMAGE" sleep infinity >/dev/null
    docker start $OQS_CLIENT >/dev/null
    sleep 1
}

check_tls() {
    log ""
    log "=================================================="
    log " TLS — Vérifications empiriques"
    log "=================================================="

    log ""
    log "[TLS-1] Test succès basique (single auth, sans mutual)..."
    start_server true false
    if docker exec $OQS_CLIENT sh -c \
        "openssl s_connection -connect \$DOCKER_HOST:4433 -new -verify 1 -CAfile \$CERT_PATH/CA.crt" \
        >/dev/null 2>&1; then
        log "  [PASS] Connexion TLS single réussie, exit=0 (comportement attendu)."
    else
        log "  [FAIL] La connexion TLS de base a échoué — s'arrêter là, il y a un problème plus"
        log "         fondamental que la resumption à régler d'abord."
    fi

    log ""
    log "[TLS-2] Exit code en cas d'échec réel (port fermé)..."
    if docker exec $OQS_CLIENT sh -c \
        "openssl s_connection -connect \$DOCKER_HOST:1 -new -verify 1 -CAfile \$CERT_PATH/CA.crt" \
        >/dev/null 2>&1; then
        log "  [FAIL] s_connection retourne exit=0 MÊME EN CAS D'ÉCHEC (port fermé)."
        log "         => Les taux d'échec dans mes scripts concurrent/resumption seront FAUX"
        log "            pour TLS tant que ce n'est pas corrigé ou contourné."
    else
        log "  [PASS] s_connection retourne bien un exit code non-nul en cas d'échec réel."
    fi

    log ""
    log "[TLS-3] Support de -sess_out/-sess_in par s_connection (custom)..."
    docker exec $OQS_CLIENT sh -c \
        "openssl s_connection -connect \$DOCKER_HOST:4433 -new -verify 1 -CAfile \$CERT_PATH/CA.crt -sess_out /tmp/t.pem" \
        >/tmp/tls_sessout_stdout.log 2>&1
    ec=$?
    has_file=$(docker exec $OQS_CLIENT sh -c "[ -s /tmp/t.pem ] && echo yes || echo no")
    if [[ "$has_file" == "yes" ]]; then
        log "  [PASS] s_connection accepte -sess_out et écrit bien un fichier de session."
        log "         => perftestClientResumption.sh peut utiliser s_connection directement,"
        log "            pas besoin de basculer sur openssl s_client standard."
    elif [[ "$ec" -ne 0 ]]; then
        log "  [INFO] s_connection a échoué avec -sess_out (exit=$ec) — probablement un flag"
        log "         inconnu. Basculer sur openssl s_client standard (déjà fait dans"
        log "         perftestClientResumption.sh) est la bonne décision."
    else
        log "  [INFO] s_connection accepte -sess_out sans erreur MAIS n'écrit aucun fichier —"
        log "         flag probablement ignoré silencieusement. Rester sur openssl s_client"
        log "         standard pour la resumption (déjà fait)."
    fi
    docker exec $OQS_CLIENT rm -f /tmp/t.pem 2>/dev/null || true

    log ""
    log "[TLS-4] Mode mutual (-cert/-key)..."
    start_server true true
    if docker exec $OQS_CLIENT sh -c \
        "openssl s_connection -connect \$DOCKER_HOST:4433 -new -verify 1 -CAfile \$CERT_PATH/CA.crt -cert \$CERT_PATH/user.crt -key \$CERT_PATH/user.key" \
        >/dev/null 2>&1; then
        log "  [PASS] Mutual TLS fonctionne avec -cert/-key (syntaxe espace)."
    else
        log "  [FAIL] Mutual TLS échoue avec la syntaxe -cert/-key actuelle."
    fi
}

check_quic() {
    log ""
    log "=================================================="
    log " QUIC — Vérifications empiriques"
    log "=================================================="

    log ""
    log "[QUIC-1] Test succès basique (single auth, sans mutual)..."
    start_server false false
    if docker exec $OQS_CLIENT sh -c \
        "quics_connection -groups:\$KEM_ALG -target:\$DOCKER_HOST -CAfile:\$CERT_PATH/CA.crt" \
        >/dev/null 2>&1; then
        log "  [PASS] Connexion QUIC single réussie, exit=0 (comportement attendu)."
    else
        log "  [FAIL] La connexion QUIC de base a échoué — s'arrêter là, il y a un problème plus"
        log "         fondamental que la resumption à régler d'abord."
    fi

    log ""
    log "[QUIC-2] Exit code en cas d'échec réel (cible invalide)..."
    if docker exec $OQS_CLIENT sh -c \
        "quics_connection -groups:\$KEM_ALG -target:198.51.100.1 -CAfile:\$CERT_PATH/CA.crt" \
        >/dev/null 2>&1; then
        log "  [FAIL] quics_connection retourne exit=0 MÊME EN CAS D'ÉCHEC (cible invalide,"
        log "         198.51.100.1 est une IP de test RFC 5737 non routable)."
        log "         => Les taux d'échec dans mes scripts concurrent/resumption seront FAUX"
        log "            pour QUIC tant que ce n'est pas corrigé ou contourné."
    else
        log "  [PASS] quics_connection retourne bien un exit code non-nul en cas d'échec réel."
    fi

    log ""
    log "[QUIC-3] Support de -sess_out:/-sess_in: par quics_connection (custom)..."
    docker exec $OQS_CLIENT sh -c \
        "quics_connection -groups:\$KEM_ALG -target:\$DOCKER_HOST -CAfile:\$CERT_PATH/CA.crt -sess_out:/tmp/t.pem" \
        >/tmp/quic_sessout_stdout.log 2>&1
    ec=$?
    has_file=$(docker exec $OQS_CLIENT sh -c "[ -s /tmp/t.pem ] && echo yes || echo no")
    if [[ "$has_file" == "yes" ]]; then
        log "  [PASS] quics_connection accepte -sess_out: et écrit bien un fichier de session."
        log "         => la reprise de session QUIC est probablement possible tel quel."
    elif [[ "$ec" -ne 0 ]]; then
        log "  [FAIL/INFO] quics_connection a échoué avec -sess_out: (exit=$ec) — flag inconnu"
        log "         ou syntaxe différente. Voir /tmp/quic_sessout_stdout.log pour le message"
        log "         d'erreur exact, qui indique souvent la bonne syntaxe attendue."
        log "         => la reprise de session QUIC n'est PAS utilisable telle quelle dans"
        log "            perftestClientResumption.sh sans corriger la syntaxe du flag."
    else
        log "  [INFO] quics_connection accepte -sess_out: sans erreur MAIS n'écrit aucun"
        log "         fichier — support de resumption incertain, à creuser manuellement."
    fi
    docker exec $OQS_CLIENT rm -f /tmp/t.pem 2>/dev/null || true

    log ""
    log "[QUIC-4] Mode mutual (-cert/-key + -verifyCAfile serveur)..."
    start_server false true
    if docker exec $OQS_CLIENT sh -c \
        "quics_connection -groups:\$KEM_ALG -target:\$DOCKER_HOST -CAfile:\$CERT_PATH/CA.crt -cert \$CERT_PATH/user.crt -key \$CERT_PATH/user.key" \
        >/dev/null 2>&1; then
        log "  [PASS] Mutual QUIC fonctionne — le flag -verifyCAfile (espace) du serveur"
        log "         est donc correctement interprété."
    else
        log "  [FAIL] Mutual QUIC échoue. Vérifiez en premier le flag -verifyCAfile dans"
        log "         perftestServerTlsQuic.sh (syntaxe espace vs deux-points, cf. échange"
        log "         précédent) — c'est le suspect principal identifié."
    fi
}

echo "Rapport détaillé : $REPORT"
log "== Preflight check — $(date) =="
setup

[[ "$PROTO_ARG" == "tls" || "$PROTO_ARG" == "both" ]] && check_tls
[[ "$PROTO_ARG" == "quic" || "$PROTO_ARG" == "both" ]] && check_quic

cleaning

log ""
log "=================================================="
log " Rapport complet : $REPORT"
log "=================================================="
