#!/bin/sh
set -e

# -------------------------------------------------------------------
# perftestServerCompress.sh  — version corrigée
# Serveur TLS/QUIC avec option compression certificat (RFC 8879)
#
# IMPORTANT — Résultat du diagnostic :
#   OpenSSL OQS est compilé SANS zlib → RFC 8879 n'est PAS disponible
#   nativement. Le serveur fonctionne en mode "standard" dans les
#   deux cas. La variable COMPRESS_CERT est conservée pour que le
#   Launcher puisse annoter les métadonnées et les CSV correctement.
#
# OpenSSL 3.4.x (OQS build) :
#   - -no_tx_cert_comp : désactive l'envoi de certificats compressés
#   - -no_rx_cert_comp : désactive la réception de certificats compressés
#   - Ces flags sont acceptés même sans zlib (no-op si pas de support)
# -------------------------------------------------------------------

# ── Valeurs par défaut ──────────────────────────────────────────────
TC_DELAY="${TC_DELAY:-0ms}"
TC_LOSS="${TC_LOSS:-0%}"
USE_TLS="${USE_TLS:-true}"
CERT_PATH="${CERT_PATH:-/cert}"
COMPRESS_CERT="${COMPRESS_CERT:-false}"
KEM_ALG="${KEM_ALG:-mlkem512}"
SIG_ALG="${SIG_ALG:-mldsa44}"

INTERFAZ="eth0"

# ── Appliquer netem ─────────────────────────────────────────────────
echo "[SERVER] Applying netem on $INTERFAZ (delay=$TC_DELAY loss=$TC_LOSS)..."
tc qdisc add dev "$INTERFAZ" root netem delay "$TC_DELAY" loss "$TC_LOSS" 2>/dev/null || true

# ── Log de démarrage ────────────────────────────────────────────────
echo "[SERVER] ============================================================"
echo "[SERVER] SIG_ALG   = $SIG_ALG"
echo "[SERVER] KEM_ALG   = $KEM_ALG"
echo "[SERVER] PROTOCOL  = $([ "$USE_TLS" = "true" ] && echo TLS || echo QUIC)"
echo "[SERVER] COMPRESS  = $COMPRESS_CERT"
echo "[SERVER] CERT_PATH = $CERT_PATH"
echo "[SERVER] ============================================================"

# ── Fix: exporter DEFAULT_GROUPS pour éviter les erreurs SSL_CONF_cmd ──
export DEFAULT_GROUPS="$KEM_ALG"

# ── Démarrage du serveur ────────────────────────────────────────────
if [ "$USE_TLS" = "true" ]; then

    if [ "$COMPRESS_CERT" = "true" ]; then
        # Phase "compressed" : on laisse OpenSSL avec son comportement par défaut
        # (compression active si zlib disponible, sinon no-op).
        # On N'ajoute PAS -no_tx_cert_comp ni -no_rx_cert_comp.
        echo "[SERVER] Mode: TLS — certificate compression ENABLED (RFC 8879 if available)"
        /opt/oqssa/bin/openssl s_server \
            -cert  "$CERT_PATH/server.crt" \
            -key   "$CERT_PATH/server.key" \
            -CAfile "$CERT_PATH/CA.crt" \
            -groups "$KEM_ALG" \
            -tls1_3 \
            -www \
            -accept :4433
    else
        # Phase "nocompress" : on force explicitement la désactivation
        # même si zlib était disponible, pour garantir la comparabilité.
        echo "[SERVER] Mode: TLS — certificate compression DISABLED (-no_tx_cert_comp -no_rx_cert_comp)"
        /opt/oqssa/bin/openssl s_server \
            -cert  "$CERT_PATH/server.crt" \
            -key   "$CERT_PATH/server.key" \
            -CAfile "$CERT_PATH/CA.crt" \
            -groups "$KEM_ALG" \
            -tls1_3 \
            -www \
            -accept :4433 \
            -no_tx_cert_comp \
            -no_rx_cert_comp
    fi

else
    # ── Mode QUIC ────────────────────────────────────────────────────
    # quics_server ne supporte pas les flags de compression RFC 8879.
    # COMPRESS_CERT est ignoré côté QUIC (noté dans les métadonnées).
    echo "[SERVER] Mode: QUIC (compression flag ignored for QUIC)"
    quics_server \
        -groups:"$KEM_ALG" \
        -cert_file:"$CERT_PATH/server.crt" \
        -key_file:"$CERT_PATH/server.key"
fi
