#!/bin/sh
# perftestClientResumption.sh — Test de reprise de session (0-RTT/PSK)

if [ -z "$USE_TLS" ]; then USE_TLS="true"; fi
if [ -z "$KEM_ALG" ]; then KEM_ALG=mlkem512; fi
export DEFAULT_GROUPS=$KEM_ALG
if [ -z "$SIG_ALG" ]; then SIG_ALG=mldsa44; fi
if [ -z "$WAVES" ]; then WAVES=20; fi

RESULT_DIR="/tmp/resumption_results_$$"
rm -rf "$RESULT_DIR"
mkdir -p "$RESULT_DIR"
SESSION_FILE="$RESULT_DIR/session.pem"
FAIL_LOG_DIR="/tmp/resumption_failed_logs_$$"

PROTO_LABEL="quic"
[ "$USE_TLS" = "true" ] && PROTO_LABEL="tls"

SUMMARY="/tmp/resumption_summary_${PROTO_LABEL}_${SIG_ALG}_${KEM_ALG}.csv"
echo "wave,phase,elapsed_ms,exit_status" > "$SUMMARY"

wave=1
while [ "$wave" -le "$WAVES" ]; do
    rm -f "$SESSION_FILE"

    # ── Phase 1 : Handshake complet + attente du ticket TLS 1.3 ──────
    stdout_full="$RESULT_DIR/stdout_full_w${wave}.log"
    start_ns=$(date +%s%N)
    if [ "$USE_TLS" = "true" ]; then
        # Utilisation de sleep 1 dans le tube pour laisser le temps au ticket d'arriver
        { sleep 1; echo "Q"; } | docker run -i --rm --network localNet -v cert:/cert \
            -e DEFAULT_GROUPS="$KEM_ALG" -e SIG_ALG="$SIG_ALG" \
            oqs-client openssl s_client -connect servidor:4433 -tls1_3 \
            -groups "$KEM_ALG" -CAfile /cert/CA.crt -sess_out /tmp/session_out.pem \
            > "$stdout_full" 2>&1
        status=$?
        
        # Extrait le ticket généré du conteneur vers l'hôte
        docker run --rm -v cert:/cert oqs-client cat /tmp/session_out.pem > "$SESSION_FILE" 2>/dev/null || true
    fi
    end_ns=$(date +%s%N)
    wall_elapsed_ms=$(( (end_ns - start_ns) / 1000000 ))
    # Correction de la durée brute pour retirer la pause du sleep 1
    elapsed_ms=$(( wall_elapsed_ms - 1000 ))
    [ "$elapsed_ms" -lt 0 ] && elapsed_ms=0

    echo "${wave},full_handshake,${elapsed_ms},${status}" >> "$SUMMARY"
    if [ "$status" != "0" ]; then
        mkdir -p "$FAIL_LOG_DIR"
        cp "$stdout_full" "$FAIL_LOG_DIR/" 2>/dev/null || true
    fi
    rm -f "$stdout_full"

    # ── Phase 2 : Reprise de session ──────
    if [ -s "$SESSION_FILE" ] && grep -q "BEGIN SESSION RECORD" "$SESSION_FILE" 2>/dev/null; then
        stdout_resumed="$RESULT_DIR/stdout_resumed_w${wave}.log"
        start_ns=$(date +%s%N)
        if [ "$USE_TLS" = "true" ]; then
            # Injection de la session sauvegardée
            { sleep 0.2; echo "Q"; } | docker run -i --rm --network localNet -v cert:/cert \
                -v "$SESSION_FILE":/tmp/session_in.pem \
                -e DEFAULT_GROUPS="$KEM_ALG" -e SIG_ALG="$SIG_ALG" \
                oqs-client openssl s_client -connect servidor:4433 -tls1_3 \
                -groups "$KEM_ALG" -CAfile /cert/CA.crt -sess_in /tmp/session_in.pem \
                > "$stdout_resumed" 2>&1
            status=$?
        fi
        end_ns=$(date +%s%N)
        wall_elapsed_ms=$(( (end_ns - start_ns) / 1000000 ))
        elapsed_ms=$(( wall_elapsed_ms - 200 ))
        [ "$elapsed_ms" -lt 0 ] && elapsed_ms=0

        echo "${wave},resumed_handshake,${elapsed_ms},${status}" >> "$SUMMARY"
        if [ "$status" != "0" ]; then
            mkdir -p "$FAIL_LOG_DIR"
            cp "$stdout_resumed" "$FAIL_LOG_DIR/" 2>/dev/null || true
        fi
        rm -f "$stdout_resumed"
    else
        echo "${wave},resumed_handshake,NA,1" >> "$SUMMARY"
        echo "  [!] Vague $wave : pas de ticket de session sauvegardé, reprise ignorée."
    fi

    wave=$((wave + 1))
done

if [ -d "$FAIL_LOG_DIR" ]; then
    echo "Logs des handshakes en échec conservés dans : $FAIL_LOG_DIR"
fi
rm -rf "$RESULT_DIR"
