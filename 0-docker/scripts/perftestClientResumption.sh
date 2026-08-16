#!/bin/sh
# -------------------------------------------------------------------
# perftestClientResumption.sh
# Approche "batch séparés" — scénario Idéal
#
# Phase 1 : N full handshakes consécutifs
#           - Chaque handshake établit une nouvelle session TLS/QUIC
#           - En TLS 1.3, un léger délai est nécessaire avant d'envoyer 'Q'
#             afin de laisser le temps d'intercepter le NewSessionTicket
#             asynchrone et d'écrire le fichier de session (-sess_out).
#
# Phase 2 : N resumed handshakes consécutifs
#           - Chaque handshake tente de charger la session du dernier full (-sess_in)
# -------------------------------------------------------------------

if [ -z "$TC_DELAY" ]; then TC_DELAY=0ms; fi
if [ -z "$TC_LOSS" ]; then TC_LOSS="0%"; fi
if [ -z "$DOCKER_HOST" ]; then DOCKER_HOST="localhost"; fi
if [ -z "$USE_TLS" ]; then USE_TLS="true"; fi
if [ -z "$NUM_RUNS" ]; then NUM_RUNS=500; fi         # N par phase
if [ -z "$CERT_PATH" ]; then export CERT_PATH=/cert; fi
if [ -z "$MUTUAL" ]; then MUTUAL="false"; fi
if [ -z "$CLIENT_ID" ]; then CLIENT_ID=0; fi
if [ -z "$RESULTS_DIR" ]; then RESULTS_DIR=/results; fi

INTERFAZ="lo"
echo "[client-$CLIENT_ID] Application netem a $INTERFAZ (delay=$TC_DELAY loss=$TC_LOSS)..."
tc qdisc add dev "$INTERFAZ" root netem delay $TC_DELAY loss $TC_LOSS 2>/dev/null || true

if [ -z "$KEM_ALG" ]; then KEM_ALG=mlkem768; fi
export DEFAULT_GROUPS=$KEM_ALG

if [ -z "$SIG_ALG" ]; then export SIG_ALG=mldsa65; fi

echo "[client-$CLIENT_ID] SIG=$SIG_ALG KEM=$KEM_ALG PROTO=$([ "$USE_TLS" = "true" ] && echo TLS || echo QUIC)"

SESSION_FILE="/tmp/session_${CLIENT_ID}.pem"

mkdir -p "$RESULTS_DIR"
CSV_FILE="${RESULTS_DIR}/resumption_${CLIENT_ID}_${SIG_ALG}_${KEM_ALG}.csv"
echo "run_id,handshake_type,duration_ms,success" > "$CSV_FILE"

# -------------------------------------------------------------------
# parse_result: interprète la sortie d'un handshake.
# -------------------------------------------------------------------
parse_result() {
    output="$1"
    duration_fallback="$2"
    run_label="$3"

    if printf '%s' "$output" | grep -q "Handshake duration"; then
        hs_line=$(printf '%s' "$output" | grep "Handshake duration" | head -n1)

        if printf '%s' "$hs_line" | grep -qi "nan"; then
            echo "[client-$CLIENT_ID] ANOMALY run $run_label: Handshake duration = NaN -> treated as FAILURE" >&2
            RESULT_DURATION=$duration_fallback
            RESULT_SUCCESS=0
            return
        fi

        hs_duration=$(printf '%s' "$hs_line" | grep -oE '[0-9]+(\.[0-9]+)?' | head -n1)
        if [ -z "$hs_duration" ]; then
            echo "[client-$CLIENT_ID] ANOMALY run $run_label: 'Handshake duration' present but unparsable: '$hs_line'" >&2
            RESULT_DURATION=$duration_fallback
            RESULT_SUCCESS=0
            return
        fi

        RESULT_DURATION=$hs_duration
        RESULT_SUCCESS=1
        return
    fi

    if printf '%s' "$output" | grep -qi "error\|failed\|abort"; then
        RESULT_DURATION=$duration_fallback
        RESULT_SUCCESS=0
        return
    fi

    RESULT_DURATION=$duration_fallback
    RESULT_SUCCESS=1
}

# -------------------------------------------------------------------
# Phase 1 : N Full Handshakes
# -------------------------------------------------------------------
echo "[client-$CLIENT_ID] Phase 1: $NUM_RUNS full handshakes..."

i=1
while [ $i -le $NUM_RUNS ]; do
    START_TIME=$(date +%s%3N)
    HS_TYPE="full"

    if [ "$USE_TLS" = "true" ]; then
        if [ "$MUTUAL" = "true" ]; then
            OUTPUT=$( (sleep 0.2; echo 'Q') | openssl s_client -connect "$DOCKER_HOST:4433" \
                -groups "$KEM_ALG" -sigalgs "$SIG_ALG" \
                -CAfile "$CERT_PATH/CA.crt" \
                -cert "$CERT_PATH/user.crt" -key "$CERT_PATH/user.key" \
                -sess_out "$SESSION_FILE" 2>&1)
        else
            OUTPUT=$( (sleep 0.2; echo 'Q') | openssl s_client -connect "$DOCKER_HOST:4433" \
                -groups "$KEM_ALG" -sigalgs "$SIG_ALG" \
                -CAfile "$CERT_PATH/CA.crt" \
                -sess_out "$SESSION_FILE" 2>&1)
        fi
    else
        if [ "$MUTUAL" = "true" ]; then
            OUTPUT=$(quics_connection -groups:"$KEM_ALG" -target:"$DOCKER_HOST" \
                -CAfile:"$CERT_PATH/CA.crt" \
                -cert "$CERT_PATH/user.crt" -key "$CERT_PATH/user.key" 2>&1)
        else
            OUTPUT=$(quics_connection -groups:"$KEM_ALG" -target:"$DOCKER_HOST" \
                -CAfile:"$CERT_PATH/CA.crt" 2>&1)
        fi
    fi

    END_TIME=$(date +%s%3N)
    DURATION=$((END_TIME - START_TIME))

    parse_result "$OUTPUT" "$DURATION" "$i"
    echo "$i,$HS_TYPE,$RESULT_DURATION,$RESULT_SUCCESS" >> "$CSV_FILE"

    i=$((i + 1))
done

echo "[client-$CLIENT_ID] Phase 1 terminee. Fichier session enregistre: $SESSION_FILE"

# -------------------------------------------------------------------
# Phase 2 : N Resumed Handshakes
# -------------------------------------------------------------------
echo "[client-$CLIENT_ID] Phase 2: $NUM_RUNS resumed handshakes..."

j=1
while [ $j -le $NUM_RUNS ]; do
    RUN_ID=$((NUM_RUNS + j))
    START_TIME=$(date +%s%3N)
    HS_TYPE="resumed"

    if [ "$USE_TLS" = "true" ]; then
        if [ -f "$SESSION_FILE" ] && [ -s "$SESSION_FILE" ]; then
            if [ "$MUTUAL" = "true" ]; then
                OUTPUT=$( (sleep 0.2; echo 'Q') | openssl s_client -connect "$DOCKER_HOST:4433" \
                    -groups "$KEM_ALG" -sigalgs "$SIG_ALG" \
                    -CAfile "$CERT_PATH/CA.crt" \
                    -cert "$CERT_PATH/user.crt" -key "$CERT_PATH/user.key" \
                    -sess_in "$SESSION_FILE" -sess_out "$SESSION_FILE" 2>&1)
            else
                OUTPUT=$( (sleep 0.2; echo 'Q') | openssl s_client -connect "$DOCKER_HOST:4433" \
                    -groups "$KEM_ALG" -sigalgs "$SIG_ALG" \
                    -CAfile "$CERT_PATH/CA.crt" \
                    -sess_in "$SESSION_FILE" -sess_out "$SESSION_FILE" 2>&1)
            fi
        else
            echo "[client-$CLIENT_ID] ANOMALY run $RUN_ID: pas de fichier session valide trouve, fallback full handshake" >&2
            HS_TYPE="full"
            if [ "$MUTUAL" = "true" ]; then
                OUTPUT=$( (sleep 0.2; echo 'Q') | openssl s_client -connect "$DOCKER_HOST:4433" \
                    -groups "$KEM_ALG" -sigalgs "$SIG_ALG" \
                    -CAfile "$CERT_PATH/CA.crt" \
                    -cert "$CERT_PATH/user.crt" -key "$CERT_PATH/user.key" \
                    -sess_out "$SESSION_FILE" 2>&1)
            else
                OUTPUT=$( (sleep 0.2; echo 'Q') | openssl s_client -connect "$DOCKER_HOST:4433" \
                    -groups "$KEM_ALG" -sigalgs "$SIG_ALG" \
                    -CAfile "$CERT_PATH/CA.crt" \
                    -sess_out "$SESSION_FILE" 2>&1)
            fi
        fi
    else
        # QUIC resumption via -resumption:1
        if [ "$MUTUAL" = "true" ]; then
            OUTPUT=$(quics_connection -groups:"$KEM_ALG" -target:"$DOCKER_HOST" \
                -CAfile:"$CERT_PATH/CA.crt" \
                -cert "$CERT_PATH/user.crt" -key "$CERT_PATH/user.key" \
                -resumption:1 2>&1)
        else
            OUTPUT=$(quics_connection -groups:"$KEM_ALG" -target:"$DOCKER_HOST" \
                -CAfile:"$CERT_PATH/CA.crt" \
                -resumption:1 2>&1)
        fi
    fi

    END_TIME=$(date +%s%3N)
    DURATION=$((END_TIME - START_TIME))

    parse_result "$OUTPUT" "$DURATION" "$RUN_ID"
    echo "$RUN_ID,$HS_TYPE,$RESULT_DURATION,$RESULT_SUCCESS" >> "$CSV_FILE"

    j=$((j + 1))
done

echo "[client-$CLIENT_ID] Termine. Full=$NUM_RUNS Resumed=$NUM_RUNS. Resultats: $CSV_FILE"
