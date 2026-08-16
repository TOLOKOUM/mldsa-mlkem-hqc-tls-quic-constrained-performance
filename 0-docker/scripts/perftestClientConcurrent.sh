#!/bin/sh
# -------------------------------------------------------------------
# perftestClientConcurrent.sh
#
# Client pour tests de charge concurrente (scénario Ideal uniquement).
# Chaque client fait NUM_RUNS handshakes et écrit les durées dans un CSV.
#
# Sortie: ${RESULTS_DIR}/client_${CLIENT_ID}_${SIG_ALG}_${KEM_ALG}.csv
#         colonnes: run_id,duration_ms,success
#
# Note (apprentissage projet) : les codes de sortie de quics_connection ne
# sont pas fiables (exit=0 même en échec). Le marqueur fiable est la valeur
# "NaN" dans la ligne "Handshake duration". Ce script traite explicitement
# ce cas comme un échec plutôt que de le laisser fuiter dans le CSV comme
# un succès à durée vide.
# -------------------------------------------------------------------

if [ -z "$TC_DELAY" ]; then TC_DELAY=0ms; fi
if [ -z "$TC_LOSS" ]; then TC_LOSS="0%"; fi
if [ -z "$DOCKER_HOST" ]; then DOCKER_HOST="localhost"; fi
if [ -z "$USE_TLS" ]; then USE_TLS="true"; fi
if [ -z "$NUM_RUNS" ]; then NUM_RUNS=500; fi
if [ -z "$CERT_PATH" ]; then export CERT_PATH=/cert; fi
if [ -z "$MUTUAL" ]; then MUTUAL="false"; fi
if [ -z "$CLIENT_ID" ]; then CLIENT_ID=0; fi
if [ -z "$RESULTS_DIR" ]; then RESULTS_DIR=/results; fi

INTERFAZ="lo"
echo "[client-$CLIENT_ID] Applying netem rules to $INTERFAZ (delay=$TC_DELAY loss=$TC_LOSS)..."
tc qdisc add dev "$INTERFAZ" root netem delay $TC_DELAY loss $TC_LOSS 2>/dev/null || true

# -------------------------------------------------------------------
# KEM and Signature algorithm
# -------------------------------------------------------------------
if [ -z "$KEM_ALG" ]; then KEM_ALG=mlkem768; fi
export DEFAULT_GROUPS=$KEM_ALG

if [ -z "$SIG_ALG" ]; then export SIG_ALG=mldsa65; fi

echo "[client-$CLIENT_ID] SIG_ALG=$SIG_ALG KEM_ALG=$KEM_ALG PROTOCOL=$([ "$USE_TLS" = "true" ] && echo TLS || echo QUIC)"

# -------------------------------------------------------------------
# Output CSV file
# -------------------------------------------------------------------
mkdir -p "$RESULTS_DIR"
CSV_FILE="${RESULTS_DIR}/client_${CLIENT_ID}_${SIG_ALG}_${KEM_ALG}.csv"
echo "run_id,duration_ms,success" > "$CSV_FILE"

# -------------------------------------------------------------------
# parse_result: interprète la sortie d'un handshake.
#   $1 = sortie brute de la commande (OUTPUT)
#   $2 = durée wall-clock mesurée en fallback (DURATION)
# Renseigne les variables globales RESULT_DURATION et RESULT_SUCCESS.
# Toute anomalie (NaN, marqueur absent) est loggée explicitement sur
# stderr plutôt que traitée silencieusement.
# -------------------------------------------------------------------
parse_result() {
    output="$1"
    duration_fallback="$2"

    if printf '%s' "$output" | grep -q "Handshake duration"; then
        hs_line=$(printf '%s' "$output" | grep "Handshake duration" | head -n1)

        if printf '%s' "$hs_line" | grep -qi "nan"; then
            echo "[client-$CLIENT_ID] ANOMALY run $i: Handshake duration = NaN -> treated as FAILURE" >&2
            RESULT_DURATION=$duration_fallback
            RESULT_SUCCESS=0
            return
        fi

        hs_duration=$(printf '%s' "$hs_line" | grep -oE '[0-9]+(\.[0-9]+)?' | head -n1)
        if [ -z "$hs_duration" ]; then
            echo "[client-$CLIENT_ID] ANOMALY run $i: 'Handshake duration' present but unparsable: '$hs_line'" >&2
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

    echo "[client-$CLIENT_ID] ANOMALY run $i: no 'Handshake duration' marker and no error keyword — using wall-clock, success assumed" >&2
    RESULT_DURATION=$duration_fallback
    RESULT_SUCCESS=1
}

# -------------------------------------------------------------------
# Execute handshakes
# -------------------------------------------------------------------
i=1
while [ $i -le $NUM_RUNS ]; do
    START_TIME=$(date +%s%3N)

    if [ "$USE_TLS" = "true" ]; then
        if [ "$MUTUAL" = "true" ]; then
            OUTPUT=$(s_connection -connect "$DOCKER_HOST:4433" -new \
                -verify 1 -CAfile "$CERT_PATH/CA.crt" \
                -cert "$CERT_PATH/user.crt" -key "$CERT_PATH/user.key" 2>&1)
        else
            OUTPUT=$(s_connection -connect "$DOCKER_HOST:4433" -new \
                -verify 1 -CAfile "$CERT_PATH/CA.crt" 2>&1)
        fi
    else
        if [ -n "${SSL_DIR:-}" ]; then
            mkdir -p "$SSL_DIR"
            KEYLOG_PATH="${SSL_DIR}/sslkeys_client_${CLIENT_ID}_${SIG_ALG}_${KEM_ALG}.log"
            export SSLKEYLOGFILE="$KEYLOG_PATH"
        fi
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

    parse_result "$OUTPUT" "$DURATION"
    echo "$i,$RESULT_DURATION,$RESULT_SUCCESS" >> "$CSV_FILE"

    i=$((i + 1))
done

echo "[client-$CLIENT_ID] Done. Results in $CSV_FILE"
