#!/bin/sh
# perftestClientConcurrent.sh — Test de charge concurrente via le conteneur client Docker

if [ -z "$TC_DELAY" ]; then TC_DELAY=0ms; fi
if [ -z "$TC_LOSS" ]; then TC_LOSS="0%"; fi
if [ -z "$USE_TLS" ]; then USE_TLS="true"; fi
if [ -z "$CERT_PATH" ]; then CERT_PATH=/cert; fi
if [ -z "$MUTUAL" ]; then MUTUAL="true"; fi
if [ -z "$KEM_ALG" ]; then KEM_ALG=mlkem512; fi
export DEFAULT_GROUPS=$KEM_ALG
if [ -z "$SIG_ALG" ]; then SIG_ALG=mldsa44; fi
if [ -z "$CONCURRENCY" ]; then CONCURRENCY=5; fi
if [ -z "$WAVES" ]; then WAVES=10; fi

RESULT_DIR="/tmp/concurrent_results_$$"
rm -rf "$RESULT_DIR"
mkdir -p "$RESULT_DIR"
FAIL_LOG_DIR="/tmp/concurrent_failed_logs_$$"

PROTO_LABEL="quic"
[ "$USE_TLS" = "true" ] && PROTO_LABEL="tls"

run_one_connection() {
    wave="$1"
    worker="$2"
    outfile="$RESULT_DIR/w${wave}_c${worker}.csv"
    stdout_file="$RESULT_DIR/stdout_w${wave}_c${worker}.log"
    start_ns=$(date +%s%N)

    # Exécution de la connexion DANS le réseau Docker 'localNet' ciblant 'servidor'
    if [ "$USE_TLS" = "true" ]; then
        if [ "$MUTUAL" = "true" ]; then
            docker run --rm --network localNet -v cert:/cert \
                -e DEFAULT_GROUPS="$KEM_ALG" -e SIG_ALG="$SIG_ALG" \
                oqs-client openssl s_connection -connect servidor:4433 -new -verify 1 \
                -CAfile /cert/CA.crt -cert /cert/user.crt -key /cert/user.key \
                > "$stdout_file" 2>&1
            status=$?
        else
            docker run --rm --network localNet -v cert:/cert \
                -e DEFAULT_GROUPS="$KEM_ALG" -e SIG_ALG="$SIG_ALG" \
                oqs-client openssl s_connection -connect servidor:4433 -new -verify 1 \
                -CAfile /cert/CA.crt > "$stdout_file" 2>&1
            status=$?
        fi
    else
        if [ "$MUTUAL" = "true" ]; then
            docker run --rm --network localNet -v cert:/cert \
                -e DEFAULT_GROUPS="$KEM_ALG" -e SIG_ALG="$SIG_ALG" \
                oqs-client quics_connection -groups:"$KEM_ALG" -target:servidor \
                -CAfile:/cert/CA.crt -cert /cert/user.crt -key /cert/user.key \
                > "$stdout_file" 2>&1
            status=$?
        else
            docker run --rm --network localNet -v cert:/cert \
                -e DEFAULT_GROUPS="$KEM_ALG" -e SIG_ALG="$SIG_ALG" \
                oqs-client quics_connection -groups:"$KEM_ALG" -target:servidor \
                -CAfile:/cert/CA.crt > "$stdout_file" 2>&1
            status=$?
        fi
    fi

    end_ns=$(date +%s%N)
    wall_elapsed_ms=$(( (end_ns - start_ns) / 1000000 ))

    hs_value=$(grep -o 'Handshake duration:[[:space:]]*[A-Za-z0-9.]*' "$stdout_file" 2>/dev/null \
        | head -1 | awk -F: '{print $2}' | tr -d ' ms')

    if [ -n "$hs_value" ] && [ "$hs_value" != "NaN" ]; then
        elapsed_ms="$hs_value"
        status=0
    else
        elapsed_ms="$wall_elapsed_ms"
    fi

    echo "${wave},${worker},${start_ns},${end_ns},${elapsed_ms},${status}" > "$outfile"
    if [ "$status" != "0" ]; then
        mkdir -p "$FAIL_LOG_DIR"
        cp "$stdout_file" "$FAIL_LOG_DIR/" 2>/dev/null || true
    fi
    rm -f "$stdout_file"
}

wave=1
while [ "$wave" -le "$WAVES" ]; do
    echo "  -> Vague $wave/$WAVES ($CONCURRENCY connexions simultanées)"
    worker=1
    while [ "$worker" -le "$CONCURRENCY" ]; do
        run_one_connection "$wave" "$worker" &
        worker=$((worker + 1))
    done
    wait
    wave=$((wave + 1))
done

SUMMARY="/tmp/concurrent_summary_${PROTO_LABEL}_${SIG_ALG}_${KEM_ALG}_c${CONCURRENCY}.csv"
echo "wave,worker,start_ns,end_ns,elapsed_ms,exit_status" > "$SUMMARY"
cat "$RESULT_DIR"/*.csv >> "$SUMMARY" 2>/dev/null

n_total=$(( WAVES * CONCURRENCY ))
n_fail=$(LC_ALL=C awk -F, 'NR>1 && $6 != 0 {c++} END{print c+0}' "$SUMMARY")
echo ""
echo "Résultats : $SUMMARY"
echo "Total connexions : $n_total | Échecs : $n_fail"
if [ -d "$FAIL_LOG_DIR" ]; then
    echo "Logs des connexions en échec conservés dans : $FAIL_LOG_DIR"
fi

rm -rf "$RESULT_DIR"
