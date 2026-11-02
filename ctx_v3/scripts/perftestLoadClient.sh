#!/bin/bash
###############################################################################
# perftestLoadClient.sh -- generateur de charge CONCURRENTE en boucle fermee (campagne v3).
#
# Pour chaque niveau de concurrence c (ordre aleatoire, graine LOAD_SEED), lance c "travailleurs" independants ;
# chacun enchaine, SANS temps de reflexion, des connexions COMPLETES (un processus `openssl s_connection` ou
# `quics_connection` par connexion, comme dans les campagnes v2) pendant LOAD_SECONDS secondes.
# Boucle fermee : c connexions en vol en permanence => debit X(c) et latence R(c) mesures a charge constante.
#
# Sortie (stdout, parsee par 13_analyse_extensions.py) :
#   LOADMETA nproc=<n> load_seconds=<s> trim_s=<s> timeout_s=<s> levels="..."
#   LEVEL conc=<c> t_start=<epoch_ms> t_end=<epoch_ms> order=<k>
#   LOADCONN conc=<c> worker=<w> t_end=<epoch_ms> ok=<0|1> hs_ms=<..> app_ms=<..> rx=<octets>
#   LEVELEND conc=<c> n_conn=<..> n_fail=<..>
#
# Le CPU cumule du conteneur client est echantillonne toutes les 0,5 s dans $TRACE_DIR/cli_cpu_trace.csv
# (le serveur ecrit srv_cpu_trace.csv, CPU_TRACE=1) : l'analyse REFUSE un niveau ou le client depasse 85 % de ses
# coeurs (le generateur serait alors le goulot, pas le serveur).
#
# Variables : CONC_LEVELS (defaut "1 2 4 8 16 32"), LOAD_SECONDS (20), LOAD_TRIM_S (2), LOAD_TIMEOUT_S (30),
#             LOAD_PAUSE_S (3), LOAD_SEED, + celles de perftestClientTlsQuic.sh (USE_TLS, DOCKER_HOST, CERT_PATH,
#             KEM_ALG, SIG_ALG, MUTUAL=false). Aucune authentification mutuelle.
###############################################################################
set -u

: "${USE_TLS:=true}"
: "${DOCKER_HOST:=localhost}"
: "${CERT_PATH:=/cert}"
: "${KEM_ALG:=mlkem512}"
: "${CONC_LEVELS:=1 2 4 8 16 32}"
: "${LOAD_SECONDS:=20}"
: "${LOAD_TRIM_S:=2}"
: "${LOAD_TIMEOUT_S:=30}"
: "${LOAD_PAUSE_S:=3}"
: "${LOAD_SEED:=1}"
: "${WARMUP_RUNS:=0}"
# Client de charge : "persistent" (DEFAUT, v3b) = UN processus multi-fils par niveau (tls_load_client / quics_connection en mode LOAD_CONC),
# "proc" = un processus par connexion (pilote du 27/10/2026 : le CPU client y depasse 50-120 ms/connexion et sature avant le serveur ;
# conserve pour memoire, NE PAS utiliser pour la mesure de saturation).
: "${LOAD_CLIENT:=persistent}"
export DEFAULT_GROUPS=$KEM_ALG

if [ "${MUTUAL:-false}" = "true" ]; then echo "Charge: authentification mutuelle non supportee" >&2; exit 1; fi

ms() { date +%s%3N; }

one_conn() {   # imprime la sortie brute du client (sans mesure derivee)
    if [ "$USE_TLS" = "true" ]; then
        timeout "${LOAD_TIMEOUT_S}s" openssl s_connection -connect "$DOCKER_HOST:4433" -new -verify 1 \
            -CAfile "$CERT_PATH/CA.crt" -www /payload.bin 2>&1
    else
        timeout "${LOAD_TIMEOUT_S}s" quics_connection -groups:"$KEM_ALG" -target:"$DOCKER_HOST" \
            -CAfile:"$CERT_PATH/CA.crt" 2>&1
    fi
}

worker() {     # worker <conc> <id> <deadline_ms> <outfile>
    local c="$1" w="$2" dl="$3" out="$4" o hs app rx ok t
    : > "$out"
    while [ "$(ms)" -lt "$dl" ]; do
        o="$(one_conn)"
        t="$(ms)"
        hs="$(printf '%s\n' "$o" | sed -n 's/^Handshake duration: \([0-9.]*\) ms.*/\1/p' | head -1)"
        app="$(printf '%s\n' "$o" | sed -n 's/^App-ready duration: \([0-9.]*\) ms.*/\1/p' | head -1)"
        rx="$(printf '%s\n' "$o" | sed -n 's/^Rx-bytes: \([0-9]*\).*/\1/p' | head -1)"
        ok=1
        if [ -z "$hs" ] || [ -z "$app" ]; then ok=0; hs="NaN"; app="NaN"; fi
        echo "LOADCONN conc=$c worker=$w t_end=$t ok=$ok hs_ms=$hs app_ms=$app rx=${rx:-NA}" >> "$out"
    done
}

# --- trace CPU du conteneur client -------------------------------------------------------------------------------
CPU_PID=""
if [ -n "${TRACE_DIR:-}" ]; then
    mkdir -p "$TRACE_DIR"
    _CT="$TRACE_DIR/cli_cpu_trace.csv"
    echo "t_epoch,cpu_usec" > "$_CT"
    (
      while :; do
        _u=$(awk '/^usage_usec/{print $2}' /sys/fs/cgroup/cpu.stat 2>/dev/null)
        [ -n "$_u" ] || _u=$(( $(cat /sys/fs/cgroup/cpuacct/cpuacct.usage 2>/dev/null || echo 0) / 1000 ))
        echo "$(date +%s.%N),$_u" >> "$_CT"
        sleep 0.5
      done
    ) &
    CPU_PID=$!
fi

if [ "$LOAD_CLIENT" = "persistent" ] && [ "$USE_TLS" = "true" ] && ! command -v tls_load_client >/dev/null 2>&1; then
    echo "Charge: tls_load_client absent de l'image (utiliser l'image v3b : docker build -f Dockerfile.v3b) ; LOAD_CLIENT=proc deconseille" >&2; exit 1
fi
if [ "$LOAD_CLIENT" = "persistent" ] && [ "$USE_TLS" != "true" ] && ! command -v quics_load >/dev/null 2>&1; then
    echo "Charge: quics_load absent de l'image (utiliser l'image v3b : docker build -f Dockerfile.v3b)" >&2; exit 1
fi
echo "LOADMETA client=$LOAD_CLIENT nproc=$(nproc) load_seconds=$LOAD_SECONDS trim_s=$LOAD_TRIM_S timeout_s=$LOAD_TIMEOUT_S levels=\"$CONC_LEVELS\" kem=$KEM_ALG sig=${SIG_ALG:-NA} proto=$([ "$USE_TLS" = "true" ] && echo tls || echo quic)"

# --- echauffement : quelques connexions jetees (cles, caches, chargement des modules) --------------------------------
w=1
while [ "$w" -le "$WARMUP_RUNS" ]; do one_conn >/dev/null 2>&1; w=$((w + 1)); done

# --- ordre aleatoire des niveaux (graine) -----------------------------------------------------------------------------
mapfile -t LEVELS < <(printf '%s\n' $CONC_LEVELS | shuf --random-source=<(openssl enc -aes-256-ctr -pass pass:"$LOAD_SEED" -nosalt </dev/zero 2>/dev/null))

TMPD="$(mktemp -d)"
k=0
for c in "${LEVELS[@]}"; do
    k=$((k + 1))
    t0="$(ms)"
    dl=$(( t0 + LOAD_SECONDS * 1000 ))
    echo "LEVEL conc=$c t_start=$t0 t_end=$dl order=$k"
    pids=()
    if [ "$LOAD_CLIENT" = "persistent" ]; then
        # un seul processus, c fils, boucle fermee ; imprime les lignes LOADCONN a la fin
        if [ "$USE_TLS" = "true" ]; then
            tls_load_client -connect "$DOCKER_HOST:4433" -CAfile "$CERT_PATH/CA.crt" -groups "$KEM_ALG" \
                -conc "$c" -seconds "$LOAD_SECONDS" -timeout_s "$LOAD_TIMEOUT_S" > "$TMPD/w_${c}_1.log" 2> "$TMPD/err_${c}.log"
        else
            LOAD_CONC="$c" LOAD_SECONDS="$LOAD_SECONDS" LOAD_TIMEOUT_S="$LOAD_TIMEOUT_S" \
                quics_load -groups:"$KEM_ALG" -target:"$DOCKER_HOST" -CAfile:"$CERT_PATH/CA.crt" > "$TMPD/w_${c}_1.log" 2> "$TMPD/err_${c}.log"
        fi
        [ -s "$TMPD/err_${c}.log" ] && sed 's/^/[charge c='"$c"'] /' "$TMPD/err_${c}.log" >&2
    else
        for ((i = 1; i <= c; i++)); do
            worker "$c" "$i" "$dl" "$TMPD/w_${c}_${i}.log" &
            pids+=($!)
        done
        for p in "${pids[@]}"; do wait "$p" 2>/dev/null; done
    fi
    cat "$TMPD"/w_${c}_*.log 2>/dev/null
    n=$(cat "$TMPD"/w_${c}_*.log 2>/dev/null | wc -l)
    nf=$(cat "$TMPD"/w_${c}_*.log 2>/dev/null | grep -c ' ok=0 ' || true)
    echo "LEVELEND conc=$c n_conn=$n n_fail=$nf"
    rm -f "$TMPD"/w_${c}_*.log
    sleep "$LOAD_PAUSE_S"
done

if [ -n "$CPU_PID" ]; then kill "$CPU_PID" 2>/dev/null || true; wait "$CPU_PID" 2>/dev/null || true; fi
rm -rf "$TMPD"
echo "LOADDONE"
