#!/bin/sh

# ---------------------------
# Set network DELAY and LOSS
# ---------------------------
set -e

#if [ "x$TC_DELAY" == "x" ]; then
if [ -z "$TC_DELAY" ]; then
    TC_DELAY=0ms
fi    

#if [ "x$TC_LOSS" == "x" ]; then
if [ -z "$TC_LOSS" ]; then
    TC_LOSS="0%"
fi 

if [ -z "$DOCKER_HOST" ]; then
    DOCKER_HOST="localhost"
fi 

if [ -z "$USE_TLS" ]; then
    USE_TLS="true"
fi 

if [ -z "$NUM_RUNS" ]; then
    NUM_RUNS=500
fi 

if [ -z "$CERT_PATH" ]; then
    export CERT_PATH=/cert
fi

if [ -z "$MUTUAL" ]; then
     MUTUAL="true"
fi

# ---------------------------------------------------------------------------
# Budget d'échec commun TLS/QUIC (résout le point 4 du rejet : "timeouts non
# harmonisés"). Avant ce patch, TLS n'avait AUCUNE échéance explicite
# (s_connection retransmettait/bloquait indéfiniment jusqu'à succès), alors
# que QUIC dépendait de la logique de retry/timeout interne de MsQuic. On
# force maintenant EXACTEMENT le même budget mur-à-mur pour les deux, et on
# produit le MÊME marqueur d'échec ("Handshake duration: NaN ms") déjà
# reconnu par scripts_analysis/parse_handshake_logs.py pour QUIC, afin que
# TLS et QUIC soient comparés sous une politique de timeout identique et
# que l'exclusion des échecs (§5.4 de l'article) s'applique uniformément
# aux deux séries de latences.
#
# Valeur par défaut : 20x le pire mean observé dans ce dataset pour un
# handshake complet et réussi (GE-Unstable, TLS, ML-DSA87+HQC256 = 7.3s,
# cf. Table net-sensitivity de l'article) arrondi à une marge large pour ne
# pas couper des handshakes légitimement lents en burst-loss. Surchargeable
# via HANDSHAKE_TIMEOUT_S pour un run de calibration si besoin.
if [ -z "$HANDSHAKE_TIMEOUT_S" ]; then
    HANDSHAKE_TIMEOUT_S=150
fi
export HANDSHAKE_TIMEOUT_S
echo "Handshake timeout budget: ${HANDSHAKE_TIMEOUT_S}s (identique TLS/QUIC)"
echo "v3: RESUME=${RESUME:-0} ZERORTT_ARM=${ZERORTT_ARM:-0} CERT_COMP=${CERT_COMP:-default}"

INTERFAZ="lo"

echo "Applying netem rules to $INTERFAZ..."
tc qdisc add dev "$INTERFAZ" root netem delay $TC_DELAY loss $TC_LOSS

echo "Showing qdisc status for the interface: $INTERFAZ"
tc -s qdisc show dev "$INTERFAZ"


# ---------------------------
# Set KEM and Signature algorithm
# ---------------------------
# Optionally set KEM to one defined in https://github.com/open-quantum-safe/oqs-provider#algorithms
#if [ "x$KEM_ALG" == "x" ]; then
if [ -z "$KEM_ALG" ]; then
    KEM_ALG=mlkem512
fi
export DEFAULT_GROUPS=$KEM_ALG

# Optionally set SIG to one defined in https://github.com/open-quantum-safe/oqs-provider#algorithms
#if [ "x$SIG_ALG" == "x" ]; then
if [ -z "$SIG_ALG" ]; then
	export SIG_ALG=mldsa44
fi

# Optionally set TEST_TIME
#if [ "x$TEST_TIME" == "x" ]; then
if [ -z "$TEST_TIME" ]; then
	export TEST_TIME=1
fi

# ---------------------------
# Create certificates 
# ---------------------------
# Optionally set server certificate alg to one defined in https://github.com/open-quantum-safe/oqs-provider#algorithms
# The root CA's signature alg remains as set when building the image
#CERT_PATH=/opt/certs

echo "Running $0 with SIG_ALG=$SIG_ALG and KEM_ALG=$KEM_ALG"


# ---------------------------
# Launch TLS OR QUIC client
# ---------------------------
# Start a TLS1.3 test server based on OpenSSL accepting only the specified KEM_ALG
# The env var DEFAULT_GROUPS activates the required Group via the system openssl.cnf:
# we put it on the command line to check for possible typos otherwise silently discarded:

NUM_RUNS=$NUM_RUNS

# ---------------------------------------------------------------------------
# Execute UNE connexion avec le budget d'échec commun et garantit que le log
# contient TOUJOURS exactement une ligne "Handshake duration" et une ligne
# "App-ready duration" par exécution.
#
# Remplace l'ancien `cmd || echo "...NaN..."$'\n'"..."` :
#  - $'\n' n'existe pas dans dash (/bin/sh Debian/Ubuntu) : le marqueur
#    sortait sur UNE ligne avec un "\n" littéral ;
#  - après un échec partiel (ex. "Handshake duration: 211 ms" suivi de
#    "App-ready duration: NaN ... request failed"), le `|| echo` ajoutait
#    deux lignes NaN qui écrasaient la vraie mesure au parsing.
# Ici, seules les lignes MANQUANTES sont complétées par un marqueur NaN.
# ---------------------------------------------------------------------------
run_measured() {
    _rm_rc=0
    _rm_out=$(timeout "${HANDSHAKE_TIMEOUT_S}"s "$@" 2>&1) || _rm_rc=$?
    if [ -n "$_rm_out" ]; then
        printf '%s\n' "$_rm_out"
    fi
    if [ "$_rm_rc" -eq 124 ]; then
        _rm_why="client-side timeout after ${HANDSHAKE_TIMEOUT_S}s"
    else
        _rm_why="no measurement, exit code ${_rm_rc}"
    fi
    if ! printf '%s\n' "$_rm_out" | grep -q 'Handshake duration:'; then
        printf 'Handshake duration: NaN ms  (%s)\n' "$_rm_why"
    fi
    if ! printf '%s\n' "$_rm_out" | grep -q 'App-ready duration:'; then
        printf 'App-ready duration: NaN ms  (%s)\n' "$_rm_why"
    fi
    return 0
}

# ---------------------------------------------------------------------------
# one_connection <label> : UNE connexion mesuree (TLS ou QUIC, mutual ou single).
# Factorisee pour etre appelee a l'identique par le WARM-UP et par la boucle
# mesuree. Le format "Execution <n> - ..." est celui attendu par logs_to_csv.py.
# ---------------------------------------------------------------------------
one_connection_base() {
    _oc_i="$1"
    if [ "$USE_TLS" = "true" ]; then
         # -www /payload.bin : echange applicatif (reponse fixe de 100 octets
         # servie par s_server -WWW) => "App-ready duration", metrique PRINCIPALE.
         if [ "$MUTUAL" = "true" ]; then
           echo "Execution $_oc_i - TLS Mutual"; mode_line
           run_measured openssl s_connection -connect $DOCKER_HOST:4433 -new  -verify 1 -CAfile $CERT_PATH/CA.crt -cert $CERT_PATH/user.crt  -key $CERT_PATH/user.key -www /payload.bin
         else
           echo "Execution $_oc_i - TLS Single"; mode_line
           run_measured openssl s_connection -connect $DOCKER_HOST:4433 -new -verify 1 -CAfile $CERT_PATH/CA.crt -www /payload.bin
         fi
    else
        if [ -n "${SSL_DIR:-}" ]; then
            mkdir -p "$SSL_DIR"
            KEYLOG_PATH="${SSL_DIR}/sslkeys_client_${SIG_ALG}_${KEM_ALG}.log"
            if [ "$_oc_i" = "1" ]; then
                echo "QUIC keys will be stored in: $KEYLOG_PATH"
            fi
            export SSLKEYLOGFILE="$KEYLOG_PATH"
        fi
        if [ "$MUTUAL" = "true" ]; then
           echo "Execution $_oc_i - QUIC Mutual"; mode_line
           run_measured quics_connection -groups:$KEM_ALG -target:$DOCKER_HOST -CAfile:"$CERT_PATH/CA.crt" -cert $CERT_PATH/user.crt  -key $CERT_PATH/user.key
         else
           echo "Execution $_oc_i - QUIC Single"; mode_line
           run_measured quics_connection -groups:$KEM_ALG -target:$DOCKER_HOST -CAfile:"$CERT_PATH/CA.crt"
         fi
    fi
}

# ---------------------------------------------------------------------------
# CAMPAGNE v3 : alternance connexion complete / connexion reprise (RESUME=1).
# Variables (absentes en v2 => comportement v2 inchange quand RESUME n'est pas defini) :
#   RESUME=1       impaires = handshake COMPLET qui sauvegarde son ticket ; paires = REPRISE avec ce ticket.
#                  Chaque reprise utilise le ticket de la connexion complete qui la precede immediatement
#                  (un ticket neuf par reprise : pas de rejeu d'un ticket deja consomme).
#   ZERORTT_ARM=1  (QUIC uniquement, exploratoire) la reprise envoie la requete en 0-RTT.
#   CERT_COMP      (none|zlib|brotli|zstd) lu directement par s_connection / la bibliotheque MsQuic.
# Le mode REEL (reprise obtenue ou non) est rapporte par le client ("Resumed: 0|1") : le mode prevu ("Mode:")
# n'est qu'une etiquette ; l'analyse ne se fie qu'a "Resumed:".
# ---------------------------------------------------------------------------
TICKET_FILE="/tmp/ticket_$$.bin"
mode_line() { if [ -n "${MODE_TAG:-}" ]; then echo "Mode: ${MODE_TAG}"; fi; }
one_connection() {
    _oc_w="$1"
    MODE_TAG=""
    unset SESS_IN SESS_OUT TICKET_IN TICKET_OUT ZERORTT 2>/dev/null || true
    if [ "${RESUME:-0}" = "1" ]; then
        case "$_oc_w" in
            W*) MODE_TAG="warmup" ;;
            *)
                if [ $(( _oc_w % 2 )) -eq 1 ]; then
                    rm -f "$TICKET_FILE"
                    MODE_TAG="full"
                    if [ "$USE_TLS" = "true" ]; then export SESS_OUT="$TICKET_FILE"; else export TICKET_OUT="$TICKET_FILE"; fi
                else
                    MODE_TAG="resumed"
                    if [ "$USE_TLS" = "true" ]; then export SESS_IN="$TICKET_FILE"; else export TICKET_IN="$TICKET_FILE"; fi
                    if [ "${ZERORTT_ARM:-0}" = "1" ] && [ "$USE_TLS" != "true" ]; then export ZERORTT=1; MODE_TAG="resumed_0rtt"; fi
                fi ;;
        esac
    fi
    one_connection_base "$_oc_w"
    MODE_TAG=""
    unset SESS_IN SESS_OUT TICKET_IN TICKET_OUT ZERORTT 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# WARM-UP (critique 1 de l'AE : etat processeur/cache/thermique) : WARMUP_RUNS
# connexions JETEES avant la mesure (defaut 0 = comportement historique).
# Les conteneurs sont recrees pour chaque paire : la premiere connexion paie
# les defauts de cache froid, le chargement des modules, la resolution de
# symboles, etc. Sortie entierement supprimee (aucune ligne ne peut polluer
# le log mesure) ; effectue AVANT le demarrage de tcpdump.
# ---------------------------------------------------------------------------
WARMUP_RUNS="${WARMUP_RUNS:-0}"
_w=1
while [ "$_w" -le "$WARMUP_RUNS" ]; do
    one_connection "W${_w}" >/dev/null 2>&1
    _w=$((_w + 1))
done
echo "Warm-up: ${WARMUP_RUNS} connexion(s) jetee(s) avant mesure"

# ── Sous-plan mecanistique (point 3 du prescreen TDSC, TDSC-2026-09-3862) :
# UNE SEULE capture pcap pour tout le bloc (pas une par connexion). Trois
# versions successives d'une capture par-connexion ont echoue en pratique
# (constate le 28-29/09) : redemarrer tcpdump 500 fois est structurellement
# trop lent par rapport a la duree d'une connexion rapide (~210ms). Ici :
# capture continue sur toute la duree du bloc (un seul demarrage/arret, cout
# amorti sur 500 connexions), et la fenetre temporelle [debut,fin] de CHAQUE
# connexion est enregistree a part (conn_windows.csv). analyze_mechanism.py
# rattache ensuite chaque FLUX (tcp.stream / udp.stream) a l'execution dont
# la fenetre contient son premier paquet : c'est independant du decalage
# d'horodatage cree par netem (les paquets client sont horodates apres le
# delai netem, donc APRES la fin du processus pour les derniers d'entre eux).
#
# Variables : CAPTURE_IF (defaut eth0), TCPDUMP_FLUSH_S (defaut 1 s : marge
# avant l'arret pour laisser sortir les derniers paquets retardes par netem).
CAPTURE_IF="${CAPTURE_IF:-eth0}"
TCPDUMP_FLUSH_S="${TCPDUMP_FLUSH_S:-1}"
TCPDUMP_PID=""
if [ "${PER_CONN_PCAP:-0}" = "1" ] && [ -n "${SSL_DIR:-}" ]; then
    mkdir -p "$SSL_DIR"
    BLOCK_PCAP="${SSL_DIR}/block.pcap"
    WINDOWS_CSV="${SSL_DIR}/conn_windows.csv"
    TCPDUMP_ERR="${SSL_DIR}/tcpdump.err"

    if ! command -v tcpdump >/dev/null 2>&1; then
        echo "ERREUR FATALE: PER_CONN_PCAP=1 mais tcpdump est introuvable dans l'image." >&2
        exit 1
    fi
    # Les fenetres exigent une horloge a la nanoseconde (GNU date).
    case "$(date +%s.%N)" in
        *N*) echo "ERREUR FATALE: 'date +%s.%N' non supporte (busybox ?) : conn_windows.csv serait faux." >&2
             exit 1 ;;
    esac

    rm -f "$BLOCK_PCAP" "$WINDOWS_CSV" "$TCPDUMP_ERR"
    echo "execution,t_start_epoch,t_end_epoch" > "$WINDOWS_CSV"
    # LD_LIBRARY_PATH (=/opt/oqssa/lib64:...) fait charger a tcpdump la libcrypto d'OpenSSL maison
    # (compilee no-deprecated, sans MD5_Init) -> "undefined symbol: MD5_Init". On l'ecarte pour tcpdump seul.
    env -u LD_LIBRARY_PATH tcpdump -i "$CAPTURE_IF" -U -n -w "$BLOCK_PCAP" "port 4433" >/dev/null 2>"$TCPDUMP_ERR" &
    TCPDUMP_PID=$!

    # Pret = tcpdump a ecrit "listening on" (socket de capture actif), ce qui
    # est plus fiable que "fichier non vide" (en-tete de 24 octets ecrit avant
    # que la capture ne soit reellement armee). Attente max 5 s.
    _waited=0
    while [ "$_waited" -lt 250 ]; do
        if grep -q "listening on" "$TCPDUMP_ERR" 2>/dev/null; then break; fi
        if ! kill -0 "$TCPDUMP_PID" 2>/dev/null; then break; fi
        sleep 0.02
        _waited=$((_waited + 1))
    done
    if ! kill -0 "$TCPDUMP_PID" 2>/dev/null || ! grep -q "listening on" "$TCPDUMP_ERR" 2>/dev/null; then
        echo "ERREUR FATALE: tcpdump n'a pas demarre sur ${CAPTURE_IF}. Sortie :" >&2
        cat "$TCPDUMP_ERR" >&2 || true
        exit 1
    fi
    sleep 0.2
    echo "tcpdump actif sur ${CAPTURE_IF} -> $BLOCK_PCAP"
fi

i=1
while [ $i -le $NUM_RUNS ]
do
    if [ -n "$TCPDUMP_PID" ]; then
        T_START=$(date +%s.%N)
    fi

    one_connection "$i"

    if [ -n "$TCPDUMP_PID" ]; then
        T_END=$(date +%s.%N)
        echo "${i},${T_START},${T_END}" >> "$WINDOWS_CSV"
    fi

    i=$((i + 1))
done

if [ -n "$TCPDUMP_PID" ]; then
    # Marge avant l'arret : les derniers paquets client (ACK final, RST) sont
    # horodates APRES le delai netem et peuvent encore etre en file.
    sleep "$TCPDUMP_FLUSH_S"
    kill "$TCPDUMP_PID" 2>/dev/null || true
    wait "$TCPDUMP_PID" 2>/dev/null || true
    # Bilan de capture : "dropped by kernel" > 0 signifie que tcpdump a perdu
    # des paquets, ce qui ressemblerait a tort a une perte reseau dans
    # l'analyse. A verifier dans chaque log de bloc.
    echo "tcpdump bilan ($(wc -c < "$BLOCK_PCAP") octets dans $BLOCK_PCAP) :"
    grep -E "packets (captured|received by filter|dropped by kernel)" "$TCPDUMP_ERR" || true
fi
