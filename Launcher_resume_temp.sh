#!/usr/bin/env bash
set -euo pipefail

###############################################################################
#  COMMAND LINE PARAMETERS
#
#  Usage: ./Launcher_unified.sh [mlkem|hqc|both] [tls|quic] [mutual|single] \
#           [capture|captureKey|nocapture] [none|simple|stable|unstable] \
#           [loss-percent] [delay-ms]
#
#  Fusionne Launcherv3_pq_mlkem.sh et Launcherv3_pq_hqc.sh.
#  Différence réelle entre les deux anciens scripts : uniquement les listes
#  KEMS_L1/L3/L5 (mlkem512/768/1024 vs hqc128/192/256). Tout le reste
#  (Docker, Pumba, Wireshark, cleaning) est strictement identique et repris
#  tel quel ci-dessous.
###############################################################################

KEM_FAMILY=${1:-both}
PROTOCOL=${2:-tls}
AUTH_MODE=${3:-single}
CAPTURE_MODE=${4:-nocapture}
NETWORK_PROFILE=${5:-none}
LOSS_PERC=${6:-0}
DELAY_MS=${7:-0}

USAGE="Usage: $0 [mlkem|hqc|both] [tls|quic] [mutual|single] [capture|captureKey|nocapture] [none|simple|stable|unstable] [loss-percent] [delay-ms]"

NETIF="eth0"
MUTUAL_AUTHENTICATION=false
IMAGE=uma-tls-quic-pq-34
os=""

###############################################################################
#  Input Validation
###############################################################################

# 0) KEM family (nouveau paramètre — remplace le choix "quel launcher exécuter")
if [[ "$KEM_FAMILY" != "mlkem" && "$KEM_FAMILY" != "hqc" && "$KEM_FAMILY" != "both" ]]; then
    echo "Invalid KEM family: must be 'mlkem', 'hqc', or 'both'."
    echo "$USAGE"
    exit 1
fi

# 1) Protocol
if [[ "$PROTOCOL" != "tls" && "$PROTOCOL" != "quic" ]]; then
    echo "$USAGE"
    exit 1
fi

# 2) Mutual authentication mode
if [[ "$AUTH_MODE" != "mutual" && "$AUTH_MODE" != "single" ]]; then
    echo "Invalid authentication mode: must be 'mutual' or 'single'."
    echo "$USAGE"
    exit 1
fi

# 3) Packet capture mode
if [[ "$CAPTURE_MODE" != "capture" && "$CAPTURE_MODE" != "captureKey" && "$CAPTURE_MODE" != "nocapture" ]]; then
    echo "Invalid capture mode: must be 'capture', 'captureKey', or 'nocapture'."
    echo "$USAGE"
    exit 1
fi

# 4) Network profile
if [[ "$NETWORK_PROFILE" != "none" && "$NETWORK_PROFILE" != "simple" && "$NETWORK_PROFILE" != "stable" && "$NETWORK_PROFILE" != "unstable" ]]; then
    echo "Invalid network profile: must be 'none', 'simple', 'stable', or 'unstable'."
    echo "$USAGE"
    exit 1
fi

# 5) Packet loss percentage (0–100)
# 5) Packet loss percentage (0–100, décimales acceptées — nécessaire pour les
#    scénarios terrain Modéré/Dégradé : 0.3% et 0.2%)
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

# 6) Delay in milliseconds (>= 0)
# 6) Delay in milliseconds (>= 0, décimales acceptées — nécessaire pour
#    30.02ms / 65.15ms des scénarios terrain)
if ! [[ "$DELAY_MS" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
    echo "Invalid delay-ms: must be a non-negative number (decimals allowed)."
    echo "$USAGE"
    exit 1
fi

NETWORK_PROFILE_LABEL="$NETWORK_PROFILE"
if [[ "$NETWORK_PROFILE" == "simple" ]]; then
    NETWORK_PROFILE_LABEL="simple_loss${LOSS_PERC}_delay${DELAY_MS}ms"
fi

###############################################################################
#  CONFIGURATION
###############################################################################

 NUM_RUNS=500

if [[ "$CAPTURE_MODE" == "capture" || "$CAPTURE_MODE" == "captureKey" ]]; then
  NUM_RUNS=1
fi

if [[ "$AUTH_MODE" == "mutual" ]]; then
   MUTUAL_AUTHENTICATION=true
fi

 OQS_SERVER="servidor"
 OQS_CLIENT="cliente"

 # ── Signatures supportées ──────────────────────────────────────────────────
 # Classiques (baseline Montenegro 2026) + Post-Quantiques (FIPS 204 ML-DSA)
 # mldsa44 → niveau sécurité NIST L1 (≡ ed25519)
 # mldsa65 → niveau sécurité NIST L3 (≡ secp384r1)
 # mldsa87 → niveau sécurité NIST L5 (≡ secp521r1)
 SUPPORTED_SIG_ALGS=("mldsa44" "mldsa65" "mldsa87")

 # ── KEMs par niveau, décomposés par famille ────────────────────────────────
 # Baseline classique : mesuré UNE SEULE FOIS, quelle que soit la famille
 # choisie (mlkem/hqc/both). Auparavant, exécuter les deux anciens scripts
 # séparément mesurait ce baseline deux fois — redondance supprimée ici.
 CLASSICAL_L1=("P-256" "x25519")
 CLASSICAL_L3=("P-384" "x448")
 CLASSICAL_L5=("P-521")

 MLKEM_L1=("p256_mlkem512" "x25519_mlkem512" "mlkem512")
 MLKEM_L3=("p384_mlkem768" "x448_mlkem768" "mlkem768")
 MLKEM_L5=("p521_mlkem1024" "mlkem1024")

 HQC_L1=("hqc128" "p256_hqc128" "x25519_hqc128")
 HQC_L3=("hqc192" "p384_hqc192" "x448_hqc192")
 HQC_L5=("hqc256" "p521_hqc256")

 KEMS_L1=("${CLASSICAL_L1[@]}")
 KEMS_L3=("${CLASSICAL_L3[@]}")
 KEMS_L5=("${CLASSICAL_L5[@]}")

 if [[ "$KEM_FAMILY" == "mlkem" || "$KEM_FAMILY" == "both" ]]; then
   KEMS_L1+=("${MLKEM_L1[@]}")
   KEMS_L3+=("${MLKEM_L3[@]}")
   KEMS_L5+=("${MLKEM_L5[@]}")
 fi

 if [[ "$KEM_FAMILY" == "hqc" || "$KEM_FAMILY" == "both" ]]; then
   KEMS_L1+=("${HQC_L1[@]}")
   KEMS_L3+=("${HQC_L3[@]}")
   KEMS_L5+=("${HQC_L5[@]}")
 fi

# Recoger el parámetro de línea de comandos
 USE_TLS=$([[ "$PROTOCOL" == "tls" ]] && echo true || echo false)
 # Perfiles GE-model (valores en %)
STABLE_GEMODEL=(10 50 70 10)    # pg10 pb50 h70 k10
UNSTABLE_GEMODEL=(20 40 90 20)  # pg20 pb40 h90 k20

# ── Pré-téléchargement de l'image helper de pumba ──────────────────────────
# pumba a besoin d'une image "tc" à CHAQUE invocation pour appliquer une
# règle netem, et retente TOUJOURS de la pull même si elle est déjà en
# cache local — c'est un bug connu de pumba (--pull-image est cassé et
# évalue toujours à true, cf. github.com/alexei-led/pumba/issues/132),
# pas quelque chose qu'on peut désactiver en ligne de commande.
#
# Solution définitive : un miroir local (localhost:5000, mis en place une
# fois via `docker run -d -p 5000:5000 --restart=always --name
# local-registry registry:2` + insecure-registries dans daemon.json) sert
# l'image sans jamais dépendre du réseau externe. Le launcher pointe
# maintenant pumba vers ce miroir (--tc-image localhost:5000/...) au lieu
# de ghcr.io directement.
#
# Ce bloc vérifie d'abord si le miroir local a déjà l'image (cas normal
# après la première exécution) ; sinon, il retombe sur ghcr.io UNE FOIS
# pour l'alimenter, afin que tous les runs suivants n'aient plus jamais
# besoin du réseau externe.
if [[ "$NETWORK_PROFILE" == "stable" || "$NETWORK_PROFILE" == "unstable" ]]; then
    LOCAL_MIRROR="localhost:5000/pumba-alpine-nettools:latest"
    echo "Vérification de l'image helper pumba dans le miroir local ($LOCAL_MIRROR)..."
    if docker pull "$LOCAL_MIRROR" >/dev/null 2>&1; then
        echo "  ↳ Déjà disponible localement, aucun accès réseau externe nécessaire."
    else
        echo "  ↳ Absente du miroir local — récupération depuis ghcr.io (une seule fois)..."
        pumba_image_ok=false
        for pull_attempt in 1 2 3 4 5; do
            if docker pull ghcr.io/alexei-led/pumba-alpine-nettools:latest; then
                pumba_image_ok=true
                break
            fi
            echo "   ↳ Échec (tentative $pull_attempt/5), le DNS répond par intermittence — nouvel essai dans 5s..."
            sleep 5
        done
        if ! $pumba_image_ok; then
            echo "ERREUR FATALE: impossible de télécharger l'image helper de pumba après 5 tentatives,"
            echo "ni depuis le miroir local ni depuis ghcr.io. Vérifiez votre connexion réseau, ou"
            echo "mettez en place le miroir local (voir commentaire ci-dessus) avant de relancer."
            exit 1
        fi
        echo "  ↳ Alimentation du miroir local pour que les prochains runs n'aient plus besoin du réseau..."
        docker tag ghcr.io/alexei-led/pumba-alpine-nettools:latest "$LOCAL_MIRROR" 2>/dev/null || true
        docker push "$LOCAL_MIRROR" 2>/dev/null \
            || echo "  ↳ [!] Push vers le miroir local échoué (miroir pas encore configuré ?) — voir README pour la mise en place."
    fi
fi


echo "*************************************"
echo "Parameters valid. Starting with:"
echo "  KEM Family:      $KEM_FAMILY"
echo "  Protocol:        $PROTOCOL"
echo "  Auth Mode:       $AUTH_MODE"
echo "  Capture Mode:    $CAPTURE_MODE"
echo "  Network Profile: $NETWORK_PROFILE"
echo "  Loss %:          $LOSS_PERC"
echo "  Delay (ms):      $DELAY_MS"
echo "  Executions:      $NUM_RUNS"

echo "  Signature:       ${SUPPORTED_SIG_ALGS[*]}"
echo "  KEMS Level 1:    ${KEMS_L1[*]}"
echo "  KEMS Level 3:    ${KEMS_L3[*]}"
echo "  KEMS Level 5:    ${KEMS_L5[*]}"
echo "*************************************"

###############################################################################
#  Function: detect_platform
#
###############################################################################

detect_platform() {
    os="$(uname -s)"
    case "$os" in
        Linux)
            echo "Runnig on Linux" ;;
        Darwin)
            echo "Runnig on macOS" ;;
        *)
            echo "Runnig on: $os" ;;
    esac
}

###############################################################################
#  Function: launch_edgeshark
#
###############################################################################
launch_edgeshark() {
    URL="https://github.com/siemens/edgeshark/raw/main/deployments/wget/docker-compose-localhost.yaml"
    COMPOSE_FILE="./docker-compose-localhost.yaml"

    mkdir -p "$(dirname "$COMPOSE_FILE")"
    wget -q --no-cache -O "$COMPOSE_FILE" "$URL"

    if [ -z "$(docker compose -f "$COMPOSE_FILE" ps -q)" ]; then
        echo "$(date '+%F %T') → No active containers. Running stack..."
        docker compose -f "$COMPOSE_FILE" up -d
    else
        echo "$(date '+%F %T') → It is runnig. Nothing to do."
    fi
}
###############################################################################
#  Function: lauch_Wireshark
#
###############################################################################

lauch_Wireshark_mac(){

     if [ -d "/Applications/Wireshark.app" ]; then
                    echo "Wireshark is installed, perfect!!!"

                    if ps aux | grep -i wireshark | grep -v grep > /dev/null; then
                        echo "Wireshark is running."
                        read -n 1 -s -r -p "Please save Wireshark data to run another experiment..."
                        echo ""
                        echo "Running now ... "
                        open -a Wireshark

                    else
                        echo "Wireshark is NOT running. Running now ... "
                        open -a Wireshark
                    fi
            else
                echo "Wireshark is not installed in /Applications."
                exit 1
            fi

            read -n 1 -s -r -p "Configure Wireshark and press any key when you are ready to continue..."
            echo ""
}

###############################################################################
#  Function: lauch_Wireshark (Linux)
#
###############################################################################

launch_wireshark_linux() {
    if command -v wireshark >/dev/null 2>&1; then
        echo "Wireshark is installed, perfect!!!"

        if pgrep -u "$USER" -x wireshark >/dev/null 2>&1; then
            echo "Wireshark is already running."
        else
            echo "Wireshark is NOT running. Starting now..."
            wireshark
            sleep 1
        fi

        read -n 1 -s -r -p "Please save Wireshark data to run another experiment, then press any key to continue..."
        echo ""
        read -n 1 -s -r -p "Configure Wireshark and press any key when you are ready to continue..."
        echo ""

    else
        echo "Wireshark is not installed. Please install it (e.g. Ubuntu/Debian: sudo apt install wireshark) and try again."
        exit 1
    fi
}
###############################################################################
#  Function: cleaning
#
###############################################################################

cleaning(){
    docker kill $OQS_SERVER &>/dev/null || true
    docker kill $OQS_CLIENT &>/dev/null || true

    sleep 1
    docker container prune -f
    docker volume rm cert || true
    docker network rm localNet || true
    sleep 1
}

###############################################################################
#  Function: read_cgroup_cpu_usec / read_cgroup_mem_peak_bytes
#
#  Mesure CPU/mémoire via les compteurs cgroup du conteneur lui-même
#  (docker exec <container> cat /sys/fs/cgroup/...), pas via docker stats.
#  Avantage : compteur cumulatif exact, pas d'échantillonnage à ~1s.
#  Comme chaque conteneur serveur/client est recréé à chaque combinaison
#  SIG_ALG/KEM, la mesure est automatiquement isolée à cette combinaison —
#  pas besoin de réinitialiser les compteurs manuellement.
#
#  LIMITE CONNUE (à documenter dans l'article) : ceci mesure la consommation
#  du conteneur entier (harnais de test perftestClientTlsQuic.sh inclus),
#  pas uniquement les opérations cryptographiques elles-mêmes — on n'a pas
#  accès au code source de ce script pour instrumenter plus finement.
#  Le delta est ensuite divisé par NUM_RUNS pour obtenir une moyenne par
#  handshake, dans le même esprit méthodologique que la latence moyenne.
###############################################################################

read_cgroup_cpu_usec() {
    local container="$1"
    local v
    # cgroup v2 unifié : cpu.stat contient "usage_usec <valeur>"
    v=$(docker exec "$container" sh -c \
        'grep -m1 usage_usec /sys/fs/cgroup/cpu.stat 2>/dev/null | awk "{print \$2}"' 2>/dev/null || true)
    if [[ -n "$v" && "$v" =~ ^[0-9]+$ ]]; then
        echo "$v"
        return
    fi
    # Repli cgroup v1 : cpuacct.usage est en nanosecondes → conversion en µs
    v=$(docker exec "$container" sh -c \
        'cat /sys/fs/cgroup/cpuacct/cpuacct.usage 2>/dev/null' 2>/dev/null || true)
    if [[ -n "$v" && "$v" =~ ^[0-9]+$ ]]; then
        echo "$((v / 1000))"
        return
    fi
    echo "NA"
}

read_cgroup_mem_peak_bytes() {
    local container="$1"
    local v
    # cgroup v2 : memory.peak = pic mémoire depuis la création du cgroup
    v=$(docker exec "$container" sh -c 'cat /sys/fs/cgroup/memory.peak 2>/dev/null' 2>/dev/null || true)
    if [[ -n "$v" && "$v" =~ ^[0-9]+$ ]]; then
        echo "$v"
        return
    fi
    # Repli cgroup v1
    v=$(docker exec "$container" sh -c 'cat /sys/fs/cgroup/memory/memory.max_usage_in_bytes 2>/dev/null' 2>/dev/null || true)
    if [[ -n "$v" && "$v" =~ ^[0-9]+$ ]]; then
        echo "$v"
        return
    fi
    echo "NA"
}

init_resource_csv() {
    RESOURCE_DIR="$SCRIPT_DIR/captures/$PROTOCOL/$AUTH_MODE/$NETWORK_PROFILE_LABEL/resource_usage"
    mkdir -p "$RESOURCE_DIR"
    RESOURCE_CSV="$RESOURCE_DIR/resource_usage_${PROTOCOL}_${AUTH_MODE}_${NETWORK_PROFILE_LABEL}.csv"
    if [[ ! -f "$RESOURCE_CSV" ]]; then
        echo "timestamp,protocol,auth_mode,sig_alg,kem,network_profile,role,n_runs,cpu_usec_total,cpu_usec_per_handshake,mem_peak_bytes" > "$RESOURCE_CSV"
    fi
}

append_resource_row() {
    local role="$1" cpu_start="$2" cpu_end="$3" mem_peak="$4"
    local cpu_total="NA" cpu_per_run="NA"
    if [[ "$cpu_start" =~ ^[0-9]+$ && "$cpu_end" =~ ^[0-9]+$ ]]; then
        cpu_total=$((cpu_end - cpu_start))
        if [[ "$NUM_RUNS" -gt 0 ]]; then
            cpu_per_run=$(LC_ALL=C awk -v t="$cpu_total" -v n="$NUM_RUNS" 'BEGIN{printf "%.3f", t/n}')
        fi
    fi
    echo "$(date -Iseconds),$PROTOCOL,$AUTH_MODE,$SIG_ALG,$KEM,$NETWORK_PROFILE,$role,$NUM_RUNS,$cpu_total,$cpu_per_run,$mem_peak" >> "$RESOURCE_CSV"
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

detect_platform

init_resource_csv

CLIENT_LOG_DIR="$SCRIPT_DIR/captures/$PROTOCOL/$AUTH_MODE/$NETWORK_PROFILE_LABEL/handshake_logs"
mkdir -p "$CLIENT_LOG_DIR"

cleaning

echo ""
echo "*************************************"
echo "***NETWORK AND VOLUMEN **************"
echo "*************************************"

if ! docker network inspect localNet >/dev/null 2>&1; then
    docker network create localNet
    echo "✅ Red localNet created."
else
    echo "ℹ️  Red localNet already exists; it won't be created."
fi

if ! docker volume inspect cert >/dev/null 2>&1; then
    docker volume create cert
    echo "✅ Volumen cert created."
else
    echo "ℹ️  Volumen cert already exists; it won't be created."
fi

echo "*************************************"

if [[ "$CAPTURE_MODE" == "capture" || "$CAPTURE_MODE" == "captureKey" ]]; then
    echo ""
    echo "Launching edgeshark"
    launch_edgeshark
 fi

SIG_ALGS=("${SUPPORTED_SIG_ALGS[@]}")

for SIG_ALG in "${SIG_ALGS[@]}"; do
    echo ""
    echo " ==> Executing for SIG_ALG: $SIG_ALG"

    # ── Mapping signature → niveau KEM ────────────────────────────────────
    if [ "$SIG_ALG" = "ed25519" ]; then
        KEMS=("${KEMS_L1[@]}")
    elif [ "$SIG_ALG" = "secp384r1" ]; then
        KEMS=("${KEMS_L3[@]}")
    elif [ "$SIG_ALG" = "secp521r1" ]; then
        KEMS=("${KEMS_L5[@]}")
    elif [ "$SIG_ALG" = "mldsa44" ]; then
        KEMS=("${KEMS_L1[@]}")
    elif [ "$SIG_ALG" = "mldsa65" ]; then
        KEMS=("${KEMS_L3[@]}")
    elif [ "$SIG_ALG" = "mldsa87" ]; then
        KEMS=("${KEMS_L5[@]}")
    fi

    echo ""
    echo " ==> Creating Certs and Keys"
    docker run --rm -v cert:/cert -e CERT_PATH=/cert/ -e SIG_ALG=$SIG_ALG -i "$IMAGE" doCert.sh


    for KEM in "${KEMS[@]}"; do
        echo ""
        echo "****************"
        echo "  -> KEM: $KEM"

            echo ""
            echo "    Executing docker Server..."

            docker rm -f $OQS_SERVER $OQS_CLIENT 2>/dev/null

            SSL_DIR="$SCRIPT_DIR/captures/$PROTOCOL/$AUTH_MODE/$NETWORK_PROFILE_LABEL/sslkeys"
            # Créé INCONDITIONNELLEMENT ici, avant le montage Docker (-v plus
            # bas) : sinon Docker crée le dossier lui-même en root au moment
            # du montage, pour CHAQUE combinaison, même en mode nocapture où
            # rien n'y est jamais écrit — pollution de captures/ avec des
            # dossiers vides root-owned (42+ par sweep).
            mkdir -p "$SSL_DIR"

            if [ "$PROTOCOL" = "tls" ] && [ "$CAPTURE_MODE" = "captureKey" ]; then                SSLKEY_NAME="sslkeys_server_${SIG_ALG}_${KEM}.log"
                SSLKEY_PATH="$SSL_DIR/$SSLKEY_NAME"

                echo "[INFO] TLS Capture mode server: saving SSL keys to $SSLKEY_PATH"
                export SSLKEYLOGFILE="$SSLKEY_PATH"
            fi


            docker run --cap-add=NET_ADMIN  \
              --name $OQS_SERVER  \
              --network localNet  \
              -v cert:/cert   \
              -v "$SSL_DIR":/sslkeys \
              -e TC_DELAY=0ms  \
              -e TC_LOSS=0% \
              -e CERT_PATH=/cert/ \
              -e KEM_ALG=$KEM  \
              -e SIG_ALG=$SIG_ALG \
              -e USE_TLS=$USE_TLS \
              -e MUTUAL=$MUTUAL_AUTHENTICATION \
             $( [ "$PROTOCOL" = "tls" ] && [ "$CAPTURE_MODE" = "captureKey" ] && echo "-e SSL_DIR=/sslkeys" ) \
              -d $IMAGE perftestServerTlsQuic.sh

            sleep 3

            echo "    Buscando IP.. "
            IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' servidor)
            echo "    IP..  $IP"

            # ── Point de départ pour la mesure CPU/mémoire du serveur ──────
            SERVER_CPU_START=$(read_cgroup_cpu_usec "$OQS_SERVER")


            if [[ "$CAPTURE_MODE" == "capture" || "$CAPTURE_MODE" == "captureKey" ]]; then
                echo ""
                echo "Launching Wireshark"

                if [[ "$os" == "Darwin" ]]; then
                    lauch_Wireshark_mac
                else
                    launch_wireshark_linux
                fi
            fi


            ############################################################################
            #  NETWORK IMPAIRMENTS (Pumba)
            ############################################################################
            PUMBA_PIDS_SERVER=()
            case "$NETWORK_PROFILE" in
              simple)
                if [[ "$LOSS_PERC" != "0" || "$DELAY_MS" != "0" ]]; then
                  echo "   ↳ Applying tc netem on server: delay=${DELAY_MS}ms loss=${LOSS_PERC}%"
                  sleep 2
                  docker exec $OQS_SERVER tc qdisc add dev $NETIF root netem \
                    delay ${DELAY_MS}ms loss ${LOSS_PERC}% || true
                fi
                ;;
              stable|unstable)
                args=("${STABLE_GEMODEL[@]}")
                [[ "$NETWORK_PROFILE" == "unstable" ]] && args=("${UNSTABLE_GEMODEL[@]}")
                echo "   ↳ Applying ${NETWORK_PROFILE} network profile (loss-gemodel pg${args[0]} pb${args[1]} h${args[2]} k${args[3]})"
                /usr/local/bin/pumba netem --duration 1h --interface $NETIF \
                  --tc-image localhost:5000/pumba-alpine-nettools:latest \
                  loss-gemodel --pg "${args[0]}" --pb "${args[1]}" \
                  --one-h "${args[2]}" --one-k "${args[3]}" "$OQS_SERVER" & PUMBA_PIDS_SERVER+=($!)

                # ── Vérification bloquante : la règle est-elle RÉELLEMENT là ? ──
                # pumba peut échouer silencieusement (ex: panne DNS transitoire
                # en tirant son image helper) sans que le script s'en rende
                # compte, étiquetant des données non dégradées comme "stable"/
                # "unstable". On vérifie via tc directement sur le conteneur,
                # avec une marge généreuse (démarrage du conteneur helper +
                # nsenter vers le namespace réseau cible peut prendre du temps,
                # surtout sous latence réseau élevée) avant d'abandonner.
                pumba_pid="${PUMBA_PIDS_SERVER[-1]}"
                gemodel_applied=false
                for attempt in $(seq 1 15); do
                    sleep 2
                    if docker exec "$OQS_SERVER" tc -s qdisc show dev "$NETIF" 2>/dev/null | grep -qi "gemodel"; then
                        gemodel_applied=true
                        break
                    fi
                    if ! kill -0 "$pumba_pid" 2>/dev/null; then
                        echo "   ↳ Le process pumba (PID $pumba_pid) s'est déjà terminé sans que la règle"
                        echo "     ne soit visible — échec réel, pas juste lent. Arrêt anticipé."
                        break
                    fi
                    echo "   ↳ Règle gemodel pas encore visible (tentative $attempt/15, pumba toujours actif)..."
                done
                if ! $gemodel_applied; then
                    echo ""
                    echo "❌ ERREUR FATALE: la règle loss-gemodel n'a pas pu être confirmée sur"
                    echo "   $OQS_SERVER après 30s d'attente (SIG_ALG=$SIG_ALG, KEM=$KEM)."
                    if kill -0 "$pumba_pid" 2>/dev/null; then
                        echo "   Le process pumba (PID $pumba_pid) est TOUJOURS actif après ce délai —"
                        echo "   possiblement bloqué. Vérifiez manuellement : ps aux | grep pumba"
                    fi
                    echo "   Vérifiez la connectivité réseau (pumba a besoin de ghcr.io) et relancez"
                    echo "   CETTE combinaison — ne pas continuer produirait des données non fiables."
                    for pid in "${PUMBA_PIDS_SERVER[@]:-}"; do kill -9 "$pid" &>/dev/null || true; done
                    docker kill $OQS_SERVER &>/dev/null || true
                    exit 1
                fi
                echo "   ↳ Règle gemodel confirmée active sur $OQS_SERVER."
                ;;
            esac


            sleep 2
            echo "    Executing docker Client... $IP"

            if [ "$PROTOCOL" = "quic" ] && [ "$CAPTURE_MODE" = "captureKey" ]; then
                mkdir -p "$SSL_DIR"

                SSLKEY_NAME="sslkeys_client_${SIG_ALG}_${KEM}.log"
                SSLKEY_PATH="$SSL_DIR/$SSLKEY_NAME"

                echo "[INFO] QUIC capture mode client: saving SSL keys to $SSLKEY_PATH"
                export SSLKEYLOGFILE="$SSLKEY_PATH"
            fi


            docker create --cap-add=NET_ADMIN \
                --network localNet \
                --name $OQS_CLIENT  \
                -v cert:/cert \
                -v "$SSL_DIR":/sslkeys \
                -e DOCKER_HOST=$IP \
                -e TC_DELAY=0ms  \
                -e TC_LOSS=0% \
                -e CERT_PATH=/cert/ \
                -e KEM_ALG=$KEM \
                -e SIG_ALG=$SIG_ALG \
                -e USE_TLS=$USE_TLS \
                -e NUM_RUNS=$NUM_RUNS \
                -e MUTUAL=$MUTUAL_AUTHENTICATION \
                $( [ "$PROTOCOL" = "quic" ]  && [ "$CAPTURE_MODE" = "captureKey" ] && echo "-e SSL_DIR=/sslkeys" ) \
                "$IMAGE" sleep infinity


            docker start $OQS_CLIENT

            echo "     Docker $OQS_CLIENT executed ... "

            ############################################################################
            #  NETWORK IMPAIRMENTS (Pumba) — CLIENT
            ############################################################################
            PUMBA_PIDS_CLIENT=()
            case "$NETWORK_PROFILE" in
              simple)
                if [[ "$DELAY_MS" != "0" ]]; then
                  echo "   ↳ Applying tc netem on client: delay=${DELAY_MS}ms"
                  docker exec $OQS_CLIENT tc qdisc add dev $NETIF root netem \
                    delay ${DELAY_MS}ms || true
                fi
                ;;
            esac

            echo ""
            echo "**************************"
            echo "     Executing test  ... "

            # ── Point de départ pour la mesure CPU/mémoire du client ───────
            CLIENT_CPU_START=$(read_cgroup_cpu_usec "$OQS_CLIENT")

            # ── Capture des logs de handshake (perdus jusqu'ici : docker exec
            #    -it affichait tout dans le terminal sans rien sauvegarder).
            #    tee garde l'affichage live ET écrit dans le fichier.
            CLIENT_LOG_FILE="$CLIENT_LOG_DIR/handshake_${PROTOCOL}_${AUTH_MODE}_${SIG_ALG}_${KEM}_${NETWORK_PROFILE_LABEL}.log"
            docker exec $OQS_CLIENT ./perftestClientTlsQuic.sh 2>&1 | tee "$CLIENT_LOG_FILE"
            echo "     Log de handshake enregistré dans $CLIENT_LOG_FILE"

            # ── Points de fin CPU + pic mémoire, capturés juste après le
            #    test et AVANT le kill des conteneurs (sinon illisibles) ──
            CLIENT_CPU_END=$(read_cgroup_cpu_usec "$OQS_CLIENT")
            SERVER_CPU_END=$(read_cgroup_cpu_usec "$OQS_SERVER")
            CLIENT_MEM_PEAK=$(read_cgroup_mem_peak_bytes "$OQS_CLIENT")
            SERVER_MEM_PEAK=$(read_cgroup_mem_peak_bytes "$OQS_SERVER")

            append_resource_row "server" "$SERVER_CPU_START" "$SERVER_CPU_END" "$SERVER_MEM_PEAK"
            append_resource_row "client" "$CLIENT_CPU_START" "$CLIENT_CPU_END" "$CLIENT_MEM_PEAK"
            echo "     CPU/mémoire enregistrés dans $RESOURCE_CSV"

            echo "     Waiting  ... "
            sleep 3

         echo "   Shutting down server and impairments..."

         docker kill $OQS_SERVER &>/dev/null || true
         docker kill $OQS_CLIENT &>/dev/null || true
         for pid in "${PUMBA_PIDS_SERVER[@]:-}"; do kill -9 "$pid" &>/dev/null || true; done
         for pid in "${PUMBA_PIDS_CLIENT[@]:-}"; do kill -9 "$pid" &>/dev/null || true; done
    done

done

sleep 3

cleaning
echo "✅  Cleanup complete. Tests finished."
