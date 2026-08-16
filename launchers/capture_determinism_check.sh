#!/usr/bin/env bash
set -uo pipefail
#
# capture_determinism_check.sh — Vérifie empiriquement que les tailles de
# message de handshake sont bien déterministes pour une combinaison
# SIG_ALG/KEM donnée (§5.2 de l'article), en répétant N fois la capture
# d'un petit nombre de configurations représentatives plutôt qu'une seule
# fois comme le fait capture_traffic_matrix.sh pour la matrice complète.
#
# Dérivé directement de la fonction capture_one() de
# launchers/capture_traffic_matrix.sh (mêmes commandes Docker, mêmes
# timings) — ce script NE MODIFIE PAS capture_traffic_matrix.sh et
# n'écrase jamais captures/traffic_size/ (utilisé par la Table 10 /
# Figures 10-11 déjà publiées). Chaque répétition est écrite dans son
# propre sous-dossier, avec la même convention de nommage que
# capture_traffic_matrix.sh, pour rester compatible avec
# parse_traffic_size.py sans le modifier.
#
# Usage: ./capture_determinism_check.sh [N_REPS]
#   Par défaut : 5 répétitions
#
# Sortie : captures/determinism_check/rep<i>/tls/...
#          (une arborescence par répétition, structure identique à
#          captures/traffic_size/tls/)
#
# Ensuite, pour chaque répétition :
#   python3 parse_traffic_size.py --input-dir captures/determinism_check/rep<i> \
#       --out-dir results_determinism/rep<i>

N_REPS="${1:-5}"
IMAGE=uma-tls-quic-pq-34
OQS_SERVER="servidor"
OQS_CLIENT="cliente"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_BASE="$SCRIPT_DIR/captures/determinism_check"

# ── Les 3 configurations ciblées, une par catégorie de risque de variation ──
# (protocol auth_mode sig_alg kem)
TARGETS=(
    "tls single mldsa44 P-256"     # classique+ML-DSA (schéma à rejet) — le plus susceptible de varier
    "tls single mldsa44 hqc128"    # PQ sig + HQC (encodage correcteur d'erreurs) — autre source possible de variation
    "tls single mldsa65 mlkem768"  # témoin : ML-KEM, pas de rejet, variation attendue nulle
)

cleaning() {
    docker kill $OQS_SERVER $OQS_CLIENT &>/dev/null || true
    docker rm -f $OQS_SERVER $OQS_CLIENT &>/dev/null || true
}

capture_one() {
    # Identique à capture_one() dans capture_traffic_matrix.sh, à l'exception
    # du chemin de sortie (out_dir passé en argument plutôt que dérivé de
    # captures/traffic_size/).
    local protocol="$1" auth_mode="$2" sig_alg="$3" kem="$4" out_dir="$5"
    local use_tls=$([[ "$protocol" == "tls" ]] && echo true || echo false)
    local mutual_auth=false
    [[ "$auth_mode" == "mutual" ]] && mutual_auth=true
    mkdir -p "$out_dir"
    local base_name="${protocol}_${auth_mode}_${sig_alg}_${kem}"
    local pcap_path="$out_dir/${base_name}.pcap"
    local keylog_path="$out_dir/${base_name}_sslkeys.log"

    cleaning
    docker run --cap-add=NET_ADMIN --name $OQS_SERVER --network localNet -v cert:/cert \
        -e TC_DELAY=0ms -e TC_LOSS=0% -e CERT_PATH=/cert/ -e KEM_ALG=$kem -e DEFAULT_GROUPS=$kem \
        -e SIG_ALG=$sig_alg -e USE_TLS=$use_tls -e MUTUAL=$mutual_auth \
        -d $IMAGE perftestServerTlsQuic.sh >/dev/null 2>&1
    sleep 3
    local ip
    ip=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $OQS_SERVER 2>/dev/null)
    if [ -z "$ip" ]; then
        echo "    [!] Serveur non démarré (SIG_ALG=$sig_alg KEM=$kem) — combo sautée."
        return 1
    fi

    docker create --cap-add=NET_ADMIN --network localNet --name $OQS_CLIENT -v cert:/cert \
        -e DOCKER_HOST="$ip" -e CERT_PATH=/cert/ -e KEM_ALG=$kem -e DEFAULT_GROUPS=$kem \
        -e SIG_ALG=$sig_alg -e USE_TLS=$use_tls "$IMAGE" sleep infinity >/dev/null 2>&1
    docker start $OQS_CLIENT >/dev/null 2>&1
    sleep 1

    docker exec -d $OQS_CLIENT sh -c "tcpdump -i eth0 -w /tmp/capture.pcap 2>/tmp/tcpdump.log"
    sleep 1

    local conn_ok=true
    if [ "$use_tls" = "true" ]; then
        if [ "$auth_mode" = "mutual" ]; then
            docker exec $OQS_CLIENT sh -c \
                "{ sleep 0.3; printf 'Q\n'; } | openssl s_client -connect \$DOCKER_HOST:4433 -tls1_3 \
                    -groups \$KEM_ALG -CAfile \$CERT_PATH/CA.crt -cert \$CERT_PATH/user.crt -key \$CERT_PATH/user.key \
                    -keylogfile /tmp/sslkeys.log" >/dev/null 2>&1 || conn_ok=false
        else
            docker exec $OQS_CLIENT sh -c \
                "{ sleep 0.3; printf 'Q\n'; } | openssl s_client -connect \$DOCKER_HOST:4433 -tls1_3 \
                    -groups \$KEM_ALG -CAfile \$CERT_PATH/CA.crt -keylogfile /tmp/sslkeys.log" >/dev/null 2>&1 || conn_ok=false
        fi
    else
        docker exec $OQS_CLIENT sh -c \
            "export SSLKEYLOGFILE=/tmp/sslkeys.log; \
             quics_connection -groups:\$KEM_ALG -target:\$DOCKER_HOST -CAfile:\$CERT_PATH/CA.crt" >/dev/null 2>&1 || conn_ok=false
    fi

    sleep 1
    docker exec $OQS_CLIENT sh -c "pkill tcpdump" >/dev/null 2>&1 || true
    sleep 1

    docker cp "$OQS_CLIENT:/tmp/capture.pcap" "$pcap_path" >/dev/null 2>&1
    if docker exec $OQS_CLIENT sh -c "[ -s /tmp/sslkeys.log ]" 2>/dev/null; then
        docker cp "$OQS_CLIENT:/tmp/sslkeys.log" "$keylog_path" >/dev/null 2>&1
    fi

    if [ "$conn_ok" = "true" ] && [ -s "$pcap_path" ]; then
        return 0
    else
        return 1
    fi
}

echo "*************************************"
echo " Vérification du déterminisme — $N_REPS répétitions x ${#TARGETS[@]} configs"
echo " Sortie : $OUT_BASE/rep<i>/<protocol>/"
echo "*************************************"

cleaning
docker network inspect localNet >/dev/null 2>&1 || docker network create localNet >/dev/null
docker volume inspect cert >/dev/null 2>&1 || docker volume create cert >/dev/null

n_ok=0
n_fail=0

for rep in $(seq 1 "$N_REPS"); do
    echo ""
    echo "=== Répétition $rep/$N_REPS ==="
    for target in "${TARGETS[@]}"; do
        read -r protocol auth_mode sig_alg kem <<< "$target"
        out_dir="$OUT_BASE/rep${rep}/${protocol}"

        # (re)génère le certificat pour ce sig_alg avant chaque connexion,
        # comme le fait capture_traffic_matrix.sh
        docker run --rm -v cert:/cert -e CERT_PATH=/cert/ -e SIG_ALG=$sig_alg -i "$IMAGE" doCert.sh >/dev/null 2>&1

        printf "    [rep %s] %s / %-10s / %-15s ... " "$rep" "$protocol" "$sig_alg" "$kem"
        if capture_one "$protocol" "$auth_mode" "$sig_alg" "$kem" "$out_dir"; then
            echo "OK"
            n_ok=$((n_ok + 1))
        else
            echo "ÉCHEC"
            n_fail=$((n_fail + 1))
        fi
    done
done

cleaning
docker volume rm cert &>/dev/null || true
docker network rm localNet &>/dev/null || true

echo ""
echo "*************************************"
echo " Terminé : $n_ok réussies, $n_fail échouées"
echo " Fichiers dans : $OUT_BASE/rep<1..$N_REPS>/"
echo " Prochaine étape, pour chaque répétition i :"
echo "   python3 parse_traffic_size.py --input-dir $OUT_BASE/rep<i> --out-dir results_determinism/rep<i>"
echo "*************************************"
