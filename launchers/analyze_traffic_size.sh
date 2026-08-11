#!/usr/bin/env bash
set -uo pipefail
#
# analyze_traffic_size.sh — Extrait la taille du trafic d'un handshake capturé
# (pcap produit par capture_pcap_demo.sh), avec ou sans déchiffrement.
#
# Filtre sur le port 4433 (TCP pour TLS, UDP pour QUIC — confirmé
# empiriquement via Wireshark) pour exclure le bruit réseau ambiant
# (ICMPv6 Multicast Listener Report, ARP, mDNS...) qui gonflerait
# artificiellement le total sinon.
#
# Sans clé : total d'octets/paquets sur le fil, filtré sur le port du test
# (déjà valide, en-têtes/tailles de records visibles même chiffrés).
# Avec clé (optionnelle) : décomposition par type de message handshake TLS.
# Un même paquet TCP peut regrouper plusieurs messages handshake (ex: "2,8"
# = ServerHello+EncryptedExtensions) — chaque type combiné est éclaté et
# compté séparément, plutôt que de rester affiché comme "type_2,8".
#
# Usage: ./analyze_traffic_size.sh <fichier.pcap> [fichier_cles.log] [port]

PCAP="${1:-}"
KEYLOG="${2:-}"
PORT="${3:-4433}"

if [ -z "$PCAP" ] || [ ! -f "$PCAP" ]; then
    echo "Usage: $0 <fichier.pcap> [fichier_cles.log] [port]"
    exit 1
fi

if ! command -v tshark >/dev/null 2>&1; then
    echo "ERREUR: tshark introuvable. Installe-le avec :"
    echo "  sudo apt-get install -y tshark"
    exit 1
fi

TSHARK_OPTS=(-r "$PCAP")
if [ -n "$KEYLOG" ] && [ -f "$KEYLOG" ]; then
    TSHARK_OPTS+=(-o "tls.keylog_file:$KEYLOG")
    echo "Déchiffrement activé avec : $KEYLOG"
else
    echo "Pas de fichier de clés fourni — analyse sur trafic chiffré (tailles brutes uniquement)."
fi

PORT_FILTER="tcp.port==${PORT} or udp.port==${PORT}"
echo "Filtre appliqué : $PORT_FILTER (exclut ICMPv6/ARP/mDNS et autre bruit réseau ambiant)"
echo ""

echo "=================================================="
echo " Résumé global : $PCAP"
echo "=================================================="
tshark "${TSHARK_OPTS[@]}" -Y "$PORT_FILTER" -q -z io,stat,0 2>/dev/null

echo ""
echo "=================================================="
echo " Détail paquet par paquet (taille + info)"
echo "=================================================="
tshark "${TSHARK_OPTS[@]}" -Y "$PORT_FILTER" -T fields -e frame.number -e frame.len -e _ws.col.Protocol -e _ws.col.Info 2>/dev/null \
    | awk -F'\t' '{printf "  #%-4s %6s octets  %-10s %s\n", $1, $2, $3, $4}'

TOTAL_BYTES=$(tshark "${TSHARK_OPTS[@]}" -Y "$PORT_FILTER" -T fields -e frame.len 2>/dev/null | awk '{s+=$1} END{print s+0}')
TOTAL_PKTS=$(tshark "${TSHARK_OPTS[@]}" -Y "$PORT_FILTER" -T fields -e frame.len 2>/dev/null | wc -l)

echo ""
echo "=================================================="
echo " TOTAL (port $PORT uniquement) : $TOTAL_PKTS paquets, $TOTAL_BYTES octets"
echo "=================================================="

# Décomposition par type de message handshake si le déchiffrement est actif
if [ -n "$KEYLOG" ] && [ -f "$KEYLOG" ]; then
    echo ""
    echo "=================================================="
    echo " Octets par type de message handshake (TLS)"
    echo "=================================================="
    echo " Note : quand plusieurs messages partagent une même trame, la taille"
    echo " de la trame est comptée pour CHAQUE type qu'elle contient (une même"
    echo " trame peut donc contribuer à plusieurs lignes) — utile pour voir"
    echo " quels types de message sont présents, pas pour sommer un budget"
    echo " d'octets par type sans double-compte (cf. TOTAL ci-dessus pour ça)."
    tshark "${TSHARK_OPTS[@]}" -Y "$PORT_FILTER and tls.handshake.type" \
        -T fields -e tls.handshake.type -e frame.len 2>/dev/null \
        | awk -F'\t' '
            BEGIN {
                names[0]="HelloRequest"; names[1]="ClientHello"; names[2]="ServerHello";
                names[4]="NewSessionTicket"; names[8]="EncryptedExtensions"; names[11]="Certificate";
                names[13]="CertificateRequest"; names[15]="CertificateVerify"; names[20]="Finished";
            }
            {
                len=$2;
                n_types = split($1, types, ",");
                for (i=1; i<=n_types; i++) {
                    t = types[i];
                    name = (t in names) ? names[t] : ("type_" t);
                    sum[name] += len;
                    count[name]++;
                }
            }
            END {
                for (k in sum) printf "  %-20s %3d message(s)  %6d octets (trame incl.)\n", k, count[k], sum[k];
            }' | sort
fi
