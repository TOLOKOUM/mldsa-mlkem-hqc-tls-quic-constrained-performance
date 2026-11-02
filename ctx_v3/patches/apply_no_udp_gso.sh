#!/bin/sh
###############################################################################
# apply_no_udp_gso.sh <datapath_epoll.c> — Desactive PAR DEFAUT l'envoi groupe UDP
# (UDP GSO, CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION) dans la fork msquic-pq.
#
# Pourquoi : avec UDP GSO, MsQuic remet au noyau UN super-paquet contenant
# plusieurs datagrammes ; netem decide de la perte par super-paquet (1 tirage
# pour ~2 datagrammes en moyenne, jusqu'a ~6) => perte correlee et nombre
# d'occasions de perte different de TLS (TCP, TSO coupe). Sans GSO, chaque
# datagramme est un paquet distinct pour netem, comme chaque segment TCP.
#
# Le groupement n'est reactive QUE si QUIC_ENABLE_UDP_GSO=1 est dans
# l'environnement du processus (pour un essai GSO-on delibere).
# Le script ECHOUE (=> le build Docker echoue) si le patch ne s'applique pas
# exactement une fois : on ne livre jamais une image non patchee par erreur.
###############################################################################
set -eu
F="${1:?usage: $0 <datapath_epoll.c>}"
[ -f "$F" ] || { echo "introuvable: $F" >&2; exit 1; }

PAT='Datapath->Features |= CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION;'
N=$(grep -c -F "$PAT" "$F" || true)
[ "$N" -eq 1 ] || { echo "ERREUR: attendu 1 occurrence de '$PAT', trouve $N" >&2; exit 1; }
if grep -q "QUIC_ENABLE_UDP_GSO" "$F"; then echo "deja patche: $F"; exit 0; fi

# getenv() : stdlib.h (GCC 14 refuse les declarations implicites)
grep -q '#include <stdlib.h>' "$F" || sed -i '0,/^#include/s//#include <stdlib.h>\n#include/' "$F"

sed -i 's#Datapath->Features |= CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION;#do { const char* _gso = getenv("QUIC_ENABLE_UDP_GSO"); if (_gso != NULL \&\& _gso[0] == 49) { Datapath->Features |= CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION; } } while (0);#' "$F"

grep -q 'QUIC_ENABLE_UDP_GSO' "$F" || { echo "ERREUR: patch non applique" >&2; exit 1; }
[ "$(grep -c -F "$PAT" "$F" || true)" -eq 1 ] || true
echo "OK: UDP GSO desactive par defaut dans $F (reactivable: QUIC_ENABLE_UDP_GSO=1)"
