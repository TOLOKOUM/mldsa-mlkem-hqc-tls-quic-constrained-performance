#!/bin/bash
###############################################################################
# probe_features.sh -- SONDE DE FAISABILITE (a lancer UNE fois dans l'image v3, avant toute campagne) :
#   docker run --rm --cap-add=NET_ADMIN uma-tls-quic-pq-34-v3 probe_features.sh
# Verifie, sur bouclage (aucun netem), que les trois mecanismes testes existent REELLEMENT dans la pile du banc :
#   TLS  : reprise (ticket -> Resumed: 1) ; compression de certificat (octets recus avec/sans, type 25) ; serveur MT.
#   QUIC : reprise ; compression de certificat (bibliotheque OpenSSL embarquee par MsQuic compilee avec zlib/brotli/zstd ?) ;
#          0-RTT (ZeroRTT-sent).
# (Lancer depuis le repertoire de travail de l'image, ou se trouve payload.bin : c'est le WORKDIR par defaut.)
# Chaque verdict est OK / KO / ABSENT. Une cellule dont le verdict est KO n'est PAS lancee (et son absence est declaree
# dans l'article : "la pile MsQuic utilisee ne permet pas ...") -- on ne simule jamais un resultat.
###############################################################################
set -u
KEM="${KEM_ALG:-x448_mlkem768}"
D=/tmp/probe; rm -rf "$D"; mkdir -p "$D"
RES=()
verdict() { printf '  %-58s %s\n' "$1" "$2"; RES+=("$1=$2"); }

mkcert() { # nom sig depth pad
    mkdir -p "$D/$1"
    SIG_ALG="$2" CHAIN_DEPTH="$3" CERT_PAD_TARGET_DER="${4:-0}" CERT_PATH="$D/$1" doCert.sh >"$D/$1.log" 2>&1 || { echo "doCert a echoue pour $1 (voir $D/$1.log)"; exit 1; }
}
mkcert ctl secp384r1 1 8700
mkcert mld mldsa65 1 0
export DEFAULT_GROUPS="$KEM"

rx_of() { sed -n 's/^Rx-bytes: \([0-9]*\).*/\1/p' | head -1; }
wait_port_tcp() { for _ in $(seq 50); do (exec 3<>/dev/tcp/127.0.0.1/4433) 2>/dev/null && return 0; sleep 0.1; done; return 1; }

echo "=== TLS (OpenSSL de l'image) ==="
C="$D/ctl"
openssl s_server -cert $C/server.crt -key $C/server.key -groups "$KEM" -WWW -tls1_3 -num_tickets 1 -cert_comp -accept :4433 >"$D/tls_srv.log" 2>&1 &
SP=$!; wait_port_tcp
full=$(openssl s_connection -connect 127.0.0.1:4433 -new -verify 1 -CAfile $C/CA.crt -www /payload.bin -sess_out $D/t.sess -cert_comp none 2>&1)
echo "$full" | grep -q "Ticket: 1" && verdict "TLS : ticket de session recu" OK || verdict "TLS : ticket de session recu" KO
res=$(openssl s_connection -connect 127.0.0.1:4433 -new -verify 1 -CAfile $C/CA.crt -www /payload.bin -sess_in $D/t.sess -cert_comp none 2>&1)
echo "$res" | grep -q "^Resumed: 1" && verdict "TLS : reprise (Resumed: 1)" OK || verdict "TLS : reprise (Resumed: 1)" KO
rx_full=$(echo "$full" | rx_of); rx_res=$(echo "$res" | rx_of)
verdict "TLS : octets recus complet=${rx_full:-?} / repris=${rx_res:-?}" "$([ -n "$rx_full" ] && [ -n "$rx_res" ] && [ "$rx_res" -lt "$rx_full" ] && echo OK || echo KO)"
for a in zlib brotli zstd; do
    o=$(openssl s_connection -connect 127.0.0.1:4433 -new -verify 1 -CAfile $C/CA.crt -www /payload.bin -cert_comp $a 2>&1)
    r=$(echo "$o" | rx_of)
    if echo "$o" | grep -q "CertMsg: type=25"; then verdict "TLS : compression $a (ECDSA 8700 o) octets=${r:-?} (vs ${rx_full:-?})" OK
    elif echo "$o" | grep -qi "indisponible\|not supported\|unsupported"; then verdict "TLS : compression $a" ABSENT
    else verdict "TLS : compression $a (type 25 non observe)" KO; fi
done
kill $SP 2>/dev/null; wait $SP 2>/dev/null

C="$D/mld"
openssl s_server -cert $C/server.crt -key $C/server.key -groups "$KEM" -WWW -tls1_3 -num_tickets 0 -cert_comp -accept :4433 >"$D/tls_srv2.log" 2>&1 &
SP=$!; wait_port_tcp
o=$(openssl s_connection -connect 127.0.0.1:4433 -new -verify 1 -CAfile $C/CA.crt -www /payload.bin -cert_comp brotli 2>&1)
echo "$o" | grep -q "CertMsg: type=25" && verdict "TLS : ML-DSA-65 compressible ? (attendu NON)" "OUI(inattendu)" || verdict "TLS : ML-DSA-65 compressible ? (attendu NON)" "NON (conforme)"
kill $SP 2>/dev/null; wait $SP 2>/dev/null

if command -v tls_mt_server >/dev/null 2>&1; then
    C="$D/mld"
    tls_mt_server -port 4433 -cert $C/server.crt -key $C/server.key -groups "$KEM" -payload ./payload.bin >"$D/mt.log" 2>&1 &
    SP=$!; wait_port_tcp
    rm -f "$D/mt.ok"; pids=""
    for _ in 1 2 3 4 5 6 7 8; do
        ( openssl s_connection -connect 127.0.0.1:4433 -new -verify 1 -CAfile $C/CA.crt -www /payload.bin 2>&1 | grep -q "App-bytes: 100" && echo ok >> "$D/mt.ok" ) &
        pids="$pids $!"
    done
    for p in $pids; do wait "$p"; done
    verdict "TLS : serveur multi-connexions, 8 clients simultanes OK" "$([ "$(wc -l < "$D/mt.ok" 2>/dev/null || echo 0)" = "8" ] && echo OK || echo KO)"
    kill $SP 2>/dev/null; wait $SP 2>/dev/null
else verdict "TLS : tls_mt_server present" ABSENT; fi

echo "=== QUIC (MsQuic de l'image) ==="
if ! command -v quics_server >/dev/null 2>&1; then verdict "QUIC : quics_server present" ABSENT; else
# IMPORTANT : un serveur QUIC UNIQUE (donc des cles de ticket uniques) pour toute la serie reprise / 0-RTT ;
# un serveur relance a chaque connexion ne peut pas dechiffrer les tickets du precedent (faux KO de reprise).
QSP=""
qsrv_start() { # cert_dir "ENV serveur"
    local C="$1" SE="$2"
    env $SE quics_server -groups:$KEM -cert_file:$C/server.crt -key_file:$C/server.key >"$D/q_srv.log" 2>&1 &
    QSP=$!; sleep 1.5
}
qsrv_stop() { [ -n "$QSP" ] && kill "$QSP" 2>/dev/null; wait "$QSP" 2>/dev/null; QSP=""; sleep 0.5; }
qcli() { # cert_dir "ENV client" -> sortie client
    env $2 timeout 20 quics_connection -groups:$KEM -target:127.0.0.1 -CAfile:"$1/CA.crt" 2>&1
}
C="$D/ctl"
qsrv_start $C "SEND_TICKETS=1"
o=$(qcli $C "TICKET_OUT=$D/q.ticket")
echo "$o" | grep -q "^Ticket: 1" && verdict "QUIC : ticket de reprise recu" OK || verdict "QUIC : ticket de reprise recu" KO
o2=$(qcli $C "TICKET_IN=$D/q.ticket")
echo "$o2" | grep -q "^Resumed: 1" && verdict "QUIC : reprise (Resumed: 1)" OK || verdict "QUIC : reprise (Resumed: 1)" KO
qfull=$(echo "$o" | rx_of); qres=$(echo "$o2" | rx_of)
verdict "QUIC : octets recus complet=${qfull:-?} / repris=${qres:-?}" "$([ -n "$qfull" ] && [ -n "$qres" ] && [ "$qres" -lt "$qfull" ] && echo OK || echo KO)"
# deuxieme essai : le ticket de la reprise a-t-il ete renouvele ? (information seulement)
o3=$(qcli $C "TICKET_IN=$D/q.ticket ZERORTT=1")
echo "$o3" | grep -q "ZeroRTT-sent: 1" && verdict "QUIC : 0-RTT envoye" OK || verdict "QUIC : 0-RTT envoye" "KO (exploratoire)"
echo "$o3" | grep -q "^Resumed: 1" && verdict "QUIC : 0-RTT + reprise acceptee" OK || verdict "QUIC : 0-RTT + reprise acceptee" "KO (exploratoire)"
qsrv_stop
echo "--- diagnostic reprise (sortie client reprise, extraits) ---"; echo "$o2" | grep -i "Resumed\|Ticket\|Rx-bytes\|failed\|error" | head -8
echo "--- diagnostic serveur (extraits) ---"; grep -i "resum\|ticket\|error\|fail" "$D/q_srv.log" | head -8

qsrv_start $C "SRV_CERT_COMP=1"
base=$(qcli $C "CERT_COMP=none"); qb=$(echo "$base" | rx_of)
for a in zlib brotli zstd; do
    oc=$(qcli $C "CERT_COMP=$a"); qc=$(echo "$oc" | rx_of)
    if [ -n "$qb" ] && [ -n "$qc" ] && [ "$qc" -lt $((qb - 2000)) ]; then verdict "QUIC : compression $a (octets $qc vs $qb sans)" OK
    else verdict "QUIC : compression $a (octets ${qc:-?} vs ${qb:-?} sans)" KO; fi
done
qsrv_stop
echo "--- diagnostic compression : lignes [v3] du serveur ---"; grep -h "^\[v3\]" "$D/q_srv.log" | head -3
echo "--- diagnostic compression : OPENSSL_NO_COMP_ALG dans les en-tetes OpenSSL de MsQuic ---"
for h in $(find /opt/msquic-pq -name configuration.h -path "*openssl*" 2>/dev/null | head -4); do echo "$h: $(grep -c 'define OPENSSL_NO_COMP_ALG' $h) (1 = compression de certificat DESACTIVEE a la compilation)"; done
fi

echo
echo "=== RESUME ==="; printf '%s\n' "${RES[@]}"
echo "(Si 'QUIC : compression' est KO pour tous les algorithmes : l'OpenSSL embarque par MsQuic n'a pas les bibliotheques de compression."
echo " Les cellules QUIC de compression ne sont alors PAS lancees ; QUIC_COMP=0 dans make_plans_ext.sh, et la limite est declaree.)"
