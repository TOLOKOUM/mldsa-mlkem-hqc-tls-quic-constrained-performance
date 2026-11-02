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

if [ -z "$CERT_PATH" ]; then
    export CERT_PATH=/cert
fi

if [ -z "$MUTUAL" ]; then
     MUTUAL="true"
fi

# Chaine realiste (CHAIN_DEPTH=2 de doCert.sh) : l option -cert de s_server ne charge QUE le premier
# certificat du fichier (verifie sous OpenSSL 3.0.13) ; l'intermediaire doit etre fourni par
# -cert_chain, sinon TLS enverrait la feuille seule alors que MsQuic envoie toute la chaine.
CHAIN_ARGS=""
if [ -s "$CERT_PATH/ICA.crt" ]; then
    CHAIN_ARGS="-cert_chain $CERT_PATH/ICA.crt"
    echo "Chaine de certificats: intermediaire $CERT_PATH/ICA.crt envoye par s_server"
fi

# ---------------------------
# Create certificates 
# ---------------------------
# Optionally set server certificate alg to one defined in https://github.com/open-quantum-safe/oqs-provider#algorithms
# The root CA's signature alg remains as set when building the image
#CERT_PATH=/opt/certs

echo "Running $0 with SIG_ALG=$SIG_ALG and KEM_ALG=$KEM_ALG"


# ---------------------------
# Launch TLS OR QUIC server
# ---------------------------
# Start a TLS1.3 test server based on OpenSSL accepting only the specified KEM_ALG
# The env var DEFAULT_GROUPS activates the required Group via the system openssl.cnf:
# we put it on the command line to check for possible typos otherwise silently discarded:

if [ "$USE_TLS" = "true" ]; then

    # Point 4 du prescreen TDSC (TDSC-2026-09-3862) : -WWW (majuscule) sert
    # un vrai fichier depuis le repertoire courant ($INSTALLDIR/bin, ou se
    # trouve payload.bin genere au build -- voir le patch du Dockerfile),
    # au lieu de la page de statut de taille variable de -www (minuscule).
    # Ca donne une charge applicative de taille fixe (100 octets), la meme
    # des deux cotes TLS/QUIC (cf. SendBufferLength dans s_connection_quic.c
    # / s_server_quic.c), pour que "App-ready duration" soit comparable.
    # Critique 4 (AE) : -num_tickets 0 supprime les NewSessionTicket post-handshake
    # que s_server envoie par defaut en TLS 1.3, alors que le serveur QUIC
    # n'en envoie pas (ConnectionSendResumptionTicket desactive) : sans cela,
    # TLS transporterait des octets/paquets supplementaires absents de QUIC.
    if [ -n "${SSL_DIR:-}" ]; then
        KEYLOG_PATH="${SSL_DIR}/sslkeys_server_${SIG_ALG}_${KEM_ALG}.log"
        echo "🔐 TLS Keys stored in: $KEYLOG_PATH"     

        if [ "$MUTUAL" = "true" ]; then    
         echo "Executing TLS - Mutual Key"
         openssl s_server -cert $CERT_PATH/server.crt -key $CERT_PATH/server.key $CHAIN_ARGS -groups $DEFAULT_GROUPS -WWW -tls1_3 -num_tickets 0 -verify 1 -verifyCAfile $CERT_PATH/CA.crt  -accept :4433 -keylogfile "$KEYLOG_PATH"
        else
         echo "Executing TLS - Single Key"   
         openssl s_server -cert $CERT_PATH/server.crt -key $CERT_PATH/server.key $CHAIN_ARGS -groups $DEFAULT_GROUPS -WWW -tls1_3 -num_tickets 0 -accept :4433 -keylogfile "$KEYLOG_PATH" 
        fi 
    else
        if [ "$MUTUAL" = "true" ]; then    
         echo "Executing TLS - Mutual"
         openssl s_server -cert $CERT_PATH/server.crt -key $CERT_PATH/server.key $CHAIN_ARGS -groups $DEFAULT_GROUPS -WWW -tls1_3 -num_tickets 0 -verify 1 -verifyCAfile $CERT_PATH/CA.crt  -accept :4433
        else
         echo "Executing TLS - Single"   
         openssl s_server -cert $CERT_PATH/server.crt -key $CERT_PATH/server.key $CHAIN_ARGS -groups $DEFAULT_GROUPS -WWW -tls1_3 -num_tickets 0 -accept :4433
        fi 
    fi    

else 
     #echo "Executing QUIC"
     if [ "$MUTUAL" = "true" ]; then    
         echo "Executing QUIC - Mutual"
         quics_server -groups:$DEFAULT_GROUPS -cert_file:$CERT_PATH/server.crt -key_file:$CERT_PATH/server.key -verifyCAfile $CERT_PATH/CA.crt
        else
         echo "Executing QUIC - Single"   
         quics_server -groups:$DEFAULT_GROUPS -cert_file:$CERT_PATH/server.crt -key_file:$CERT_PATH/server.key
        fi 
fi

# Give server time to come up first:
#sleep 1
