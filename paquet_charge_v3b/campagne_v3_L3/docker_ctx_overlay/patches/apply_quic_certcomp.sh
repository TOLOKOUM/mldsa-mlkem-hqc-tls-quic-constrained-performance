#!/bin/sh
###############################################################################
# apply_quic_certcomp.sh <tls_openssl.c> -- campagne v3 : compression de certificat (RFC 8879) dans MsQuic.
#
# MsQuic (QUIC_TLS=openssl3) cree ses SSL_CTX sans jamais configurer la compression de certificat. Or, avec OpenSSL >= 3.2,
#  (a) un client annonce l'extension compress_certificate PAR DEFAUT si la bibliotheque a ete compilee avec zlib/brotli/zstd ;
#  (b) un serveur n'envoie un message Certificate compresse (type 25) que s'il a PRE-COMPRESSE sa chaine
#      (SSL_CTX_compress_certs) : il n'y a pas de compression a la volee.
# Ce patch ajoute, derriere deux variables d'environnement (absentes => comportement v2 inchange) :
#   serveur : SRV_CERT_COMP=1   -> SSL_CTX_compress_certs(ctx, 0) apres le chargement de la chaine ;
#   client  : CERT_COMP=none|zlib|brotli|zstd -> options / preference d'algorithme (comme s_connection TLS).
# Le tout est sous #if OPENSSL_VERSION_NUMBER >= 0x30200000L && !OPENSSL_NO_COMP_ALG : si l'OpenSSL embarque par MsQuic
# (sous-module quictls openssl-3.3.0+quic) n'a pas ete compile avec les bibliotheques de compression, le code est
# simplement ecarte et le probe (probe_quic_features.sh) l'indique : on ne pretend alors pas mesurer la compression QUIC.
# Le script ECHOUE (=> le build Docker echoue) si une ancre n'est pas trouvee exactement une fois.
###############################################################################
set -eu
F="${1:?usage: $0 <tls_openssl.c>}"
[ -f "$F" ] || { echo "introuvable: $F" >&2; exit 1; }
grep -q 'SRV_CERT_COMP' "$F" && { echo "deja patche: $F"; exit 0; }

A1='#include "platform_internal.h"'
A2='    if (CredConfigFlags & QUIC_CREDENTIAL_FLAG_SET_CA_CERTIFICATE_FILE &&'
A3='        SSL_CTX_set_cert_verify_callback(SecurityConfig->SSLCtx, CxPlatTlsCertificateVerifyCallback, NULL);'
for A in "$A1" "$A2" "$A3"; do
    N=$(grep -c -F -- "$A" "$F" || true)
    [ "$N" -eq 1 ] || { echo "ERREUR: ancre attendue 1 fois, trouvee $N : $A" >&2; exit 1; }
done

export A1 A2 A3
perl -0pi -e '
my ($a1,$a2,$a3)=($ENV{A1},$ENV{A2},$ENV{A3});
my $inc = "\n#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n";
my $srv = <<"SRV";
#if OPENSSL_VERSION_NUMBER >= 0x30200000L && !defined(OPENSSL_NO_COMP_ALG)
    /* campagne v3 : pre-compression de la chaine cote serveur (SRV_CERT_COMP=1) */
    if (!(CredConfigFlags & QUIC_CREDENTIAL_FLAG_CLIENT) && CredConfig->Type != QUIC_CREDENTIAL_TYPE_NONE) {
        const char* SrvCertComp = getenv("SRV_CERT_COMP");
        if (SrvCertComp != NULL && SrvCertComp[0] == 49) {
            int CompOk = SSL_CTX_compress_certs(SecurityConfig->SSLCtx, 0);
            ERR_clear_error();
            fprintf(stderr, "[v3] SRV_CERT_COMP=1 : pre-compression de la chaine : %s\\n", CompOk ? "OK" : "aucun gain (chaine envoyee non compressee)");
        }
    }
#endif

SRV
my $cli = <<"CLI";

#if OPENSSL_VERSION_NUMBER >= 0x30200000L && !defined(OPENSSL_NO_COMP_ALG)
        /* campagne v3 : choix de l algorithme de compression de certificat cote client (CERT_COMP) */
        {
            const char* CertComp = getenv("CERT_COMP");
            if (CertComp != NULL && CertComp[0] != 0) {
                if (strcmp(CertComp, "none") == 0) {
                    SSL_CTX_set_options(SecurityConfig->SSLCtx, SSL_OP_NO_RX_CERTIFICATE_COMPRESSION | SSL_OP_NO_TX_CERTIFICATE_COMPRESSION);
                } else {
                    int Alg = (strcmp(CertComp, "zlib") == 0) ? TLSEXT_comp_cert_zlib
                            : (strcmp(CertComp, "brotli") == 0) ? TLSEXT_comp_cert_brotli
                            : (strcmp(CertComp, "zstd") == 0) ? TLSEXT_comp_cert_zstd : -1;
                    if (Alg < 0 || !SSL_CTX_set1_cert_comp_preference(SecurityConfig->SSLCtx, &Alg, 1)) {
                        fprintf(stderr, "[v3] CERT_COMP=%s indisponible dans cette build\\n", CertComp);
                    }
                }
            }
        }
#endif
CLI
s/\Q$a1\E/$a1$inc/;
s/\Q$a2\E/$srv$a2/;
s/(\Q$a3\E)/$1$cli/;
' "$F"

grep -q 'SRV_CERT_COMP' "$F" && grep -q 'getenv("CERT_COMP")' "$F" || { echo "ERREUR: patch non applique" >&2; exit 1; }
echo "OK: compression de certificat (v3) ajoutee dans $F"
