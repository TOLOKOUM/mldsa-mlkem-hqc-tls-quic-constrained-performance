#!/bin/sh
###############################################################################
# apply_quic_chpad.sh <tls_openssl.c> -- campagne S3 : remplissage du ClientHello QUIC (variable d'environnement CH_PAD_BYTES).
# But : faire varier B_c SANS changer ni le KEM, ni la signature, ni la chaine, donc le vol serveur. Le client ajoute au ClientHello
# UNE extension TLS privee de N octets (type 0xFFB3, usage prive) que le serveur ignore (RFC 8446 §4.2).
# Sans CH_PAD_BYTES : comportement INCHANGE. Effet cote CLIENT seulement. A appliquer APRES apply_quic_certcomp.sh.
# Le script ECHOUE (donc le build) si une ancre n'est pas trouvee exactement une fois.
###############################################################################
set -eu
F="${1:?usage: $0 <tls_openssl.c>}"
[ -f "$F" ] || { echo "introuvable: $F" >&2; exit 1; }
grep -q 'CH_PAD_BYTES' "$F" && { echo "deja patche: $F"; exit 0; }

A1='extern EVP_CIPHER *CXPLAT_AES_256_CBC_ALG_HANDLE;'
A2='        SSL_CTX_set_cert_verify_callback(SecurityConfig->SSLCtx, CxPlatTlsCertificateVerifyCallback, NULL);'
for A in "$A1" "$A2"; do
    N=$(grep -c -F -- "$A" "$F" || true)
    [ "$N" -eq 1 ] || { echo "ERREUR: ancre attendue 1 fois, trouvee $N : $A" >&2; exit 1; }
done

export A1 A2
perl -0pi -e '
my ($a1,$a2)=($ENV{A1},$ENV{A2});
my $fn = <<"FN";

/* campagne S3 : extension privee de remplissage du ClientHello (CH_PAD_BYTES) */
#define S3_CHPAD_EXT_TYPE 0xFFB3u
static unsigned char S3ChPadBuf[65536];
static size_t S3ChPadLen = 0;
static int S3ChPadAddCb(SSL* s, unsigned int ExtType, const unsigned char** Out, size_t* OutLen, int* Al, void* Arg)
{
    (void)s; (void)ExtType; (void)Al; (void)Arg;
    *Out = S3ChPadBuf;
    *OutLen = S3ChPadLen;
    return 1;
}
static void S3ChPadFreeCb(SSL* s, unsigned int ExtType, const unsigned char* Out, void* Arg)
{
    (void)s; (void)ExtType; (void)Out; (void)Arg;
}
FN
my $cli = <<"CLI";

        /* campagne S3 : remplissage du ClientHello (CH_PAD_BYTES=N, N octets de donnees dans une extension privee) */
        {
            const char* ChPad = getenv("CH_PAD_BYTES");
            if (ChPad != NULL && ChPad[0] != 0) {
                long ChPadN = strtol(ChPad, NULL, 10);
                if (ChPadN > 0 && ChPadN <= 60000) {
                    S3ChPadLen = (size_t)ChPadN;
                    memset(S3ChPadBuf, 0, sizeof(S3ChPadBuf));
                    if (SSL_CTX_add_client_custom_ext(SecurityConfig->SSLCtx, S3_CHPAD_EXT_TYPE,
                                                      S3ChPadAddCb, S3ChPadFreeCb, NULL, NULL, NULL) != 1) {
                        fprintf(stderr, "[S3] CH_PAD_BYTES=%ld : SSL_CTX_add_client_custom_ext a echoue\\n", ChPadN);
                    } else {
                        fprintf(stderr, "[S3] CH_PAD_BYTES=%ld : extension 0x%04x ajoutee au ClientHello\\n", ChPadN, (unsigned)S3_CHPAD_EXT_TYPE);
                    }
                } else {
                    fprintf(stderr, "[S3] CH_PAD_BYTES=%s ignore (attendu : entier 1..60000)\\n", ChPad);
                }
            }
        }
CLI
my $n1 = s/\Q$a1\E/$a1$fn/;
my $n2 = s/\Q$a2\E/$a2$cli/;
die "remplacement ancre: $n1 $n2\n" unless $n1==1 && $n2==1;
' "$F"
echo "OK: remplissage du ClientHello (S3) ajoute dans $F"
