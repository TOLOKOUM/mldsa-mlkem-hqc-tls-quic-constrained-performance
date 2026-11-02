#!/bin/sh
###############################################################################
# doCert.sh — Genere CA + certificats serveur/utilisateur pour SIG_ALG.
#
# COMPORTEMENT PAR DEFAUT INCHANGE (CHAIN_DEPTH=1, pas de padding) : memes
# commandes openssl, memes fichiers (CA.*, server.*, user.*) qu'avant.
#
# Nouveaux controles (critiques 3 et 6 de l'AE, TDSC-2026-09-3862) :
#
#   CHAIN_DEPTH=2           Chaine REALISTE racine -> intermediaire -> feuille.
#                           server.crt et user.crt contiennent feuille + intermediaire
#                           (le serveur/client envoie 2 certificats) ; CA.crt reste la
#                           racine seule (ancre de confiance du pair). Limite a 1 ou 2 :
#                           les commandes de la campagne utilisent -verify 1 (profondeur
#                           = 1 intermediaire au maximum).
#
#   CERT_PAD_BYTES=N        EXPERIENCE DE CONTROLE DE TAILLE : ajoute aux certificats
#                           FEUILLES (serveur ET utilisateur) une extension X.509 privee
#                           NON critique (OID 1.3.6.1.4.1.32473.1.1, arc de documentation)
#                           portant N octets. Permet d'agrandir un certificat classique
#                           (ECDSA/EdDSA) jusqu'a la taille d'un certificat ML-DSA SANS
#                           changer l'algorithme de signature : on separe ainsi le cout
#                           cryptographique du cout induit par la taille (paquetisation,
#                           recuperation de pertes). Les verificateurs ignorent les
#                           extensions non critiques inconnues.
#
#   CERT_PAD_TARGET_DER=T   Variante automatique : ajuste le padding pour que la taille DER
#                           de chaque feuille soit T octets (tolerance +-3 : la signature
#                           ECDSA varie de 1-2 octets d'une generation a l'autre).
#                           Exclusif avec CERT_PAD_BYTES.
#   Remarque : seule la CHAINE de certificats est paddee ; le CertificateVerify (signature)
#   ne peut pas l'etre. Pour egaler le vol serveur d'une configuration ML-DSA :
#       T = DER(feuille ML-DSA) + (CertificateVerify_MLDSA - CertificateVerify_classique)
#   (tailles lues dans traffic_size_summary.csv / cert_sizes.txt).
#
# Sortie d'audit : $CERT_PATH/cert_sizes.txt (tailles DER racine/intermediaire/feuilles).
#
# Compatible /bin/sh (dash). Variables optionnelles de test : OPENSSL_CNF.
###############################################################################
set -e

if [ -z "$SIG_ALG" ]; then
	export SIG_ALG=mldsa44
fi

if [ -z "$CERT_PATH" ]; then
   CERT_PATH=/opt/certs
   mkdir -p $CERT_PATH
fi

: "${OPENSSL_CNF:=/opt/oqssa/ssl/openssl.cnf}"
: "${CHAIN_DEPTH:=1}"
: "${CERT_PAD_BYTES:=0}"
: "${CERT_PAD_TARGET_DER:=0}"

die() { echo "doCert.sh: ERREUR: $*" >&2; exit 1; }

case "$CHAIN_DEPTH" in 1|2) ;; *) die "CHAIN_DEPTH='$CHAIN_DEPTH' invalide (1 ou 2)";; esac
case "$CERT_PAD_BYTES" in ''|*[!0-9]*) die "CERT_PAD_BYTES='$CERT_PAD_BYTES' invalide (entier >= 0)";; esac
case "$CERT_PAD_TARGET_DER" in ''|*[!0-9]*) die "CERT_PAD_TARGET_DER='$CERT_PAD_TARGET_DER' invalide (entier >= 0)";; esac
if [ "$CERT_PAD_BYTES" -gt 0 ] && [ "$CERT_PAD_TARGET_DER" -gt 0 ]; then
    die "CERT_PAD_BYTES et CERT_PAD_TARGET_DER sont exclusifs"
fi
if [ "$CERT_PAD_BYTES" -gt 60000 ]; then die "CERT_PAD_BYTES trop grand (max 60000)"; fi

echo "Creating certificates"
# Le volume 'cert' peut contenir une chaine d'un run precedent : un ICA.crt perime serait
# ajoute a tort par le serveur TLS (perftestServerTlsQuic.sh detecte ICA.crt).
rm -f $CERT_PATH/ICA.* $CERT_PATH/ica.ext $CERT_PATH/server.leaf.crt $CERT_PATH/user.leaf.crt $CERT_PATH/pad.ext
[ -d /opt/oqssa/bin ] && cd /opt/oqssa/bin

# ---------------------------------------------------------------------------
# Primitives (memes commandes openssl que la version historique)
# ---------------------------------------------------------------------------

# gen_root : CA racine auto-signee -> CA.key, CA.crt
gen_root() {
    case "$SIG_ALG" in
    secp*)
        openssl ecparam -out $CERT_PATH/CA.key  -name $SIG_ALG -genkey
        openssl req -x509 -new -key $CERT_PATH/CA.key  -out $CERT_PATH/CA.crt  -sha384 -nodes -subj "/CN=oqstest CA" -days 365 -config $OPENSSL_CNF
        ;;
    *)
        openssl req -x509 -new -newkey $SIG_ALG -keyout $CERT_PATH/CA.key -out $CERT_PATH/CA.crt -nodes -subj "/CN=oqstest CA" -days 365 -config $OPENSSL_CNF
        ;;
    esac
}

# gen_key_csr <nom> <sujet> : cle + CSR -> <nom>.key, <nom>.csr
gen_key_csr() {
    case "$SIG_ALG" in
    secp*)
        openssl ecparam -out $CERT_PATH/$1.key  -name $SIG_ALG -genkey
        openssl req -new -key $CERT_PATH/$1.key  -out $CERT_PATH/$1.csr  -sha384 -nodes -subj "$2"
        ;;
    *)
        openssl req -new -newkey $SIG_ALG -keyout $CERT_PATH/$1.key -out $CERT_PATH/$1.csr -nodes -subj "$2"
        ;;
    esac
}

# sign_csr <csr> <sortie> <cert emetteur> <cle emetteur> [extfile]
sign_csr() {
    if [ -n "$5" ]; then
        openssl x509 -req -in $1 -out $2 -CA $3 -CAkey $4 -CAcreateserial -days 365 -extfile $5
    else
        openssl x509 -req -in $1 -out $2 -CA $3 -CAkey $4 -CAcreateserial -days 365
    fi
}

der_size() { openssl x509 -in "$1" -outform DER | wc -c | tr -d ' '; }

# write_pad_ext <N> <fichier> : extension privee non critique de N octets (0xA5)
write_pad_ext() {
    {
        printf '1.3.6.1.4.1.32473.1.1=ASN1:FORMAT:HEX,OCTETSTRING:'
        yes A5 | head -n "$1" | tr -d '\n'
        printf '\n'
    } > "$2"
}

# sign_leaf_pad <csr> <sortie> <emetteur crt> <emetteur key> <pad>
sign_leaf_pad() {
    if [ "$5" -gt 0 ]; then
        write_pad_ext "$5" $CERT_PATH/pad.ext
        sign_csr "$1" "$2" "$3" "$4" $CERT_PATH/pad.ext
    else
        sign_csr "$1" "$2" "$3" "$4"
    fi
}

# issue_leaf <nom> <sujet> <emetteur crt> <emetteur key> : produit <nom>.crt (feuille seule)
# puis, si CHAIN_DEPTH=2, <nom>.crt = feuille + intermediaire (la feuille seule reste en <nom>.leaf.crt)
issue_leaf() {
    name="$1"; subj="$2"; icrt="$3"; ikey="$4"
    gen_key_csr "$name" "$subj"
    if [ "$CHAIN_DEPTH" = "2" ]; then leaf=$CERT_PATH/$name.leaf.crt; else leaf=$CERT_PATH/$name.crt; fi

    if [ "$CERT_PAD_TARGET_DER" -gt 0 ]; then
        T=$CERT_PAD_TARGET_DER
        sign_leaf_pad $CERT_PATH/$name.csr "$leaf" "$icrt" "$ikey" 0
        s=$(der_size "$leaf")
        [ "$s" -lt "$T" ] || die "cible $T <= taille sans padding ($s octets) pour $name"
        pad=$(( T - s - 30 ))            # 1re estimation (surcout d'extension ~30 octets)
        [ "$pad" -ge 1 ] || pad=1
        n=0
        while [ "$n" -lt 8 ]; do
            sign_leaf_pad $CERT_PATH/$name.csr "$leaf" "$icrt" "$ikey" "$pad"
            s=$(der_size "$leaf")
            d=$(( T - s ))
            [ "$d" -eq 0 ] && break
            pad=$(( pad + d ))
            [ "$pad" -ge 1 ] || pad=1
            n=$(( n + 1 ))
        done
        s=$(der_size "$leaf"); d=$(( T - s )); [ "$d" -ge 0 ] || d=$(( -d ))
        [ "$d" -le 3 ] || die "padding automatique non convergent pour $name (taille $s, cible $T)"
        echo "  $name: cible DER=$T -> obtenu $s (pad=$pad octets)"
    else
        sign_leaf_pad $CERT_PATH/$name.csr "$leaf" "$icrt" "$ikey" "$CERT_PAD_BYTES"
    fi

    if [ "$CHAIN_DEPTH" = "2" ]; then
        cat "$leaf" $CERT_PATH/ICA.crt > $CERT_PATH/$name.crt
    fi
}

# ---------------------------------------------------------------------------
# Generation
# ---------------------------------------------------------------------------
echo "Using $( [ "${SIG_ALG#secp}" != "$SIG_ALG" ] && echo ECDSA || echo default ) procedure for $SIG_ALG (chain_depth=$CHAIN_DEPTH pad_bytes=$CERT_PAD_BYTES pad_target_der=$CERT_PAD_TARGET_DER)"

gen_root

if [ "$CHAIN_DEPTH" = "2" ]; then
    # Intermediaire : meme algorithme que la racine et les feuilles.
    printf 'basicConstraints=critical,CA:TRUE\n' > $CERT_PATH/ica.ext
    gen_key_csr ICA "/CN=oqstest Intermediate CA"
    sign_csr $CERT_PATH/ICA.csr $CERT_PATH/ICA.crt $CERT_PATH/CA.crt $CERT_PATH/CA.key $CERT_PATH/ica.ext
    ISSUER_CRT=$CERT_PATH/ICA.crt; ISSUER_KEY=$CERT_PATH/ICA.key
else
    ISSUER_CRT=$CERT_PATH/CA.crt;  ISSUER_KEY=$CERT_PATH/CA.key
fi

issue_leaf server "/CN=localhost" "$ISSUER_CRT" "$ISSUER_KEY"
issue_leaf user   "/CN=user"      "$ISSUER_CRT" "$ISSUER_KEY"

# ---------------------------------------------------------------------------
# Verification de coherence (uniquement pour les modes NOUVEAUX, pour ne pas
# risquer de regression sur le chemin historique) + rapport de tailles
# ---------------------------------------------------------------------------
if [ "$CHAIN_DEPTH" = "2" ]; then
    for n in server user; do
        openssl verify -CAfile $CERT_PATH/CA.crt -untrusted $CERT_PATH/ICA.crt $CERT_PATH/$n.leaf.crt >/dev/null \
            || die "chaine invalide pour $n (verify)"
    done
elif [ "$CERT_PAD_BYTES" -gt 0 ] || [ "$CERT_PAD_TARGET_DER" -gt 0 ]; then
    for n in server user; do
        openssl verify -CAfile $CERT_PATH/CA.crt $CERT_PATH/$n.crt >/dev/null || die "certificat padde invalide pour $n (verify)"
    done
fi

if [ "$CHAIN_DEPTH" = "2" ]; then
    S_LEAF=$(der_size $CERT_PATH/server.leaf.crt); U_LEAF=$(der_size $CERT_PATH/user.leaf.crt); ICA_DER=$(der_size $CERT_PATH/ICA.crt)
else
    S_LEAF=$(der_size $CERT_PATH/server.crt);      U_LEAF=$(der_size $CERT_PATH/user.crt);      ICA_DER=0
fi
ROOT_DER=$(der_size $CERT_PATH/CA.crt)
{
    echo "sig=$SIG_ALG chain_depth=$CHAIN_DEPTH pad_bytes=$CERT_PAD_BYTES pad_target_der=$CERT_PAD_TARGET_DER"
    echo "der_bytes: root=$ROOT_DER intermediate=$ICA_DER server_leaf=$S_LEAF user_leaf=$U_LEAF server_chain_sent=$(( S_LEAF + ICA_DER )) user_chain_sent=$(( U_LEAF + ICA_DER ))"
} > $CERT_PATH/cert_sizes.txt
cat $CERT_PATH/cert_sizes.txt

echo "Running $0 with SIG_ALG=$SIG_ALG and certificates created"
echo
