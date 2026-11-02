#!/usr/bin/env bash
###############################################################################
# size_targets.sh — Calcule la taille cible du certificat ECDSA "gonfle" pour
# l'EXPERIENCE DE CONTROLE DE TAILLE (critique 3), a partir de MESURES reelles
# dans l'image (aucune valeur supposee).
#
# Principe : on veut que ECDSA-gonfle envoie sur le fil le meme nombre d'octets
# d'authentification que ML-DSA-65 (certificat + signature CertificateVerify),
# tout en gardant un calcul cryptographique classique :
#   T = der(leaf ML-DSA-65) + sig(ML-DSA-65) - sig(ECDSA P-384)
# ou T est la taille DER cible de la FEUILLE ECDSA (CERT_PAD_TARGET_DER).
#
# Usage : bash size_targets.sh [image] [dossier_plans]
# Sortie : affiche les mesures + ecrit <plans>/size_targets.env (SIZE_TARGET_DER=...)
# Volume Docker temporaire 'cert_sizecalc' : ne touche PAS au volume 'cert'.
###############################################################################
set -uo pipefail
IMAGE="${1:-uma-tls-quic-pq-34}"
PLANS="${2:-plans}"
VOL=cert_sizecalc
die() { echo "❌ $*" >&2; exit 1; }
command -v docker >/dev/null || die "docker introuvable."
docker image inspect "$IMAGE" >/dev/null 2>&1 || die "image $IMAGE absente."
mkdir -p "$PLANS"
docker volume rm -f $VOL >/dev/null 2>&1 || true
docker volume create $VOL >/dev/null

gen() { # sig [pad_target] -> imprime server_leaf
  docker run --rm -v $VOL:/cert -e CERT_PATH=/cert/ -e SIG_ALG="$1" -e CHAIN_DEPTH=1 \
     -e CERT_PAD_BYTES=0 -e CERT_PAD_TARGET_DER="${2:-0}" -i "$IMAGE" doCert.sh >/dev/null 2>&1 || return 1
  docker run --rm -v $VOL:/cert --entrypoint cat "$IMAGE" /cert/cert_sizes.txt | sed -n 's/.*server_leaf=\([0-9]*\).*/\1/p'
}
# Taille de signature mesuree : 20 signatures d'un fichier de 100 octets avec la cle du serveur.
sigsize() {
  docker run --rm -v $VOL:/cert --entrypoint sh "$IMAGE" -c '
    head -c 100 /dev/urandom > /tmp/m
    t=0; n=0
    for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
      if openssl pkeyutl -sign -rawin -inkey /cert/server.key -in /tmp/m -out /tmp/s 2>/dev/null || \
         openssl dgst -sha384 -sign /cert/server.key -out /tmp/s /tmp/m 2>/dev/null; then
        t=$((t + $(wc -c < /tmp/s))); n=$((n+1))
      fi
    done
    [ $n -gt 0 ] && echo $((t / n)) || echo 0'
}

echo ">> mesure ML-DSA-65 ..."
ML_LEAF=$(gen mldsa65) || die "doCert mldsa65 a echoue"
ML_SIG=$(sigsize)
echo ">> mesure ECDSA P-384 ..."
EC_LEAF=$(gen secp384r1) || die "doCert secp384r1 a echoue"
EC_SIG=$(sigsize)
[[ "$ML_LEAF" =~ ^[0-9]+$ && "$EC_LEAF" =~ ^[0-9]+$ && "$ML_SIG" =~ ^[0-9]+$ && "$EC_SIG" =~ ^[0-9]+$ ]] || die "mesures non numeriques (ML leaf='$ML_LEAF' sig='$ML_SIG' ; EC leaf='$EC_LEAF' sig='$EC_SIG')."
(( ML_SIG > 1000 && EC_SIG > 50 && EC_SIG < 200 )) || die "tailles de signature invraisemblables (ML=$ML_SIG, EC=$EC_SIG) : verifier l'image."

T=$(( ML_LEAF + ML_SIG - EC_SIG ))
echo ">> verification : ECDSA gonfle a T=$T ..."
GOT=$(gen secp384r1 "$T") || die "doCert avec padding a echoue"
DIFF=$(( GOT > T ? GOT - T : T - GOT ))
echo ""
echo "  ML-DSA-65  : feuille DER = $ML_LEAF o ; signature = $ML_SIG o"
echo "  ECDSA P-384: feuille DER = $EC_LEAF o ; signature = $EC_SIG o (moyenne)"
echo "  Octets d'authentification (cert+signature) : ML-DSA-65 = $(( ML_LEAF + ML_SIG )) ; ECDSA normal = $(( EC_LEAF + EC_SIG )) ; ECDSA gonfle = $(( GOT + EC_SIG ))"
echo "  Cible T = $T ; feuille gonflee obtenue = $GOT (ecart $DIFF)"
docker volume rm -f $VOL >/dev/null 2>&1 || true
(( DIFF <= 2 )) || die "ecart > 2 octets entre cible et feuille gonflee : ne pas utiliser cette valeur."
{
  echo "# genere par size_targets.sh le $(date -Iseconds) -- mesures reelles de l'image $IMAGE"
  echo "# ml_leaf=$ML_LEAF ml_sig=$ML_SIG ec_leaf=$EC_LEAF ec_sig=$EC_SIG got=$GOT"
  echo "SIZE_TARGET_DER=$T"
} > "$PLANS/size_targets.env"
echo ""
echo "✅ $PLANS/size_targets.env ecrit. Ensuite : source $PLANS/size_targets.env && export SIZE_TARGET_DER && bash make_plans.sh $PLANS"
