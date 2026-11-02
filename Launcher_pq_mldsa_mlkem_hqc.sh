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
# ─────────────────────────────────────────────────────────────────────────
# AJOUT (résout le point 2 du rejet : "ordre fixe, campagne unique, pas de
# blocs indépendants") : le sweep total de 500 handshakes par configuration
# peut être fractionné en N_BLOCKS blocs indépendants, exécutés à des
# moments différents (idéalement des jours différents) via des invocations
# séparées du launcher avec un BLOCK_INDEX différent à chaque fois. L'ordre
# des configurations (SIG_ALG × KEM) est systématiquement mélangé (jamais
# l'ordre fixe du tableau SUPPORTED_SIG_ALGS), avec une graine tracée dans
# un manifeste pour audit/reproductibilité.
#
#   N_BLOCKS    : nombre total de blocs (défaut 1 = comportement historique,
#                 mais avec ordre DÉSORMAIS toujours randomisé)
#   BLOCK_INDEX : indice du bloc exécuté par CET appel (1..N_BLOCKS)
#   SEED        : graine de mélange. Vide = dérivée de l'horodatage courant
#                 (et alors loggée pour pouvoir être rejouée à l'identique).
N_BLOCKS=${8:-1}
BLOCK_INDEX=${9:-1}
SEED=${10:-}

if ! [[ "$N_BLOCKS" =~ ^[0-9]+$ ]] || [[ "$N_BLOCKS" -lt 1 ]]; then
    echo "Invalid n-blocks: must be a positive integer."
    exit 1
fi
if ! [[ "$BLOCK_INDEX" =~ ^[0-9]+$ ]] || [[ "$BLOCK_INDEX" -lt 1 ]] || [[ "$BLOCK_INDEX" -gt "$N_BLOCKS" ]]; then
    echo "Invalid block-index: must satisfy 1 <= block-index <= n-blocks ($N_BLOCKS)."
    exit 1
fi
if [[ -z "$SEED" ]]; then
    SEED=$(date +%s)
    echo "Aucune graine fournie -- graine dérivée de l'horodatage : $SEED (notez-la pour rejouer cet ordre exact)."
fi
if ! [[ "$SEED" =~ ^[0-9]+$ ]]; then
    echo "Invalid seed: must be a non-negative integer."
    exit 1
fi

# ─────────────────────────────────────────────────────────────────────────
# Facteurs experimentaux controles (points 1, 3 et 5 du prescreen TDSC).
# Passes par variables d'environnement pour ne pas allonger la liste des
# arguments positionnels ; les valeurs par defaut reproduisent le
# comportement historique.
#   MTU             : MTU des interfaces eth0 serveur ET client (1280..1500)
#   LOSS_DIRECTION  : s2c (defaut) | c2s | both -- direction d'application de
#                     la perte (le delai reste toujours symetrique)
#   NETEM_LIMIT     : taille de file netem en paquets, fixee explicitement
#   PIN_CPUS        : auto (defaut) = un coeur physique dedie (2 threads
#                     freres) au serveur et un autre au client ; off = pas
#                     d'epinglage
#   ONLY_PAIRS      : restreint le sweep, ex "mldsa65|x448_mlkem768,secp384r1|x448_mlkem768"
#   PER_CONN_PCAP   : 1 = un pcap par connexion (campagne mecanistique)
MTU=${MTU:-1500}
LOSS_DIRECTION=${LOSS_DIRECTION:-s2c}
NETEM_LIMIT=${NETEM_LIMIT:-1000}
PIN_CPUS=${PIN_CPUS:-auto}
ONLY_PAIRS=${ONLY_PAIRS:-}
PER_CONN_PCAP=${PER_CONN_PCAP:-0}
#
# ── Isolation des connexions TCP (critiques 2 et 4 de l'AE) ─────────────────
#   TCP_ISOLATE : 1 (defaut) = reglages TCP imposes aux DEUX conteneurs :
#     - net.ipv4.tcp_no_metrics_save=1 : le noyau ne memorise plus RTT / ssthresh /
#       cwnd par destination. Sans cela, les ~30 connexions TLS d'une paire
#       s'heritent les unes des autres (cache tcp_metrics), alors que QUIC
#       (MsQuic, espace utilisateur) n'a pas de tel cache : essais consecutifs
#       correles cote TLS seulement (critique 2) et politique de connexion
#       differente entre protocoles (critique 4).
#     - net.ipv4.tcp_syn_retries=8 : par defaut (6) le connect() TCP abandonne
#       apres ~127 s, AVANT le budget commun de HANDSHAKE_TIMEOUT_S (150 s)
#       applique a QUIC. Avec 8 (~511 s), l'unique arbitre de l'echec est le
#       `timeout` externe, identique TLS/QUIC (critique 4).
#     Appliques aussi au conteneur QUIC (sans effet sur UDP) pour garder un
#     environnement noyau strictement identique entre protocoles.
#     0 = comportement historique (a declarer dans l'article si utilise).
TCP_ISOLATE=${TCP_ISOLATE:-1}
#
# ── Controles ajoutes pour la campagne randomisee 20x25 (critiques 1, 2, 4, 5) ──
#   TOTAL_RUNS          : connexions mesurees par paire sur l'ENSEMBLE des blocs
#                         (defaut 500 => 20 blocs x 25). Doit etre divisible par N_BLOCKS.
#   WARMUP_RUNS         : connexions jetees par paire avant mesure (defaut 0 ; campagne : 5)
#   HANDSHAKE_TIMEOUT_S : budget d'echec mur-a-mur COMMUN TLS/QUIC (defaut 150 s)
#   VISIT_TAG           : si defini (ex. pre|mid|post) => visite "sentinelle" : sortie
#                         isolee dans <profil>__sentinel_<tag>, jamais melangee aux
#                         donnees principales (estimation directe de la derive).
#   COOLDOWN_TEMP_C     : si defini, attend (max COOLDOWN_MAX_S) que x86_pkg_temp <= cette
#                         valeur avant chaque paire (stabilise l'etat thermique).
#   OFFLOAD_OFF=1       : desactive TSO/GSO/GRO sur eth0 des 2 conteneurs, pour que netem
#                         applique la perte PAQUET PAR PAQUET (necessite ethtool dans l'image).
#   PRINT_ORDER=1       : affiche l'ordre melange des paires pour cette graine puis quitte
#                         (aucune action Docker) -- pour tester la reproductibilite.
TOTAL_RUNS=${TOTAL_RUNS:-500}
WARMUP_RUNS=${WARMUP_RUNS:-0}
HANDSHAKE_TIMEOUT_S=${HANDSHAKE_TIMEOUT_S:-150}
VISIT_TAG=${VISIT_TAG:-}
COOLDOWN_TEMP_C=${COOLDOWN_TEMP_C:-}
COOLDOWN_MAX_S=${COOLDOWN_MAX_S:-180}
OFFLOAD_OFF=${OFFLOAD_OFF:-0}
#   QUIC_MTU_SYNC       : 0 (defaut) = MsQuic garde son comportement par defaut (handshake a 1280 octets, sondage
#                         DPLPMTUD ensuite : le MTU d'interface ne change alors PAS la paquetisation QUIC) ;
#                         1 = MinimumMtu=MaximumMtu=MTU cote QUIC (client ET serveur), comme le MSS TCP suit le MTU.
#                         A utiliser dans les cellules ou le MTU est un FACTEUR (plans mech et sizectl).
QUIC_MTU_SYNC=${QUIC_MTU_SYNC:-0}
PRINT_ORDER=${PRINT_ORDER:-0}
#   MICRO_BATCHES       : 1 (defaut, historique) | M>1 = ENTRELACEMENT en micro-lots (critique 1) : le bloc est
#                         execute en M tours ; a chaque tour TOUTES les paires sont visitees dans un ordre
#                         RE-TIRE (graine derivee, journalisee) avec RUNS_THIS_BLOCK/M connexions par paire.
#                         Une derive lente se repartit ainsi sur toutes les paires au lieu de s'aligner sur
#                         l'ordre d'un seul tirage. Cout : M fois plus d'installations de conteneurs (+ warm-up
#                         par tour) -> a reserver aux sous-plans a peu de paires (contrastes cles).
MICRO_BATCHES=${MICRO_BATCHES:-1}
#   CHAIN_DEPTH         : 1 (defaut, historique) | 2 = chaine realiste racine->intermediaire->feuille
#                         (critique 6, certificats). Transmis a doCert.sh ; le serveur TLS ajoute -cert_chain.
#   CERT_PAD_BYTES / CERT_PAD_TARGET_DER : experience de controle de taille (critique 3), cf. doCert.sh.
CHAIN_DEPTH=${CHAIN_DEPTH:-1}
CERT_PAD_BYTES=${CERT_PAD_BYTES:-0}
CERT_PAD_TARGET_DER=${CERT_PAD_TARGET_DER:-0}
#   RATE_MBIT           : debit du lien (Mbit/s), applique par netem 'rate' sur l'egress de CHAQUE conteneur
#                         (critique 5 : la bande passante devient un facteur FIXE et declare, pas implicite).
#                         Vide/0 = non limite (comportement historique). Incompatible avec les profils
#                         pumba stable/unstable (pas de regle netem) : ils restent reserves a l'ancienne campagne.
#   CAPTURES_ROOT       : racine des sorties (defaut <repertoire du Launcher>/captures). La campagne
#                         randomisee 20x25 utilise un dossier DISTINCT (captures_v2) pour ne jamais melanger
#                         ni 'reprendre' par erreur les donnees de l'ancienne campagne (4 blocs).
RATE_MBIT=${RATE_MBIT:-}
CAPTURES_ROOT=${CAPTURES_ROOT:-}

for v in TOTAL_RUNS HANDSHAKE_TIMEOUT_S COOLDOWN_MAX_S; do
    if ! [[ "${!v}" =~ ^[0-9]+$ ]] || [[ "${!v}" -lt 1 ]]; then echo "Invalid $v: entier positif."; exit 1; fi
done
if ! [[ "$WARMUP_RUNS" =~ ^[0-9]+$ ]]; then echo "Invalid WARMUP_RUNS: entier >= 0."; exit 1; fi
if [[ -n "$COOLDOWN_TEMP_C" ]] && ! [[ "$COOLDOWN_TEMP_C" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then echo "Invalid COOLDOWN_TEMP_C."; exit 1; fi
if [[ "$OFFLOAD_OFF" != "0" && "$OFFLOAD_OFF" != "1" ]]; then echo "Invalid OFFLOAD_OFF: 0 ou 1."; exit 1; fi
if [[ "$QUIC_MTU_SYNC" != "0" && "$QUIC_MTU_SYNC" != "1" ]]; then echo "Invalid QUIC_MTU_SYNC: 0 ou 1."; exit 1; fi
if [[ "$PRINT_ORDER" != "0" && "$PRINT_ORDER" != "1" ]]; then echo "Invalid PRINT_ORDER: 0 ou 1."; exit 1; fi
if ! [[ "$MICRO_BATCHES" =~ ^[0-9]+$ ]] || (( MICRO_BATCHES < 1 )); then echo "Invalid MICRO_BATCHES: entier >= 1."; exit 1; fi
if [[ "$CHAIN_DEPTH" != "1" && "$CHAIN_DEPTH" != "2" ]]; then echo "Invalid CHAIN_DEPTH: 1 ou 2."; exit 1; fi
for v in CERT_PAD_BYTES CERT_PAD_TARGET_DER; do
    if ! [[ "${!v}" =~ ^[0-9]+$ ]]; then echo "Invalid $v: entier >= 0."; exit 1; fi
done
if (( CERT_PAD_BYTES > 0 && CERT_PAD_TARGET_DER > 0 )); then echo "CERT_PAD_BYTES et CERT_PAD_TARGET_DER sont exclusifs."; exit 1; fi
if [[ -n "$VISIT_TAG" ]] && ! [[ "$VISIT_TAG" =~ ^[A-Za-z0-9]+$ ]]; then echo "Invalid VISIT_TAG: alphanumerique."; exit 1; fi

if ! [[ "$MTU" =~ ^[0-9]+$ ]] || [[ "$MTU" -lt 1280 ]] || [[ "$MTU" -gt 1500 ]]; then
    echo "Invalid MTU: entier entre 1280 et 1500 (le pont Docker est a 1500, pas de jumbo)."
    exit 1
fi
if [[ "$LOSS_DIRECTION" != "s2c" && "$LOSS_DIRECTION" != "c2s" && "$LOSS_DIRECTION" != "both" ]]; then
    echo "Invalid LOSS_DIRECTION: s2c, c2s ou both."
    exit 1
fi
if ! [[ "$NETEM_LIMIT" =~ ^[0-9]+$ ]] || [[ "$NETEM_LIMIT" -lt 1 ]]; then
    echo "Invalid NETEM_LIMIT: entier positif."
    exit 1
fi
if [[ -n "$RATE_MBIT" ]] && ! [[ "$RATE_MBIT" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
    echo "Invalid RATE_MBIT: nombre positif (Mbit/s) ou vide."
    exit 1
fi
if [[ -n "$RATE_MBIT" ]] && LC_ALL=C awk -v r="$RATE_MBIT" 'BEGIN{exit !(r+0==0)}'; then RATE_MBIT=""; fi
if [[ -n "$RATE_MBIT" && ( "$NETWORK_PROFILE" == "stable" || "$NETWORK_PROFILE" == "unstable" ) ]]; then
    echo "RATE_MBIT=$RATE_MBIT est incompatible avec le profil pumba '$NETWORK_PROFILE' (debit non controle). Utilisez ge-mild-*/ge-severe-* ou videz RATE_MBIT."
    exit 1
fi
if [[ "$PIN_CPUS" != "auto" && "$PIN_CPUS" != "off" ]]; then
    echo "Invalid PIN_CPUS: auto ou off."
    exit 1
fi
if [[ "$PER_CONN_PCAP" != "0" && "$PER_CONN_PCAP" != "1" ]]; then
    echo "Invalid PER_CONN_PCAP: 0 ou 1."
    exit 1
fi
if [[ "$TCP_ISOLATE" != "0" && "$TCP_ISOLATE" != "1" ]]; then
    echo "Invalid TCP_ISOLATE: 0 ou 1."
    exit 1
fi
if [[ "$TCP_ISOLATE" == "1" ]]; then
    TCP_SYSCTLS=(--sysctl net.ipv4.tcp_no_metrics_save=1 --sysctl net.ipv4.tcp_syn_retries=8)
else
    TCP_SYSCTLS=()
fi
if [[ ( "$NETWORK_PROFILE" == "stable" || "$NETWORK_PROFILE" == "unstable" ) && "$LOSS_DIRECTION" != "s2c" ]]; then
    echo "LOSS_DIRECTION=$LOSS_DIRECTION non supporte pour stable/unstable (pumba, serveur uniquement)."
    exit 1
fi

USAGE="Usage: $0 [mlkem|hqc|both] [tls|quic] [mutual|single] [capture|captureKey|nocapture] [none|simple|delay-only|loss-only|stable|unstable|ge-mild-1|ge-mild-2|ge-mild-5|ge-severe-1|ge-severe-2|ge-severe-5] [loss-percent] [delay-ms] [n-blocks] [block-index] [seed]"

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
# ─────────────────────────────────────────────────────────────────────────
# AJOUT "delay-only" / "loss-only" (résout le point 3 du rejet : "Degraded et
# GE-Stable diffèrent simultanément en délai, perte marginale et burstiness
# -- aucun plan factoriel ne les isole"). "simple" reste le scénario combiné
# existant (délai+perte ensemble, tel que Moderate/Degraded dans l'article
# actuel) ; "delay-only" et "loss-only" isolent chaque dimension séparément,
# avec la MÊME valeur numérique que "simple" pour permettre la décomposition
# additive : simple(D,L) vs delay-only(D,0) vs loss-only(0,L).
#
# AJOUT ge-mild-{1,2,5} / ge-severe-{1,2,5} (résout le point 5 du prescreen
# TDSC-2026-09-3862 : grille factorielle RTT × taux de perte × corrélation
# de perte, avec perte marginale EXACTEMENT égale entre l'arm iid
# (loss-only, meme LOSS_PERC) et l'arm corrélé (ces 6 profils), pour isoler
# la corrélation temporelle de perte comme facteur causal independant du
# taux de perte). "mild" = longueur de rafale field-calibrated sur 12
# sessions terrain MTN/Orange (r=0.54, rafales <=15 paquets uniquement,
# macro-coupures exclues -- voir memoire projet) ; "severe" = contraste
# synthetique plus corrélé (r=0.20), pas une pretention de realisme terrain.
# Contrairement a stable/unstable (délai figé a 0, uniquement des points de
# validation terrain conservés tels quels), ces 6 profils appliquent
# DELAY_MS en plus de la perte GE -- le RTT redevient un facteur libre,
# combinable avec n'importe quel palier de corrélation de perte.
if [[ "$NETWORK_PROFILE" != "none" && "$NETWORK_PROFILE" != "simple" && "$NETWORK_PROFILE" != "delay-only" && "$NETWORK_PROFILE" != "loss-only" && "$NETWORK_PROFILE" != "stable" && "$NETWORK_PROFILE" != "unstable" \
      && "$NETWORK_PROFILE" != "ge-mild-1" && "$NETWORK_PROFILE" != "ge-mild-2" && "$NETWORK_PROFILE" != "ge-mild-5" \
      && "$NETWORK_PROFILE" != "ge-severe-1" && "$NETWORK_PROFILE" != "ge-severe-2" && "$NETWORK_PROFILE" != "ge-severe-5" ]]; then
    echo "Invalid network profile: must be 'none', 'simple', 'delay-only', 'loss-only', 'stable', 'unstable', 'ge-mild-1', 'ge-mild-2', 'ge-mild-5', 'ge-severe-1', 'ge-severe-2', or 'ge-severe-5'."
    echo "$USAGE"
    exit 1
fi

# 5) Packet loss percentage (0–100, décimales acceptées — nécessaire pour les
#    scénarios terrain Modéré/Dégradé : 1.3% et 1.5833%, cf. make_plans.sh)
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

# 6) Delay in milliseconds (>= 0, décimales acceptées — nécessaire pour
#    62.51 ms / 83.52 ms des scénarios terrain Modéré/Dégradé).
#    CONVENTION : DELAY_MS est le délai UNIDIRECTIONNEL appliqué sur CHAQUE
#    interface (client ET serveur) ; le RTT effectif est donc 2 x DELAY_MS
#    (62.51 -> RTT 125 ms ; 83.52 -> RTT 167 ms ; valeurs issues de
#    Collect_Session.sh). À déclarer ainsi dans l'article.
if ! [[ "$DELAY_MS" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
    echo "Invalid delay-ms: must be a non-negative number (decimals allowed)."
    echo "$USAGE"
    exit 1
fi

NETWORK_PROFILE_LABEL="$NETWORK_PROFILE"
if [[ "$NETWORK_PROFILE" == "simple" ]]; then
    NETWORK_PROFILE_LABEL="simple_loss${LOSS_PERC}_delay${DELAY_MS}ms"
elif [[ "$NETWORK_PROFILE" == "delay-only" ]]; then
    NETWORK_PROFILE_LABEL="delayonly_delay${DELAY_MS}ms"
elif [[ "$NETWORK_PROFILE" == "loss-only" ]]; then
    NETWORK_PROFILE_LABEL="lossonly_loss${LOSS_PERC}"
elif [[ "$NETWORK_PROFILE" == ge-mild-* || "$NETWORK_PROFILE" == ge-severe-* ]]; then
    # Le RTT est un facteur libre pour ces profils (contrairement à
    # stable/unstable) -- il DOIT apparaître dans le label, sinon deux runs
    # au même palier de perte mais à des RTT différents écraseraient le même
    # dossier de sortie.
    NETWORK_PROFILE_LABEL="${NETWORK_PROFILE}_delay${DELAY_MS}ms"
fi

# MTU et direction de perte sont des facteurs : ils DOIVENT apparaitre dans le
# label, sinon deux cellules differentes ecraseraient le meme dossier.
if [[ "$MTU" != "1500" ]]; then
    NETWORK_PROFILE_LABEL="${NETWORK_PROFILE_LABEL}_mtu${MTU}"
fi
if [[ "$LOSS_DIRECTION" != "s2c" ]]; then
    case "$NETWORK_PROFILE" in
      simple|loss-only|ge-mild-*|ge-severe-*)
        NETWORK_PROFILE_LABEL="${NETWORK_PROFILE_LABEL}_dir${LOSS_DIRECTION}" ;;
    esac
fi

# Un run avec tcpdump actif (PER_CONN_PCAP=1) charge le CPU : ses latences ne
# doivent JAMAIS se melanger a la campagne de latence principale ni ecraser ses
# fichiers (memes noms sinon) -> sous-dossier distinct.
# Chaine de certificats et padding = facteurs : ils DOIVENT figurer dans le label (sinon une cellule
# 'secp384r1 paddee' ou 'chaine a 2 niveaux' ecraserait / serait confondue avec la cellule de base).
if [[ "$QUIC_MTU_SYNC" == "1" ]]; then NETWORK_PROFILE_LABEL="${NETWORK_PROFILE_LABEL}__qmtu"; fi
if [[ "$CHAIN_DEPTH" == "2" ]]; then NETWORK_PROFILE_LABEL="${NETWORK_PROFILE_LABEL}__chain2"; fi
if (( CERT_PAD_BYTES > 0 )); then NETWORK_PROFILE_LABEL="${NETWORK_PROFILE_LABEL}__pad${CERT_PAD_BYTES}b"; fi
if (( CERT_PAD_TARGET_DER > 0 )); then NETWORK_PROFILE_LABEL="${NETWORK_PROFILE_LABEL}__padto${CERT_PAD_TARGET_DER}"; fi
if [[ "$PER_CONN_PCAP" == "1" ]]; then
    NETWORK_PROFILE_LABEL="${NETWORK_PROFILE_LABEL}__pcap"
fi
# Entrelacement en micro-lots = facteur de design : une cellule M=1 et une cellule M=5 ne doivent JAMAIS
# partager un dossier (sinon la reprise "deja fait" saute des tours et les donnees se melangent).
if (( MICRO_BATCHES > 1 )) && [[ "$CAPTURE_MODE" != "capture" && "$CAPTURE_MODE" != "captureKey" ]]; then
    NETWORK_PROFILE_LABEL="${NETWORK_PROFILE_LABEL}__mb${MICRO_BATCHES}"
fi
# Visite sentinelle : dossier distinct par visite (pre/mid/post), donc
# already_done() et les noms de fichiers restent sans collision.
if [[ -n "$VISIT_TAG" ]]; then
    NETWORK_PROFILE_LABEL="${NETWORK_PROFILE_LABEL}__sentinel_${VISIT_TAG}"
fi

# PRINT_LABEL=1 : affiche le label de sortie (= nom de dossier de la cellule) puis quitte. Sert au controle
# d'unicite des cellules d'un plan (selftest_p0.sh / make_plans.sh) : deux cellules de meme label, meme
# protocole et meme paire ecraseraient le meme dossier et la reprise "deja fait" sauterait la seconde.
QUIC_MTU_EFF=""
if [[ "$QUIC_MTU_SYNC" == "1" ]]; then QUIC_MTU_EFF="$MTU"; fi

if [[ "${PRINT_LABEL:-0}" == "1" ]]; then
    echo "$NETWORK_PROFILE_LABEL"
    exit 0
fi

###############################################################################
#  CONFIGURATION
###############################################################################

 NUM_RUNS=$TOTAL_RUNS

if [[ "$CAPTURE_MODE" == "capture" || "$CAPTURE_MODE" == "captureKey" ]]; then
  NUM_RUNS=1
  if [[ "$N_BLOCKS" != "1" || "$BLOCK_INDEX" != "1" ]]; then
      echo "ℹ️  Mode capture : le découpage en blocs n'a pas de sens ici (NUM_RUNS=1) -- N_BLOCKS/BLOCK_INDEX ignorés."
      N_BLOCKS=1
      BLOCK_INDEX=1
  fi
else
  # ── Découpage en blocs (résout le point 2) ──────────────────────────────
  if (( NUM_RUNS % N_BLOCKS != 0 )); then
      echo "ERREUR: N_BLOCKS=$N_BLOCKS ne divise pas NUM_RUNS=$NUM_RUNS exactement."
      echo "        Choisissez un diviseur de $NUM_RUNS (1, 2, 4, 5, 10, 20, 25, 50, 100, ...)."
      exit 1
  fi
  RUNS_THIS_BLOCK=$(( NUM_RUNS / N_BLOCKS ))
  echo "Découpage en blocs : $N_BLOCKS blocs de $RUNS_THIS_BLOCK runs -- ce lancement exécute le bloc $BLOCK_INDEX/$N_BLOCKS."
  NUM_RUNS=$RUNS_THIS_BLOCK
fi
if (( MICRO_BATCHES > 1 )); then
    if [[ "$CAPTURE_MODE" == "capture" || "$CAPTURE_MODE" == "captureKey" ]]; then MICRO_BATCHES=1; fi
fi
if (( NUM_RUNS % MICRO_BATCHES != 0 )); then
    echo "ERREUR: MICRO_BATCHES=$MICRO_BATCHES ne divise pas les $NUM_RUNS connexions du bloc (par paire)."
    exit 1
fi
RUNS_PER_ROUND=$(( NUM_RUNS / MICRO_BATCHES ))
if (( MICRO_BATCHES > 1 )); then
    echo "Entrelacement : $MICRO_BATCHES tours de $RUNS_PER_ROUND connexions par paire (ordre des paires re-tire a chaque tour)."
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
 SUPPORTED_SIG_ALGS=("ed25519" "secp384r1" "secp521r1" "mldsa44" "mldsa65" "mldsa87")

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

# ── Profils GE de la grille factorielle (point 5, prescreen TDSC) ──────────
# Modèle "Simple Gilbert" : perte nulle en état Good (one-k=0), perte
# déterministe en état Bad (one-h=100). Perte marginale = pg/(pg+pb), donc
# pg = M*pb/(100-M) pour une cible M (en %). Ordre : pg pb one-h one-k (en %).
#   mild   : pb=54 (rafale moyenne ~1,85 paquet, calibrée sur 12 sessions
#            terrain MTN/Orange, macro-coupures >15 paquets exclues)
#   severe : pb=20 (rafale moyenne 5 paquets, contraste synthétique)
GE_MILD_1_GEMODEL=(0.546 54 100 0)
GE_MILD_2_GEMODEL=(1.102 54 100 0)
GE_MILD_5_GEMODEL=(2.842 54 100 0)
GE_SEVERE_1_GEMODEL=(0.202 20 100 0)
GE_SEVERE_2_GEMODEL=(0.408 20 100 0)
GE_SEVERE_5_GEMODEL=(1.053 20 100 0)

###############################################################################
#  Application des perturbations reseau, verification, metadonnees
#  (fonctions utilisees plus bas dans la boucle principale)
###############################################################################

# Construit les arguments netem de chaque cote selon profil et direction.
# Delai : toujours applique des DEUX cotes (delai unidirectionnel symetrique,
# RTT = 2 x DELAY_MS). Perte : cote(s) choisi(s) par LOSS_DIRECTION.
compute_netem_args() {
    local delay_arg="" loss_arg="" ge=()
    SRV_NEEDS_GE_CHECK=false
    CLI_NEEDS_GE_CHECK=false
    case "$NETWORK_PROFILE" in
      simple|delay-only|ge-mild-*|ge-severe-*)
        if [[ "$DELAY_MS" != "0" ]]; then delay_arg="delay ${DELAY_MS}ms"; fi ;;
    esac
    case "$NETWORK_PROFILE" in
      simple|loss-only)
        if [[ "$LOSS_PERC" != "0" ]]; then loss_arg="loss ${LOSS_PERC}%"; fi ;;
      ge-mild-1)   ge=("${GE_MILD_1_GEMODEL[@]}") ;;
      ge-mild-2)   ge=("${GE_MILD_2_GEMODEL[@]}") ;;
      ge-mild-5)   ge=("${GE_MILD_5_GEMODEL[@]}") ;;
      ge-severe-1) ge=("${GE_SEVERE_1_GEMODEL[@]}") ;;
      ge-severe-2) ge=("${GE_SEVERE_2_GEMODEL[@]}") ;;
      ge-severe-5) ge=("${GE_SEVERE_5_GEMODEL[@]}") ;;
    esac
    if [[ ${#ge[@]} -gt 0 ]]; then
        loss_arg="loss gemodel ${ge[0]}% ${ge[1]}% ${ge[2]}% ${ge[3]}%"
    fi
    SRV_NETEM_ARGS="$delay_arg"
    CLI_NETEM_ARGS="$delay_arg"
    # Debit fixe (facteur controle) : meme 'rate' sur les deux egress. Applique aussi au profil 'none'
    # (cellule ideale) pour que TOUTES les cellules aient le meme lien.
    RATE_ARG=""
    if [[ -n "$RATE_MBIT" ]]; then RATE_ARG="rate ${RATE_MBIT}mbit"; fi
    if [[ -n "$loss_arg" ]]; then
        if [[ "$LOSS_DIRECTION" == "s2c" || "$LOSS_DIRECTION" == "both" ]]; then
            SRV_NETEM_ARGS="$SRV_NETEM_ARGS $loss_arg"
            if [[ ${#ge[@]} -gt 0 ]]; then SRV_NEEDS_GE_CHECK=true; fi
        fi
        if [[ "$LOSS_DIRECTION" == "c2s" || "$LOSS_DIRECTION" == "both" ]]; then
            CLI_NETEM_ARGS="$CLI_NETEM_ARGS $loss_arg"
            if [[ ${#ge[@]} -gt 0 ]]; then CLI_NEEDS_GE_CHECK=true; fi
        fi
    fi
    if [[ -n "$RATE_ARG" ]]; then
        SRV_NETEM_ARGS="$SRV_NETEM_ARGS $RATE_ARG"
        CLI_NETEM_ARGS="$CLI_NETEM_ARGS $RATE_ARG"
    fi
    SRV_NETEM_ARGS="${SRV_NETEM_ARGS# }"
    CLI_NETEM_ARGS="${CLI_NETEM_ARGS# }"
    return 0
}

# Applique une regle netem et VERIFIE qu'elle est reellement active (aucun
# "|| true" silencieux : une regle absente etiquetterait des donnees non
# degradees comme degradees). Refermer cette asymetrie etait une limite
# documentee du depot (safeguard limite aux profils pumba).
apply_netem() {
    local container="$1" args="$2" need_ge="${3:-false}" shown
    if [[ -z "$args" ]]; then return 0; fi
    echo "   ↳ tc netem sur $container : limit ${NETEM_LIMIT} ${args}"
    # $args volontairement non quote (decoupage en mots)
    if ! docker exec "$container" tc qdisc add dev "$NETIF" root netem limit "$NETEM_LIMIT" $args; then
        echo "❌ ERREUR FATALE: tc qdisc add a echoue sur $container (args: $args)."
        docker kill $OQS_SERVER $OQS_CLIENT &>/dev/null || true
        exit 1
    fi
    shown=$(docker exec "$container" tc qdisc show dev "$NETIF" 2>/dev/null || true)
    if ! grep -q "netem" <<< "$shown"; then
        echo "❌ ERREUR FATALE: aucune regle netem visible sur $container apres application."
        docker kill $OQS_SERVER $OQS_CLIENT &>/dev/null || true
        exit 1
    fi
    if [[ "$need_ge" == "true" ]] && ! grep -qi "gemodel" <<< "$shown"; then
        echo "❌ ERREUR FATALE: regle gemodel non visible sur $container (SIG=$SIG_ALG KEM=$KEM)."
        docker kill $OQS_SERVER $OQS_CLIENT &>/dev/null || true
        exit 1
    fi
    echo "     regle active : $shown"
    echo "netem[pair=${SIG_ALG}|${KEM}][$container]=$shown" >> "$MANIFEST_FILE"
    return 0
}

# Fixe et verifie le MTU de eth0 dans un conteneur.
set_mtu() {
    local container="$1"
    if ! docker exec "$container" ip link set dev "$NETIF" mtu "$MTU"; then
        echo "❌ ERREUR FATALE: impossible de fixer MTU=$MTU sur $container."
        exit 1
    fi
    if ! docker exec "$container" ip link show dev "$NETIF" | grep -q "mtu ${MTU} "; then
        echo "❌ ERREUR FATALE: MTU=$MTU non confirme sur $container."
        exit 1
    fi
    return 0
}

# Verifie que les reglages TCP d'isolation sont REELLEMENT actifs dans le
# conteneur (un sysctl non applique ne doit jamais etre suppose) et les
# journalise dans le manifeste. Echec = arret (donnees non comparables).
check_tcp_isolation() {
    local container="$1" nm sr
    if [[ "$TCP_ISOLATE" != "1" ]]; then
        echo "tcp_isolation[pair=${SIG_ALG}|${KEM}][$container]=off" >> "$MANIFEST_FILE"
        return 0
    fi
    nm=$(docker exec "$container" cat /proc/sys/net/ipv4/tcp_no_metrics_save 2>/dev/null | tr -d '\r\n' || true)
    sr=$(docker exec "$container" cat /proc/sys/net/ipv4/tcp_syn_retries 2>/dev/null | tr -d '\r\n' || true)
    if [[ "$nm" != "1" || "$sr" != "8" ]]; then
        echo "❌ ERREUR FATALE: isolation TCP non active sur $container (tcp_no_metrics_save='$nm' attendu 1, tcp_syn_retries='$sr' attendu 8)."
        docker kill $OQS_SERVER $OQS_CLIENT &>/dev/null || true
        exit 1
    fi
    echo "tcp_isolation[pair=${SIG_ALG}|${KEM}][$container]=no_metrics_save=${nm} syn_retries=${sr}" >> "$MANIFEST_FILE"
    return 0
}

# Nombre d'entrees du cache tcp_metrics apres la paire : doit rester 0 avec
# tcp_no_metrics_save=1. Journalise (ne bloque pas) : sert de preuve d'audit.
log_tcp_metrics_count() {
    local container="$1" n
    n=$(docker exec "$container" sh -c 'ip tcp_metrics show 2>/dev/null | grep -c .' 2>/dev/null | tr -d '\r\n' || true)
    echo "tcp_metrics_entries[pair=${SIG_ALG}|${KEM}][$container]=${n:-NA}" >> "$MANIFEST_FILE"
    return 0
}

# Offloads (TSO/GSO/GRO) : avec des super-paquets, netem pourrait appliquer la
# perte a un segment de plusieurs paquets MTU, faussant la perte "par paquet"
# (surtout cote TCP/TLS). OFFLOAD_OFF=1 les desactive ; dans TOUS les cas l'etat
# effectif est journalise dans le manifeste (tracabilite exigee par la relecture).
set_offloads() {
    local container="$1" feat
    if [[ "$OFFLOAD_OFF" == "1" ]]; then
        if ! docker exec "$container" sh -c 'command -v ethtool >/dev/null 2>&1'; then
            echo "❌ ERREUR FATALE: OFFLOAD_OFF=1 mais ethtool absent de l'image (reconstruire l'image)."
            exit 1
        fi
        if ! docker exec "$container" ethtool -K "$NETIF" tso off gso off gro off >/dev/null 2>&1; then
            echo "❌ ERREUR FATALE: impossible de desactiver TSO/GSO/GRO sur $container."
            exit 1
        fi
        # Offloads UDP : MsQuic emet via UDP_SEGMENT (UDP GSO). Sans couper
        # tx-udp-segmentation, un "super-datagramme" traverse la veth tel quel :
        # le pcap contient des trames > MTU et netem compte (donc perd) N
        # datagrammes d'un seul coup -> perte effective et nombre de paquets
        # QUIC faux, alors que TLS (TCP) n'est pas touche. Chaque nom est tente
        # SEPAREMENT (un nom inconnu du noyau ne doit pas faire echouer les autres).
        for _f in tx-udp-segmentation rx-udp-gro-forwarding rx-gro-list; do
            docker exec "$container" ethtool -K "$NETIF" "$_f" off >/dev/null 2>&1 || true
        done
        # Fatal si un de ces offloads reste actif ET modifiable ("[fixed]" = non
        # modifiable par le noyau : toleré ici, mais la capture le detecte (trames > MTU)).
        if docker exec "$container" ethtool -k "$NETIF" 2>/dev/null \
             | grep -E '^(tcp-segmentation-offload|generic-segmentation-offload|generic-receive-offload|tx-udp-segmentation|rx-udp-gro-forwarding|rx-gro-list):' | grep ': on' | grep -v '\[fixed\]' | grep -q .; then
            echo "❌ ERREUR FATALE: offload encore actif sur $container apres desactivation."
            exit 1
        fi
    fi
    feat=$(docker exec "$container" ethtool -k "$NETIF" 2>/dev/null \
             | grep -E '^(tcp-segmentation-offload|generic-segmentation-offload|generic-receive-offload|tx-udp-segmentation|rx-udp-gro-forwarding|rx-gro-list):' \
             | tr -s ' \n' ' ' || true)
    echo "offload[pair=${SIG_ALG}|${KEM}][$container]=${feat:-NA(ethtool_absent)}" >> "$MANIFEST_FILE"
    return 0
}

# Voisinage L2 PERMANENT (client <-> serveur). Sans cela, la perte netem (et surtout
# la perte en rafale) frappe aussi les requetes/reponses ARP : en TCP, connect()
# echoue alors IMMEDIATEMENT ("No route to host") au lieu de retransmettre, alors
# qu'en UDP/QUIC l'envoi continue silencieusement jusqu'au timeout. Resultat : une
# politique d'echec TLS/QUIC non comparable, et une "perte" qui n'est pas celle du
# modele (paquets IP) mais aussi celle de la resolution d'adresses. On retire donc
# ARP du modele de perte : seules les paquets IP applicatifs sont affectes.
pin_neighbors() {
    local srv_ip cli_ip srv_mac cli_mac
    srv_ip=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$OQS_SERVER" 2>/dev/null)
    cli_ip=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$OQS_CLIENT" 2>/dev/null)
    srv_mac=$(docker exec "$OQS_SERVER" cat "/sys/class/net/$NETIF/address" 2>/dev/null | tr -d '\r\n')
    cli_mac=$(docker exec "$OQS_CLIENT" cat "/sys/class/net/$NETIF/address" 2>/dev/null | tr -d '\r\n')
    if [[ -z "$srv_ip" || -z "$cli_ip" || -z "$srv_mac" || -z "$cli_mac" ]]; then
        echo "❌ ERREUR FATALE: IP/MAC introuvables (srv=$srv_ip/$srv_mac cli=$cli_ip/$cli_mac)."
        exit 1
    fi
    if ! docker exec "$OQS_CLIENT" ip neigh replace "$srv_ip" lladdr "$srv_mac" dev "$NETIF" nud permanent \
       || ! docker exec "$OQS_SERVER" ip neigh replace "$cli_ip" lladdr "$cli_mac" dev "$NETIF" nud permanent; then
        echo "❌ ERREUR FATALE: impossible de fixer le voisinage permanent."
        exit 1
    fi
    echo "neighbors[pair=${SIG_ALG}|${KEM}]=permanent srv=${srv_ip}/${srv_mac} cli=${cli_ip}/${cli_mac}" >> "$MANIFEST_FILE"
    return 0
}

# Compteurs qdisc (paquets emis, paquets abandonnes) d'un conteneur.
# Sortie : "<pkts> <dropped>" ou "NA NA".
qdisc_stats() {
    local out
    out=$(docker exec "$1" tc -s qdisc show dev "$NETIF" 2>/dev/null | LC_ALL=C awk '
        /Sent/ { gsub(/,/, ""); pk=$4; for (i = 1; i <= NF; i++) if ($i == "(dropped") d=$(i+1) }
        END { if (pk == "") print "NA NA"; else print pk, d }' || true)
    if [[ -z "$out" ]]; then echo "NA NA"; else echo "$out"; fi
    return 0
}

record_qdisc_row() {
    local role="$1" pk0="$2" dr0="$3" pk1="$4" dr1="$5" eff="NA" f
    f="$MANIFEST_DIR/qdisc_stats_block${BLOCK_INDEX}of${N_BLOCKS}_seed${SEED}.csv"
    if [[ ! -f "$f" ]]; then
        echo "timestamp,block_index,n_blocks,position,sig_alg,kem,role,pkts_before,dropped_before,pkts_after,dropped_after,effective_drop_pct" > "$f"
    fi
    if [[ "$pk0" =~ ^[0-9]+$ && "$dr0" =~ ^[0-9]+$ && "$pk1" =~ ^[0-9]+$ && "$dr1" =~ ^[0-9]+$ ]]; then
        eff=$(LC_ALL=C awk -v p0="$pk0" -v d0="$dr0" -v p1="$pk1" -v d1="$dr1" \
            'BEGIN{o=(p1-p0)+(d1-d0); if (o>0) printf "%.4f", 100*(d1-d0)/o; else print "NA"}')
    fi
    echo "$(date -Iseconds),$BLOCK_INDEX,$N_BLOCKS,$POSITION,$SIG_ALG,$KEM,$role,$pk0,$dr0,$pk1,$dr1,$eff" >> "$f"
    return 0
}

read_sysfs() {
    local v=""
    if [[ -r "$1" ]]; then v=$(cat "$1" 2>/dev/null || true); fi
    if [[ -n "$v" ]]; then echo "$v"; else echo "NA"; fi
    return 0
}

read_cpu_temp_c() {
    local z t=""
    for z in /sys/class/thermal/thermal_zone*; do
        if [[ -r "$z/type" ]] && [[ "$(cat "$z/type" 2>/dev/null || true)" == "x86_pkg_temp" ]]; then
            t=$(cat "$z/temp" 2>/dev/null || true)
            break
        fi
    done
    if [[ "$t" =~ ^[0-9]+$ ]]; then
        LC_ALL=C awk -v t="$t" 'BEGIN{printf "%.1f", t/1000}'
    else
        echo "NA"
    fi
    return 0
}

# Attend que la temperature paquet CPU retombe sous COOLDOWN_TEMP_C (si defini).
# Evite que l'etat thermique herite de la paire precedente ne biaise la suivante.
wait_cooldown() {
    local waited=0 t
    if [[ -z "$COOLDOWN_TEMP_C" ]]; then return 0; fi
    while (( waited < COOLDOWN_MAX_S )); do
        t=$(read_cpu_temp_c)
        if [[ "$t" == "NA" ]]; then return 0; fi
        if LC_ALL=C awk -v t="$t" -v m="$COOLDOWN_TEMP_C" 'BEGIN{exit !(t<=m)}'; then return 0; fi
        sleep 5
        waited=$((waited + 5))
    done
    echo "   [!] cooldown: ${t}C > ${COOLDOWN_TEMP_C}C apres ${COOLDOWN_MAX_S}s -- on poursuit (enregistre dans env_metadata)."
    return 0
}

read_cpu_mhz_mean() {
    local f vals=""
    for f in /sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_cur_freq; do
        if [[ -r "$f" ]]; then vals="$vals $(cat "$f" 2>/dev/null || true)"; fi
    done
    if [[ -z "${vals// /}" ]]; then echo "NA"; return 0; fi
    echo "$vals" | LC_ALL=C awk '{for(i=1;i<=NF;i++){s+=$i;n++}} END{if(n) printf "%.0f", s/n/1000; else print "NA"}'
    return 0
}

# Enregistre temperature, frequence, charge, gouverneur avant/apres chaque
# paire : permet de montrer que l'effet de signature survit a la
# randomisation, plutot que de plaider apres coup l'absence d'effet de position.
record_env() {
    local event="$1" f
    f="$MANIFEST_DIR/env_metadata_block${BLOCK_INDEX}of${N_BLOCKS}_seed${SEED}.csv"
    if [[ ! -f "$f" ]]; then
        echo "timestamp,event,block_index,n_blocks,position,sig_alg,kem,cpu_temp_c,cpu_mhz_mean,load1,governor,no_turbo" > "$f"
    fi
    echo "$(date -Iseconds),$event,$BLOCK_INDEX,$N_BLOCKS,$POSITION,$SIG_ALG,$KEM,$(read_cpu_temp_c),$(read_cpu_mhz_mean),$(awk '{print $1}' /proc/loadavg),$(read_sysfs /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor),$(read_sysfs /sys/devices/system/cpu/intel_pstate/no_turbo)" >> "$f"
    return 0
}

# Epinglage : un coeur PHYSIQUE dedie (les deux threads freres) au serveur,
# un autre au client, pour qu'ils ne se disputent ni un thread ni un cache L1/L2.
compute_pinning() {
    SRV_CPUSET=""
    CLI_CPUSET=""
    if [[ "$PIN_CPUS" != "auto" ]]; then return 0; fi
    local groups=() g
    while IFS= read -r g; do
        if [[ -n "$g" ]]; then groups+=("$g"); fi
    done < <(cat /sys/devices/system/cpu/cpu[0-9]*/topology/thread_siblings_list 2>/dev/null | sort -uV)
    if [[ ${#groups[@]} -lt 3 ]]; then
        echo "⚠️  Moins de 3 coeurs physiques detectes : epinglage CPU desactive."
        return 0
    fi
    SRV_CPUSET="--cpuset-cpus=${groups[1]}"
    CLI_CPUSET="--cpuset-cpus=${groups[2]}"
    return 0
}

write_env_header() {
    echo "kernel=$(uname -r)"
    echo "cpu_model=$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | sed 's/^ //')"
    echo "governor=$(read_sysfs /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor) no_turbo=$(read_sysfs /sys/devices/system/cpu/intel_pstate/no_turbo)"
    echo "mtu=$MTU loss_direction=$LOSS_DIRECTION netem_limit=$NETEM_LIMIT pin_cpus=$PIN_CPUS server_cpuset=${SRV_CPUSET:-none} client_cpuset=${CLI_CPUSET:-none}"
    echo "bandwidth=${RATE_MBIT:+${RATE_MBIT}Mbit/s_netem_rate}${RATE_MBIT:-non_limitee(pas_de_rate)} rate_mbit=${RATE_MBIT:-0} jitter=0(pas_d_argument_jitter) file=netem_limit_${NETEM_LIMIT}_paquets"
    echo "docker_version=$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo NA)"
    echo "image_id=$(docker image inspect -f '{{.Id}}' "$IMAGE" 2>/dev/null || echo NA)"
    echo "only_pairs=${ONLY_PAIRS:-all} per_conn_pcap=$PER_CONN_PCAP"
    echo "chain_depth=$CHAIN_DEPTH cert_pad_bytes=$CERT_PAD_BYTES cert_pad_target_der=$CERT_PAD_TARGET_DER udp_gso=${QUIC_ENABLE_UDP_GSO:-0} quic_mtu_sync=${QUIC_MTU_SYNC} quic_mtu=${QUIC_MTU_EFF:-default(1280+DPLPMTUD)}"
    echo "total_runs=$TOTAL_RUNS n_blocks=$N_BLOCKS warmup_runs=$WARMUP_RUNS handshake_timeout_s=$HANDSHAKE_TIMEOUT_S"
    echo "cooldown_temp_c=${COOLDOWN_TEMP_C:-off} offload_off=$OFFLOAD_OFF visit_tag=${VISIT_TAG:-none} tcp_isolate=$TCP_ISOLATE"
    return 0
}

compute_netem_args
compute_pinning

# ─────────────────────────────────────────────────────────────────────────
# Construction de la liste à plat (SIG_ALG, KEM) puis mélange (résout le
# point 2 du rejet). Remplace l'ancienne double boucle imbriquée
# "for SIG_ALG { for KEM {...} }", qui exécutait toujours mldsa87 après
# mldsa65 après mldsa44 après secp521r1 après secp384r1 après ed25519, dans
# cet ordre exact, à chaque appel -- un effet temporel (charge machine,
# dérive thermique) aurait pu s'aligner systématiquement avec l'identité de
# l'algorithme sans qu'on puisse le distinguer d'un effet cryptographique.
# ─────────────────────────────────────────────────────────────────────────
PAIRS=()
for SIG_ALG in "${SUPPORTED_SIG_ALGS[@]}"; do
    if [ "$SIG_ALG" = "ed25519" ] || [ "$SIG_ALG" = "mldsa44" ]; then
        KEMS_FOR_SIG=("${KEMS_L1[@]}")
    elif [ "$SIG_ALG" = "secp384r1" ] || [ "$SIG_ALG" = "mldsa65" ]; then
        KEMS_FOR_SIG=("${KEMS_L3[@]}")
    elif [ "$SIG_ALG" = "secp521r1" ] || [ "$SIG_ALG" = "mldsa87" ]; then
        KEMS_FOR_SIG=("${KEMS_L5[@]}")
    fi
    for KEM in "${KEMS_FOR_SIG[@]}"; do
        PAIRS+=("${SIG_ALG}|${KEM}")
    done
done

# Restriction optionnelle du sweep (sous-plan mecanistique : quelques paires
# seulement au lieu des 42).
if [[ -n "$ONLY_PAIRS" ]]; then
    IFS=',' read -ra WANT_PAIRS <<< "$ONLY_PAIRS"
    FILTERED_PAIRS=()
    for cand in "${PAIRS[@]}"; do
        for w in "${WANT_PAIRS[@]}"; do
            if [[ "$cand" == "$w" ]]; then FILTERED_PAIRS+=("$cand"); fi
        done
    done
    if [[ ${#FILTERED_PAIRS[@]} -eq 0 ]]; then
        echo "ERREUR: ONLY_PAIRS='$ONLY_PAIRS' ne correspond a aucune paire valide (verifiez KEM_FAMILY et le format sig|kem)."
        exit 1
    fi
    PAIRS=("${FILTERED_PAIRS[@]}")
    echo "ONLY_PAIRS actif : ${#PAIRS[@]} paire(s) au lieu de la matrice complete."
fi

# Mélange déterministe par graine : deux appels avec le même SEED produisent
# EXACTEMENT le même ordre (traçabilité/reproductibilité), un SEED différent
# produit un ordre différent. Technique standard : un flux pseudo-aléatoire
# dérivé de la graine sert de source à `shuf`.
mapfile -t PAIRS_SHUFFLED < <(
    printf '%s\n' "${PAIRS[@]}" | \
    shuf --random-source=<(openssl enc -aes-256-ctr -pass pass:"$SEED" -nosalt </dev/zero 2>/dev/null)
)

# Ordre des paires pour un tour donne. Tour 1 = ordre historique (graine SEED) => compatible avec
# PRINT_ORDER et avec les anciens runs ; tours suivants = graine derivee de (SEED, tour).
pairs_for_round() {
    local r="$1" rseed
    if (( r == 1 )); then printf '%s\n' "${PAIRS_SHUFFLED[@]}"; return 0; fi
    rseed="$(printf '%s' "$SEED mb $r" | cksum | awk '{print $1}')"
    printf '%s\n' "${PAIRS[@]}" | shuf --random-source=<(openssl enc -aes-256-ctr -pass pass:"$rseed" -nosalt </dev/zero 2>/dev/null)
}

# Test de reproductibilite de l'ordre (aucune action Docker) :
if [[ "$PRINT_ORDER" == "1" ]]; then
    PRINT_ROUND="${PRINT_ROUND:-1}"
    pairs_for_round "$PRINT_ROUND"
    exit 0
fi


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
echo "  Executions:      $NUM_RUNS (micro_batches=$MICRO_BATCHES, $RUNS_PER_ROUND par tour)"

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
    RESOURCE_DIR="$CAPTURES_ROOT/$PROTOCOL/$AUTH_MODE/$NETWORK_PROFILE_LABEL/resource_usage"
    mkdir -p "$RESOURCE_DIR"
    RESOURCE_CSV="$RESOURCE_DIR/resource_usage_${PROTOCOL}_${AUTH_MODE}_${NETWORK_PROFILE_LABEL}.csv"
    if [[ ! -f "$RESOURCE_CSV" ]]; then
        echo "timestamp,protocol,auth_mode,sig_alg,kem,network_profile,role,n_runs,cpu_usec_total,cpu_usec_per_handshake,mem_peak_bytes,block_index,n_blocks,seed" > "$RESOURCE_CSV"
    fi
}

append_resource_row() {
    local role="$1" cpu_start="$2" cpu_end="$3" mem_peak="$4"
    local cpu_total="NA" cpu_per_run="NA"
    if [[ "$cpu_start" =~ ^[0-9]+$ && "$cpu_end" =~ ^[0-9]+$ ]]; then
        cpu_total=$((cpu_end - cpu_start))
        # La fenetre CPU inclut aussi les connexions de warm-up : on divise par le
        # nombre TOTAL de connexions executees (mesurees + jetees).
        if [[ "$RUNS_PER_ROUND" -gt 0 ]]; then
            cpu_per_run=$(LC_ALL=C awk -v t="$cpu_total" -v n="$((RUNS_PER_ROUND + WARMUP_RUNS))" 'BEGIN{printf "%.3f", t/n}')
        fi
    fi
    echo "$(date -Iseconds),$PROTOCOL,$AUTH_MODE,$SIG_ALG,$KEM,$NETWORK_PROFILE,$role,$RUNS_PER_ROUND,$cpu_total,$cpu_per_run,$mem_peak,$BLOCK_INDEX,$N_BLOCKS,$SEED" >> "$RESOURCE_CSV"
}


# ── Reprise idempotente ──────────────────────────────────────────────────
# Vérifie si (sig_alg, kem, block_index) a déjà une ligne "client" dans le
# CSV de ce scénario -- basé sur les colonnes exactes (pas de correspondance
# de sous-chaîne, pour ne pas confondre "x25519" et "x25519_mlkem512").
# AJOUT block_index : sans lui, relancer le launcher pour le bloc 2 sauterait
# à tort les configs déjà faites pour le bloc 1 (et vice-versa) -- chaque
# (sig, kem, network_profile, block) est maintenant une unité de reprise
# distincte, ce qui est indispensable pour le découpage multi-jours.
already_done() {
    local sig="$1" kem="$2"
    [[ -f "$RESOURCE_CSV" ]] || return 1
    # Une ligne client est ajoutee par TOUR : le tour R est fait si >= R lignes existent.
    awk -F',' -v s="$sig" -v k="$kem" -v np="$NETWORK_PROFILE" -v b="$BLOCK_INDEX" -v nb="$N_BLOCKS" -v r="${ROUND:-1}" \
        '$4==s && $5==k && $6==np && $7=="client" && $12==b && $13==nb {c++} END{exit !(c>=r)}' \
        "$RESOURCE_CSV"
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CAPTURES_ROOT="${CAPTURES_ROOT:-$SCRIPT_DIR/captures}"

detect_platform

init_resource_csv

CLIENT_LOG_DIR="$CAPTURES_ROOT/$PROTOCOL/$AUTH_MODE/$NETWORK_PROFILE_LABEL/handshake_logs"
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

# ── Manifeste d'audit du bloc (traçabilité exigée par la relecture) ───────
MANIFEST_DIR="$CAPTURES_ROOT/$PROTOCOL/$AUTH_MODE/$NETWORK_PROFILE_LABEL"
mkdir -p "$MANIFEST_DIR"
MANIFEST_FILE="$MANIFEST_DIR/block_manifest_block${BLOCK_INDEX}of${N_BLOCKS}_seed${SEED}.log"
{
    echo "timestamp_start=$(date -Iseconds)"
    echo "protocol=$PROTOCOL auth_mode=$AUTH_MODE network_profile=$NETWORK_PROFILE_LABEL"
    echo "n_blocks=$N_BLOCKS block_index=$BLOCK_INDEX seed=$SEED runs_this_block=$NUM_RUNS micro_batches=$MICRO_BATCHES runs_per_round=$RUNS_PER_ROUND"
    write_env_header
    for r in $(seq 1 "$MICRO_BATCHES"); do
        echo "execution_order round=$r/$MICRO_BATCHES:"
        i=1
        while IFS= read -r p; do
            echo "  $i) $p"
            i=$((i+1))
        done < <(pairs_for_round "$r")
    done
} > "$MANIFEST_FILE"
echo "Manifeste d'audit du bloc écrit dans $MANIFEST_FILE"

POSITION=0
for ROUND in $(seq 1 "$MICRO_BATCHES"); do
mapfile -t ROUND_PAIRS < <(pairs_for_round "$ROUND")
echo ""
echo "################ TOUR $ROUND / $MICRO_BATCHES ($RUNS_PER_ROUND connexions par paire) ################"
for PAIR in "${ROUND_PAIRS[@]}"; do
    POSITION=$((POSITION+1))
    SIG_ALG="${PAIR%%|*}"
    KEM="${PAIR##*|}"

    echo ""
    echo "****************"
    echo " ==> SIG_ALG: $SIG_ALG  |  KEM: $KEM  |  bloc $BLOCK_INDEX/$N_BLOCKS"
    if already_done "$SIG_ALG" "$KEM"; then
        echo "     (deja present dans $RESOURCE_CSV pour ce scenario/bloc -- ignore, reprise automatique)"
        continue
    fi

    wait_cooldown
    ROUND_SUFFIX=""
    if (( MICRO_BATCHES > 1 )); then ROUND_SUFFIX="_mb${ROUND}of${MICRO_BATCHES}"; fi

    # ── Certs régénérés à CHAQUE paire, pas une fois par SIG_ALG ──────────
    # Indispensable maintenant que l'ordre est mélangé : deux paires
    # consécutives peuvent appartenir à des SIG_ALG différents, contrairement
    # à l'ancienne boucle imbriquée où toutes les paires d'un même SIG_ALG
    # se suivaient et ne nécessitaient qu'une génération de certs.
    echo " ==> Creating Certs and Keys for $SIG_ALG"
    docker run --rm -v cert:/cert -e CERT_PATH=/cert/ -e SIG_ALG=$SIG_ALG \
        -e CHAIN_DEPTH=$CHAIN_DEPTH -e CERT_PAD_BYTES=$CERT_PAD_BYTES -e CERT_PAD_TARGET_DER=$CERT_PAD_TARGET_DER \
        -i "$IMAGE" doCert.sh || { echo "❌ ERREUR FATALE: doCert.sh a echoue pour $SIG_ALG."; exit 1; }
    # Tailles DER reelles des certificats de CETTE paire -> manifeste d'audit (critiques 3 et 6).
    CERT_SIZES=$(docker run --rm -v cert:/cert --entrypoint cat "$IMAGE" /cert/cert_sizes.txt 2>/dev/null | tr '\n' ' ' || true)
    echo "cert_sizes[$SIG_ALG|$KEM block=$BLOCK_INDEX]: ${CERT_SIZES:-NA}" >> "$MANIFEST_FILE"


            echo ""
            echo "    Executing docker Server..."

            docker rm -f $OQS_SERVER $OQS_CLIENT 2>/dev/null

            SSL_DIR="$CAPTURES_ROOT/$PROTOCOL/$AUTH_MODE/$NETWORK_PROFILE_LABEL/sslkeys"
            SRV_SSL_ENV=""
            CLI_SSL_ENV=""
            if [[ "$PER_CONN_PCAP" == "1" ]]; then
                # Campagne mecanistique : un dossier par bloc, par TOUR (micro-lots : ROUND_SUFFIX, sinon chaque
                # tour ecraserait block.pcap/conn_windows.csv du precedent) et par paire,
                # qui recevra block.pcap (capture continue cote client),
                # conn_windows.csv, tcpdump.err + les cles de session.
                SSL_DIR="$CAPTURES_ROOT/$PROTOCOL/$AUTH_MODE/$NETWORK_PROFILE_LABEL/pcap_perconn/block${BLOCK_INDEX}of${N_BLOCKS}${ROUND_SUFFIX}/${SIG_ALG}_${KEM}"
                SRV_SSL_ENV="-e SSL_DIR=/sslkeys"
                CLI_SSL_ENV="-e SSL_DIR=/sslkeys -e PER_CONN_PCAP=1 -e CAPTURE_IF=$NETIF"
            else
                if [ "$PROTOCOL" = "tls" ] && [ "$CAPTURE_MODE" = "captureKey" ]; then SRV_SSL_ENV="-e SSL_DIR=/sslkeys"; fi
                if [ "$PROTOCOL" = "quic" ] && [ "$CAPTURE_MODE" = "captureKey" ]; then CLI_SSL_ENV="-e SSL_DIR=/sslkeys"; fi
            fi
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
              ${TCP_SYSCTLS[@]+"${TCP_SYSCTLS[@]}"} \
              $SRV_CPUSET \
              -v cert:/cert   \
              -v "$SSL_DIR":/sslkeys \
              -e TC_DELAY=0ms  \
              -e TC_LOSS=0% \
              -e CERT_PATH=/cert/ \
              -e KEM_ALG=$KEM  \
              -e SIG_ALG=$SIG_ALG \
              -e USE_TLS=$USE_TLS \
              -e MUTUAL=$MUTUAL_AUTHENTICATION \
              -e QUIC_ENABLE_UDP_GSO=${QUIC_ENABLE_UDP_GSO:-0} \
              -e QUIC_MTU=${QUIC_MTU_EFF} \
              $SRV_SSL_ENV \
              -d $IMAGE perftestServerTlsQuic.sh

            sleep 3
            set_mtu "$OQS_SERVER"
            set_offloads "$OQS_SERVER"
            check_tcp_isolation "$OQS_SERVER"

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
              none|simple|delay-only|loss-only|ge-mild-*|ge-severe-*)
                sleep 2
                apply_netem "$OQS_SERVER" "$SRV_NETEM_ARGS" "$SRV_NEEDS_GE_CHECK"
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
                ${TCP_SYSCTLS[@]+"${TCP_SYSCTLS[@]}"} \
                $CLI_CPUSET \
                -v cert:/cert \
                -v "$SSL_DIR":/sslkeys \
                -e DOCKER_HOST=$IP \
                -e TC_DELAY=0ms  \
                -e TC_LOSS=0% \
                -e CERT_PATH=/cert/ \
                -e KEM_ALG=$KEM \
                -e SIG_ALG=$SIG_ALG \
                -e USE_TLS=$USE_TLS \
                -e NUM_RUNS=$RUNS_PER_ROUND \
                -e WARMUP_RUNS=$WARMUP_RUNS \
                -e HANDSHAKE_TIMEOUT_S=$HANDSHAKE_TIMEOUT_S \
                -e MUTUAL=$MUTUAL_AUTHENTICATION \
                -e QUIC_ENABLE_UDP_GSO=${QUIC_ENABLE_UDP_GSO:-0} \
                -e QUIC_MTU=${QUIC_MTU_EFF} \
                $CLI_SSL_ENV \
                "$IMAGE" sleep infinity


            docker start $OQS_CLIENT
            set_mtu "$OQS_CLIENT"
            set_offloads "$OQS_CLIENT"
            check_tcp_isolation "$OQS_CLIENT"
            pin_neighbors

            echo "     Docker $OQS_CLIENT executed ... "

            ############################################################################
            #  NETWORK IMPAIRMENTS (Pumba) — CLIENT
            ############################################################################
            PUMBA_PIDS_CLIENT=()
            case "$NETWORK_PROFILE" in
              none|simple|delay-only|loss-only|ge-mild-*|ge-severe-*)
                apply_netem "$OQS_CLIENT" "$CLI_NETEM_ARGS" "$CLI_NEEDS_GE_CHECK"
                ;;
            esac

            echo ""
            echo "**************************"
            echo "     Executing test  ... "

            # ── Point de départ pour la mesure CPU/mémoire du client ───────
            record_env before
            read -r SRV_PK0 SRV_DR0 <<< "$(qdisc_stats "$OQS_SERVER")"
            read -r CLI_PK0 CLI_DR0 <<< "$(qdisc_stats "$OQS_CLIENT")"
            CLIENT_CPU_START=$(read_cgroup_cpu_usec "$OQS_CLIENT")

            # ── Capture des logs de handshake (perdus jusqu'ici : docker exec
            #    -it affichait tout dans le terminal sans rien sauvegarder).
            #    tee garde l'affichage live ET écrit dans le fichier.
            CLIENT_LOG_FILE="$CLIENT_LOG_DIR/handshake_${PROTOCOL}_${AUTH_MODE}_${SIG_ALG}_${KEM}_${NETWORK_PROFILE_LABEL}_block${BLOCK_INDEX}of${N_BLOCKS}${ROUND_SUFFIX}.log"
            docker exec $OQS_CLIENT ./perftestClientTlsQuic.sh 2>&1 | tee "$CLIENT_LOG_FILE"
            echo "     Log de handshake enregistré dans $CLIENT_LOG_FILE"

            # ── Points de fin CPU + pic mémoire, capturés juste après le
            #    test et AVANT le kill des conteneurs (sinon illisibles) ──
            CLIENT_CPU_END=$(read_cgroup_cpu_usec "$OQS_CLIENT")
            SERVER_CPU_END=$(read_cgroup_cpu_usec "$OQS_SERVER")
            CLIENT_MEM_PEAK=$(read_cgroup_mem_peak_bytes "$OQS_CLIENT")
            SERVER_MEM_PEAK=$(read_cgroup_mem_peak_bytes "$OQS_SERVER")
            read -r SRV_PK1 SRV_DR1 <<< "$(qdisc_stats "$OQS_SERVER")"
            read -r CLI_PK1 CLI_DR1 <<< "$(qdisc_stats "$OQS_CLIENT")"
            record_qdisc_row "server_egress" "$SRV_PK0" "$SRV_DR0" "$SRV_PK1" "$SRV_DR1"
            record_qdisc_row "client_egress" "$CLI_PK0" "$CLI_DR0" "$CLI_PK1" "$CLI_DR1"
            record_env after
            log_tcp_metrics_count "$OQS_CLIENT"
            log_tcp_metrics_count "$OQS_SERVER"

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

echo "timestamp_end=$(date -Iseconds)" >> "$MANIFEST_FILE"

sleep 3

cleaning
echo "✅  Cleanup complete. Tests finished. Bloc $BLOCK_INDEX/$N_BLOCKS terminé (graine $SEED)."
