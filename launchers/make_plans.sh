#!/usr/bin/env bash
###############################################################################
# make_plans.sh — Genere les plans de campagne (CSV) consommes par run_campaign.sh
#
# DESIGN (reponse au prescreen TDSC-2026-09-3862 ; trajectoire A) :
#   Le coeur de l'inference est FACTORIEL et MECANISTIQUE ; les profils
#   "terrain" (Moderate/Degraded) deviennent des points de VALIDATION externe.
#   Facteurs fixes et declares dans tous les plans : debit (RATE_MBIT, defaut
#   100 Mbit/s dans run_campaign.sh), file netem (limit 1000), gigue nulle,
#   MTU 1500 sauf plan mecanistique, perte serveur->client sauf plan direction.
#
#   plan_main.csv          VALIDATION terrain : 42 paires x {TLS single, TLS mutual,
#                          QUIC single} x {Ideal, Moderate, Degraded} = 9 cellules,
#                          500 connexions/paire (20 blocs x 25). Les profils pumba
#                          GE-Stable/GE-Unstable (debit non controlable) sortent de la
#                          campagne principale -> plan_legacy_pumba.csv (facultatif).
#   plan_factorial_L3.csv  RQ3 : RTT {0,50,100,150} x perte {0,1,2,5}% x processus
#                          {iid, GE-mild, GE-severe} a perte marginale EGALE ; TLS+QUIC
#                          single ; 4 paires (2 signatures x 2 KEM) ; MICRO_BATCHES=2.
#   plan_direction_L3.csv  RQ3 : direction de la perte (s2c / c2s / both).
#   plan_mech_L3.csv       RQ2 : signature x MTU x perte avec pcap par connexion
#                          (PER_CONN_PCAP=1), dossier __pcap separe.
#   plan_sizectl_L3.csv    RQ2 : EXPERIENCE DE CONTROLE DE TAILLE : ECDSA P-384 normal,
#                          ECDSA P-384 GONFLE a la taille ML-DSA-65 (meme octets sur le
#                          fil, calcul classique), ML-DSA-65 ; x MTU x perte. Necessite
#                          SIZE_TARGET_DER (voir size_targets.sh).
#   plan_all.csv           FUSION de main + factorial + direction + mech + chain + sizectl : c'est CE plan
#                          qu'on lance pour la campagne (voir ci-dessous pourquoi).
#   plan_pilot.csv         PILOTE (10 cellules) : calibration du temps/disque, variance inter-blocs.
#   plan_chain_L3.csv      RQ4 : chaine REALISTE (CHAIN_DEPTH=2 : racine->intermediaire->
#                          feuille), memes conditions que les cellules RTT 50 iid du plan
#                          factoriel (chaine minimale) pour comparer directement.
#
# USAGE : ./make_plans.sh [dossier_sortie] ; SIZE_TARGET_DER=NNNN ./make_plans.sh plans
# Convention : DELAY_MS = delai UNIDIRECTIONNEL applique des deux cotes, donc
#              RTT = 2 x DELAY_MS  (RTT 50/100/150 ms => DELAY_MS 25/50/75).
# LOSSY_RUNS=400 : cellules avec perte des plans factoriel/direction/chain (voir commentaire plus bas).
# MICRO_BATCHES=M (extra_env) : bloc execute en M tours a ordre de paires re-tire ;
#   total_runs/20 doit etre divisible par M (200/20 = 10 -> M=2 => 5 connexions/tour).
###############################################################################
set -euo pipefail
OUT="${1:-plans}"
mkdir -p "$OUT"
HDR="cell_id,protocol,auth,kem_family,profile,loss,delay,total_runs,only_pairs,extra_env"
PAIRS_L3="secp384r1|x448_mlkem768;mldsa65|x448_mlkem768;secp384r1|hqc192;mldsa65|hqc192"
PAIRS_DIR="secp384r1|x448_mlkem768;mldsa65|x448_mlkem768"
MB="MICRO_BATCHES=2"
# Cellules AVEC PERTE des plans factoriel / direction / chaine : 400 connexions par paire (20 par bloc, 10 par tour).
# Raison (pilote, projection de puissance) : sous perte l'ecart-type par connexion est de 50 a 650 ms (queue des
# retransmissions), la difference minimale detectable a 20 blocs x 10 connexions etait de 11 a 140 ms ; doubler les
# connexions par visite coute peu (le temps est domine par le surcout fixe de ~30 s par visite de paire) et la
# reduit d'un facteur 1.4. Les cellules SANS perte (ecart-type < 7 ms) restent a 200.
LOSSY_RUNS=400

# ── plan_main : validation terrain (9 cellules) ─────────────────────────────
{
  echo "$HDR"
  for pa in "tls single" "tls mutual" "quic single"; do
    set -- $pa; proto=$1; auth=$2
    echo "main_${proto}_${auth}_ideal,$proto,$auth,both,none,0,0,500,,"
    echo "main_${proto}_${auth}_moderate,$proto,$auth,both,simple,1.3,62.51,500,,"
    echo "main_${proto}_${auth}_degraded,$proto,$auth,both,simple,1.5833,83.52,500,,"
  done
} > "$OUT/plan_main.csv"

# ── plan_legacy_pumba : ancien design (facultatif, SANS debit controle) ─────
{
  echo "$HDR"
  for pa in "tls single" "tls mutual" "quic single"; do
    set -- $pa; proto=$1; auth=$2
    echo "legacy_${proto}_${auth}_gestable,$proto,$auth,both,stable,0,0,500,,RATE_MBIT="
    echo "legacy_${proto}_${auth}_geunstable,$proto,$auth,both,unstable,0,0,500,,RATE_MBIT="
  done
} > "$OUT/plan_legacy_pumba.csv"

# ── plan_factorial_L3 : RTT x perte x processus ─────────────────────────────
{
  echo "$HDR"
  for proto in tls quic; do
    for rtt in 0 50 100 150; do
      d=$(( rtt / 2 ))
      if [[ "$rtt" == "0" ]]; then
        echo "fx_${proto}_rtt0_loss0,$proto,single,both,none,0,0,200,$PAIRS_L3,$MB"
      else
        echo "fx_${proto}_rtt${rtt}_loss0,$proto,single,both,delay-only,0,$d,200,$PAIRS_L3,$MB"
      fi
      for L in 1 2 5; do
        echo "fx_${proto}_rtt${rtt}_loss${L}_iid,$proto,single,both,simple,$L,$d,$LOSSY_RUNS,$PAIRS_L3,$MB"
        echo "fx_${proto}_rtt${rtt}_loss${L}_gemild,$proto,single,both,ge-mild-${L},0,$d,$LOSSY_RUNS,$PAIRS_L3,$MB"
        echo "fx_${proto}_rtt${rtt}_loss${L}_gesevere,$proto,single,both,ge-severe-${L},0,$d,$LOSSY_RUNS,$PAIRS_L3,$MB"
      done
    done
  done
} > "$OUT/plan_factorial_L3.csv"

# ── plan_direction_L3 (RTT 100 ms, perte 2 %) : c2s et both ; reference s2c = plan factoriel ──────
{
  echo "$HDR"
  for proto in tls quic; do
    # La direction s2c (defaut) est IDENTIQUE aux cellules fx_*_rtt100_loss2_{iid,gemild} (meme label, memes
    # paires) : elle sert de reference et n'est PAS dupliquee ici (sinon collision de dossiers silencieuse).
    for dir in c2s both; do
      echo "dir_${proto}_iid_${dir},$proto,single,mlkem,simple,2,50,$LOSSY_RUNS,$PAIRS_DIR,LOSS_DIRECTION=$dir;$MB"
      echo "dir_${proto}_gemild_${dir},$proto,single,mlkem,ge-mild-2,0,50,$LOSSY_RUNS,$PAIRS_DIR,LOSS_DIRECTION=$dir;$MB"
    done
  done
} > "$OUT/plan_direction_L3.csv"

# ── plan_mech_L3 : signature x MTU x perte, pcap continu (RTT 50 ms) ─────────
{
  echo "$HDR"
  for proto in tls quic; do
    # QUIC : le MTU d'interface seul ne change pas la paquetisation du handshake (MsQuic demarre a 1280 et ne
    # sonde qu'ensuite) -> QUIC_MTU_SYNC=1 fixe MinimumMtu=MaximumMtu=MTU cote QUIC. Sans effet sur TLS.
    QS=""; [[ "$proto" == "quic" ]] && QS="QUIC_MTU_SYNC=1;"
    for mtu in 1280 1500; do
      echo "mech_${proto}_mtu${mtu}_loss0,$proto,single,mlkem,delay-only,0,25,200,$PAIRS_DIR,${QS}MTU=$mtu;PER_CONN_PCAP=1;$MB"
      for L in 1 2 5; do
        echo "mech_${proto}_mtu${mtu}_loss${L},$proto,single,mlkem,simple,$L,25,200,$PAIRS_DIR,${QS}MTU=$mtu;PER_CONN_PCAP=1;$MB"
      done
    done
  done
} > "$OUT/plan_mech_L3.csv"

# ── plan_chain_L3 : chaine realiste (depth 2), conditions RTT 50 iid ─────────
{
  echo "$HDR"
  for proto in tls quic; do
    echo "chain_${proto}_rtt50_loss0,$proto,single,both,delay-only,0,25,200,$PAIRS_L3,CHAIN_DEPTH=2;$MB"
    for L in 1 2 5; do
      echo "chain_${proto}_rtt50_loss${L}_iid,$proto,single,both,simple,$L,25,$LOSSY_RUNS,$PAIRS_L3,CHAIN_DEPTH=2;$MB"
    done
  done
} > "$OUT/plan_chain_L3.csv"

# ── plan_sizectl_L3 : controle de taille (necessite SIZE_TARGET_DER) ─────────
# ECDSA P-384 GONFLE a la taille ML-DSA-65 (CERT_PAD_TARGET_DER). Les deux bras de reference (ECDSA normal et
# ML-DSA-65) sont les cellules du plan mech (meme RTT 50, MTU, perte, pcap, micro-lots, memes paires) : les
# redonner ici creerait des collisions de dossiers. Les trois bras sont donc compares dans les memes blocs
# (plans fusionnes dans plan_all.csv), ordre des cellules randomise.
if [[ -n "${SIZE_TARGET_DER:-}" ]]; then
  [[ "$SIZE_TARGET_DER" =~ ^[0-9]+$ ]] || { echo "SIZE_TARGET_DER invalide" >&2; exit 1; }
  {
    echo "$HDR"
    for proto in tls quic; do
      QS=""; [[ "$proto" == "quic" ]] && QS="QUIC_MTU_SYNC=1;"
      for mtu in 1280 1500; do
        for L in 0 1 2 5; do
          if [[ "$L" == "0" ]]; then prof="delay-only"; else prof="simple"; fi
          echo "size_${proto}_ecdsapad_mtu${mtu}_loss${L},$proto,single,mlkem,$prof,$L,25,200,secp384r1|x448_mlkem768,${QS}MTU=$mtu;PER_CONN_PCAP=1;CERT_PAD_TARGET_DER=$SIZE_TARGET_DER;$MB"
        done
      done
    done
  } > "$OUT/plan_sizectl_L3.csv"
else
  echo "ℹ️  plan_sizectl_L3.csv non genere : definissez SIZE_TARGET_DER (voir size_targets.sh)." >&2
fi

# ── plan_pilot : PILOTE (calibration temps/disque + variance pour l'analyse de puissance) ──
# A lancer avec --n-blocks 4 (total_runs=100 -> 25 connexions/bloc) et une graine, un dossier d'etat et
# un dossier de sortie DISTINCTS de la campagne ; les donnees du pilote ne servent JAMAIS a l'inference finale.
{
  echo "$HDR"
  for proto in tls quic; do
    echo "pilot_${proto}_rtt0_loss0,$proto,single,both,none,0,0,100,$PAIRS_L3,"
    echo "pilot_${proto}_rtt50_loss2_iid,$proto,single,both,simple,2,25,100,$PAIRS_L3,"
    echo "pilot_${proto}_rtt100_loss5_gemild,$proto,single,both,ge-mild-5,0,50,100,$PAIRS_L3,"
  done
  # entrelacement 5 tours x 5 connexions (teste aussi le nommage des logs en micro-lots)
  echo "pilot_tls_mb5,tls,single,both,simple,2,25,100,$PAIRS_L3,MICRO_BATCHES=5"
  # un pcap par connexion : mesure la taille disque reelle d'une cellule mecanistique
  echo "pilot_quic_rtt50_loss2_pcap,quic,single,mlkem,simple,2,25,100,$PAIRS_DIR,PER_CONN_PCAP=1"
  # pcap TLS (le pilote precedent n'avait qu'un pcap QUIC) et pcap + micro-lots (cas du plan mecanistique)
  echo "pilot_tls_rtt50_loss2_pcap,tls,single,mlkem,simple,2,25,100,$PAIRS_DIR,PER_CONN_PCAP=1"
  echo "pilot_quic_pcap_mb5,quic,single,mlkem,simple,2,25,100,$PAIRS_DIR,PER_CONN_PCAP=1;MICRO_BATCHES=5"
} > "$OUT/plan_pilot.csv"

# ── plan_all : TOUS les plans de la campagne principale fusionnes (a lancer en UNE seule fois) ─────────
# Une seule fusion => (1) cellules de tous les plans randomisees ENSEMBLE dans chaque bloc (critique 1) ;
# (2) sentinelles pre/mid/post autour de TOUT le bloc ; (3) un seul order_block*.txt ; (4) pas de collision d'etat.
# Le controle d'unicite des dossiers est fait par check_plan.py (selftest + a lancer avant la campagne).
{
  echo "$HDR"
  for f in plan_main plan_factorial_L3 plan_direction_L3 plan_mech_L3 plan_chain_L3 plan_sizectl_L3; do
    [[ -f "$OUT/$f.csv" ]] && tail -n +2 "$OUT/$f.csv"
  done
} > "$OUT/plan_all.csv"

for f in "$OUT"/plan_*.csv; do printf '%-34s %3d cellules\n' "$f" "$(( $(wc -l < "$f") - 1 ))"; done
