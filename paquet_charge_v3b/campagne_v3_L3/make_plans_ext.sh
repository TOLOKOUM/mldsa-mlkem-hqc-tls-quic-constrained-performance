#!/bin/bash
###############################################################################
# make_plans_ext.sh [dossier_sortie] -- plans de la campagne v3 (niveau de securite 3 uniquement) :
#   plan_resume_L3.csv        reprise de session (TLS 1.3 PSK-DHE / QUIC), RTT {0,50,100,150} + perte {1,2,5} % a 50 ms
#   plan_resume0rtt_L3.csv    (exploratoire, QUIC) reprise avec requete en 0-RTT
#   plan_certcomp_L3.csv      compression de certificat RFC 8879 : chaines 1/2 niveaux + temoins ECDSA remplis
#   plan_load_L3.csv          charge concurrente en boucle fermee (serveur 1 CPU) + calibration serveur stock / multi-connexions
#   plan_pilot_ext.csv        pilote (a lancer avec --n-blocks 1, voir README)
#   plan_all_ext.csv          concatenation (hors pilote et hors 0-RTT)
# Format identique a make_plans.sh de la campagne v2 (run_campaign.sh les lit tels quels).
# Variables : QUIC_COMP=1 (defaut 0) inclut les cellules de compression QUIC (apres probe_quic_features.sh positif) ;
#             COMP_ALGS="none zlib brotli" (ajouter zstd si le probe le confirme) ; N_BLOCKS=20.
###############################################################################
set -euo pipefail
OUT="${1:-plans_ext}"
N_BLOCKS="${N_BLOCKS:-20}"
QUIC_COMP="${QUIC_COMP:-0}"
COMP_ALGS="${COMP_ALGS:-none zlib brotli}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAUNCHER_EXT="${LAUNCHER_EXT:-$HERE/Launcher_ext.sh}"
mkdir -p "$OUT"
HDR="cell_id,protocol,auth,kem_family,profile,loss,delay,total_runs,only_pairs,extra_env"
PAIRS_L3="secp384r1|x448_mlkem768;mldsa65|x448_mlkem768;secp384r1|hqc192;mldsa65|hqc192"
PAIRS_ECDSA="secp384r1|x448_mlkem768;secp384r1|hqc192"
MB="MICRO_BATCHES=2"
RUNS=$(( N_BLOCKS * 20 ))       # 20 connexions par bloc et par paire (10 completes + 10 reprises pour la reprise)

prof() { # rtt -> "profil;delay_unidirectionnel"
  if [[ "$1" == "0" ]]; then echo "none 0"; else echo "delay-only $(( $1 / 2 ))"; fi
}

# ─── 1. REPRISE ───────────────────────────────────────────────────────────────────────────────────────────────────
{
  echo "$HDR"
  for proto in tls quic; do
    for rtt in 0 50 100 150; do
      read -r p d <<< "$(prof $rtt)"
      echo "res_${proto}_rtt${rtt},$proto,single,both,$p,0,$d,$RUNS,$PAIRS_L3,RESUME=1;$MB"
    done
    for L in 1 2 5; do
      echo "res_${proto}_rtt50_loss${L}_iid,$proto,single,both,simple,$L,25,$RUNS,$PAIRS_L3,RESUME=1;$MB"
    done
  done
} > "$OUT/plan_resume_L3.csv"
{
  echo "$HDR"
  for rtt in 0 50 100 150; do
    read -r p d <<< "$(prof $rtt)"
    echo "res0rtt_quic_rtt${rtt},quic,single,both,$p,0,$d,$RUNS,$PAIRS_L3,RESUME=1;ZERORTT_ARM=1;$MB"
  done
} > "$OUT/plan_resume0rtt_L3.csv"

# ─── 2. COMPRESSION DE CERTIFICAT ──────────────────────────────────────────────────────────────────────────────
{
  echo "$HDR"
  protos="tls"; [[ "$QUIC_COMP" == "1" ]] && protos="tls quic"
  for proto in $protos; do
    for rtt in 0 50; do
      read -r p d <<< "$(prof $rtt)"
      for alg in $COMP_ALGS; do
        # chaine 1 niveau et 2 niveaux, 4 paires L3 (ECDSA / ML-DSA-65 x ML-KEM / HQC)
        echo "comp_${proto}_chain1_rtt${rtt}_${alg},$proto,single,both,$p,0,$d,$RUNS,$PAIRS_L3,CERT_COMP=$alg;$MB"
        echo "comp_${proto}_chain2_rtt${rtt}_${alg},$proto,single,both,$p,0,$d,$RUNS,$PAIRS_L3,CERT_COMP=$alg;CHAIN_DEPTH=2;$MB"
        # temoins positifs : ECDSA artificiellement rempli (compressible) a 8700 o (bascule QUIC) et 16000 o (bascule TLS)
        for T in 8700 16000; do
          echo "comp_${proto}_ctl${T}_rtt${rtt}_${alg},$proto,single,both,$p,0,$d,$RUNS,$PAIRS_ECDSA,CERT_COMP=$alg;CERT_PAD_TARGET_DER=$T;$MB"
        done
      done
    done
  done
} > "$OUT/plan_certcomp_L3.csv"

# ─── 3. CHARGE CONCURRENTE ─────────────────────────────────────────────────────────────────────────────────────
# total_runs = N_BLOCKS (1 visite de charge par bloc et par paire : la valeur n'est pas un nombre de connexions).
{
  echo "$HDR"
  for rtt in 0; do
    read -r p d <<< "$(prof $rtt)"
    echo "load_tls_mt_rtt${rtt},tls,single,both,$p,0,$d,$N_BLOCKS,$PAIRS_L3,LOAD=1;TLS_SERVER=mt"
    echo "load_quic_rtt${rtt},quic,single,both,$p,0,$d,$N_BLOCKS,$PAIRS_L3,LOAD=1"
    # calibration : serveur stock (sequentiel) vs multi-connexions a concurrence 1 -> le serveur MT doit etre equivalent
    echo "loadcal_tls_stock_rtt${rtt},tls,single,both,$p,0,$d,$N_BLOCKS,$PAIRS_L3,LOAD=1;TLS_SERVER=stock;CONC_LEVELS=1"
    echo "loadcal_tls_mt_rtt${rtt},tls,single,both,$p,0,$d,$N_BLOCKS,$PAIRS_L3,LOAD=1;TLS_SERVER=mt;CONC_LEVELS=1"
  done
} > "$OUT/plan_load_L3.csv"

# ─── PILOTE (1 bloc ; lancer avec --n-blocks 1 --block 1 et un CAPTURES_ROOT distinct) ─────────────────────────
{
  echo "$HDR"
  echo "pilot_res_tls_rtt50,tls,single,both,delay-only,0,25,20,$PAIRS_L3,RESUME=1;$MB"
  echo "pilot_res_quic_rtt50,quic,single,both,delay-only,0,25,20,$PAIRS_L3,RESUME=1;$MB"
  for alg in none zlib brotli; do
    echo "pilot_comp_tls_chain1_rtt50_${alg},tls,single,both,delay-only,0,25,20,$PAIRS_L3,CERT_COMP=$alg;$MB"
    echo "pilot_comp_tls_ctl16000_rtt50_${alg},tls,single,both,delay-only,0,25,20,$PAIRS_ECDSA,CERT_COMP=$alg;CERT_PAD_TARGET_DER=16000;$MB"
  done
  # pilote charge v3b (clients persistants) : IMAGE=uma-tls-quic-pq-34-v3b ; plan separe plan_pilot_load_v3b.csv
} > "$OUT/plan_pilot_ext.csv"

# pilote de charge (image v3b, clients persistants) : c=1 4 16 32, 12 s, + calibration serveur stock vs MT a c=1
{
  echo "$HDR"
  echo "pilot2_load_tls_mt_rtt0,tls,single,both,none,0,0,1,$PAIRS_L3,LOAD=1;TLS_SERVER=mt;CONC_LEVELS=1 4 16 32;LOAD_SECONDS=12"
  echo "pilot2_load_quic_rtt0,quic,single,both,none,0,0,1,$PAIRS_L3,LOAD=1;CONC_LEVELS=1 4 16 32;LOAD_SECONDS=12"
  echo "pilot2_loadcal_tls_stock_rtt0,tls,single,both,none,0,0,1,$PAIRS_L3,LOAD=1;TLS_SERVER=stock;CONC_LEVELS=1;LOAD_SECONDS=12"
  echo "pilot2_loadcal_tls_mt_rtt0,tls,single,both,none,0,0,1,$PAIRS_L3,LOAD=1;TLS_SERVER=mt;CONC_LEVELS=1;LOAD_SECONDS=12"
} > "$OUT/plan_pilot_load_v3b.csv"

{
  echo "$HDR"
  for f in plan_resume_L3 plan_certcomp_L3 plan_load_L3; do tail -n +2 "$OUT/$f.csv"; done
} > "$OUT/plan_all_ext.csv"

# ─── controle d'unicite des dossiers de sortie (meme garde-fou que selftest_p0.sh) ──────────────────────────────
if [[ -f "$LAUNCHER_EXT" ]]; then
  tmp="$(mktemp)"
  while IFS=, read -r cid proto auth kemf prof loss delay total pairs extra; do
    [[ "$cid" == "cell_id" ]] && continue
    envs=(); IFS=';' read -ra kv <<< "$extra"; for e in "${kv[@]}"; do [[ -n "$e" ]] && envs+=("$e"); done
    lab=$(env PRINT_LABEL=1 "${envs[@]}" bash "$LAUNCHER_EXT" "$kemf" "$proto" "$auth" nocapture "$prof" "$loss" "$delay" "$N_BLOCKS" 1 1 2>&1 | tail -1) || true
    echo "$proto/$lab" >> "$tmp"
  done < <(tail -n +1 "$OUT/plan_all_ext.csv"; tail -n +2 "$OUT/plan_resume0rtt_L3.csv")
  dup=$(sort "$tmp" | uniq -d | head -3)
  rm -f "$tmp"
  if [[ -n "$dup" ]]; then echo "❌ labels de sortie dupliques :"; echo "$dup"; exit 1; fi
  echo "✔ labels de sortie tous distincts"
fi

# ─── duree estimee (hypotheses explicites, a recalibrer sur le pilote) ──────────────────────────────────────────
python3 - "$OUT" "$N_BLOCKS" <<'PY'
import csv,sys,os,re
out,nb=sys.argv[1],int(sys.argv[2])
OVER=40.0   # s de surcout fixe par visite (certificats, 2 conteneurs, sleeps du lanceur) -- valeur v2 typique
def est(row):
    rtt=float(row['delay'])*2/1000.0
    pairs=len(row['only_pairs'].split(';')) if row['only_pairs'] else 1
    ex=row['extra_env']
    if 'LOAD=1' in ex:
        m=re.search(r'CONC_LEVELS=([0-9 ]+)',ex); lv=len(m.group(1).split()) if m else 6
        m=re.search(r'LOAD_SECONDS=(\d+)',ex); ls=int(m.group(1)) if m else 20
        return pairs*(OVER+lv*(ls+3+30*0))   # le generateur tourne ls s par niveau
    nconn=int(row['total_runs'])/nb
    per=max(0.25,(3*rtt+0.15)) if 'RESUME' not in ex else max(0.25,2*rtt+0.12)
    return pairs*(OVER+nconn*(per+0.35))
for f in sorted(os.listdir(out)):
    if not f.startswith('plan_') or f=='plan_all_ext.csv': continue
    rows=list(csv.DictReader(open(os.path.join(out,f))))
    t=sum(est(r) for r in rows)
    print("%-28s %3d cellules  ~%5.1f min / bloc  ~%5.1f h pour %d blocs" % (f,len(rows),t/60,t*nb/3600,nb))
PY
