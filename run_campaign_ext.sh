#!/usr/bin/env bash
###############################################################################
# run_campaign_ext.sh (campagne v3 : reprise, compression de certificat, charge) — derive de run_campaign.sh. Orchestrateur de campagne RANDOMISEE PAR BLOCS (20 x 25).
#
# Repond aux critiques 1 et 2 de l'Associate Editor (TDSC-2026-09-3862) :
#   (1) ordre fixe / derive      -> l'ordre des CELLULES (protocole x auth x
#       reseau) est tire INDEPENDAMMENT a chaque bloc, et l'ordre des PAIRES
#       (SIG x KEM) l'est aussi a l'interieur de chaque cellule (graine
#       derivee, journalisee) ; warm-up, refroidissement, offloads controles ;
#       visites SENTINELLES (pre/mid/post) = estimateur direct de la derive.
#   (2) 4 blocs seulement        -> N_BLOCKS=20 blocs de 25 connexions, executes
#       a la demande bloc par bloc (--block K), repartis sur plusieurs jours
#       (garde-fou --max-blocks-per-day).
#
# USAGE
#   ./run_campaign.sh --plan plans/plan_main.csv --master-seed 20261001 --block 1
#   ./run_campaign.sh --plan plans/plan_main.csv --master-seed 20261001 --blocks 1-4
#   ./run_campaign.sh ... --dry-run          # affiche l'ordre et les commandes
#
# Options : --n-blocks N (defaut 20) | --warmup W (defaut 5) | --no-sentinels
#           --max-blocks-per-day M (defaut 4) | --force | --state-dir DIR
# Facteurs FIXES et declares (critiques 1 et 5), appliques par defaut ici :
#   no_turbo=1 obligatoire (intel_pstate) : frequence stable, sinon arret (ALLOW_TURBO=1 pour deroger,
#     a declarer). Sur une plateforme sans ce reglage (ARM) : avertissement, a declarer.
#   RATE_MBIT=100 : debit du lien fixe par netem 'rate' sur les deux egress (RATE_MBIT= pour desactiver).
#   MTU=1500, NETEM_LIMIT=1000, gigue nulle, perte s2c : valeurs par defaut du Launcher, journalisees.
#   MICRO_BATCHES (via extra_env du plan) : entrelacement en M tours par bloc (cf. Launcher).
# Variables d'environnement transmises au Launcher : COOLDOWN_TEMP_C,
#   HANDSHAKE_TIMEOUT_S, OFFLOAD_OFF (defaut 1 ici), PIN_CPUS, NETEM_LIMIT...
#   SENTINEL_PAIRS (defaut: secp384r1|x448_mlkem768,mldsa65|x448_mlkem768)
#   SENTINEL_PROTOCOLS (defaut: tls,quic) | SENTINEL_RUNS_PER_BLOCK (defaut 25)
#
# FORMAT DU PLAN (CSV, voir make_plans.sh) :
#   cell_id,protocol,auth,kem_family,profile,loss,delay,total_runs,only_pairs,extra_env
#   only_pairs : paires "sig|kem" separees par ';'   (vide = les 42 paires)
#   extra_env  : "CLE=VAL;CLE=VAL" (ex. MTU=1280;PER_CONN_PCAP=1)
###############################################################################
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAUNCHER="${LAUNCHER:-$SCRIPT_DIR/Launcher_ext.sh}"
# v3 : image Docker dediee (patches de reprise/compression + tls_mt_server) ; elle est transmise au Launcher.
export IMAGE="${IMAGE:-uma-tls-quic-pq-34-v3}"

ORIG_ARGS=("$@")
PLAN=""
N_BLOCKS=20
BLOCKS_SPEC=""
MASTER_SEED=""
WARMUP=5
SENTINELS=true
DRY_RUN=false
FORCE=false
MAX_BLOCKS_PER_DAY=4
STATE_DIR="$SCRIPT_DIR/campaign_state_v3"      # ne JAMAIS partager l'etat (ni la graine maitre) avec la campagne v2

while [[ $# -gt 0 ]]; do
    case "$1" in
        --plan) PLAN="$2"; shift 2 ;;
        --n-blocks) N_BLOCKS="$2"; shift 2 ;;
        --block) BLOCKS_SPEC="$2-$2"; shift 2 ;;
        --blocks) BLOCKS_SPEC="$2"; shift 2 ;;
        --master-seed) MASTER_SEED="$2"; shift 2 ;;
        --warmup) WARMUP="$2"; shift 2 ;;
        --no-sentinels) SENTINELS=false; shift ;;
        --dry-run) DRY_RUN=true; shift ;;
        --force) FORCE=true; shift ;;
        --max-blocks-per-day) MAX_BLOCKS_PER_DAY="$2"; shift 2 ;;
        --state-dir) STATE_DIR="$2"; shift 2 ;;
        -h|--help) sed -n 2,40p "$0"; exit 0 ;;
        *) echo "Option inconnue: $1"; exit 1 ;;
    esac
done

die() { echo "❌ $*" >&2; exit 1; }
# ── Anti-veille : une mise en veille/hibernation en plein bloc (constatee sur le pilote : 101 min perdues,
# la machine a hiberne) fausse les durees et le temps de campagne. On relance ce script sous
# systemd-inhibit (veille, inactivite, fermeture du capot, touche veille BLOQUEES tant qu'il tourne).
if [[ "$DRY_RUN" != "true" && -z "${CAMPAIGN_INHIBITED:-}" ]] && command -v systemd-inhibit >/dev/null 2>&1 \
   && systemd-inhibit --what=sleep --why="test" --mode=block true >/dev/null 2>&1; then
    export CAMPAIGN_INHIBITED=1
    echo "Anti-veille : systemd-inhibit actif pendant toute la campagne (veille/hibernation/capot bloques)."
    exec systemd-inhibit --what=sleep:idle:handle-lid-switch:handle-suspend-key:handle-hibernate-key \
        --who="run_campaign" --why="campagne PQC en cours" --mode=block bash "$0" "${ORIG_ARGS[@]}"
elif [[ "$DRY_RUN" != "true" && -z "${CAMPAIGN_INHIBITED:-}" ]]; then
    echo "⚠️  systemd-inhibit indisponible : DESACTIVEZ MANUELLEMENT la veille et la fermeture du capot (voir prepare_env.sh)."
fi
[[ -f "$PLAN" ]] || die "--plan requis (fichier CSV introuvable: '$PLAN')."
[[ "$MASTER_SEED" =~ ^[0-9]+$ ]] || die "--master-seed requis (entier). Fixez-le UNE fois pour toute la campagne."
[[ "$N_BLOCKS" =~ ^[0-9]+$ && "$N_BLOCKS" -ge 1 ]] || die "--n-blocks invalide."
[[ "$WARMUP" =~ ^[0-9]+$ ]] || die "--warmup invalide."
[[ -n "$BLOCKS_SPEC" ]] || die "--block K ou --blocks A-B requis."
[[ "$BLOCKS_SPEC" =~ ^([0-9]+)-([0-9]+)$ ]] || die "--blocks attend A-B (ex. 1-4)."
B_FIRST="${BASH_REMATCH[1]}"; B_LAST="${BASH_REMATCH[2]}"
(( B_FIRST >= 1 && B_LAST <= N_BLOCKS && B_FIRST <= B_LAST )) || die "Blocs hors de 1..$N_BLOCKS."

mkdir -p "$STATE_DIR"
STATE_FILE="$STATE_DIR/state.csv"
[[ -f "$STATE_FILE" ]] || echo "timestamp,block,kind,cell_id,visit,exit_code,seed" > "$STATE_FILE"

# La graine maitre est FIGEE pour toute la campagne (sinon deux sessions
# utiliseraient des plans de randomisation incoherents).
SEED_FILE="$STATE_DIR/master_seed.txt"
if [[ -f "$SEED_FILE" && "$(cat "$SEED_FILE")" != "$MASTER_SEED" ]]; then
    die "Graine maitre deja fixee a $(cat "$SEED_FILE") dans $SEED_FILE (recue: $MASTER_SEED)."
fi
[[ "$DRY_RUN" == "true" ]] || echo "$MASTER_SEED" > "$SEED_FILE"

# ── Outils de randomisation reproductible ────────────────────────────────────
derive_seed() { printf '%s' "$*" | cksum | awk '{print $1}'; }
shuffle_seeded() {
    shuf --random-source=<(openssl enc -aes-256-ctr -pass pass:"$1" -nosalt </dev/zero 2>/dev/null)
}

# ── Lecture et validation du plan ────────────────────────────────────────────
declare -A CELL_ROW
CELL_IDS=()
VALID_PROFILES=" none simple delay-only loss-only stable unstable ge-mild-1 ge-mild-2 ge-mild-5 ge-severe-1 ge-severe-2 ge-severe-5 "
NEEDS_PUMBA=false
lineno=0
while IFS=, read -r cell_id protocol auth kem_family profile loss delay total_runs only_pairs extra_env || [[ -n "${cell_id:-}" ]]; do
    lineno=$((lineno+1))
    [[ "$lineno" -eq 1 ]] && continue                    # en-tete
    [[ -z "${cell_id// }" || "$cell_id" == \#* ]] && continue
    [[ -z "${CELL_ROW[$cell_id]+x}" ]] || die "plan: cell_id duplique '$cell_id' (ligne $lineno)."
    [[ "$protocol" == "tls" || "$protocol" == "quic" ]] || die "plan[$cell_id]: protocol '$protocol' invalide."
    [[ "$auth" == "single" || "$auth" == "mutual" ]] || die "plan[$cell_id]: auth '$auth' invalide."
    [[ "$protocol" == "quic" && "$auth" == "mutual" ]] && die "plan[$cell_id]: QUIC mutual non supporte (limitation MsQuic documentee)."
    [[ "$VALID_PROFILES" == *" $profile "* ]] || die "plan[$cell_id]: profile '$profile' invalide."
    [[ "$profile" == "stable" || "$profile" == "unstable" ]] && NEEDS_PUMBA=true
    [[ "$total_runs" =~ ^[0-9]+$ ]] || die "plan[$cell_id]: total_runs invalide."
    (( total_runs % N_BLOCKS == 0 )) || die "plan[$cell_id]: total_runs=$total_runs non divisible par N_BLOCKS=$N_BLOCKS."
    CELL_ROW[$cell_id]="$protocol,$auth,$kem_family,$profile,$loss,$delay,$total_runs,$only_pairs,$extra_env"
    CELL_IDS+=("$cell_id")
done < "$PLAN"
(( ${#CELL_IDS[@]} > 0 )) || die "plan vide."
echo "Plan: ${#CELL_IDS[@]} cellule(s) | N_BLOCKS=$N_BLOCKS | blocs ${B_FIRST}..${B_LAST} | warm-up=$WARMUP | graine maitre=$MASTER_SEED"

# ── Preflight environnement (critique 1 : etat processeur controle) ──────────
# Governor de TOUS les coeurs (un gestionnaire d'energie -- power-profiles-daemon, TLP,
# passage sur batterie -- peut le REMETTRE en powersave en cours de campagne).
gov_now() {
    local g
    g="$(cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor 2>/dev/null | sort -u | tr '\n' ',' | sed 's/,$//')"
    echo "${g:-NA}"
}
turbo_now() { cat /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null || echo NA; }
NOTURBO="$(turbo_now)"
GOV="$(gov_now)"
echo "Preflight: governor=$GOV no_turbo=$NOTURBO"
TURBO_HELP="echo 1 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo   (a refaire apres un redemarrage ; verifier : cat /sys/devices/system/cpu/intel_pstate/no_turbo -> 1)"
if [[ "$NOTURBO" == "NA" ]]; then
    echo "⚠️  Pas d'interface intel_pstate/no_turbo (autre architecture ou pilote) : la frequence turbo ne peut pas etre figee ici -- a DECLARER dans l'article."
elif [[ "$NOTURBO" != "1" ]]; then
    msg="turbo actif (no_turbo=$NOTURBO ; attendu 1). Corriger : $TURBO_HELP"
    if [[ "${ALLOW_TURBO:-0}" == "1" || "$DRY_RUN" == "true" ]]; then echo "⚠️  $msg"; else die "$msg  (ou ALLOW_TURBO=1 pour forcer, a declarer dans l'article)"; fi
fi
GOV_HELP="sudo cpupower frequency-set -g performance   (et arreter le gestionnaire d'energie : sudo systemctl stop power-profiles-daemon tlp ; rester sur secteur)"
if [[ "$GOV" != "performance" ]]; then
    msg="governor='$GOV' (attendu 'performance'). Corriger : $GOV_HELP"
    if [[ "${ALLOW_GOVERNOR_MISMATCH:-0}" == "1" || "$DRY_RUN" == "true" ]]; then echo "⚠️  $msg"; else die "$msg  (ou ALLOW_GOVERNOR_MISMATCH=1 pour forcer, a declarer dans l'article)"; fi
fi
# Alimentation : sur batterie le CPU peut etre bride (limites de puissance) et la machine s'eteindre en pleine
# campagne. Lit /sys/class/power_supply (type Mains) : yes = secteur, no = batterie, NA = information absente.
ac_state() {
    local f d any=NA
    for f in /sys/class/power_supply/*/type; do
        [[ -e "$f" ]] || continue
        d="$(dirname "$f")"
        [[ "$(cat "$f" 2>/dev/null)" == "Mains" ]] || continue
        if [[ "$(cat "$d/online" 2>/dev/null)" == "1" ]]; then echo yes; return; fi
        any=no
    done
    echo "$any"
}
if [[ "$(ac_state)" == "no" ]]; then
    msg="machine sur BATTERIE (secteur debranche). Brancher l'alimentation : une campagne dure des jours."
    if [[ "${ALLOW_BATTERY:-0}" == "1" || "$DRY_RUN" == "true" ]]; then echo "⚠️  $msg"; else die "$msg  (ou ALLOW_BATTERY=1 pour forcer, a declarer dans l'article)"; fi
fi
# Re-verification AVANT CHAQUE visite : un campagne dure des jours.
require_governor() {
    [[ "$DRY_RUN" == "true" || "${ALLOW_GOVERNOR_MISMATCH:-0}" == "1" ]] && return 0
    local g t; g="$(gov_now)"; t="$(turbo_now)"
    if [[ "$(ac_state)" == "no" && "${ALLOW_BATTERY:-0}" != "1" ]]; then
        echo "❌ ARRET : secteur debranche en cours de campagne (machine sur batterie)." >&2
        echo "   Rebranchez l'alimentation puis relancez la MEME commande : les parties deja faites sont sautees." >&2
        exit 3
    fi
    if [[ "$t" != "NA" && "$t" != "1" && "${ALLOW_TURBO:-0}" != "1" ]]; then
        echo "❌ ARRET : turbo reactive en cours de campagne (no_turbo=$t, attendu 1)." >&2
        echo "   Corriger : $TURBO_HELP" >&2
        echo "   Puis relancez la MEME commande : les parties deja faites sont sautees." >&2
        exit 3
    fi
    if [[ "$g" != "performance" ]]; then
        echo "❌ ARRET : governor passe a '$g' en cours de campagne (attendu 'performance')." >&2
        echo "   Corriger : $GOV_HELP" >&2
        echo "   Puis relancez la MEME commande : les parties deja faites sont sautees." >&2
        exit 3
    fi
}
if [[ "$DRY_RUN" != "true" ]]; then
    command -v docker >/dev/null 2>&1 || die "docker introuvable."
    docker image inspect "$IMAGE" >/dev/null 2>&1 || die "image $IMAGE absente (docker build -f Dockerfile.v3 -t $IMAGE ., voir README_v3)."
    [[ -f "$LAUNCHER" ]] || die "Launcher introuvable: $LAUNCHER"
    if [[ "$NEEDS_PUMBA" == "true" ]]; then command -v pumba >/dev/null 2>&1 || [[ -x /usr/local/bin/pumba ]] || die "plan avec stable/unstable mais pumba introuvable."; fi
fi

export OFFLOAD_OFF="${OFFLOAD_OFF:-1}"
# Dossier de sortie DISTINCT de l'ancienne campagne (4 blocs) : jamais de melange ni de reprise par erreur.
export CAPTURES_ROOT="${CAPTURES_ROOT:-$(dirname "$LAUNCHER")/captures_v3}"
echo "Sorties : $CAPTURES_ROOT | debit RATE_MBIT=${RATE_MBIT-100} Mbit/s"
# Debit explicite par defaut (facteur controle, critique 5). Vide = non limite (a declarer).
export RATE_MBIT="${RATE_MBIT-100}"
if [[ -n "$RATE_MBIT" ]]; then
    for c in "${CELL_IDS[@]}"; do
        IFS=, read -r _p _a _k prof _l _d _t _pairs ex <<< "${CELL_ROW[$c]}"
        if [[ ( "$prof" == "stable" || "$prof" == "unstable" ) && "$ex" != *"RATE_MBIT="* ]]; then
            die "plan[$c]: profil pumba '$prof' incompatible avec RATE_MBIT=$RATE_MBIT (debit non controle). Mettez RATE_MBIT= dans extra_env de la cellule (ancien design, a declarer) ou retirez-la."
        fi
    done
fi
export WARMUP_RUNS="$WARMUP"

# Temps total passe en veille/hibernation depuis le demarrage (CLOCK_BOOTTIME - CLOCK_MONOTONIC).
# Une augmentation pendant une visite = visite contaminee.
suspend_total() {
    python3 -c 'import time;print("%.3f"%(time.clock_gettime(time.CLOCK_BOOTTIME)-time.clock_gettime(time.CLOCK_MONOTONIC)))' 2>/dev/null || echo 0
}

# ── Execution d'une visite (cellule ou sentinelle) ───────────────────────────
already_ok() {  # block kind cell visit
    awk -F, -v b="$1" -v k="$2" -v c="$3" -v v="$4" '$2==b && $3==k && $4==c && $5==v && $6==0 {f=1} END{exit !f}' "$STATE_FILE"
}

run_visit() {   # block kind cell_id visit protocol auth kem_family profile loss delay total_runs only_pairs extra_env
    local block="$1" kind="$2" cell_id="$3" visit="$4" protocol="$5" auth="$6" kemf="$7" profile="$8" loss="$9" delay="${10}" total="${11}" pairs="${12}" extra="${13}"
    local seed envs=() rc=0
    seed="$(derive_seed "$MASTER_SEED" "$block" "$kind" "$cell_id" "$visit")"
    envs+=("TOTAL_RUNS=$total")
    [[ -n "$pairs" ]] && envs+=("ONLY_PAIRS=${pairs//;/,}")
    [[ "$kind" == "sentinel" ]] && envs+=("VISIT_TAG=$visit")
    if [[ -n "$extra" ]]; then IFS=';' read -ra kv <<< "$extra"; for e in "${kv[@]}"; do envs+=("$e"); done; fi

    if already_ok "$block" "$kind" "$cell_id" "$visit"; then
        echo "   [skip] bloc $block $kind $cell_id${visit:+/$visit} deja OK."
        return 0
    fi
    echo ">>> [bloc $block/$N_BLOCKS] $kind $cell_id${visit:+ ($visit)}  seed=$seed"
    echo "    env ${envs[*]} $(basename "$LAUNCHER") $kemf $protocol $auth nocapture $profile $loss $delay $N_BLOCKS $block $seed"
    if [[ "$DRY_RUN" == "true" ]]; then return 0; fi
    require_governor
    local susp0 susp1; susp0="$(suspend_total)"
    env "${envs[@]}" bash "$LAUNCHER" "$kemf" "$protocol" "$auth" nocapture "$profile" "$loss" "$delay" "$N_BLOCKS" "$block" "$seed" || rc=$?
    susp1="$(suspend_total)"
    if awk -v a="$susp0" -v b="$susp1" 'BEGIN{exit !(b-a>1.0)}'; then
        echo "❌ VISITE CONTAMINEE : la machine a ete mise en veille/hibernation pendant cette visite (+$(awk -v a="$susp0" -v b="$susp1" 'BEGIN{printf "%.0f", b-a}') s)." >&2
        echo "$(date -Iseconds),$block,$kind,$cell_id,$visit,98,$seed" >> "$STATE_FILE"
        echo "   Les donnees de cette visite NE DOIVENT PAS etre analysees (code 98 dans $STATE_FILE) : supprimez le dossier de cette cellule/bloc puis relancez." >&2
        exit 4
    fi
    echo "$(date -Iseconds),$block,$kind,$cell_id,$visit,$rc,$seed" >> "$STATE_FILE"
    [[ $rc -eq 0 ]] || echo "   ⚠️  ECHEC (rc=$rc) -- relancez la MEME commande : seules les parties manquantes seront refaites."
    return 0
}

run_sentinels() {  # block visit
    local block="$1" visit="$2" proto
    [[ "$SENTINELS" == "true" ]] || return 0
    local sp="${SENTINEL_PAIRS:-secp384r1|x448_mlkem768,mldsa65|x448_mlkem768}"
    IFS=',' read -ra SP <<< "${SENTINEL_PROTOCOLS:-tls,quic}"
    for proto in "${SP[@]}"; do
        run_visit "$block" sentinel "sent_${proto}" "$visit" "$proto" single mlkem none 0 0 "$(( ${SENTINEL_RUNS_PER_BLOCK:-25} * N_BLOCKS ))" "${sp//,/;}" ""
    done
}

# ── Boucle principale sur les blocs ──────────────────────────────────────────
for (( K=B_FIRST; K<=B_LAST; K++ )); do
    # Garde-fou multi-jours : un bloc = une occasion ; on etale sur plusieurs jours.
    today="$(date +%F)"
    started_today=$(awk -F, -v d="$today" -v b="$K" '$3=="blockstart" && substr($1,1,10)==d && $2!=b {print $2}' "$STATE_FILE" | sort -u | wc -l)
    if (( started_today >= MAX_BLOCKS_PER_DAY )) && [[ "$FORCE" != "true" && "$DRY_RUN" != "true" ]]; then
        die "$started_today bloc(s) deja demarre(s) aujourd'hui (max $MAX_BLOCKS_PER_DAY). Reprenez demain, ou --force (a declarer)."
    fi
    [[ "$DRY_RUN" == "true" ]] || echo "$(date -Iseconds),$K,blockstart,,,0,$MASTER_SEED" >> "$STATE_FILE"

    BLOCK_SEED="$(derive_seed "$MASTER_SEED" "cellorder" "$K")"
    mapfile -t ORDER < <(printf '%s\n' "${CELL_IDS[@]}" | shuffle_seeded "$BLOCK_SEED")
    ORDER_FILE="$STATE_DIR/order_block${K}of${N_BLOCKS}.txt"
    if [[ "$DRY_RUN" != "true" ]]; then
        { echo "# bloc=$K n_blocks=$N_BLOCKS master_seed=$MASTER_SEED block_seed=$BLOCK_SEED date=$(date -Iseconds)"; printf '%s\n' "${ORDER[@]}"; } > "$ORDER_FILE"
    fi
    echo ""
    echo "=================== BLOC $K / $N_BLOCKS (graine de bloc $BLOCK_SEED) ==================="
    echo "Ordre des cellules : ${ORDER[*]}"

    n=${#ORDER[@]}
    mid=$(( n / 2 ))
    run_sentinels "$K" pre
    idx=0
    for cell in "${ORDER[@]}"; do
        idx=$((idx+1))
        IFS=, read -r protocol auth kemf profile loss delay total pairs extra <<< "${CELL_ROW[$cell]}"
        run_visit "$K" cell "$cell" "" "$protocol" "$auth" "$kemf" "$profile" "$loss" "$delay" "$total" "$pairs" "$extra"
        (( idx == mid )) && run_sentinels "$K" mid
    done
    run_sentinels "$K" post

    if [[ "$DRY_RUN" != "true" ]]; then
        nfail=$(awk -F, -v b="$K" '$2==b && $3!="blockstart" && $6!=0' "$STATE_FILE" | wc -l)
        echo "Bloc $K termine. Echecs journalises: $nfail (voir $STATE_FILE)."
    fi
done
echo ""
echo "✅ run_campaign termine (blocs ${B_FIRST}..${B_LAST})."
