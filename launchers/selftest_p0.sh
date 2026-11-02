#!/usr/bin/env bash
###############################################################################
# selftest_p0.sh — Verifie que les correctifs P0 fonctionnent AVANT la campagne.
#
#   bash launchers/selftest_p0.sh static    # sans Docker (< 1 min)
#   bash launchers/selftest_p0.sh docker    # smoke test reel (image requise, ~10 min, root/sudo docker)
#   bash launchers/selftest_p0.sh all
#
# A lancer depuis la RACINE du depot. Le mode docker ecrit uniquement dans des
# dossiers "__sentinel_smoke" (jamais melanges aux donnees de campagne) et les
# supprime a la fin.
###############################################################################
set -uo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

PASS=0; FAIL=0
ok()   { echo "  ✅ $*"; PASS=$((PASS+1)); }
bad()  { echo "  ❌ $*"; FAIL=$((FAIL+1)); }
check() { local name="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$name"; else bad "$name"; fi; }
# hasF <fichier> <motif litteral>... : vrai si TOUS les motifs (chaines fixes) sont dans le fichier
hasF() { local f="$1" p; shift; for p in "$@"; do grep -qF -- "$p" "$f" || return 1; done; }

LAUNCHER=Launcher_pq_mldsa_mlkem_hqc.sh
CLIENT=0-docker/scripts/perftestClientTlsQuic.sh
SERVER=0-docker/scripts/perftestServerTlsQuic.sh

###############################################################################
static_tests() {
echo "=== [S1] Syntaxe ==="
check "bash -n Launcher"            bash -n $LAUNCHER
check "bash -n run_campaign.sh"     bash -n launchers/run_campaign.sh
check "bash -n make_plans.sh"       bash -n launchers/make_plans.sh
check "dash -n perftestClient (sh)" dash -n $CLIENT
check "dash -n perftestServer (sh)" dash -n $SERVER
check "python logs_to_csv.py"       python3 -c "import ast;ast.parse(open('scripts_analysis/logs_to_csv.py').read())"

echo "=== [S2] Correctifs presents dans les sources ==="
check "TLS: horloge monotone, plus de gettimeofday actif" bash -c "! grep -v '^ *\\*\\|^/\\*' 0-docker/patches/s_connection_tls.c | grep -q 'gettimeofday(' && grep -q CLOCK_MONOTONIC 0-docker/patches/s_connection_tls.c"
check "QUIC client: horloge monotone"                    bash -c "! grep -v '^ *//' 0-docker/patches/s_connection_quic.c | grep -q 'gettimeofday(' && grep -q CLOCK_MONOTONIC 0-docker/patches/s_connection_quic.c"
check "QUIC serveur: attente passive (pause), plus de boucle for(;;){} active" bash -c "grep -q 'pause()' 0-docker/patches/s_server_quic.c && ! grep -Pzoq 'for \\(;;\\) \\{\\s*(//[^\\n]*\\s*)*\\}' 0-docker/patches/s_server_quic.c"
check "QUIC client: HandshakeIdleTimeoutMs fixe"         grep -q "Settings.HandshakeIdleTimeoutMs" 0-docker/patches/s_connection_quic.c
check "QUIC serveur: HandshakeIdleTimeoutMs fixe"        grep -q "Settings.HandshakeIdleTimeoutMs" 0-docker/patches/s_server_quic.c
check "TLS serveur: -num_tickets 0 sur les 4 invocations" bash -c "[ \$(grep 'openssl s_server' $SERVER | grep -c -- '-num_tickets 0') -eq 4 ] && [ \$(grep -c 'openssl s_server' $SERVER) -eq 4 ]"
check "Dockerfile: ethtool installe"                     grep -q "ethtool" 0-docker/Dockerfile
check "payload.bin = 100 octets"                         bash -c "[ \$(stat -c %s 0-docker/patches/payload.bin) -eq 100 ]"
check "QUIC SendBufferLength = 100 (client et serveur)"  bash -c "grep -q 'SendBufferLength = 100' 0-docker/patches/s_connection_quic.c && grep -q 'SendBufferLength = 100' 0-docker/patches/s_server_quic.c"
check "TLS APP_BODY_EXPECTED = 100"                      grep -q "define APP_BODY_EXPECTED 100" 0-docker/patches/s_connection_tls.c
check "Launcher: sysctl isolation TCP sur serveur ET client" bash -c "[ \$(grep -c 'TCP_SYSCTLS\[@\]+' $LAUNCHER) -eq 2 ] && grep -q 'tcp_no_metrics_save=1' $LAUNCHER && grep -q 'tcp_syn_retries=8' $LAUNCHER"
check "Launcher: isolation TCP verifiee apres demarrage (2 appels)" bash -c "[ \$(grep -c '^ *check_tcp_isolation \"' $LAUNCHER) -eq 2 ]"
check "Launcher: coupe aussi l'UDP GSO (tx-udp-segmentation) et le verifie" hasF $LAUNCHER 'for _f in tx-udp-segmentation' 'generic-receive-offload|tx-udp-segmentation'
check "Launcher: TCP_ISOLATE invalide refuse"            bash -c "! TCP_ISOLATE=2 PRINT_ORDER=1 bash $LAUNCHER both tls single nocapture none 0 0 20 1 1"
check "dash -n doCert.sh (sh)"                           dash -n 0-docker/scripts/doCert.sh
check "Dockerfile: UDP GSO MsQuic desactive au build (apply_no_udp_gso.sh)" bash -c "[ -f 0-docker/patches/apply_no_udp_gso.sh ] && grep -q 'apply_no_udp_gso.sh' 0-docker/Dockerfile && grep -q 'datapath_epoll.c' 0-docker/Dockerfile"
check "Launcher: CHAIN_DEPTH / CERT_PAD_* transmis a doCert.sh" hasF $LAUNCHER 'CHAIN_DEPTH=$CHAIN_DEPTH' 'CERT_PAD_BYTES=$CERT_PAD_BYTES' 'CERT_PAD_TARGET_DER=$CERT_PAD_TARGET_DER' 'cert_sizes['
check "Launcher: CHAIN_DEPTH=3 refuse"                    bash -c "! CHAIN_DEPTH=3 PRINT_ORDER=1 bash $LAUNCHER both tls single nocapture none 0 0 20 1 1"
check "Serveur TLS: -cert_chain (ICA.crt) sur les 4 invocations" bash -c "[ \$(grep 'openssl s_server' $SERVER | grep -c 'CHAIN_ARGS') -eq 4 ] && grep -q 'ICA.crt' $SERVER"
check "Client TLS: -verify effectif (set_verify + profondeur + return_error)" hasF 0-docker/patches/s_connection_tls.c 'SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER' 'SSL_CTX_set_verify_depth' 'verify_args.return_error = 1'
check "tcpdump lance sans LD_LIBRARY_PATH (client perftest + scripts de capture)" bash -c "grep -q 'env -u LD_LIBRARY_PATH tcpdump -i' $CLIENT && for f in launchers/capture_pcap_demo.sh launchers/capture_traffic_matrix.sh capture_pcap_demo.sh capture_traffic_matrix.sh; do [ -f \$f ] && { grep -q 'env -u LD_LIBRARY_PATH tcpdump -i' \$f || exit 1; }; done; true"
check "run_campaign: no_turbo=1 exige + reverifie par visite" hasF launchers/run_campaign.sh 'turbo_now()' 'ALLOW_TURBO' 'turbo reactive en cours de campagne'
check "run_campaign: anti-veille (systemd-inhibit) + detection de visite contaminee" hasF launchers/run_campaign.sh 'systemd-inhibit' 'suspend_total()' 'VISITE CONTAMINEE'
check "run_campaign + prepare_env: refus sur batterie (ac_state, ALLOW_BATTERY)" bash -c "grep -q 'ac_state()' launchers/run_campaign.sh && grep -q ALLOW_BATTERY launchers/run_campaign.sh && grep -q ALLOW_BATTERY launchers/prepare_env.sh"
check "run_campaign: debit 100 Mbit/s par defaut + sorties captures_v2" hasF launchers/run_campaign.sh 'RATE_MBIT="${RATE_MBIT-100}"' 'captures_v2'
check "Launcher: MICRO_BATCHES (tours, ordre re-tire, reprise par tour)" hasF $LAUNCHER 'pairs_for_round()' 'RUNS_PER_ROUND' 'c>=r'
check "Launcher: micro-lots dans le label du dossier (pas de collision M=1/M=5)" hasF $LAUNCHER '__mb${MICRO_BATCHES}'
check "QUIC: MTU de depart impose (QUIC_MTU -> MinimumMtu/MaximumMtu) client ET serveur" bash -c "for f in 0-docker/patches/s_connection_quic.c 0-docker/patches/s_server_quic.c; do grep -q 'Settings.IsSet.MinimumMtu' \$f && grep -q 'Settings.IsSet.MaximumMtu' \$f && grep -q 'getenv(\"QUIC_MTU\")' \$f || exit 1; done"
check "Launcher: QUIC_MTU_SYNC (label __qmtu, transmis aux 2 conteneurs)" bash -c "[ \$(grep -c 'QUIC_MTU=\${QUIC_MTU_EFF}' $LAUNCHER) -eq 2 ] && [ \"\$(PRINT_LABEL=1 QUIC_MTU_SYNC=1 bash $LAUNCHER both quic single nocapture simple 2 25 20 1 1 | tail -1)\" = simple_loss2_delay25ms__qmtu ]"
check "Launcher: PRINT_LABEL (label de cellule sans docker)" bash -c "[ \"\$(PRINT_LABEL=1 MICRO_BATCHES=2 bash $LAUNCHER both tls single nocapture simple 2 25 20 1 1 | tail -1)\" = simple_loss2_delay25ms__mb2 ]"
check "Launcher: QUIC_ENABLE_UDP_GSO transmis aux conteneurs" bash -c "[ \$(grep -c 'QUIC_ENABLE_UDP_GSO=' $LAUNCHER) -ge 2 ]"

echo "=== [S3] Parseur de reponse applicative TLS (test unitaire C) ==="
if command -v gcc >/dev/null 2>&1; then
  T=$(mktemp -d)
  awk '/^#define APP_BODY_EXPECTED/{p=1} p{print} /^static int app_response_status/{f=1} f&&/^}/{exit}' 0-docker/patches/s_connection_tls.c > "$T/fn.inc"
  cat > "$T/t.c" <<'EOF'
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "fn.inc"
int main(void){ char b[512]; size_t bl; int f=0; const char*H="HTTP/1.0 200 ok\r\nContent-type: text/plain\r\n\r\n"; size_t hl=strlen(H);
 memset(b,'A',100); f+= !(app_response_status(b,100,&bl)==1 && bl==100);
 f+= !(app_response_status(b,99,&bl)==0);
 memcpy(b,H,hl); memset(b+hl,'B',100); f+= !(app_response_status(b,hl+100,&bl)==1 && bl==100);
 f+= !(app_response_status(b,hl+99,&bl)==0); f+= !(app_response_status(b,hl,&bl)==0);
 const char*E="HTTP/1.0 404 Not Found\r\n\r\nerror"; f+= !(app_response_status(E,strlen(E),&bl)==-1);
 return f; }
EOF
  if gcc -o "$T/t" "$T/t.c" 2>/dev/null && "$T/t"; then ok "parseur reponse: raw/HTTP/tronque/404"; else bad "parseur reponse"; fi
  rm -rf "$T"
else echo "  (gcc absent : test C saute)"; fi

echo "=== [S4] Ordre randomise reproductible (Launcher, PRINT_ORDER) ==="
o() { PRINT_ORDER=1 bash $LAUNCHER both tls single nocapture none 0 0 20 "$1" "$2" 2>/dev/null | grep '|'; }
o 3 111 > /tmp/st_a.txt; o 3 111 > /tmp/st_b.txt; o 3 112 > /tmp/st_c.txt
check "42 paires par ordre"                         bash -c "[ \$(wc -l < /tmp/st_a.txt) -eq 42 ] && [ \$(sort -u /tmp/st_a.txt | wc -l) -eq 42 ]"
check "meme graine => meme ordre"                   cmp /tmp/st_a.txt /tmp/st_b.txt
check "graine differente => ordre different"        bash -c "! cmp -s /tmp/st_a.txt /tmp/st_c.txt"
check "decoupage 20x25 accepte"                     bash -c "PRINT_ORDER=1 bash $LAUNCHER both tls single nocapture none 0 0 20 1 1 2>&1 | grep -q '20 blocs de 25 runs'"
check "N_BLOCKS=7 refuse (ne divise pas 500)"       bash -c "! PRINT_ORDER=1 bash $LAUNCHER both tls single nocapture none 0 0 7 1 1"
check "BLOCK_INDEX hors bornes refuse"              bash -c "! PRINT_ORDER=1 bash $LAUNCHER both tls single nocapture none 0 0 20 21 1"
mb() { MICRO_BATCHES=5 PRINT_ROUND=$1 PRINT_ORDER=1 bash $LAUNCHER both tls single nocapture none 0 0 20 3 111 2>/dev/null | grep '|'; }
mb 1 > /tmp/st_m1.txt; mb 2 > /tmp/st_m2.txt; mb 2 > /tmp/st_m2b.txt; mb 3 > /tmp/st_m3.txt
check "micro-lots: tour 1 = ordre historique (M=1)"  cmp /tmp/st_a.txt /tmp/st_m1.txt
check "micro-lots: tour 2 reproductible"             cmp /tmp/st_m2.txt /tmp/st_m2b.txt
check "micro-lots: tours 1, 2, 3 tous differents"    bash -c "! cmp -s /tmp/st_m1.txt /tmp/st_m2.txt && ! cmp -s /tmp/st_m2.txt /tmp/st_m3.txt && ! cmp -s /tmp/st_m1.txt /tmp/st_m3.txt"
check "micro-lots: chaque tour = les 42 memes paires" bash -c "cmp -s <(sort /tmp/st_m2.txt) <(sort /tmp/st_a.txt)"
check "micro-lots: M=3 refuse (25 non divisible)"    bash -c "! MICRO_BATCHES=3 PRINT_ORDER=1 bash $LAUNCHER both tls single nocapture none 0 0 20 1 1"
check "micro-lots: M=0 refuse"                       bash -c "! MICRO_BATCHES=0 PRINT_ORDER=1 bash $LAUNCHER both tls single nocapture none 0 0 20 1 1"

echo "=== [S5] Plans et orchestrateur (dry-run) ==="
T=$(mktemp -d)
check "make_plans.sh genere 9 plans dont plan_all (avec SIZE_TARGET_DER)" bash -c "SIZE_TARGET_DER=9000 bash launchers/make_plans.sh $T | grep -c cellules | grep -q 9"
check "pilote: 10 cellules, dry-run --n-blocks 4 OK (25 connexions/bloc, M=5 -> 5/tour)" bash -c "[ \$(( \$(wc -l < $T/plan_pilot.csv) - 1 )) -eq 10 ] && bash launchers/run_campaign.sh --state-dir $T/csp --dry-run --master-seed 20261000 --n-blocks 4 --plan $T/plan_pilot.csv --block 1 2>&1 | grep -c '\\] cell ' | grep -q 10"
check "plan_main = 9 cellules terrain (sans pumba)"  bash -c "[ \$(( \$(wc -l < $T/plan_main.csv) - 1 )) -eq 9 ] && ! grep -qE 'stable|unstable' $T/plan_main.csv"
check "plan_legacy_pumba: RATE_MBIT= vide sur chaque cellule" bash -c "[ \$(grep -c 'RATE_MBIT=\$' $T/plan_legacy_pumba.csv) -eq 6 ]"
check "plans cibles: MICRO_BATCHES=2 sur chaque cellule" bash -c "for f in factorial_L3 direction_L3 mech_L3 chain_L3; do [ \$(tail -n +2 $T/plan_\$f.csv | grep -vc 'MICRO_BATCHES=2') -eq 0 ] || exit 1; done"
check "plan_sizectl: variante gonflee seule (ecdsa/mldsa65 viennent du plan mech), micro-lots" bash -c "[ \$(( \$(wc -l < $T/plan_sizectl_L3.csv) - 1 )) -eq 16 ] && [ \$(tail -n +2 $T/plan_sizectl_L3.csv | grep -vc 'CERT_PAD_TARGET_DER=9000;MICRO_BATCHES=2') -eq 0 ]"
check "plan_direction: pas de cellule s2c (doublon du plan factoriel)" bash -c "! grep -q 's2c' $T/plan_direction_L3.csv && [ \$(( \$(wc -l < $T/plan_direction_L3.csv) - 1 )) -eq 8 ]"
check "plan_all = fusion des 6 plans (137 cellules)" bash -c "[ \$(( \$(wc -l < $T/plan_all.csv) - 1 )) -eq 137 ]"
check "check_plan.py: plan_all sans collision de dossiers" python3 launchers/check_plan.py $T/plan_all.csv --launcher $LAUNCHER
check "check_plan.py: pilote et legacy sans collision" bash -c "python3 launchers/check_plan.py $T/plan_pilot.csv --launcher $LAUNCHER >/dev/null && python3 launchers/check_plan.py $T/plan_legacy_pumba.csv --launcher $LAUNCHER >/dev/null"
check "check_plan.py: une collision (doublon s2c) est REFUSEE" bash -c "{ cat $T/plan_all.csv; echo 'dir_tls_iid_s2c,tls,single,mlkem,simple,2,50,200,secp384r1|x448_mlkem768,LOSS_DIRECTION=s2c;MICRO_BATCHES=2'; } > $T/plan_bad.csv; ! python3 launchers/check_plan.py $T/plan_bad.csv --launcher $LAUNCHER >/dev/null"
check "plans mech/sizectl: QUIC_MTU_SYNC=1 sur chaque cellule QUIC, jamais sur TLS" bash -c "for f in mech_L3 sizectl_L3; do [ \$(grep -c '^[a-z]*_quic_' $T/plan_\$f.csv) -eq \$(grep '^[a-z]*_quic_' $T/plan_\$f.csv | grep -c QUIC_MTU_SYNC=1) ] && ! grep '^[a-z]*_tls_' $T/plan_\$f.csv | grep -q QUIC_MTU_SYNC || exit 1; done"
check "plan_chain: CHAIN_DEPTH=2 partout"            bash -c "[ \$(tail -n +2 $T/plan_chain_L3.csv | grep -vc 'CHAIN_DEPTH=2') -eq 0 ]"
D="bash launchers/run_campaign.sh --state-dir $T/cs --dry-run --master-seed 20261001"
check "plan_all: 137 cellules + 3 visites sentinelles par protocole planifiees" bash -c "o=\$($D --plan $T/plan_all.csv --block 1 2>&1); [ \$(grep -c '\\] cell ' <<< \"\$o\") -eq 137 ] && [ \$(grep -c 'sentinel sent_' <<< \"\$o\") -eq 6 ]"
$D --plan $T/plan_main.csv --block 1 2>&1 | grep '^Ordre' > $T/o1; $D --plan $T/plan_main.csv --block 1 2>&1 | grep '^Ordre' > $T/o1b; $D --plan $T/plan_main.csv --block 2 2>&1 | grep '^Ordre' > $T/o2
check "ordre des cellules reproductible (bloc 1)"   cmp $T/o1 $T/o1b
check "ordre des cellules independant entre blocs"  bash -c "! cmp -s $T/o1 $T/o2"
check "3 visites sentinelles par bloc (pre/mid/post)" bash -c "[ \$($D --plan $T/plan_main.csv --block 1 2>&1 | grep -c 'sentinel sent_tls') -eq 3 ]"
check "9 cellules du plan_main toutes planifiees"   bash -c "[ \$($D --plan $T/plan_main.csv --block 1 2>&1 | grep -c '\\] cell ') -eq 9 ]"
check "80 cellules factorielles planifiees"          bash -c "[ \$($D --plan $T/plan_factorial_L3.csv --block 1 2>&1 | grep -c '\\] cell ') -eq 80 ]"
check "sizectl/chain/mech/direction/legacy: dry-run OK" bash -c "for f in sizectl_L3 chain_L3 mech_L3 direction_L3 legacy_pumba; do $D --plan $T/plan_\$f.csv --block 1 >/dev/null 2>&1 || exit 1; done"
check "pumba sans RATE_MBIT= refuse (debit non controle)" bash -c "printf 'h\nx,tls,single,both,stable,0,0,500,,\n' > $T/pb.csv; ! $D --plan $T/pb.csv --block 1"
check "run_campaign: MICRO_BATCHES transmis via extra_env" bash -c "$D --plan $T/plan_chain_L3.csv --block 1 2>&1 | grep -q 'MICRO_BATCHES=2'"
check "QUIC mutual refuse dans un plan"             bash -c "printf 'h\nx,quic,mutual,both,none,0,0,500,,\n' > $T/bad.csv; ! $D --plan $T/bad.csv --block 1"
rm -rf "$T"

echo "=== [S6] Client perftest avec faux binaires (warm-up, NaN, timeout) + logs_to_csv ==="
M=$(mktemp -d); mkdir -p "$M/bin" "$M/h"
printf '#!/bin/sh\nexit 0\n' > "$M/bin/tc"
cat > "$M/bin/openssl" <<'EOF'
#!/bin/sh
case "$MOCK_MODE" in
  ok)   echo "App-bytes: 100"; echo "Handshake duration: 12.50 ms"; echo "App-ready duration: 25.10 ms";;
  fail) exit 1;;
  hang) sleep 30;;
esac
EOF
cp "$M/bin/openssl" "$M/bin/quics_connection"; chmod +x "$M/bin/"*
runc() { MOCK_MODE=$1 PATH="$M/bin:$PATH" USE_TLS=$2 NUM_RUNS=$3 WARMUP_RUNS=$4 HANDSHAKE_TIMEOUT_S=${5:-150} CERT_PATH=/tmp KEM_ALG=k SIG_ALG=s MUTUAL=false DOCKER_HOST=h sh $CLIENT 2>&1; }
runc ok   true 3 2 > "$M/ok.log";   runc fail true 2 0 > "$M/fail.log";   runc hang false 1 0 2 > "$M/hang.log"
check "warm-up jete (3 Execution, pas 5)"           bash -c "[ \$(grep -c '^Execution' $M/ok.log) -eq 3 ]"
check "1 Handshake + 1 App-ready par execution"     bash -c "[ \$(grep -c 'Handshake duration' $M/ok.log) -eq 3 ] && [ \$(grep -c 'App-ready duration' $M/ok.log) -eq 3 ]"
check "echec sans sortie => 2 marqueurs NaN"        bash -c "[ \$(grep -c 'NaN' $M/fail.log) -eq 4 ]"
check "timeout 2 s => NaN 'client-side timeout'"    grep -q "client-side timeout after 2s" "$M/hang.log"
cp "$M/ok.log"   "$M/h/handshake_tls_single_s_k_none_block1of20.log"
cp "$M/fail.log" "$M/h/handshake_tls_single_s_k_none_block2of20.log"
cp "$M/ok.log" "$M/h/handshake_tls_single_s_k_none__mb5_block3of20_mb2of5.log"
python3 scripts_analysis/logs_to_csv.py "$M/h" > /dev/null 2>&1
check "CSV: colonnes app_ready_ms/app_success/app_bytes" grep -q "app_ready_ms,app_success,app_bytes" "$M/csv/handshake_tls_single_s_k_none_block1of20.csv"
check "CSV: succes -> app_success=1, app_bytes=100" grep -q "^1,TLS Single,12.5,1,1,20,25.1,1,100" "$M/csv/handshake_tls_single_s_k_none_block1of20.csv"
check "CSV: echec -> app_success=0"                 grep -q "^1,TLS Single,NaN,0,2,20,NaN,0," "$M/csv/handshake_tls_single_s_k_none_block2of20.csv"
check "CSV: micro-lots -> bloc 3/20, tour 2/5 (suffixe _mbRofM reconnu)" grep -q "^1,TLS Single,12.5,1,3,20,25.1,1,100,2,5" "$M/csv/handshake_tls_single_s_k_none__mb5_block3of20_mb2of5.csv"
check "analyze_mechanism.py --selftest (labels/chemins/qdisc avec micro-lots)" bash -c "f=\$(find . -name analyze_mechanism.py -not -path './captures*' | head -1); [ -n \"\$f\" ] && python3 \"\$f\" --selftest"
rm -rf "$M"

echo "=== [S7] Scripts de capture harmonises avec la campagne (critique 4) ==="
for name in capture_pcap_demo.sh capture_traffic_matrix.sh; do
  P=$(ls "$name" "launchers/$name" 2>/dev/null | head -1)
  if [[ -z "$P" ]]; then bad "$name introuvable (racine ou launchers/)"; continue; fi
  check "bash -n $name"                              bash -n "$P"
  check "$name: client TLS = s_connection -www /payload.bin" bash -c "grep -v '^ *#' '$P' | grep -q 's_connection' && grep -v '^ *#' '$P' | grep -q -- '-www /payload.bin'"
  check "$name: plus de openssl s_client"            bash -c "! grep -v '^ *#' '$P' | grep -q 's_client'"
  check "$name: tcpdump filtre 'port 4433' + -U"     bash -c "grep -v '^ *#' '$P' | grep 'tcpdump -i' | grep -q \"port 4433\" && grep -v '^ *#' '$P' | grep 'tcpdump -i' | grep -q -- ' -U '"
  check "$name: MTU + offloads + isolation TCP"      bash -c "grep -q 'ethtool -K' '$P' && grep -q 'ip link set dev' '$P' && grep -q 'tcp_no_metrics_save=1' '$P'"
  check "$name: keylog TLS cote serveur (SSL_DIR)"   bash -c "grep -q 'SSL_DIR=/tmp' '$P'"
  check "$name: critere de succes App-ready/App-bytes" bash -c "grep -q 'App-ready duration' '$P' && grep -q 'App-bytes' '$P'"
  check "$name: UDP GSO coupe + garde trames > MTU"  hasF "$P" 'tx-udp-segmentation' 'greater $((MTU + 15))' 'oversize_frames'
done
P=$(ls capture_pcap_demo.sh launchers/capture_pcap_demo.sh 2>/dev/null | head -1)
[[ -n "$P" ]] && check "capture_pcap_demo.sh: netem jamais avale (pas de '|| true')" bash -c "! grep -E 'tc qdisc add.*\\|\\| true' '$P'"
}

###############################################################################
docker_tests() {
command -v docker >/dev/null 2>&1 || { echo "docker introuvable"; return 1; }
docker image inspect uma-tls-quic-pq-34 >/dev/null 2>&1 || { echo "Image uma-tls-quic-pq-34 absente : docker build -t uma-tls-quic-pq-34 -f 0-docker/Dockerfile 0-docker/"; return 1; }
rm -rf captures/*/*/*__sentinel_smoke* 2>/dev/null || true    # reliquats d'un test interrompu
export VISIT_TAG=smoke ONLY_PAIRS="mldsa65|x448_mlkem768" WARMUP_RUNS=2 OFFLOAD_OFF=1 HANDSHAKE_TIMEOUT_S=150
PAIR="mldsa65_x448_mlkem768"

logf() { echo "captures/$1/single/$2__sentinel_smoke/handshake_logs/handshake_$1_single_${PAIR}_$2__sentinel_smoke_block1of2.log"; }

echo "=== [D1] Reseau ideal : TLS et QUIC, 5 mesures + 2 warm-up ==="
for proto in tls quic; do
  TOTAL_RUNS=10 bash $LAUNCHER mlkem $proto single nocapture none 0 0 2 1 4242 > /tmp/smoke_$proto.out 2>&1
  L=$(logf $proto none)
  if [[ ! -f "$L" ]]; then bad "$proto: log introuvable ($L) -- voir /tmp/smoke_$proto.out"; continue; fi
  check "$proto: 5 executions (warm-up exclu)"         bash -c "[ \$(grep -c '^Execution' '$L') -eq 5 ]"
  check "$proto: 5 Handshake + 5 App-ready"            bash -c "[ \$(grep -c 'Handshake duration' '$L') -eq 5 ] && [ \$(grep -c 'App-ready duration' '$L') -eq 5 ]"
  check "$proto: aucun NaN en reseau ideal"            bash -c "! grep -q NaN '$L'"
  check "$proto: App-bytes = 100 sur les 5 executions" bash -c "[ \$(grep -c '^App-bytes: 100\$' '$L') -eq 5 ]"
  # Relation attendue : App-ready >= Handshake natif, execution par execution.
  rel=$(LC_ALL=C awk '/^Execution/{n++} /Handshake duration: [0-9]/{h[n]=$3} /App-ready duration: [0-9]/{a[n]=$3} END{ok=0; for(i=1;i<=n;i++){ if(a[i]>=h[i]) ok++; g=g sprintf(" %.2f",a[i]-h[i]) } printf "%d/%d|%s", ok, n, g}' "$L")
  [[ "${rel%%|*}" == "5/5" ]] && ok "$proto: App-ready >= Handshake sur 5/5 (ecarts ms:${rel#*|})" || bad "$proto: App-ready >= Handshake seulement ${rel%%|*} (ecarts ms:${rel#*|})"
  M=$(ls captures/$proto/single/none__sentinel_smoke/block_manifest_*.log | head -1)
  check "$proto: manifeste journalise offloads OFF"    bash -c "grep -E 'offload\\[.*(tcp-segmentation-offload: off|generic-segmentation-offload: off)' '$M' | grep -q ."
  check "$proto: aucun offload UDP actif (manifeste)"  bash -c "grep 'offload\[' '$M' | grep -q 'tx-udp-segmentation' && ! grep 'offload\[' '$M' | grep -E '(tx-udp-segmentation|rx-udp-gro-forwarding|rx-gro-list): on(\$| [^[])'"
  check "$proto: manifeste journalise warm-up/timeout" bash -c "grep -q 'warmup_runs=2 handshake_timeout_s=150' '$M'"
  check "$proto: voisinage ARP permanent journalise"   bash -c "grep -q 'neighbors\\[pair=.*=permanent' '$M'"
  check "$proto: isolation TCP active (serveur+client)" bash -c "[ \$(grep -c 'tcp_isolation\\[.*no_metrics_save=1 syn_retries=8' '$M') -eq 2 ]"
  check "$proto: cache tcp_metrics vide apres la paire" bash -c "[ \$(grep 'tcp_metrics_entries' '$M' | grep -vc '=0\$') -eq 0 ]"
  python3 scripts_analysis/logs_to_csv.py "captures/$proto/single/none__sentinel_smoke/handshake_logs" >/dev/null 2>&1
done

echo "=== [D2] Perte 5 %, RTT 50 ms : succes + perte effective ==="
for proto in tls quic; do
  TOTAL_RUNS=20 bash $LAUNCHER mlkem $proto single nocapture simple 5 25 2 1 4243 > /tmp/smoke_loss_$proto.out 2>&1
  L=$(logf $proto simple_loss5_delay25ms)
  if [[ ! -f "$L" ]]; then bad "$proto loss: log introuvable"; continue; fi
  napp=$(grep -c 'App-ready duration: [0-9]' "$L")
  [[ $napp -ge 8 ]] && ok "$proto loss5: $napp/10 App-ready reussis" || bad "$proto loss5: seulement $napp/10 App-ready"
  Q=$(ls captures/$proto/single/simple_loss5_delay25ms__sentinel_smoke/qdisc_stats_*.csv 2>/dev/null | head -1)
  [[ -n "$Q" ]] && echo "     perte effective serveur (attendu ~5 %, bruite sur peu de paquets) : $(grep server_egress "$Q" | awk -F, '{print $NF}') %"
done

echo "=== [D3] Politique d'echec commune : perte 100 %, budget 10 s ==="
for proto in tls quic; do
  HANDSHAKE_TIMEOUT_S=10 WARMUP_RUNS=0 TOTAL_RUNS=2 bash $LAUNCHER mlkem $proto single nocapture simple 100 0 2 1 4244 > /tmp/smoke_to_$proto.out 2>&1
  L=$(logf $proto simple_loss100_delay0ms)
  if [[ ! -f "$L" ]]; then bad "$proto timeout: log introuvable"; continue; fi
  check "$proto: pas d'echec L2 ('No route to host')"      bash -c "! grep -q 'No route to host' '$L'"
  check "$proto: Handshake NaN + App-ready NaN (timeout 10 s)" bash -c "grep -q 'Handshake duration: NaN.*timeout after 10s' '$L' && grep -q 'App-ready duration: NaN.*timeout after 10s' '$L'"
done

echo "=== [D4] Verification TLS client EFFECTIVE : bonne CA => succes, mauvaise CA => echec ==="
d4=$(docker run --rm --cap-add=NET_ADMIN -e CERT_PATH=/tmp/c1/ -e SIG_ALG=mldsa65 -e KEM_ALG=x448_mlkem768 \
      -e DEFAULT_GROUPS=x448_mlkem768 -e USE_TLS=true -e MUTUAL=false uma-tls-quic-pq-34 sh -c '
        mkdir -p /tmp/c1 /tmp/c2
        doCert.sh >/dev/null 2>&1
        CERT_PATH=/tmp/c2/ doCert.sh >/dev/null 2>&1
        perftestServerTlsQuic.sh >/tmp/s.log 2>&1 &
        sleep 4
        echo "GOOD_BEGIN"; openssl s_connection -connect localhost:4433 -new -verify 1 -CAfile /tmp/c1/CA.crt -www /payload.bin 2>&1; echo "GOOD_END"
        echo "BAD_BEGIN";  openssl s_connection -connect localhost:4433 -new -verify 1 -CAfile /tmp/c2/CA.crt -www /payload.bin 2>&1; echo "BAD_END"' 2>&1)
good=$(sed -n '/GOOD_BEGIN/,/GOOD_END/p' <<< "$d4"); bad=$(sed -n '/BAD_BEGIN/,/BAD_END/p' <<< "$d4")
grep -q 'App-ready duration: [0-9]' <<< "$good" && ok "TLS: bonne CA => App-ready numerique" || bad "TLS: bonne CA refusee a tort"
if grep -q 'Handshake duration: [0-9]' <<< "$bad"; then bad "TLS: MAUVAISE CA acceptee (verification non effective)"; else ok "TLS: mauvaise CA => handshake refuse"; fi

echo "=== [D5] tcpdump utilisable dans l'image (sans LD_LIBRARY_PATH) ==="
t5=$(docker run --rm uma-tls-quic-pq-34 sh -c 'env -u LD_LIBRARY_PATH tcpdump --version 2>&1 | head -1')
grep -q 'tcpdump version' <<< "$t5" && ok "tcpdump demarre : $t5" || bad "tcpdump inutilisable dans l'image : $t5"

echo "=== nettoyage des dossiers __sentinel_smoke ==="
rm -rf captures/*/*/*__sentinel_smoke* 2>/dev/null || true
}

###############################################################################
case "${1:-static}" in
  static) static_tests ;;
  docker) docker_tests ;;
  all)    static_tests; docker_tests ;;
  *) echo "usage: $0 [static|docker|all]"; exit 1 ;;
esac
echo ""
echo "================ RESULTAT : $PASS OK, $FAIL ECHEC(S) ================"
[[ $FAIL -eq 0 ]]
