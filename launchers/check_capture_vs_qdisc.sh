#!/usr/bin/env bash
###############################################################################
# check_capture_vs_qdisc.sh — Compare ce que netem COMPTE (qdisc) a ce que le
# client RECOIT reellement (pcap), pour 100 connexions sous perte.
#
#   bash launchers/check_capture_vs_qdisc.sh quic [loss_pct=5] [delay_ms=25]
#   bash launchers/check_capture_vs_qdisc.sh tls
#
# Les captures sont CONSERVEES dans captures/<proto>/single/*__sentinel_capchk
# (supprimez-les vous-meme a la fin : rm -rf captures/*/*/*__sentinel_capchk*).
# Necessite tshark. A lancer depuis n'importe ou (se replace a la racine).
###############################################################################
set -uo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

proto="${1:?usage: $0 <tls|quic> [loss_pct] [delay_ms]}"
loss="${2:-5}"
delay="${3:-25}"
[[ "$proto" == "tls" || "$proto" == "quic" ]] || { echo "protocole: tls|quic"; exit 1; }
command -v tshark >/dev/null 2>&1 || { echo "tshark introuvable"; exit 1; }

export VISIT_TAG=capchk ONLY_PAIRS="mldsa65|x448_mlkem768" WARMUP_RUNS=0 OFFLOAD_OFF=1 PER_CONN_PCAP=1
rm -rf captures/"$proto"/single/*__sentinel_capchk* 2>/dev/null
echo ">> $proto : 100 connexions, perte ${loss} %, delai ${delay} ms/sens (environ 2-4 min)..."
TOTAL_RUNS=200 bash Launcher_pq_mldsa_mlkem_hqc.sh mlkem "$proto" single nocapture simple "$loss" "$delay" 2 1 78 \
    > "/tmp/capchk_${proto}.out" 2>&1 || echo "[!] le Launcher a retourne une erreur (voir /tmp/capchk_${proto}.out)"

D=$(ls -d captures/"$proto"/single/*__pcap__sentinel_capchk 2>/dev/null | head -1)
[[ -n "$D" ]] || { echo "dossier de capture introuvable (voir /tmp/capchk_${proto}.out)"; exit 1; }
P=$(ls "$D"/pcap_perconn/block1of2/*/block.pcap 2>/dev/null | head -1)
[[ -f "$P" ]] || { echo "block.pcap introuvable dans $D"; exit 1; }
PD=$(dirname "$P")
SRV=$(grep -o 'srv=[0-9.]*' "$D"/block_manifest_*.log | head -1 | cut -d= -f2)
[[ -n "$SRV" ]] || { echo "IP serveur introuvable dans le manifeste"; exit 1; }
if [[ "$proto" == "quic" ]]; then L4="udp.port==4433"; else L4="tcp.port==4433"; fi

NCONN=$(( $(wc -l < "$PD/conn_windows.csv") - 1 ))
S2C=$(tshark -r "$P" -Y "$L4 && ip.src==$SRV" 2>/dev/null | wc -l)
C2S=$(tshark -r "$P" -Y "$L4 && ip.dst==$SRV" 2>/dev/null | wc -l)
TOT=$(tshark -r "$P" 2>/dev/null | wc -l)
read -r SSENT SDROP CSENT CDROP < <(LC_ALL=C awk -F, '$7=="server_egress"{s=$10;d=$11} $7=="client_egress"{cs=$10;cd=$11} END{print s,d,cs,cd}' "$D"/qdisc_stats_*.csv)

echo ""
echo "================ $proto : bilan ================"
echo "connexions (conn_windows)                    : $NCONN"
echo "pcap : frames serveur->client / client->serveur : $S2C / $C2S   (total pcap: $TOT)"
echo "qdisc: serveur 'Sent' (survivants) + perdus   : $SSENT + $SDROP"
echo "qdisc: client  'Sent' + perdus                : $CSENT + $CDROP"
LC_ALL=C awk -v s2c="$S2C" -v ssent="$SSENT" -v sdrop="$SDROP" -v c2s="$C2S" -v csent="$CSENT" 'BEGIN{
  printf "ratio pcap s->c / qdisc serveur Sent          : %.3f   (attendu ~1.00 si compteurs et capture fiables)\n", s2c/ssent;
  printf "ratio pcap c->s / qdisc client  Sent          : %.3f   (attendu ~1.00 : aucune perte cote client)\n", c2s/csent;
  printf "perte effective officielle  drop/(Sent+drop)  : %.2f %%\n", 100*sdrop/(ssent+sdrop);
  printf "perte si Sent etait compte 2 fois (hyp. A)    : %.2f %%\n", 100*sdrop/(ssent/2+sdrop);
  printf "perte vue par le client  1 - recus/(recus+drop): %.2f %%\n", 100*sdrop/(s2c+sdrop);
}'
echo ""
echo "--- tcpdump (paquets perdus par le noyau ?) ---"
grep -E "packets (captured|received by filter|dropped by kernel)" "$PD/tcpdump.err" 2>/dev/null || echo "(tcpdump.err absent)"
echo ""
echo "--- Taille des frames serveur->client (detecte un regroupement GRO/GSO) ---"
tshark -r "$P" -Y "$L4 && ip.src==$SRV" -T fields -e frame.len 2>/dev/null | LC_ALL=C awk '
  {n++; if($1>m)m=$1; if($1<=1300)a++; else if($1<=1514)b++; else c++; s+=$1}
  END{printf "frames=%d  moyenne=%.0f o  max=%d o  [<=1300: %d | 1301-1514: %d | >1514: %d]\n", n, s/n, m, a, b, c}'
echo ""
echo "Lecture :"
echo "  - ratio s->c ~0.5 ET ratio c->s ~1.0 : le compteur 'Sent' du serveur compte ~2x (hyp. A)  => perte reelle = ligne 'hyp. A'."
echo "  - ratio s->c ~0.5 ET ratio c->s ~0.5 : la capture pcap perd/regroupe la moitie des frames (verifier 'dropped by kernel' et frames > 1514)."
echo "  - frames > 1514 nombreuses : regroupement GRO cote client (les frames recues ne sont plus 1 datagramme)."
echo "  - ratios ~1.0 : pas de probleme de comptage ; l'ecart a 5 % est du hasard d'echantillonnage."
