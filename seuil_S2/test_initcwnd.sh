#!/usr/bin/env bash
# Test isole (hors campagne) de l'intervention INIT_CWND : un conteneur jetable, meme image et meme reseau que le banc.
# Verifie (1) que `ip route change ... initcwnd N` est accepte, (2) que la route le porte, (3) si python3 est present dans l'image,
# que le cwnd d'une vraie connexion TCP sortant du serveur est N (lu par `ss -ti`).
# Usage : bash seuil_S2/test_initcwnd.sh [IMAGE] [N]      (defauts : uma-tls-quic-pq-34-v3, 4)
set -u
IMG="${1:-uma-tls-quic-pq-34-v3}"; N="${2:-4}"
NET=localNet
SRV=t_iw_srv; CLI=t_iw_cli
cleanup() { docker rm -f "$SRV" "$CLI" >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET" >/dev/null
cleanup
docker run -d --name "$SRV" --cap-add=NET_ADMIN --network "$NET" --entrypoint sleep "$IMG" 300 >/dev/null || { echo "ECHEC: demarrage serveur"; exit 1; }
docker run -d --name "$CLI" --cap-add=NET_ADMIN --network "$NET" --entrypoint sleep "$IMG" 300 >/dev/null || { echo "ECHEC: demarrage client"; exit 1; }
sleep 1
line=$(docker exec "$SRV" ip -4 route show dev eth0 scope link proto kernel | head -1)
echo "route avant : $line"
prefix=$(awk '{print $1}' <<< "$line"); src=$(awk '{for(i=1;i<NF;i++) if($i=="src") print $(i+1)}' <<< "$line")
[[ -n "$prefix" && -n "$src" ]] || { echo "ECHEC: route du reseau connecte introuvable"; exit 1; }
docker exec "$SRV" ip route change "$prefix" dev eth0 proto kernel scope link src "$src" initcwnd "$N" || { echo "ECHEC: ip route change refuse"; exit 1; }
after=$(docker exec "$SRV" ip -4 route show "$prefix" dev eth0 | head -1)
echo "route apres : $after"
grep -qE "initcwnd[[:space:]]+${N}([[:space:]]|\$)" <<< "$after" && echo "OK (1,2): route portant initcwnd $N" || { echo "ECHEC: initcwnd $N non porte par la route"; exit 1; }
if docker exec "$SRV" sh -c 'command -v python3 >/dev/null && command -v ss >/dev/null'; then
  SIP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$SRV")
  docker exec -d "$SRV" python3 -c "
import socket,time
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(('0.0.0.0',9999)); s.listen(1)
c,_=s.accept(); c.sendall(b'x'*200000); time.sleep(8)"
  sleep 1
  docker exec "$CLI" python3 -c "
import socket,time
c=socket.create_connection(('$SIP',9999)); time.sleep(6)" &
  sleep 2
  echo "ss -ti cote serveur (premiere ligne cwnd) :"
  docker exec "$SRV" ss -tin state established '( sport = :9999 )' | grep -o 'cwnd:[0-9]*' | head -1
  echo "(le cwnd lu apres quelques ACK peut depasser N ; la verification qui fait foi pour la campagne est la phase 0 : segments de la 1re ronde dans le pcap)"
  wait
else
  echo "(python3 ou ss absent de l'image : etape 3 sautee ; la phase 0 verifie l'effet par pcap)"
fi
echo "TEST TERMINE"
