#!/usr/bin/env python3
"""diag_netem_tcp_udp.py -- test ISOLE (sans OpenSSL ni MsQuic) : la perte realisee par netem depend-elle
du protocole (TCP vs UDP) et du nombre de paquets par connexion ?

Montage : 2 espaces de noms reseau relies par une paire veth ; netem (delay + loss + rate + limit) sur la sortie du
"serveur" (ns pqa), delay + rate sur la sortie du "client" (ns pqb), comme dans le Launcher ; TSO/GSO/GRO coupes.
Le serveur envoie SIZE octets par connexion (TCP) ou en datagrammes de 1200 o (UDP). Compteurs lus avec `tc -s`.

USAGE (root) :   sudo python3 diag_netem_tcp_udp.py            # monte, mesure, demonte
Variables : LOSS=5 DELAY=25 N=300 (connexions par taille) SIZES=1500,10000,30000,100000
            GSO_MAX_SEGS=1  (optionnel : plafonne a 1 segment la taille des super-paquets emis par la pile TCP)
"""
import os, re, socket, subprocess, sys, time

LOSS = float(os.environ.get("LOSS", 5)); DELAY = os.environ.get("DELAY", "25"); N = int(os.environ.get("N", 300))
SIZES = [int(x) for x in os.environ.get("SIZES", "1500,10000,30000,100000").split(",")]
GSO_MAX_SEGS = os.environ.get("GSO_MAX_SEGS", "")
A, B, VA, VB = "pqa", "pqb", "va", "vb"; IPA, IPB, PORT = "10.9.0.1", "10.9.0.2", 5000


def sh(cmd, check=True):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and r.returncode:
        print(f"[ERREUR] {cmd}\n{r.stderr}", file=sys.stderr); sys.exit(1)
    return r.stdout


def counters(ns, dev):
    t = sh(f"ip netns exec {ns} tc -s qdisc show dev {dev}")
    m = re.search(r"Sent (\d+) bytes (\d+) pkt \(dropped (\d+)", t)
    return int(m.group(2)), int(m.group(3))   # paquets envoyes (hors pertes), pertes


def setup():
    teardown()
    for ns in (A, B): sh(f"ip netns add {ns}")
    sh(f"ip link add {VA} type veth peer name {VB}")
    sh(f"ip link set {VA} netns {A}"); sh(f"ip link set {VB} netns {B}")
    for ns, dev, ip in ((A, VA, IPA), (B, VB, IPB)):
        sh(f"ip -n {ns} addr add {ip}/24 dev {dev}"); sh(f"ip -n {ns} link set {dev} up"); sh(f"ip -n {ns} link set lo up")
        sh(f"ip netns exec {ns} ethtool -K {dev} tso off gso off gro off tx-udp-segmentation off", check=False)
        if GSO_MAX_SEGS:
            sh(f"ip -n {ns} link set dev {dev} gso_max_segs {GSO_MAX_SEGS}")
        print(f"[{ns}] limites GSO :", " ".join(re.findall(r"(?:gso_max_size|gso_max_segs|tso_max_size|tso_max_segs) \d+", sh(f"ip -n {ns} -d link show dev {dev}"))))
        print(f"[{ns}] offloads :", " ".join(sh(f"ip netns exec {ns} ethtool -k {dev} | grep -E '^(tcp-segmentation|generic-segmentation|generic-receive|tx-udp-segmentation)'", check=False).split()))
    sh(f"ip netns exec {A} tc qdisc add dev {VA} root netem limit 1000 delay {DELAY}ms loss {LOSS}% rate 100Mbit")
    sh(f"ip netns exec {B} tc qdisc add dev {VB} root netem limit 1000 delay {DELAY}ms rate 100Mbit")
    time.sleep(1)


def teardown():
    for ns in (A, B): sh(f"ip netns del {ns}", check=False)


def serve():   # dans le ns A : repond a chaque requete par SIZE octets
    ts = socket.socket(); ts.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); ts.bind((IPA, PORT)); ts.listen(256)
    us = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); us.bind((IPA, PORT))
    import threading
    def tcp_loop():
        while True:
            c, _ = ts.accept(); n = int(c.recv(16).decode() or 0); c.sendall(b"x" * n); c.close()
    threading.Thread(target=tcp_loop, daemon=True).start()
    while True:
        d, addr = us.recvfrom(64); n = int(d.decode())
        for _ in range(-(-n // 1200)): us.sendto(b"x" * 1200, addr)


def client(proto, size, n):   # dans le ns B
    ok = 0
    for _ in range(n):
        try:
            if proto == "tcp":
                s = socket.create_connection((IPA, PORT), timeout=15); s.sendall(str(size).encode()); got = 0
                while got < size:
                    b = s.recv(65536)
                    if not b: break
                    got += len(b)
                s.close(); ok += got >= size
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(0.5); s.sendto(str(size).encode(), (IPA, PORT))
                try:
                    while True: s.recv(2000)
                except socket.timeout: pass
                s.close(); ok += 1
        except Exception: pass
    return ok


def main():
    if os.geteuid(): sys.exit("a lancer avec sudo")
    setup()
    srv = subprocess.Popen(["ip", "netns", "exec", A, sys.executable, __file__, "serve"]); time.sleep(1)
    print(f"\nnominal {LOSS}% | delay {DELAY} ms/sens | N={N} | GSO_MAX_SEGS={GSO_MAX_SEGS or 'defaut'}\n{'proto':5s} {'octets':>7s} {'pkts_serveur/conn':>18s} {'perte reelle %':>15s} {'rapport/nominal':>16s}")
    try:
        for proto in ("tcp", "udp"):
            for size in SIZES:
                p0, d0 = counters(A, VA)
                subprocess.run(["ip", "netns", "exec", B, sys.executable, __file__, "client", proto, str(size), str(N)], check=True)
                time.sleep(2); p1, d1 = counters(A, VA); P, D = p1 - p0, d1 - d0
                print(f"{proto:5s} {size:7d} {(P + D) / N:18.1f} {100 * D / max(P + D, 1):15.3f} {100 * D / max(P + D, 1) / LOSS:16.3f}", flush=True)
    finally:
        srv.terminate(); teardown()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "serve": serve()
    elif len(sys.argv) > 1 and sys.argv[1] == "client": client(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]))
    else: main()
