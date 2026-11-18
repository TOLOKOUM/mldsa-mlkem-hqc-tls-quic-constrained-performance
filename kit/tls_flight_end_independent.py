#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tls_flight_end_independent.py -- fin de vol serveur TLS determinee SANS taille predite (revue du 15/11/2026, point 3).

Delimiteur independant : le vol serveur (ServerHello..Finished) se termine quand le client envoie le premier segment portant des donnees apres le debut du vol
(ClientHello = 1er (eventuellement en plusieurs segments) ; Finished client = 1er segment client portant des donnees apres le debut du vol serveur). Octets serveur du vol = somme des octets TCP de charge
utile (sans retransmissions : seq deja vue) emis par le serveur avant ce segment. Premiere ronde = octets serveur avant le premier
segment client suivant la premiere donnee serveur (ACK pur compris).
Sorties : <out>.csv (une ligne par flux) ; avec --pred F : ecart au F predit. Necessite tshark. Pas besoin de cles TLS.
Usage : python3 tls_flight_end_independent.py --pcap block.pcap --port 4433 --out flights [--pred 13165]
"""
import argparse, csv, subprocess, sys, collections

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True); ap.add_argument("--port", type=int, default=4433)
    ap.add_argument("--out", required=True); ap.add_argument("--pred", type=int, default=None)
    a = ap.parse_args()
    cmd = ["tshark", "-r", a.pcap, "-Y", "tcp.port==%d" % a.port, "-T", "fields", "-E", "separator=,",
           "-e", "tcp.stream", "-e", "frame.time_epoch", "-e", "tcp.srcport", "-e", "tcp.len", "-e", "tcp.seq_raw"]
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode: sys.exit(p.stderr)
    fl = collections.defaultdict(list)
    for ln in p.stdout.splitlines():
        s, t, sp, ln_, seq = ln.split(",")
        fl[int(s)].append((float(t), int(sp), int(ln_ or 0), int(seq)))
    rows = []
    for s, L in sorted(fl.items()):
        L.sort(); cdata = [x for x in L if x[1] != a.port and x[2] > 0]
        sdata = [x for x in L if x[1] == a.port and x[2] > 0]
        if not sdata: continue
        t_first_srv = sdata[0][0]
        after = [x for x in cdata if x[0] > t_first_srv]          # le ClientHello peut tenir en plusieurs segments : on prend le 1er segment client APRES le debut du vol
        if not after: continue
        t_end = after[0][0]
        seen = set(); flight = 0; first = 0; t_first_srv = None; round1_closed = False
        for t, sp, n, seq in L:
            if sp == a.port and n > 0 and seq not in seen:
                seen.add(seq)
                if t_first_srv is None: t_first_srv = t
                if t < t_end: flight += n
                if not round1_closed: first += n
            elif sp != a.port and t_first_srv is not None and t > t_first_srv:
                round1_closed = True
        rows.append(dict(stream=s, flight_bytes=flight, first_round_bytes=first, extra_round=int(flight > first),
                         diff_to_pred=(flight - a.pred) if a.pred else ""))
    with open(a.out + ".csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()) if rows else ["stream"]); w.writeheader(); w.writerows(rows)
    print("flux : %d" % len(rows))
    for r in rows[:10]: print(r)

if __name__ == "__main__":
    main()
