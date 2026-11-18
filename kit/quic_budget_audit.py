#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""quic_budget_audit.py -- chronologie du budget d'anti-amplification d'un serveur QUIC, flux par flux (revue du 15/11/2026, point 1).

Pour chaque flux UDP d'une capture (port 4433), reconstruit cote serveur :
  * B_c  = octets UDP recus du client avant le premier datagramme du serveur ; allocation A0 = 3 x B_c (RFC 9000 s.8.1 ; MsQuic : connection.c) ;
  * pour chaque datagramme serveur de la premiere ronde (avant le premier datagramme client suivant) : taille UDP, paquets QUIC
    (type, longueur, trames), paquet sollicitant un ACK ou non, octets DEBITES selon MsQuic (somme des longueurs des SEULS paquets
    sollicitant un ACK, loss_detection.c) et budget restant ;
  * resume : octets envoyes, octets debites, octets non debites (ACK seul), derniere taille de datagramme, budget restant, et les
    deux verifications : (a) somme debitee <= A0 ; (b) dernier datagramme = (budget restant avant lui) - 28 si le budget restant < MTU IP.
Les trames des paquets Handshake ne sont lisibles qu'avec les secrets de session (--keylog) ; sans eux, un paquet Handshake est
compte comme sollicitant un ACK (il porte du CRYPTO) et le rapport l'indique ('inconnu').
Sorties : <out>.datagrams.csv (une ligne par datagramme serveur de la ronde 1) et <out>.flows.csv (une ligne par flux).
Usage : python3 quic_budget_audit.py --pcap block.pcap [--keylog sslkeys.log] [--port 4433] --out audit_quic_c
Necessite tshark (>= 3.6).
"""
import argparse, csv, subprocess, sys
import xml.etree.ElementTree as ET

NON_ELICITING = {0, 2, 3, 28, 29}   # PADDING, ACK, ACK_ECN, CONNECTION_CLOSE (RFC 9000 s.13.2 / 19)


def run(pcap, keylog, port):
    cmd = ["tshark", "-r", pcap, "-d", "udp.port==%d,quic" % port, "-Y", "quic", "-T", "pdml"]
    if keylog:
        cmd += ["-o", "tls.keylog_file:" + keylog]
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        sys.exit(p.stderr)
    return p.stdout


def fval(el, name):
    for f in el.iter("field"):
        if f.get("name") == name:
            return f.get("show"), f.get("value")
    return None, None


def parse(xml):
    root = ET.fromstring(xml)
    out = []
    for pkt in root.iter("packet"):
        d = dict(ts=None, src=None, udplen=None, stream=None, pk=[])
        for proto in pkt.findall("proto"):
            n = proto.get("name")
            if n == "frame":
                d["ts"] = float(fval(proto, "frame.time_epoch")[0])
            elif n == "ip" or n == "ipv6":
                d["src"] = fval(proto, "ip.src")[0] or fval(proto, "ipv6.src")[0]
            elif n == "udp":
                d["udplen"] = int(fval(proto, "udp.length")[0]) - 8
                d["stream"] = fval(proto, "udp.stream")[0]
            elif n == "quic":
                typ = fval(proto, "quic.long.packet_type")[0]
                plen = fval(proto, "quic.packet_length")[0]
                frames = [int(f.get("show")) for f in proto.iter("field") if f.get("name") == "quic.frame_type" and f.get("show", "").isdigit()]
                d["pk"].append(dict(type=("short" if typ is None else int(typ)), length=int(plen) if plen else None, frames=frames))
        if d["ts"] is not None and d["udplen"] is not None:
            out.append(d)
    return out


def eliciting(p):
    if not p["frames"]:
        return None                       # contenu illisible (pas de cle)
    return any(f not in NON_ELICITING for f in p["frames"])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True); ap.add_argument("--keylog", default=None)
    ap.add_argument("--port", type=int, default=4433); ap.add_argument("--out", required=True)
    ap.add_argument("--mtu-headers", type=int, default=28, help="en-tetes IP+UDP soustraits par MsQuic (28 pour IPv4, 48 pour IPv6)")
    a = ap.parse_args()
    pk = parse(run(a.pcap, a.keylog, a.port))
    streams = {}
    for d in pk:
        streams.setdefault(d["stream"], []).append(d)
    drows, frows = [], []
    for sid, L in sorted(streams.items(), key=lambda kv: int(kv[0])):
        L.sort(key=lambda d: d["ts"])
        client = L[0]["src"]
        t_srv = next((d["ts"] for d in L if d["src"] != client), None)
        if t_srv is None:
            continue
        bc = sum(d["udplen"] for d in L if d["src"] == client and d["ts"] < t_srv)
        t_c1 = next((d["ts"] for d in L if d["src"] == client and d["ts"] > t_srv), None)
        a0 = 3 * bc; allow = a0; sent = 0; charged = 0; unknown = 0; first = True; last = None
        for d in L:
            if d["src"] == client or d["ts"] < t_srv or (t_c1 is not None and d["ts"] >= t_c1):
                continue
            ch = 0; unk = False
            for p in d["pk"]:
                e = eliciting(p)
                if e is None:
                    e = True; unk = True            # paquet chiffre : suppose sollicitant (CRYPTO)
                if e:
                    ch += p["length"] or 0
            allow_before = allow; allow -= ch; sent += d["udplen"]; charged += ch; unknown += int(unk)
            drows.append(dict(stream=sid, t_ms=round((d["ts"] - t_srv) * 1000, 3), udp_payload=d["udplen"],
                              packets="|".join("%s:%s:%s" % (p["type"], p["length"], "+".join(map(str, p["frames"])) or "?") for p in d["pk"]),
                              charged=ch, allowance_before=allow_before, allowance_after=allow, unreadable=int(unk)))
            last = (d["udplen"], allow_before)
        ok_a = charged <= a0
        ok_b = None
        if last is not None:
            ok_b = (last[0] == last[1] - a.mtu_headers) if last[1] < 1500 else None
        frows.append(dict(stream=sid, B_c=bc, A0_3Bc=a0, server_bytes_round1=sent, charged_bytes=charged, uncharged_bytes=sent - charged,
                          last_datagram=last[0] if last else None, allowance_before_last=last[1] if last else None, allowance_end=allow,
                          check_charged_le_A0=ok_a, check_last_eq_remaining_minus_headers=ok_b, datagrams_with_unreadable_packets=unknown))
    for name, rows in (("datagrams", drows), ("flows", frows)):
        if rows:
            with open("%s.%s.csv" % (a.out, name), "w", newline="") as fh:
                w = csv.DictWriter(fh, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
    print("flux : %d ; datagrammes serveur (ronde 1) : %d" % (len(frows), len(drows)))
    for r in frows[:20]:
        print(r)


if __name__ == "__main__":
    main()
