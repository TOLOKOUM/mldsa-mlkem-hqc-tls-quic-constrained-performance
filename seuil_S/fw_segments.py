#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fw_segments.py -- POINT D'ARRET MECANISTE (M1) de la campagne S : que fait reellement le reseau pendant le premier aller-retour ?

Format reel du banc (PER_CONN_PCAP=1) : <racine>/<proto>/<auth>/<label>/pcap_perconn/block<K>of<N>/<sig>_<kem>/block.pcap + conn_windows.csv
(capture continue cote client, port 4433 ; chaque FLUX est rattache a l'execution dont la fenetre contient son premier paquet).
Rien n'est dechiffre. Par flux :
  TLS/TCP : segments serveur->client portant des donnees ; on prend les F premiers octets du flux serveur (F = vol serveur predit) ;
            segs_first / bytes_first : segments et octets de la premiere ronde (avant tout ACK du client) ; rounds_obs : rondes
            (ecart > 0,4 RTT precede d'un ACK du client) ; k_obs = rounds_obs - 1
  QUIC    : datagrammes UDP ; bc = octets des datagrammes client precedant la premiere reponse du serveur ;
            burst1_* = datagrammes serveur emis avant la premiere reponse du client (ronde 1) ; ratio = burst1_bytes / bc
Sans dependance externe (lecteur pcap/pcapng integre, repris de 06_flight_timeline.py).
Usage : python3 fw_segments.py --pcaps DOSSIER [DOSSIER...] --pred freeze_S --out mech_S
"""
from __future__ import annotations
import argparse, bisect, collections, csv, glob, os, re, struct
import numpy as np
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))


def read_packets(path):
    """Genere (ts_epoch_float, linktype, bytes). pcap (us/ns, 2 endianness) ou pcapng minimal (resolution us par defaut)."""
    with open(path, "rb") as fh:
        head = fh.read(4)
        if head == b"\x0a\x0d\x0d\x0a":
            fh.seek(0); data = fh.read(); off = 0; links = []; tsres = []
            while off + 12 <= len(data):
                btype, blen = struct.unpack_from("<II", data, off)
                if blen < 12: break
                body = data[off + 8: off + blen - 4]
                if btype == 1:
                    links.append(struct.unpack_from("<H", body, 0)[0]); res = 1e6; o = 8
                    while o + 4 <= len(body):                              # options : if_tsresol (code 9)
                        code, ln = struct.unpack_from("<HH", body, o)
                        if code == 0: break
                        if code == 9 and ln >= 1:
                            v = body[o + 4]; res = float(2 ** (v & 0x7f)) if v & 0x80 else float(10 ** v)
                        o += 4 + ((ln + 3) & ~3)
                    tsres.append(res)
                elif btype == 6:
                    iface, hi, lo, cap, _ = struct.unpack_from("<IIIII", body, 0)
                    r = tsres[iface] if iface < len(tsres) else 1e6
                    yield ((hi << 32) | lo) / r, (links[iface] if iface < len(links) else 1), body[20:20 + cap]
                off += blen
            return
        if head in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"): e = "<"
        elif head in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"): e = ">"
        else: return
        nano = head in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        hdr = fh.read(20); link = struct.unpack(e + "I", hdr[16:20])[0] & 0x0fffffff
        while True:
            rec = fh.read(16)
            if len(rec) < 16: break
            sec, frac, cap, _ = struct.unpack(e + "IIII", rec)
            pkt = fh.read(cap)
            if len(pkt) < cap: break
            yield sec + frac / (1e9 if nano else 1e6), link, pkt


def l4_of(link, pkt):
    """-> (proto, src_ip, dst_ip, sport, dport, flags, payload_len) pour IPv4 TCP/UDP, sinon None."""
    if link == 1:
        if len(pkt) < 14: return None
        et = struct.unpack("!H", pkt[12:14])[0]; off = 14
        while et in (0x8100, 0x88a8) and len(pkt) >= off + 4:
            et = struct.unpack("!H", pkt[off + 2: off + 4])[0]; off += 4
        if et != 0x0800: return None
    elif link == 113: off = 16
    elif link == 0: off = 4
    elif link in (12, 101): off = 0
    else: return None
    ip = pkt[off:]
    if len(ip) < 20 or ip[0] >> 4 != 4: return None
    ihl = (ip[0] & 15) * 4; tl = struct.unpack("!H", ip[2:4])[0]; pr = ip[9]; l4 = ip[ihl:]
    if pr == 6 and len(l4) >= 20:
        sp, dp, _, _, doff, fl = struct.unpack("!HHIIBB", l4[:14])
        return "tcp", ip[12:16], ip[16:20], sp, dp, fl, max(min(tl, len(ip)) - ihl - (doff >> 4) * 4, 0)
    if pr == 17 and len(l4) >= 8:
        sp, dp, ul = struct.unpack("!HHH", l4[:6])
        return "udp", ip[12:16], ip[16:20], sp, dp, 0, max(ul - 8, 0)
    return None


def load_windows(path):
    w = []
    with open(path) as fh:
        for r in csv.DictReader(fh):
            w.append((int(r["execution"]), float(r["t_start_epoch"]), float(r["t_end_epoch"])))
    return sorted(w, key=lambda x: x[1])



def flows_in_block(pcap, windows):
    """-> liste de dict(execution, proto, pk=[(ts, from_client, plen)]) ; client = emetteur du premier paquet CHRONOLOGIQUE du flux."""
    flows = {}
    starts = [w[1] for w in windows]
    for ts, link, pkt in read_packets(pcap):
        t = l4_of(link, pkt)
        if t is None:
            continue
        pr, s, d, sp, dp, fl, pl = t
        if 4433 not in (sp, dp):
            continue
        a, b = (s, sp), (d, dp)
        key = (pr,) + ((a, b) if a <= b else (b, a))
        f = flows.get(key)
        if f is None:
            flows[key] = f = dict(first_src=a, pk=[], proto=pr)
        f["pk"].append((ts, a == f["first_src"], pl))
    out = []
    for key, f in flows.items():
        pk = sorted(f["pk"])
        first_ts = pk[0][0]
        i = bisect.bisect_right(starts, first_ts + 0.001) - 1
        if i < 0 or not (windows[i][1] - 0.001 <= first_ts <= windows[i][2] + 0.001):
            continue
        flip = not pk[0][1]
        pk2 = [(ts, (not fc) if flip else fc, pl) for ts, fc, pl in pk]
        out.append(dict(execution=windows[i][0], proto=f["proto"], pk=pk2))
    return out


def tls_flow(pk, F, rtt_ms):
    """pk = [(ts, from_client, plen)]. Une nouvelle ronde commence quand le serveur emet apres un ecart > 0,4 RTT ET apres un ACK
    du client (un ecart du seul au calcul du serveur n'ouvre pas de ronde)."""
    acks = [ts for ts, fc, n in pk if fc and n == 0]
    segs, cum = [], 0
    for ts, fc, n in pk:
        if fc or n == 0:
            continue
        if cum >= F:
            break
        segs.append((ts, n))
        cum += n
    if not segs:
        return {}
    rnd, rounds = 1, [1]
    for (tp, _), (tc, _) in zip(segs[:-1], segs[1:]):
        if (tc - tp) * 1000.0 > 0.4 * rtt_ms and any(tp < a < tc for a in acks):
            rnd += 1
        rounds.append(rnd)
    rounds = np.array(rounds)
    n = np.array([x[1] for x in segs])
    first = rounds == 1
    return dict(seg_sizes=",".join(map(str, n[first])), segs_first=int(first.sum()), bytes_first=int(n[first].sum()),
                rounds_obs=int(rounds.max()), flight_bytes_seen=int(n.sum()), t_last_ms=float((segs[-1][0] - segs[0][0]) * 1000.0))


def quic_flow(pk, rtt_ms):
    """Ronde 1 = datagrammes serveur emis avant le premier datagramme CLIENT qui suit le premier datagramme serveur."""
    t_srv = next((ts for ts, fc, n in pk if not fc and n > 0), None)
    if t_srv is None:
        return {}
    cl = [n for ts, fc, n in pk if fc and ts < t_srv]
    bc = sum(cl)
    t_c1 = next((ts for ts, fc, n in pk if fc and ts > t_srv), None)
    srv = [(ts, n) for ts, fc, n in pk if not fc and n > 0]
    b1 = [p for p in srv if t_c1 is None or p[0] < t_c1]
    rest = [p for p in srv if t_c1 is not None and t_c1 <= p[0] < t_c1 + 0.95 * rtt_ms / 1000.0]
    return dict(bc=int(bc), n_client_dgrams=len(cl), client_dgram_sizes=",".join(map(str, cl)),
                burst1_bytes=int(sum(p[1] for p in b1)), burst1_dgrams=len(b1), burst1_sizes=",".join(str(p[1]) for p in b1),
                burst2_bytes=int(sum(p[1] for p in rest)),
                ratio=(sum(p[1] for p in b1) / bc) if bc else np.nan)


def parse_label(label):
    mtu = re.search(r"_mtu(\d+)", label)
    pad = re.search(r"padto(\d+)", label)
    d = re.search(r"delay(\d+(?:\.\d+)?)ms", label)
    return dict(mtu=int(mtu.group(1)) if mtu else 1500, pad=int(pad.group(1)) if pad else 0,
                rtt=2 * float(d.group(1)) if d else 0.0)


def block_files(roots):
    """-> [(chemin block.pcap, dict(proto, label, block, sig, kem, mtu, pad, rtt))]"""
    out = []
    for root in roots:
        for p in sorted(glob.glob(os.path.join(root, "**", "pcap_perconn", "*", "*", "block.pcap"), recursive=True)):
            parts = os.path.normpath(p).split(os.sep)
            i = len(parts) - 1 - parts[::-1].index("pcap_perconn")
            if i < 3:
                continue
            proto, label, blockdir, pair = parts[i - 3], parts[i - 1], parts[i + 1], parts[i + 2]
            m = re.match(r"^(mldsa\d+|secp\d+r1|ed25519|rsa\w*?)_(.+)$", pair)
            if proto not in ("tls", "quic") or not m or not os.path.exists(os.path.join(os.path.dirname(p), "conn_windows.csv")):
                continue
            info = dict(proto=proto, label=label, block=blockdir, sig=m.group(1), kem=m.group(2), **parse_label(label))
            out.append((p, info))
    return out


def collect(roots, pred=None, rtt_override=None):
    """-> DataFrame d'une ligne par flux."""
    rows = []
    for f, info in block_files(roots):
        windows = load_windows(os.path.join(os.path.dirname(f), "conn_windows.csv"))
        rtt = rtt_override or info["rtt"] or 50.0
        F = None
        if info["proto"] == "tls":
            if pred is not None:
                x = pred[(pred.proto == "tls") & (pred.kem == info["kem"]) & (pred.mtu == info["mtu"]) & (pred.chain_target == info["pad"]) &
                         (pred.sig == info["sig"])]
                F = int(x.flight_a.iloc[0]) if len(x) else None
            if F is None:
                F = 10 ** 9
        for fl in flows_in_block(f, windows):
            if fl["proto"] != info["proto"].replace("tls", "tcp").replace("quic", "udp"):
                continue
            row = dict(info, execution=fl["execution"], file=f)
            row.update(tls_flow(fl["pk"], F, rtt) if info["proto"] == "tls" else quic_flow(fl["pk"], rtt))
            rows.append(row)
    return pd.DataFrame(rows)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcaps", nargs="+", required=True)
    ap.add_argument("--pred", default=None)
    ap.add_argument("--out", default="mech_S")
    ap.add_argument("--rtt", type=float, default=None, help="RTT nominal (ms) ; par defaut lu dans le label")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    pred = pd.read_csv(os.path.join(a.pred, "predictions_frozen.csv")) if a.pred else None
    flows = collect(a.pcaps, pred, a.rtt)
    flows.to_csv(os.path.join(a.out, "M1_flows.csv"), index=False)
    print("flux analyses : %d" % len(flows))
    if flows.empty:
        return
    pd.set_option("display.width", 250, "display.max_rows", 400)
    if pred is None:
        print(flows.drop(columns=["file"]).to_string(index=False))
        return
    out = []
    for (proto, kem, mtu, pad, sig), g in flows.groupby(["proto", "kem", "mtu", "pad", "sig"]):
        x = pred[(pred.proto == proto) & (pred.kem == kem) & (pred.mtu == mtu) & (pred.chain_target == pad) & (pred.sig == sig)]
        if x.empty:
            continue
        x = x.iloc[0]
        if proto == "tls":
            ma = (g.bytes_first - x.fw_bytes_a).abs() <= 5
            mb = (g.bytes_first - x.fw_bytes_b).abs() <= 5
            ra = (g.rounds_obs - 1 == x.k_a)
            rb = (g.rounds_obs - 1 == x.k_b)
            out.append(dict(proto=proto, kem=kem, mtu=mtu, pad=pad, sig=sig, n=len(g), disc=int(x.disc), rule_a=x.rule_a, rule_b=x.rule_b,
                            fw_bytes_a=x.fw_bytes_a, fw_bytes_b=x.fw_bytes_b, bytes_first_median=float(g.bytes_first.median()),
                            frac_bytes_match_a=float(ma.mean()), frac_bytes_match_b=float(mb.mean()),
                            k_obs_median=float(g.rounds_obs.median() - 1), frac_k_match_a=float(ra.mean()), frac_k_match_b=float(rb.mean()),
                            k_a=x.k_a, k_b=x.k_b))
        else:
            kobs = (g.burst2_bytes >= 500).astype(int)
            out.append(dict(proto=proto, kem=kem, mtu=mtu, pad=pad, sig=sig, n=len(g), disc=int(x.disc), rule_a=x.rule_a, rule_b=x.rule_b,
                            bc_median=float(g.bc.median()), burst1_median=float(g.burst1_bytes.median()), ratio_median=float(g.ratio.median()),
                            burst2_median=float(g.burst2_bytes.median()), k_obs_step1=float(kobs.mean()),
                            frac_k_match_a=float((kobs == min(1, x.k_a)).mean()), frac_k_match_b=float((kobs == min(1, x.k_b)).mean()),
                            k_a=x.k_a, k_b=x.k_b))
    o = pd.DataFrame(out)
    o.to_csv(os.path.join(a.out, "M1_cells.csv"), index=False)
    print(o.to_string(index=False))


if __name__ == "__main__":
    main()
