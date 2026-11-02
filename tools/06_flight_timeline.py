#!/usr/bin/env python3
"""06_flight_timeline.py -- reconstruit, a partir des pcap par connexion DEJA capturees (aucune experience), la chronologie des
VOLS (rafales) du serveur pendant l'etablissement de TLS (TCP) et de QUIC (UDP), pour tester le modele de SEUIL :
  "ML-DSA coute un aller-retour quand le premier vol serveur depasse la limite de depart du transport"
   - QUIC : limite d'anti-amplification (3 x octets recus du client avant validation d'adresse) ;
   - TCP  : fenetre de congestion initiale (10 segments, ~14,5 ko).
Rien n'est dechiffre : seules les tailles et les instants des paquets sont utilises.

Principe
  * Flux = paire (IP, port) <-> (IP, port) ; client = emetteur du premier paquet du flux ; le flux est rattache a une execution par
    l'instant de son premier paquet dans les fenetres de conn_windows.csv (colonnes execution,t_start_epoch,t_end_epoch).
  * Une RAFALE serveur = paquets serveur->client portant des donnees (charge utile > 0) sans paquet client entre eux
    (un paquet client, meme un ACK pur, ferme la rafale). Pour chaque flux : octets client avant la 1re donnee serveur,
    octets / instants (relatifs au 1er paquet) des 4 premieres rafales, nombre de rafales, octets serveur totaux.
  * Lecture attendue du modele : rafale 1 plafonnee (QUIC : ~3 x octets client ; TCP : ~14,5 ko) et rafale 2 environ un RTT plus tard
    quand le vol complet depasse le plafond ; une seule rafale sinon ; ecarts de ~25-40 ms (minuterie d'ACK) distincts du RTT.

USAGE : python3 06_flight_timeline.py --root captures_v2 --out analysis_v2/phase2 [--proto tls,quic] [--max-loss 0] [--labels REGEX]
Sorties : flight_timeline_by_flow.csv, flight_timeline_summary.csv (+ tableau a l'ecran).
"""
from __future__ import annotations
import argparse, bisect, collections, csv, re, statistics as st, struct, sys
from pathlib import Path


# ------------------------------------------------------------------------------------------------ lecture pcap / pcapng
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


# ------------------------------------------------------------------------------------------------ analyse d'un fichier
def load_windows(path):
    w = []
    with open(path) as fh:
        for r in csv.DictReader(fh):
            w.append((int(r["execution"]), float(r["t_start_epoch"]), float(r["t_end_epoch"])))
    return sorted(w, key=lambda x: x[1])


def bursts_of(pk):
    """pk = [(ts, from_client, plen)] trie. -> (octets client avant 1re donnee serveur, [ (t_rel, octets, n_paquets) ... ])"""
    t0 = pk[0][0]; cb = 0; seen_server = False; bursts = []; cur = None; client_since = True
    for ts, fc, pl in pk:
        if fc:
            if not seen_server: cb += pl
            client_since = True
        elif pl > 0:
            seen_server = True
            if cur is None or client_since:
                cur = [ts - t0, 0, 0]; bursts.append(cur)
            cur[1] += pl; cur[2] += 1; client_since = False
    return cb, bursts


def analyse(pcap, windows):
    flows = {}                                                    # cle non orientee -> liste de (ts, src_is_first, plen, proto)
    starts = [w[1] for w in windows]
    for ts, link, pkt in read_packets(pcap):
        t = l4_of(link, pkt)
        if t is None: continue
        pr, s, d, sp, dp, fl, pl = t
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
        if i < 0 or not (windows[i][1] - 0.001 <= first_ts <= windows[i][2] + 0.001): continue
        # pk[i][1] vaut True si l'emetteur est f['first_src'] (1er paquet dans l'ordre du fichier) ; le client est l'emetteur du 1er paquet
        # CHRONOLOGIQUE : on inverse l'orientation si besoin
        flip = not pk[0][1]
        pk2 = [(ts, (not fc) if flip else fc, pl) for ts, fc, pl in pk]
        cb, br = bursts_of(pk2)
        sb = sum(p[2] for p in pk2 if not p[1])
        r = dict(execution=windows[i][0], proto=f["proto"], dur_ms=1000 * (windows[i][2] - windows[i][1]), client_bytes_before=cb,
                 n_bursts=len(br), server_bytes=sb)
        for k in range(4):
            r[f"b{k + 1}_bytes"] = br[k][1] if k < len(br) else ""
            r[f"b{k + 1}_t_ms"] = round(1000 * br[k][0], 3) if k < len(br) else ""
        out.append(r)
    return out


# ------------------------------------------------------------------------------------------------ programme
def med(v):
    v = [x for x in v if x != ""]
    return st.median(v) if v else float("nan")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True, type=Path)
    ap.add_argument("--out", type=Path, default=Path("."))
    ap.add_argument("--proto", default="tls,quic")
    ap.add_argument("--max-loss", type=float, default=0.0, help="ne traite que les labels de perte nominale <= N (0 = sans perte)")
    ap.add_argument("--labels", default="", help="regex facultative sur le label")
    ap.add_argument("--max-files", type=int, default=100000)
    a = ap.parse_args()
    rows = []; nfiles = 0
    for proto in a.proto.split(","):
        for p in sorted(a.root.glob(f"{proto}/*/*/pcap_perconn/*/*/block.pcap")):
            parts = p.relative_to(a.root).parts
            label, blockdir, pairdir = parts[2], parts[4], parts[5]
            m = re.search(r"loss(\d+(?:\.\d+)?)", label); nom = float(m.group(1)) if m else 0.0
            if nom > a.max_loss or (a.labels and not re.search(a.labels, label)): continue
            cw = p.parent / "conn_windows.csv"
            if not cw.exists(): continue
            nfiles += 1
            if nfiles > a.max_files: break
            for r in analyse(p, load_windows(cw)):
                r.update(proto=proto, label=label, pair=pairdir, block=blockdir, file=str(p)); rows.append(r)
    if not rows: sys.exit("aucun flux exploitable (verifiez --root, le chemin pcap_perconn/*/*/block.pcap et conn_windows.csv)")
    a.out.mkdir(parents=True, exist_ok=True)
    flds = ["proto", "label", "pair", "block", "execution", "dur_ms", "client_bytes_before", "n_bursts", "server_bytes"] + \
           [f"b{k}_{u}" for k in range(1, 5) for u in ("bytes", "t_ms")] + ["file"]
    with open(a.out / "flight_timeline_by_flow.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=flds, extrasaction="ignore"); w.writeheader(); w.writerows(rows)
    g = collections.defaultdict(list)
    for r in rows: g[(r["proto"], r["label"], r["pair"])].append(r)
    summ = []
    print(f"{nfiles} fichiers, {len(rows)} flux\n")
    print(f"{'proto':5s} {'label':46s} {'paire':28s} {'n':>4s} {'dur':>7s} {'cli B':>6s} {'nB':>3s} {'b1 B':>6s} {'b2 B':>6s} {'b1 t':>6s} {'b2 t':>7s} {'b3 t':>7s} {'srv B':>7s} {'b1/cli':>6s}")
    for (proto, label, pair), L in sorted(g.items()):
        s = dict(proto=proto, label=label, pair=pair, n=len(L), dur_ms=med([r["dur_ms"] for r in L]),
                 client_bytes=med([r["client_bytes_before"] for r in L]), n_bursts=med([r["n_bursts"] for r in L]),
                 b1_bytes=med([r["b1_bytes"] for r in L]), b2_bytes=med([r["b2_bytes"] for r in L]),
                 b1_t_ms=med([r["b1_t_ms"] for r in L]), b2_t_ms=med([r["b2_t_ms"] for r in L]), b3_t_ms=med([r["b3_t_ms"] for r in L]),
                 server_bytes=med([r["server_bytes"] for r in L]))
        s["b1_over_client"] = s["b1_bytes"] / s["client_bytes"] if s["client_bytes"] else float("nan")
        summ.append(s)
        print(f"{proto:5s} {label[:46]:46s} {pair[:28]:28s} {s['n']:4d} {s['dur_ms']:7.1f} {s['client_bytes']:6.0f} {s['n_bursts']:3.0f} {s['b1_bytes']:6.0f} "
              f"{s['b2_bytes']:6.0f} {s['b1_t_ms']:6.1f} {s['b2_t_ms']:7.1f} {s['b3_t_ms']:7.1f} {s['server_bytes']:7.0f} {s['b1_over_client']:6.2f}")
    with open(a.out / "flight_timeline_summary.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(summ[0].keys())); w.writeheader(); w.writerows(summ)
    print(f"\n[OK] {a.out}/flight_timeline_by_flow.csv + flight_timeline_summary.csv")
    print("Lecture : 'b1 B' = octets de la 1re rafale serveur ; 'b2 t' = instant (ms, depuis le 1er paquet) de la 2e rafale ; 'b1/cli' = b1 / octets client\n"
          "avant la 1re donnee serveur (QUIC : ~3 si limite d'anti-amplification). Comparez classique / ML-DSA / ECDSA rempli au meme label.")


if __name__ == "__main__":
    main()
