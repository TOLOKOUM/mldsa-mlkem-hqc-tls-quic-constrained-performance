#!/usr/bin/env python3
"""03_tls_loss_process.py -- caracterise le PROCESSUS DE PERTE reellement subi par les flux TLS, a partir des pcap
par connexion DEJA capturees (aucune nouvelle experience). Python standard uniquement (pcap/pcapng, Ethernet/SLL/raw, IPv4).

Question : la perte netem appliquee au TCP est-elle (a) i.i.d. par paquet (trous d'1 segment, ~95 % pour p=5 %) ou
(b) groupee par super-paquet (trous de plusieurs segments consecutifs) ? On lit, cote CLIENT, le flux serveur->client :
chaque trou dans les numeros de sequence = segment(s) perdu(s) avant le client (la capture voit les survivants).

Par connexion : trous detectes, taille de chaque trou en segments (octets / MSS), segments perdus a la premiere emission.
Limites : une perte en QUEUE de flux (dernier segment) ne cree pas de trou et n'est pas vue -> taux de perte sous-estime ;
une perte de retransmission n'est pas vue. Les comparaisons entre groupes restent valides (meme biais).

USAGE : python3 03_tls_loss_process.py --root captures_v2 [--proto tls] [--min-loss 1] [--max-files 5000] --out analysis_v2
Sorties : tls_loss_process_by_file.csv, tls_loss_process_summary.csv (+ tableau a l'ecran).
"""
from __future__ import annotations
import argparse, collections, math, re, struct, sys
from pathlib import Path


def read_packets(path):
    """Genere (linktype, bytes) pour pcap classique (us/ns, 2 endianness) ou pcapng minimal."""
    with open(path, "rb") as fh:
        head = fh.read(4)
        if head == b"\x0a\x0d\x0d\x0a":                       # pcapng
            fh.seek(0); data = fh.read(); off = 0; links = []
            while off + 12 <= len(data):
                btype, blen = struct.unpack_from("<II", data, off)
                if blen < 12: break
                body = data[off + 8: off + blen - 4]
                if btype == 1: links.append(struct.unpack_from("<H", body, 0)[0])
                elif btype == 6:
                    iface, _, _, cap, _ = struct.unpack_from("<IIIII", body, 0)
                    yield (links[iface] if iface < len(links) else 1), body[20:20 + cap]
                off += blen
            return
        magic = head
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"): e = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"): e = ">"
        else: return
        hdr = fh.read(20); link = struct.unpack(e + "I", hdr[16:20])[0] & 0x0fffffff
        while True:
            rec = fh.read(16)
            if len(rec) < 16: break
            _, _, cap, _ = struct.unpack(e + "IIII", rec)
            pkt = fh.read(cap)
            if len(pkt) < cap: break
            yield link, pkt


def tcp_of(link, pkt):
    """-> (src_ip, dst_ip, sport, dport, seq, flags, payload_len) ou None (IPv4/TCP seulement)."""
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
    if len(ip) < 20 or ip[0] >> 4 != 4 or ip[9] != 6: return None
    ihl = (ip[0] & 15) * 4; tl = struct.unpack("!H", ip[2:4])[0]
    tcp = ip[ihl:]
    if len(tcp) < 20: return None
    sport, dport, seq, _, doff, flags = struct.unpack("!HHIIBB", tcp[:14])
    plen = max(min(tl, len(ip)) - ihl - (doff >> 4) * 4, 0)
    return ip[12:16], ip[16:20], sport, dport, seq, flags, plen


def analyse_file(path):
    """Un fichier = une ou plusieurs connexions. Retourne la liste des dictionnaires de resultats."""
    conns = {}
    for link, pkt in read_packets(path):
        t = tcp_of(link, pkt)
        if t is None: continue
        s, d, sp, dp, seq, fl, plen = t
        key = (s, sp, d, dp)
        if (fl & 0x12) == 0x12:                                   # SYN+ACK : s = serveur
            conns[key] = dict(base=(seq + 1) & 0xffffffff, hi=0, holes=[], first=0, fills=0, mss=collections.Counter(), pend=[])
            continue
        c = conns.get(key)
        if c is None or plen == 0 or (fl & 0x02): continue
        rel = (seq - c["base"]) & 0xffffffff
        if rel > 0x7fffffff: continue                             # avant la base (retransmission SYN, etc.)
        c["mss"][plen] += 1
        if rel > c["hi"]:                                         # trou : segments manquants avant celui-ci
            c["holes"].append((c["hi"], rel - c["hi"])); c["pend"].append((c["hi"], rel)); c["hi"] = rel + plen; c["first"] += 1
        elif rel + plen > c["hi"]:                                # chevauchement / suite normale
            c["hi"] = rel + plen; c["first"] += 1
        else:                                                     # deja vu : retransmission ou remplissage de trou
            c["fills"] += 1
    out = []
    for key, c in conns.items():
        if not c["mss"]: continue
        mss = max(c["mss"])                                       # MSS effectif = plus grand segment observe
        sizes = [max(1, round(b / mss)) for _, b in c["holes"]]
        out.append(dict(n_first=c["first"], holes=len(sizes), lost_segs=sum(sizes), mss=mss,
                        h1=sum(s == 1 for s in sizes), h2=sum(s == 2 for s in sizes), h3=sum(s == 3 for s in sizes), h4p=sum(s >= 4 for s in sizes),
                        max_hole=max(sizes) if sizes else 0))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True, type=Path)
    ap.add_argument("--out", type=Path, default=Path("."))
    ap.add_argument("--proto", default="tls")
    ap.add_argument("--min-loss", type=float, default=0.0, help="ne traite que les labels dont la perte nominale (loss<N>) est >= N")
    ap.add_argument("--max-files", type=int, default=100000)
    a = ap.parse_args()
    files = [p for p in sorted(a.root.glob(f"{a.proto}/*/*/pcap_perconn/**/*")) if p.is_file() and p.suffix in (".pcap", ".pcapng", ".cap")]
    if not files:
        files = [p for p in sorted(a.root.glob(f"{a.proto}/*/*/**/*")) if p.is_file() and p.suffix in (".pcap", ".pcapng", ".cap")]
    print(f"{len(files)} fichiers pcap sous {a.root}/{a.proto}")
    rows = []
    for i, p in enumerate(files[:a.max_files]):
        rel = p.relative_to(a.root).parts; label = rel[2] if len(rel) > 2 else "?"
        m = re.search(r"loss(\d+(?:\.\d+)?)", label); nom = float(m.group(1)) if m else 0.0
        if nom < a.min_loss: continue
        sigc = "pqc" if "mldsa" in str(p).lower() else "classical"
        for r in analyse_file(p):
            r.update(label=label, nominal=nom, sig_class=sigc, file=str(p)); rows.append(r)
        if (i + 1) % 500 == 0: print(f"   ... {i + 1}/{min(len(files), a.max_files)}", flush=True)
    if not rows: sys.exit("aucune connexion TCP exploitable (SYN+ACK absent des captures ?)")
    import csv
    a.out.mkdir(parents=True, exist_ok=True)
    with open(a.out / "tls_loss_process_by_file.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
    agg = collections.defaultdict(lambda: collections.Counter())
    for r in rows:
        for g in ((r["label"], r["sig_class"]), (f"TOUS loss{r['nominal']:g}", r["sig_class"]), (f"TOUS loss{r['nominal']:g}", "tous")):
            c = agg[g]; c["conns"] += 1
            for k in ("n_first", "holes", "lost_segs", "h1", "h2", "h3", "h4p"): c[k] += r[k]
    out = []
    print(f"\n{'groupe':44s} {'sig':9s} {'conn':>5s} {'trous/conn':>10s} {'1 seg %':>8s} {'2 seg %':>8s} {'3 seg %':>8s} {'>=4 %':>7s} {'perte seg %':>12s} {'nominal %':>9s} {'iid: 1 seg %':>12s}")
    for (g, s), c in sorted(agg.items()):
        H = c["holes"]; tot = c["n_first"] + c["lost_segs"]
        pl = 100 * c["lost_segs"] / tot if tot else float("nan")
        mm = re.search(r"loss(\d+(?:\.\d+)?)", g); nom = float(mm.group(1)) if mm else float("nan")
        iid1 = 100 * (1 - nom / 100) if nom == nom else float("nan")
        fr = lambda k: 100 * c[k] / H if H else float("nan")
        out.append(dict(groupe=g, sig=s, conns=c["conns"], holes_per_conn=H / c["conns"], pct1=fr("h1"), pct2=fr("h2"), pct3=fr("h3"), pct4p=fr("h4p"), seg_loss_pct=pl, nominal=nom, iid_pct1=iid1))
        print(f"{g[:44]:44s} {s:9s} {c['conns']:5d} {H / c['conns']:10.3f} {fr('h1'):8.1f} {fr('h2'):8.1f} {fr('h3'):8.1f} {fr('h4p'):7.1f} {pl:12.3f} {nom:9.1f} {iid1:12.1f}")
    with open(a.out / "tls_loss_process_summary.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(out[0].keys())); w.writeheader(); w.writerows(out)
    print(f"\n[OK] {a.out}/tls_loss_process_by_file.csv + tls_loss_process_summary.csv")
    print("Lecture : sous perte i.i.d. par paquet, '1 seg %' ~ 100-p ; une part nettement plus faible de trous d'1 segment (et des trous de 2, 3, >=4 segments)\n"
          "= pertes groupees par super-paquet. 'perte seg %' = segments perdus a la 1re emission / segments (borne basse, pertes de queue non vues).")


if __name__ == "__main__":
    main()
