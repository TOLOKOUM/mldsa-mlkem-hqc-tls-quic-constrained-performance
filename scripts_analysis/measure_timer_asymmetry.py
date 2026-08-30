#!/usr/bin/env python3
"""
measure_timer_asymmetry.py

Objectif : quantifier, a partir des captures .pcap DEJA PRODUITES
(captures/pcap_demo/), l'ecart reel entre :
  - le timer QUIC actuel du papier (HandshakeFlightEnd -- RFC 9001
    "handshake complete"), approxime ici par l'arrivee du DERNIER
    paquet Handshake-space envoye par le serveur ;
  - le vrai "handshake confirmed" RFC 9001, marque par la reception
    du frame HANDSHAKE_DONE (type 0x1e) par le client.

Fait la meme chose cote TLS (temps jusqu'au Finished du client) pour
validation croisee avec la duree deja mesuree par s_connection.

Ne fait AUCUNE nouvelle mesure reseau : relit uniquement les .pcap et
.log (NSS keylog) deja presents sur disque.

PREREQUIS: tshark installe (teste avec 4.2.2), fichiers *_sslkeys.log
a cote de chaque .pcap dans le meme dossier.

USAGE:
    python3 measure_timer_asymmetry.py --root captures/pcap_demo --out timer_asymmetry.csv
"""

import argparse
import csv
import glob
import os
import subprocess
import sys


def run_tshark_fields(pcap, keylog, display_filter, fields, debug=False):
    cmd = ["tshark", "-r", pcap, "-o", f"tls.keylog_file:{keylog}", "-Y", display_filter, "-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        print(f"[WARN] timeout tshark sur {pcap}", file=sys.stderr)
        return []
    if debug or out.returncode != 0 or not out.stdout.strip():
        print(f"[DEBUG] CMD: {' '.join(cmd)}", file=sys.stderr)
        print(f"[DEBUG] returncode={out.returncode}", file=sys.stderr)
        print(f"[DEBUG] stdout={out.stdout[:300]!r}", file=sys.stderr)
        print(f"[DEBUG] stderr={out.stderr[:500]!r}", file=sys.stderr)
    if out.returncode != 0:
        return []
    rows = []
    for line in out.stdout.strip().splitlines():
        if not line:
            continue
        rows.append(line.split("\t"))
    return rows


def get_client_server_ips(pcap, keylog):
    """Le premier paquet IP du fichier (pas forcement frame #1 : le pont
    Docker peut capturer une trame ARP avant le trafic applicatif) est le
    ClientHello/Initial : sa source est le client, sa destination le serveur."""
    rows = run_tshark_fields(pcap, keylog, "ip", ["ip.src", "ip.dst"])
    if not rows or len(rows[0]) < 2 or not rows[0][0] or not rows[0][1]:
        return None, None
    return rows[0][0], rows[0][1]


def analyze_quic(pcap, keylog):
    client_ip, server_ip = get_client_server_ips(pcap, keylog)
    if not client_ip:
        print(f"[SKIP-QUIC] pas d'IP client/serveur trouvee : {pcap}", file=sys.stderr)
        return None

    # t0 : premier paquet IP reel (Initial du client) -- pas frame.number==1
    # qui peut tomber sur une trame non-IP (ARP) capturee avant le trafic.
    t0_rows = run_tshark_fields(pcap, keylog, "ip", ["frame.time_relative"])
    if not t0_rows:
        print(f"[SKIP-QUIC] t0 introuvable : {pcap}", file=sys.stderr)
        return None
    t0 = float(t0_rows[0][0])

    # Dernier paquet Handshake-space (long header, packet_type == 2) venant du serveur
    # ADAPT-ME si le nom de champ differe selon la version de tshark :
    # certaines versions utilisent 'quic.packet_type' au lieu de 'quic.long.packet_type'.
    hs_rows = run_tshark_fields(
        pcap, keylog,
        f"quic.long.packet_type == 2 && ip.src == {server_ip}",
        ["frame.time_relative"],
    )
    if not hs_rows:
        print(f"[SKIP-QUIC] aucun paquet Handshake du serveur trouve : {pcap}", file=sys.stderr)
        return None
    t_flightend_proxy = max(float(r[0]) for r in hs_rows if r and r[0])

    # Paquet contenant HANDSHAKE_DONE (0x1e), doit venir du serveur, recu par le client
    done_rows = run_tshark_fields(
        pcap, keylog,
        "quic.frame_type == 0x1e",
        ["frame.time_relative"],
    )
    if not done_rows:
        return {
            "t0": t0, "t_flightend_proxy_ms": (t_flightend_proxy - t0) * 1000,
            "t_confirmed_ms": None, "delta_confirm_ms": None,
            "note": "HANDSHAKE_DONE not found (decryption failed or frame absent)",
        }
    t_confirmed = float(done_rows[0][0])

    return {
        "t0": t0,
        "t_flightend_proxy_ms": (t_flightend_proxy - t0) * 1000,
        "t_confirmed_ms": (t_confirmed - t0) * 1000,
        "delta_confirm_ms": (t_confirmed - t_flightend_proxy) * 1000,
        "note": "",
    }


def analyze_tls(pcap, keylog):
    client_ip, server_ip = get_client_server_ips(pcap, keylog)
    if not client_ip:
        print(f"[SKIP-TLS] pas d'IP client/serveur trouvee : {pcap}", file=sys.stderr)
        return None

    t0_rows = run_tshark_fields(pcap, keylog, "ip", ["frame.time_relative"])
    if not t0_rows:
        print(f"[SKIP-TLS] t0 introuvable : {pcap}", file=sys.stderr)
        return None
    t0 = float(t0_rows[0][0])

    # Finished du client : tls.handshake.type == 20, envoye par le client
    fin_rows = run_tshark_fields(
        pcap, keylog,
        f"tls.handshake.type == 20 && ip.src == {client_ip}",
        ["frame.time_relative"],
    )
    if not fin_rows:
        return {"t0": t0, "t_client_finished_ms": None, "note": "Client Finished not found (decryption failed?)"}
    t_fin = float(fin_rows[0][0])
    return {"t0": t0, "t_client_finished_ms": (t_fin - t0) * 1000, "note": ""}


def find_pairs(root):
    """Retourne [(pcap_path, keylog_path), ...] pour tous les .pcap trouves."""
    pairs = []
    for pcap in glob.glob(os.path.join(root, "**", "*.pcap"), recursive=True):
        keylog = pcap.replace(".pcap", "_sslkeys.log")
        if not os.path.isfile(keylog):
            print(f"[WARN] pas de keylog pour {pcap}", file=sys.stderr)
            continue
        pairs.append((pcap, keylog))
    return pairs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--out", default="timer_asymmetry.csv")
    ap.add_argument("--limit", type=int, default=None, help="Ne traiter que les N premieres paires (debug rapide)")
    args = ap.parse_args()

    pairs = find_pairs(args.root)
    if args.limit:
        pairs = pairs[: args.limit]
    print(f"[INFO] {len(pairs)} paires pcap+keylog trouvees sous {args.root}", file=sys.stderr)

    rows_out = []
    for pcap, keylog in pairs:
        base = os.path.basename(pcap)
        protocol = "quic" if "_quic_" in base else ("tls" if "_tls_" in base else "unknown")
        # extrait grossierement network depuis le chemin parent
        network = os.path.normpath(pcap).split(os.sep)[-4] if len(os.path.normpath(pcap).split(os.sep)) >= 4 else "unknown"

        if protocol == "quic":
            res = analyze_quic(pcap, keylog)
            if res:
                rows_out.append({
                    "protocol": "quic", "network": network, "file": base,
                    "flightend_proxy_ms": res.get("t_flightend_proxy_ms"),
                    "confirmed_ms": res.get("t_confirmed_ms"),
                    "delta_confirm_ms": res.get("delta_confirm_ms"),
                    "client_finished_ms": "",
                    "note": res.get("note", ""),
                })
        elif protocol == "tls":
            res = analyze_tls(pcap, keylog)
            if res:
                rows_out.append({
                    "protocol": "tls", "network": network, "file": base,
                    "flightend_proxy_ms": "", "confirmed_ms": "", "delta_confirm_ms": "",
                    "client_finished_ms": res.get("t_client_finished_ms"),
                    "note": res.get("note", ""),
                })

    with open(args.out, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "protocol", "network", "file", "flightend_proxy_ms", "confirmed_ms",
            "delta_confirm_ms", "client_finished_ms", "note",
        ])
        writer.writeheader()
        for r in rows_out:
            writer.writerow(r)

    # Resume par (protocol, network)
    from collections import defaultdict
    agg = defaultdict(list)
    for r in rows_out:
        if r["protocol"] == "quic" and r["delta_confirm_ms"] not in (None, ""):
            agg[("quic_delta", r["network"])].append(r["delta_confirm_ms"])
        if r["protocol"] == "tls" and r["client_finished_ms"] not in (None, ""):
            agg[("tls_client_finished", r["network"])].append(r["client_finished_ms"])

    print("\n=== RESUME (ms) ===")
    for (kind, network), vals in sorted(agg.items()):
        vals_sorted = sorted(vals)
        n = len(vals_sorted)
        mean = sum(vals_sorted) / n
        median = vals_sorted[n // 2]
        print(f"{kind:22s} | {network:35s} | n={n:3d} | mean={mean:8.3f} | median={median:8.3f} | min={vals_sorted[0]:8.3f} | max={vals_sorted[-1]:8.3f}")

    n_failed = sum(1 for r in rows_out if r["note"])
    print(f"\n[INFO] {n_failed} fichiers avec note/echec de dechiffrement sur {len(rows_out)} traites")
    print(f"[INFO] Rapport detaille : {args.out}")


if __name__ == "__main__":
    main()
