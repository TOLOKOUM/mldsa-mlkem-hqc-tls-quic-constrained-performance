#!/usr/bin/env python3
"""
parse_traffic_size.py — Agrège les pcap produits par capture_traffic_matrix.sh
(un pcap + un fichier de clés par combinaison protocole/SIG_ALG/KEM) en un CSV
comparatif de la taille du trafic (classique / hybride / PQ pur), via tshark.

Nécessite tshark installé (sudo apt-get install -y tshark).

USAGE:
    python3 parse_traffic_size.py --input-dir captures/traffic_size --out-dir results_traffic_size/
"""

from __future__ import annotations  # compat Python < 3.10 pour "Path | None"

import argparse
import csv
import re
import shutil
import subprocess
import statistics
from pathlib import Path
from collections import defaultdict

FNAME_RE = re.compile(r"^(tls|quic)_(single|mutual)_(.+?)_(.+)_sslkeys\.log$")

HANDSHAKE_TYPE_NAMES = {
    "0": "HelloRequest", "1": "ClientHello", "2": "ServerHello",
    "4": "NewSessionTicket", "8": "EncryptedExtensions", "11": "Certificate",
    "13": "CertificateRequest", "15": "CertificateVerify", "20": "Finished",
}

PORT = "4433"


def classify_kem(kem: str) -> str:
    """Même logique que Analyze_resource_usage.py, pour rester cohérent."""
    k = kem.lower().replace("-", "")
    is_pq = any(tag in k for tag in ("mlkem", "hqc"))
    is_classical_component = any(tag in k for tag in ("p256", "p384", "p521", "x25519", "x448"))
    if is_pq and is_classical_component:
        return "hybride"
    if is_pq:
        return "pq_pur"
    return "classique"


def run_tshark(pcap: Path, keylog: Path | None, fields_args, extra_filter=""):
    cmd = ["tshark", "-r", str(pcap)]
    if keylog is not None:
        cmd += ["-o", f"tls.keylog_file:{keylog}"]
    port_filter = f"(tcp.port=={PORT} or udp.port=={PORT})"
    display_filter = port_filter if not extra_filter else f"{port_filter} and {extra_filter}"
    cmd += ["-Y", display_filter] + fields_args
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout


def analyze_pcap(pcap: Path, keylog: Path | None):
    """Retourne (total_bytes, total_packets, {type_name: bytes}).
    total_bytes/total_packets = taille réelle sur le fil (frame.len), fiable.
    by_type = utilise tls.handshake.length (taille PROPRE à chaque message,
    déclarée dans son en-tête), PAS frame.len : plusieurs messages handshake
    partagent souvent une même trame TCP (ex: ServerHello+EncryptedExtensions+
    Certificate+CertificateVerify pour un petit certificat classique), et leur
    attribuer à chacun la taille totale de la trame partagée les rendrait tous
    artificiellement identiques et beaucoup trop gros — biais qui écraserait
    justement la différence classique/PQ qu'on cherche à mesurer."""
    lens_out = run_tshark(pcap, keylog, ["-T", "fields", "-e", "frame.len"])
    lens = [int(x) for x in lens_out.splitlines() if x.strip()]
    total_bytes = sum(lens)
    total_packets = len(lens)

    by_type = defaultdict(int)
    if keylog is not None:
        ht_out = run_tshark(
            pcap, keylog,
            ["-T", "fields", "-e", "tls.handshake.type", "-e", "tls.handshake.length"],
            extra_filter="tls.handshake.type",
        )
        for line in ht_out.splitlines():
            if not line.strip():
                continue
            parts = line.split("\t")
            if len(parts) != 2:
                continue
            types_raw, msg_lengths_raw = parts
            types = types_raw.split(",")
            msg_lengths = msg_lengths_raw.split(",")
            if len(types) != len(msg_lengths):
                # Désalignement inattendu (ne devrait pas arriver) — on saute
                # cette trame plutôt que d'attribuer une taille à la mauvaise
                # combinaison type/longueur.
                continue
            for t, msg_len_str in zip(types, msg_lengths):
                try:
                    msg_len = int(msg_len_str)
                except ValueError:
                    continue
                name = HANDSHAKE_TYPE_NAMES.get(t.strip(), f"type_{t.strip()}")
                by_type[name] += msg_len

    return total_bytes, total_packets, dict(by_type)


def load_all(input_dir: Path):
    if not shutil.which("tshark"):
        raise RuntimeError("tshark introuvable — installe-le avec: sudo apt-get install -y tshark")

    rows = []
    keylog_files = sorted(input_dir.rglob("*_sslkeys.log"))
    if not keylog_files:
        print(f"[!] Aucun *_sslkeys.log trouvé sous {input_dir} — "
              f"vérifie que capture_traffic_matrix.sh a bien tourné.")

    for keylog in keylog_files:
        m = FNAME_RE.search(keylog.name)
        if not m:
            print(f"[!] Nom non conforme, ignoré: {keylog.name}")
            continue
        protocol, auth_mode, sig_alg, kem = m.groups()
        pcap = keylog.parent / f"{protocol}_{auth_mode}_{sig_alg}_{kem}.pcap"
        if not pcap.exists():
            print(f"[!] pcap manquant pour {keylog.name}, ignoré.")
            continue

        total_bytes, total_packets, by_type = analyze_pcap(pcap, keylog if keylog.stat().st_size > 0 else None)

        row = {
            "protocol": protocol,
            "auth_mode": auth_mode,
            "sig_alg": sig_alg,
            "kem": kem,
            "kem_class": classify_kem(kem),
            "total_bytes": total_bytes,
            "total_packets": total_packets,
        }
        for type_name in ["ClientHello", "ServerHello", "EncryptedExtensions",
                           "Certificate", "CertificateVerify", "Finished",
                           "CertificateRequest", "NewSessionTicket"]:
            row[f"{type_name}_bytes"] = by_type.get(type_name, "NA")
        rows.append(row)
        print(f"  {protocol}/{sig_alg}/{kem}: {total_bytes} octets, {total_packets} paquets")

    return rows


def write_csv(path, rows):
    if not rows:
        return
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


def write_report(path, rows):
    lines = ["# Taille du trafic — comparaison classique / hybride / PQ pur\n"]
    lines.append("| Protocole | Auth | SIG_ALG | KEM | Classe | Total (octets) | Paquets | "
                  "ClientHello | Certificate |")
    lines.append("|---|---|---|---|---|---|---|---|---|")
    for r in sorted(rows, key=lambda r: (r["protocol"], r["kem_class"], r["sig_alg"], r["kem"])):
        lines.append(f"| {r['protocol']} | {r['auth_mode']} | {r['sig_alg']} | {r['kem']} | "
                      f"{r['kem_class']} | {r['total_bytes']} | {r['total_packets']} | "
                      f"{r['ClientHello_bytes']} | {r['Certificate_bytes']} |")

    lines.append("\n## Moyenne du total d'octets par protocole et classe KEM\n")
    groups = defaultdict(list)
    for r in rows:
        groups[(r["protocol"], r["kem_class"])].append(r["total_bytes"])
    lines.append("| Protocole | Classe KEM | N | Total moyen (octets) |")
    lines.append("|---|---|---|---|")
    for (protocol, kem_class), vals in sorted(groups.items()):
        lines.append(f"| {protocol} | {kem_class} | {len(vals)} | {round(statistics.mean(vals), 1)} |")

    lines.append("\n## Note méthodologique\n")
    lines.append("Une seule connexion capturée par combinaison (pas de distribution statistique "
                  "sur plusieurs runs) : la taille des messages de handshake TLS/QUIC est "
                  "déterministe pour une combinaison SIG_ALG/KEM donnée (à la taille du nonce/des "
                  "champs aléatoires près, négligeable). Le total (`total_bytes`) inclut l'overhead "
                  "de transport (en-têtes TCP/QUIC), filtré sur le port applicatif (4433) pour "
                  "exclure tout bruit réseau ambiant (ICMPv6, ARP, mDNS). Les colonnes de détail par "
                  "type de message handshake proviennent du déchiffrement TLS via le fichier de clés "
                  "(SSLKEYLOGFILE) capturé au moment de la connexion — pas de clé privée du serveur "
                  "requise, seulement les secrets de session éphémères de cette connexion précise.\n\n"
                  "Les colonnes par type de message (`ClientHello_bytes`, `Certificate_bytes`, etc.) "
                  "utilisent la taille intrinsèque du message (`tls.handshake.length`, corps du "
                  "message hors en-tête de 4 octets), PAS la taille de la trame TCP qui le contient : "
                  "plusieurs messages handshake partagent souvent une même trame (regroupement qui "
                  "varie selon le volume total transmis, donc selon la combinaison testée), et leur "
                  "attribuer la taille de la trame entière produirait des valeurs incomparables d'une "
                  "ligne à l'autre — biais détecté empiriquement lors du développement de ce script "
                  "(ex: `ServerHello` variant de 102 à plus de 4600 octets selon la combinaison "
                  "testée alors qu'il s'agit d'un message de taille quasi fixe).")

    Path(path).write_text("\n".join(lines))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input-dir", required=True, type=Path)
    ap.add_argument("--out-dir", default="results_traffic_size", type=Path)
    args = ap.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)

    try:
        rows = load_all(args.input_dir)
    except RuntimeError as e:
        print(f"ERREUR: {e}")
        return
    print(f"\n{len(rows)} combinaison(s) analysée(s) depuis {args.input_dir}")
    if not rows:
        return

    write_csv(args.out_dir / "traffic_size_summary.csv", rows)
    write_report(args.out_dir / "traffic_size_report.md", rows)

    print(f"Fichiers écrits dans {args.out_dir}/: traffic_size_summary.csv, traffic_size_report.md")


if __name__ == "__main__":
    main()
