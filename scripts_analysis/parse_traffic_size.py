#!/usr/bin/env python3
"""
parse_traffic_size.py — Agrège et analyse les fichiers PCAP issus des campagnes d'essais.
Extrait la taille globale du trafic (taille réelle frame.len) et le détail fin par type
de message TLS (via tls.handshake.length) en utilisant les fichiers de clés SSLKEYLOGFILE.

Nécessite tshark installé (sudo apt-get install -y tshark).

USAGE:
    python3 parse_traffic_size.py --input-dir captures/pcap_demo --out-dir results_traffic
"""

from __future__ import annotations  # compat Python < 3.10 pour "Path | None"

import argparse
import csv
import os
import re
import shutil
import subprocess
import statistics
from collections import defaultdict
from pathlib import Path

# Expression régulière adaptée aux noms de fichiers log/pcap générés par la campagne
# Ex: capture_quic_single_ed25519_p256_hqc128_none_20260826_131657_sslkeys.log
# Ex: capture_tls_single_mldsa44_mlkem768_wifi_20260826_140000.pcap
FNAME_RE = re.compile(
    r"^(?:capture_)?(tls|quic)_(single|mutual)_([^_]+)_(.+?)(?:_[a-zA-Z0-9]+_\d{8}_\d{6})?(?:_sslkeys\.log|\.pcap)?$"
)

HANDSHAKE_TYPE_NAMES = {
    "0": "HelloRequest",
    "1": "ClientHello",
    "2": "ServerHello",
    "4": "NewSessionTicket",
    "8": "EncryptedExtensions",
    "11": "Certificate",
    "13": "CertificateRequest",
    "15": "CertificateVerify",
    "20": "Finished",
}

PORT = "4433"


def classify_kem(kem: str) -> str:
    """Classifie le KEM en classique, hybride ou PQ pur."""
    k = kem.lower().replace("-", "")
    is_pq = any(tag in k for tag in ("mlkem", "hqc", "kyber"))
    is_classical_component = any(tag in k for tag in ("p256", "p384", "p521", "x25519", "x448"))
    if is_pq and is_classical_component:
        return "hybride"
    if is_pq:
        return "pq_pur"
    return "classique"


def run_tshark(pcap: Path, keylog: Path | None, fields_args: list[str], extra_filter: str = "") -> str:
    """Exécute tshark sur un fichier PCAP avec filtrage optionnel par port et décodage SSLKEYLOGFILE."""
    cmd = ["tshark", "-r", str(pcap)]
    if keylog is not None and keylog.exists() and keylog.stat().st_size > 0:
        cmd += ["-o", f"tls.keylog_file:{keylog}"]
    
    port_filter = f"(tcp.port=={PORT} or udp.port=={PORT})"
    display_filter = port_filter if not extra_filter else f"{port_filter} and {extra_filter}"
    cmd += ["-Y", display_filter] + fields_args
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout


def analyze_pcap(pcap: Path, keylog: Path | None):
    """
    Retourne (total_bytes, total_packets, {type_name: bytes}).
    
    total_bytes/total_packets = taille réelle sur le fil (frame.len).
    by_type = utilise tls.handshake.length (taille propre à chaque message),
    évitant le biais de la taille totale de la trame partagée.
    """
    lens_out = run_tshark(pcap, keylog, ["-T", "fields", "-e", "frame.len"])
    lens = [int(x) for x in lens_out.splitlines() if x.strip()]
    total_bytes = sum(lens)
    total_packets = len(lens)

    by_type = defaultdict(int)
    if keylog is not None and keylog.exists() and keylog.stat().st_size > 0:
        ht_out = run_tshark(
            pcap,
            keylog,
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
    """Parcourt l'arborescence des fichiers .pcap et leurs fichiers de clés correspondants."""
    if not shutil.which("tshark"):
        raise RuntimeError("tshark introuvable — installe-le avec : sudo apt-get install -y tshark")

    rows = []
    pcap_files = sorted(input_dir.rglob("*.pcap"))
    
    if not pcap_files:
        print(f"[!] Aucun fichier .pcap trouvé sous {input_dir}")
        return rows

    for pcap in pcap_files:
        # Extraction du chemin relatif pour identifier la campagne et le profil réseau si présent
        rel_parts = pcap.relative_to(input_dir).parts
        campaign = rel_parts[0] if len(rel_parts) > 1 else "default"
        network_profile = rel_parts[1] if len(rel_parts) > 2 else "default"

        # Recherche du fichier de clés associé (ex: même nom avec _sslkeys.log ou dans le même dossier)
        keylog = pcap.with_name(pcap.stem + "_sslkeys.log")
        if not keylog.exists():
            # Cherche un fichier .log unique dans le même répertoire
            logs = list(pcap.parent.glob("*.log"))
            keylog = logs[0] if logs else None

        # Extraction des paramètres depuis le nom de fichier ou la structure
        filename = pcap.name
        name_no_ext = pcap.stem
        
        # Découpage du nom de fichier standard de campagne
        tokens = name_no_ext.split("_")
        protocol = "unknown"
        auth_mode = "single"
        sig_alg = "unknown"
        kem = "none"

        # Analyse adaptative des tokens
        if "quic" in tokens:
            protocol = "quic"
        elif "tls" in tokens:
            protocol = "tls"

        if "mutual" in tokens:
            auth_mode = "mutual"
        elif "single" in tokens:
            auth_mode = "single"

        # Tentative d'extraction par Regex ou par position de tokens
        m = FNAME_RE.search(filename)
        if m:
            protocol, auth_mode, sig_alg, kem = m.groups()
        elif len(tokens) >= 4:
            # Repli sur le découpage par token
            idx = 3 if tokens[0] == "capture" else 2
            if idx < len(tokens):
                sig_alg = tokens[idx]
            crypto_parts = tokens[idx+1:-2] if len(tokens) > idx+3 else tokens[idx+1:]
            if crypto_parts:
                kem = "_".join(crypto_parts)

        total_bytes, total_packets, by_type = analyze_pcap(pcap, keylog)

        row = {
            "campaign": campaign,
            "network_profile": network_profile,
            "protocol": protocol,
            "auth_mode": auth_mode,
            "sig_alg": sig_alg,
            "kem": kem,
            "kem_class": classify_kem(kem),
            "pcap_file": filename,
            "total_bytes": total_bytes,
            "total_packets": total_packets,
        }
        
        for type_name in [
            "ClientHello", "ServerHello", "EncryptedExtensions",
            "Certificate", "CertificateVerify", "Finished",
            "CertificateRequest", "NewSessionTicket"
        ]:
            row[f"{type_name}_bytes"] = by_type.get(type_name, "NA")

        rows.append(row)
        print(f"  [{protocol.upper()}] {sig_alg} / {kem} ({row['kem_class']}): {total_bytes} octets, {total_packets} paquets")

    return rows


def write_csv(path: Path, rows: list[dict]):
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


def write_report(path: Path, rows: list[dict]):
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# Taille du trafic — comparaison classique / hybride / PQ pur\n"]
    lines.append("| Protocole | Auth | SIG_ALG | KEM | Classe | Total (octets) | Paquets | ClientHello | Certificate |")
    lines.append("|---|---|---|---|---|---|---|---|---|")
    
    for r in sorted(rows, key=lambda r: (r["protocol"], r["kem_class"], r["sig_alg"], r["kem"])):
        lines.append(
            f"| {r['protocol']} | {r['auth_mode']} | {r['sig_alg']} | {r['kem']} | "
            f"{r['kem_class']} | {r['total_bytes']} | {r['total_packets']} | "
            f"{r['ClientHello_bytes']} | {r['Certificate_bytes']} |"
        )

    lines.append("\n## Moyenne du total d'octets par protocole et classe KEM\n")
    groups = defaultdict(list)
    for r in rows:
        groups[(r["protocol"], r["kem_class"])].append(r["total_bytes"])
    lines.append("| Protocole | Classe KEM | N | Total moyen (octets) |")
    lines.append("|---|---|---|---|")
    for (protocol, kem_class), vals in sorted(groups.items()):
        lines.append(f"| {protocol} | {kem_class} | {len(vals)} | {round(statistics.mean(vals), 1)} |")

    lines.append("\n## Note méthodologique\n")
    lines.append(
        "Une seule connexion capturée par combinaison : la taille des messages de handshake TLS/QUIC est "
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
        "testée alors qu'il s'agit d'un message de taille quasi fixe)."
    )

    path.write_text("\n".join(lines))


def main():
    ap = argparse.ArgumentParser(description="Agrégation et analyse de la taille du trafic PCAP.")
    ap.add_argument("--input-dir", default=Path("captures"), type=Path, help="Dossier racine contenant les captures")
    ap.add_argument("--out-dir", default=Path("results_traffic"), type=Path, help="Dossier de sortie des résultats")
    args = ap.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)

    try:
        rows = load_all(args.input_dir)
    except RuntimeError as e:
        print(f"ERREUR: {e}")
        return

    print(f"\n[+] {len(rows)} combinaison(s) analysée(s) depuis {args.input_dir}")
    if not rows:
        return

    csv_file = args.out_dir / "traffic_size_summary.csv"
    report_file = args.out_dir / "traffic_size_report.md"

    write_csv(csv_file, rows)
    write_report(report_file, rows)

    print(f"[+] Fichiers écrits dans {args.out_dir}/: traffic_size_summary.csv, traffic_size_report.md")


if __name__ == "__main__":
    main()
