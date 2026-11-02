#!/usr/bin/env python3
"""
parse_traffic_size.py — Agrège et analyse les pcap produits par
capture_traffic_matrix.sh et capture_pcap_demo.sh (versions HARMONISEES avec la
campagne, critique 4 de l'AE, TDSC-2026-09-3862).

Ce qui change par rapport a la version precedente :
  * Les parametres (protocole, auth, SIG, KEM, profil reseau) sont lus dans le
    fichier d'audit <base>.meta.txt ecrit par les scripts de capture, et plus
    devines depuis le nom de fichier (le profil "simple_loss1.3_delay62.51ms"
    etait absorbe dans le nom du KEM ; "campaign"/"network_profile" etaient
    decales selon l'arborescence).
  * Une capture n'entre dans les statistiques que si sa connexion est VALIDE :
    conn_ok=true, App-bytes=100, aucun paquet perdu par tcpdump. Les autres sont
    listees dans traffic_size_excluded.csv.
  * Les captures SANS .meta.txt (anciennes : TLS mesure avec openssl s_client,
    sans echange applicatif) sont EXCLUES par defaut : elles ne decrivent pas la
    meme operation que QUIC. --include-legacy pour les garder (a declarer).
  * Le keylog n'est associe que par nom exact (plus de "premier .log du dossier",
    qui pouvait attribuer la cle d'une AUTRE combinaison).
  * Nouvelles colonnes : octets IP, repartition client->serveur / serveur->client
    et ratio S->C / C->S (amplification), temps du client (handshake / App-ready).
  * Le rapport separe le profil IDEAL (taille deterministe) des profils degrades
    (une connexion = un tirage, retransmissions incluses : indicatif seulement).

Necessite tshark (sudo apt-get install -y tshark).

USAGE:
    python3 parse_traffic_size.py --input-dir launchers/captures/pcap_demo --out-dir results_traffic
    python3 parse_traffic_size.py --input-dir captures/traffic_size --out-dir results_traffic_size
"""

from __future__ import annotations  # compat Python < 3.10

import argparse
import csv
import re
import shutil
import statistics
import subprocess
from collections import defaultdict
from pathlib import Path

PORT = "4433"
IDEAL_PROFILE = "none"

# Repli (captures SANS meta, seulement avec --include-legacy). Le profil reseau
# eventuel (peut contenir '_' et '.') est suivi de _YYYYMMDD_HHMMSS.
FNAME_RE = re.compile(
    r"^(?:capture_)?(tls|quic)_(single|mutual)_([^_]+)_(.+?)"
    r"(?:_[A-Za-z0-9_.\-]+?_\d{8}_\d{6})?(?:_sslkeys\.log|\.pcap)?$"
)

HANDSHAKE_TYPE_NAMES = {
    "0": "HelloRequest", "1": "ClientHello", "2": "ServerHello",
    "4": "NewSessionTicket", "8": "EncryptedExtensions", "11": "Certificate",
    "13": "CertificateRequest", "15": "CertificateVerify", "20": "Finished",
}
TYPE_COLUMNS = [
    "ClientHello", "ServerHello", "EncryptedExtensions", "Certificate",
    "CertificateVerify", "Finished", "CertificateRequest", "NewSessionTicket",
]


def classify_kem(kem: str) -> str:
    """Classifie le KEM en classique, hybride ou PQ pur."""
    k = kem.lower().replace("-", "")
    is_pq = any(tag in k for tag in ("mlkem", "hqc", "kyber"))
    is_classical = any(tag in k for tag in ("p256", "p384", "p521", "x25519", "x448"))
    if is_pq and is_classical:
        return "hybride"
    if is_pq:
        return "pq_pur"
    return "classique"


# ── tshark ───────────────────────────────────────────────────────────────────
def run_tshark(pcap: Path, keylog: Path | None, fields_args: list[str], extra_filter: str = "") -> str:
    cmd = ["tshark", "-r", str(pcap)]
    if keylog is not None and keylog.exists() and keylog.stat().st_size > 0:
        cmd += ["-o", f"tls.keylog_file:{keylog}"]
    port_filter = f"(tcp.port=={PORT} or udp.port=={PORT})"
    display_filter = port_filter if not extra_filter else f"{port_filter} and {extra_filter}"
    cmd += ["-Y", display_filter] + fields_args
    return subprocess.run(cmd, capture_output=True, text=True).stdout


def _first_int(s: str) -> int:
    tok = s.strip().split(",")[0].strip()
    return int(tok) if tok.isdigit() else 0


def analyze_pcap(pcap: Path, keylog: Path | None, mtu: int = 1500) -> dict:
    """
    Taille reelle sur le fil. Le port PORT est celui du SERVEUR : une trame dont
    le port SOURCE est PORT va du serveur vers le client (S->C).
    frame.len = trame complete (en-tete Ethernet de 14 octets inclus) ;
    ip_bytes  = ip.len (couche IP, comparable a la litterature).
    oversize  = nombre de trames > mtu + 14 : impossible sur une liaison de MTU
    `mtu`, donc signe de super-trames GSO/GRO (typiquement UDP GSO de MsQuic)
    dans la capture -> nombre de paquets et octets ne refletent plus le fil.
    """
    out = run_tshark(pcap, keylog, ["-T", "fields", "-e", "frame.len", "-e", "ip.len",
                                    "-e", "tcp.srcport", "-e", "udp.srcport"])
    total_bytes = ip_bytes = total_packets = 0
    c2s_b = c2s_n = s2c_b = s2c_n = 0
    max_frame = oversize = 0
    for line in out.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        parts += [""] * (4 - len(parts))
        flen = _first_int(parts[0])
        if flen == 0:
            continue
        total_bytes += flen
        max_frame = max(max_frame, flen)
        if flen > mtu + 14:
            oversize += 1
        ip_bytes += _first_int(parts[1])
        total_packets += 1
        src_port = (parts[2].strip() or parts[3].strip()).split(",")[0]
        if src_port == PORT:
            s2c_b += flen
            s2c_n += 1
        else:
            c2s_b += flen
            c2s_n += 1

    by_type: dict[str, int] = defaultdict(int)
    if keylog is not None and keylog.exists() and keylog.stat().st_size > 0:
        ht_out = run_tshark(pcap, keylog,
                            ["-T", "fields", "-e", "tls.handshake.type", "-e", "tls.handshake.length"],
                            extra_filter="tls.handshake.type")
        for line in ht_out.splitlines():
            parts = line.split("\t")
            if len(parts) != 2:
                continue
            types, lengths = parts[0].split(","), parts[1].split(",")
            if len(types) != len(lengths):
                continue
            for t, ln in zip(types, lengths):
                try:
                    msg_len = int(ln)
                except ValueError:
                    continue
                by_type[HANDSHAKE_TYPE_NAMES.get(t.strip(), f"type_{t.strip()}")] += msg_len

    return {
        "total_bytes": total_bytes, "ip_bytes": ip_bytes, "total_packets": total_packets,
        "c2s_bytes": c2s_b, "c2s_packets": c2s_n, "s2c_bytes": s2c_b, "s2c_packets": s2c_n,
        "max_frame": max_frame, "oversize": oversize,
        "by_type": dict(by_type),
    }


# ── meta (ecrit par les scripts de capture) ──────────────────────────────────
def read_meta(pcap: Path) -> dict | None:
    path = pcap.with_name(pcap.stem + ".meta.txt")
    if not path.exists():
        return None
    meta: dict[str, str] = {}
    for line in path.read_text(errors="replace").splitlines():
        if line.startswith("--- "):          # debut de la sortie brute du client
            break
        for tok in line.split():
            if "=" in tok:
                k, v = tok.split("=", 1)
                meta[k] = v
    return meta


def meta_problems(meta: dict) -> list[str]:
    """Raisons d'invalidite d'une capture (liste vide = valide)."""
    problems = []
    if meta.get("conn_ok") != "true":
        problems.append("conn_ok!=true")
    if meta.get("capture_ok") == "false":
        problems.append("capture_ok=false")
    if meta.get("app_bytes") != "100":
        problems.append(f"app_bytes={meta.get('app_bytes', 'NA')}")
    if meta.get("tcpdump_dropped_by_kernel", "NA") != "0":
        problems.append(f"tcpdump_dropped={meta.get('tcpdump_dropped_by_kernel', 'NA')}")
    if "oversize_frames" in meta and meta["oversize_frames"] != "0":
        problems.append(f"oversize_frames={meta['oversize_frames']}")
    return problems


def _num(s: str | None):
    try:
        return float(s)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return "NA"


# ── chargement ───────────────────────────────────────────────────────────────
def load_all(input_dir: Path, include_legacy: bool):
    if not shutil.which("tshark"):
        raise RuntimeError("tshark introuvable — installe-le avec : sudo apt-get install -y tshark")

    rows, excluded = [], []
    pcap_files = sorted(input_dir.rglob("*.pcap"))
    if not pcap_files:
        print(f"[!] Aucun fichier .pcap trouvé sous {input_dir}")
        return rows, excluded

    for pcap in pcap_files:
        meta = read_meta(pcap)
        keylog = pcap.with_name(pcap.stem + "_sslkeys.log")
        if not keylog.exists() or keylog.stat().st_size == 0:
            keylog = None                      # PAS de repli sur un autre .log

        if meta is not None:
            problems = meta_problems(meta)
            if problems:
                excluded.append({"pcap_file": pcap.name, "reason": ";".join(problems)})
                print(f"  [EXCLU] {pcap.name}: {';'.join(problems)}")
                continue
            protocol, auth_mode = meta.get("protocol", "unknown"), meta.get("auth", "single")
            sig_alg, kem = meta.get("sig", "unknown"), meta.get("kem", "none")
            network_profile = meta.get("network_profile", IDEAL_PROFILE)
            harmonized = "yes"
        else:
            if not include_legacy:
                excluded.append({"pcap_file": pcap.name,
                                 "reason": "legacy: pas de .meta.txt (capture avant harmonisation TLS/QUIC)"})
                print(f"  [EXCLU] {pcap.name}: legacy (pas de .meta.txt)")
                continue
            m = FNAME_RE.search(pcap.name)
            if not m:
                excluded.append({"pcap_file": pcap.name, "reason": "legacy: nom non reconnu"})
                continue
            protocol, auth_mode, sig_alg, kem = m.groups()
            network_profile = "unknown"
            harmonized = "no"

        try:
            mtu = int((meta or {}).get("mtu", "1500"))
        except ValueError:
            mtu = 1500
        res = analyze_pcap(pcap, keylog, mtu)
        if res["oversize"] > 0:
            reason = (f"oversize_frames={res['oversize']} (max {res['max_frame']} o > MTU+14={mtu + 14}): "
                      "GSO/GRO actif pendant la capture")
            excluded.append({"pcap_file": pcap.name, "reason": reason})
            print(f"  [EXCLU] {pcap.name}: {reason}")
            continue
        if res["total_packets"] == 0:
            excluded.append({"pcap_file": pcap.name, "reason": "aucun paquet sur le port 4433"})
            print(f"  [EXCLU] {pcap.name}: aucun paquet sur le port {PORT}")
            continue

        row = {
            "network_profile": network_profile,
            "protocol": protocol, "auth_mode": auth_mode,
            "sig_alg": sig_alg, "kem": kem, "kem_class": classify_kem(kem),
            "pcap_file": pcap.name, "harmonized": harmonized,
            "mtu": (meta or {}).get("mtu", "NA"),
            "total_bytes": res["total_bytes"], "ip_bytes": res["ip_bytes"],
            "total_packets": res["total_packets"], "max_frame_len": res["max_frame"],
            "c2s_bytes": res["c2s_bytes"], "c2s_packets": res["c2s_packets"],
            "s2c_bytes": res["s2c_bytes"], "s2c_packets": res["s2c_packets"],
            "s2c_c2s_ratio": round(res["s2c_bytes"] / res["c2s_bytes"], 2) if res["c2s_bytes"] else "NA",
            "client_handshake_ms": _num((meta or {}).get("handshake_ms")),
            "client_app_ready_ms": _num((meta or {}).get("app_ready_ms")),
        }
        for t in TYPE_COLUMNS:
            row[f"{t}_bytes"] = res["by_type"].get(t, "NA")
        rows.append(row)
        print(f"  [{protocol.upper()}] {sig_alg} / {kem} ({row['kem_class']}) [{network_profile}]: "
              f"{res['total_bytes']} o, {res['total_packets']} paquets "
              f"(C->S {res['c2s_bytes']} o / S->C {res['s2c_bytes']} o)")
    return rows, excluded


# ── sorties ──────────────────────────────────────────────────────────────────
def write_csv(path: Path, rows: list[dict]):
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


def write_report(path: Path, rows: list[dict], excluded: list[dict]):
    path.parent.mkdir(parents=True, exist_ok=True)
    L = ["# Taille du trafic — comparaison classique / hybride / PQ pur\n"]

    ideal = [r for r in rows if r["network_profile"] in (IDEAL_PROFILE, "unknown")]
    degraded = [r for r in rows if r not in ideal]

    L.append("## Profil idéal (réseau sans perte ni délai) — taille déterministe\n")
    L.append("| Protocole | Auth | SIG_ALG | KEM | Classe | Total (o) | IP (o) | Paquets | C→S (o) | S→C (o) | S→C / C→S | ClientHello | Certificate |")
    L.append("|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    for r in sorted(ideal, key=lambda r: (r["protocol"], r["auth_mode"], r["kem_class"], r["sig_alg"], r["kem"])):
        L.append(f"| {r['protocol']} | {r['auth_mode']} | {r['sig_alg']} | {r['kem']} | {r['kem_class']} | "
                 f"{r['total_bytes']} | {r['ip_bytes']} | {r['total_packets']} | {r['c2s_bytes']} | "
                 f"{r['s2c_bytes']} | {r['s2c_c2s_ratio']} | {r['ClientHello_bytes']} | {r['Certificate_bytes']} |")

    L.append("\n## Moyenne du total d'octets par profil, protocole, authentification et classe de KEM\n")
    groups = defaultdict(list)
    for r in rows:
        groups[(r["network_profile"], r["protocol"], r["auth_mode"], r["kem_class"])].append(r["total_bytes"])
    L.append("| Profil | Protocole | Auth | Classe KEM | N | Total moyen (o) |")
    L.append("|---|---|---|---|---|---|")
    for (prof, proto, auth, klass), vals in sorted(groups.items()):
        L.append(f"| {prof} | {proto} | {auth} | {klass} | {len(vals)} | {round(statistics.mean(vals), 1)} |")

    if degraded:
        L.append("\n## Profils dégradés — INDICATIF uniquement\n")
        L.append("Sous perte, une connexion capturée = UN tirage aléatoire (retransmissions comprises) : "
                 "ces tailles ne sont pas déterministes et ne doivent pas servir de comparaison de moyennes.\n")
        L.append("| Profil | Protocole | SIG_ALG | KEM | Total (o) | Paquets | S→C / C→S |")
        L.append("|---|---|---|---|---|---|---|")
        for r in sorted(degraded, key=lambda r: (r["network_profile"], r["protocol"], r["sig_alg"], r["kem"])):
            L.append(f"| {r['network_profile']} | {r['protocol']} | {r['sig_alg']} | {r['kem']} | "
                     f"{r['total_bytes']} | {r['total_packets']} | {r['s2c_c2s_ratio']} |")

    # Verification empirique de l'hypothese "deterministe" (>1 capture identique)
    rep = defaultdict(list)
    for r in ideal:
        rep[(r["protocol"], r["auth_mode"], r["sig_alg"], r["kem"])].append(r["total_bytes"])
    multi = {k: v for k, v in rep.items() if len(v) > 1}
    if multi:
        L.append("\n## Vérification du déterminisme (captures répétées, profil idéal)\n")
        L.append("| Protocole | Auth | SIG_ALG | KEM | N | min | max | écart |")
        L.append("|---|---|---|---|---|---|---|---|")
        for (proto, auth, sig, kem), v in sorted(multi.items()):
            L.append(f"| {proto} | {auth} | {sig} | {kem} | {len(v)} | {min(v)} | {max(v)} | {max(v) - min(v)} |")

    if excluded:
        L.append(f"\n## Captures exclues ({len(excluded)})\n")
        L.append("Détail dans `traffic_size_excluded.csv`. Raisons : " +
                 ", ".join(sorted({e['reason'] for e in excluded})) + ".")

    L.append("\n## Note méthodologique\n")
    L.append(
        "Chaque capture est celle de la connexion EXACTE mesurée par la campagne : TLS via "
        "`s_connection -www /payload.bin` et QUIC via `quics_connection`, tous deux avec un échange "
        "applicatif de 100 octets, sans tickets de reprise, MTU fixé, offloads TSO/GSO/GRO coupés, "
        "tcpdump filtré sur le port 4433. Une capture n'est retenue que si sa connexion a abouti "
        "(App-ready numérique, 100 octets de corps) et si tcpdump n'a perdu aucun paquet.\n\n"
        "`Total` = somme de `frame.len` (trame complète, en-tête Ethernet de 14 octets inclus) ; `IP` = "
        "somme de `ip.len`. Le total inclut la fermeture de connexion (RST côté TLS, CONNECTION_CLOSE "
        "côté QUIC) et les ACK purs : c'est le coût complet de la connexion, pas seulement du handshake. "
        "Le ratio S→C / C→S est calculé sur TOUTE la connexion : il ne mesure PAS la limite d'amplification "
        "de QUIC (3× les octets reçus AVANT validation d'adresse), qui exige une analyse dédiée de l'ordre des "
        "paquets sur une capture avec délai.\n\n"
        "Dans le profil idéal, la taille des messages est déterministe pour une combinaison donnée "
        "(aux champs aléatoires et à la longueur DER des signatures ECDSA près, ±1-2 octets) : la section "
        "« Vérification du déterminisme » le contrôle lorsqu'une combinaison est capturée plusieurs fois. "
        "Les colonnes par type de message (`ClientHello_bytes`, `Certificate_bytes`...) utilisent "
        "`tls.handshake.length` (corps du message, en-tête de 4 octets exclu) et non la taille de la trame "
        "qui le contient, plusieurs messages pouvant partager une trame. Elles exigent le fichier de clés "
        "de la MÊME connexion (côté serveur pour TLS, côté client pour QUIC)."
    )
    path.write_text("\n".join(L) + "\n")


def main():
    ap = argparse.ArgumentParser(description="Agrégation et analyse de la taille du trafic PCAP.")
    ap.add_argument("--input-dir", default=Path("captures"), type=Path, help="Dossier racine contenant les captures")
    ap.add_argument("--out-dir", default=Path("results_traffic"), type=Path, help="Dossier de sortie")
    ap.add_argument("--include-legacy", action="store_true",
                    help="Garde les captures sans .meta.txt (avant harmonisation TLS/QUIC) ; à déclarer dans l'article.")
    args = ap.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)

    try:
        rows, excluded = load_all(args.input_dir, args.include_legacy)
    except RuntimeError as e:
        print(f"ERREUR: {e}")
        raise SystemExit(1)

    print(f"\n[+] {len(rows)} capture(s) retenue(s), {len(excluded)} exclue(s) depuis {args.input_dir}")
    write_csv(args.out_dir / "traffic_size_excluded.csv", excluded)
    if not rows:
        print("[!] Rien à agréger.")
        raise SystemExit(1)
    write_csv(args.out_dir / "traffic_size_summary.csv", rows)
    write_report(args.out_dir / "traffic_size_report.md", rows, excluded)
    print(f"[+] Fichiers écrits dans {args.out_dir}/ : traffic_size_summary.csv, traffic_size_report.md"
          + (", traffic_size_excluded.csv" if excluded else ""))


if __name__ == "__main__":
    main()
