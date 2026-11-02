#!/usr/bin/env python3
"""
analyze_mechanism.py -- Point 3 du prescreen TDSC (TDSC-2026-09-3862).

Reconstruit, pour CHAQUE connexion de la campagne mecanistique (Launcher avec
PER_CONN_PCAP=1 : UN pcap continu par bloc et par paire SIG_ALG/KEM, plus
conn_windows.csv), la chaine

    signature -> taille des messages -> paquetisation -> pertes/recuperation
              -> latence "application-ready"

et joint la duree mesuree par le client (lignes "Handshake duration" /
"App-ready duration" du log).

POINT DE CAPTURE ET LIMITES (a documenter dans l'article)
  tcpdump tourne dans le conteneur CLIENT sur eth0. Sous Linux, l'ecoute
  "egress" se fait APRES la file qdisc, donc :
    (a) un paquet supprime par netem n'est JAMAIS visible dans le pcap de
        l'interface qui l'emet. Une capture cote serveur ne changerait rien
        pour les pertes serveur->client : elles restent invisibles.
    (b) les paquets emis par le client sont horodates APRES le delai netem
        du client (decalage de +delay_ms_oneway par rapport a l'horloge du
        processus). Les paquets recus (serveur->client) sont horodates a
        leur arrivee reelle. Les durees "pcap" (t_first_s2c_payload_ms,
        capture_duration_ms...) ne sont donc PAS directement comparables aux
        durees "processus" (handshake_ms, app_ready_ms) : elles servent aux
        comparaisons internes, pas a reconstituer ces durees.
  Consequences pour la detection des pertes serveur->client :
    - QUIC : une retransmission recoit un NOUVEAU numero de paquet, donc un
      trou de numero apparait meme si le paquet perdu etait le dernier.
    - TCP  : une retransmission reutilise le numero de sequence. Si le
      segment perdu est le dernier du vol (perte en queue) ou fait partie du
      premier vol, aucun trou n'apparait et la retransmission n'est pas
      signalee. Ces pertes ne sont detectables que par leur cout temporel :
      c'est le role de la colonne loss_evidence (voir plus bas).
    - Verite terrain au niveau BLOC : qdisc_stats_*.csv du launcher (paquets
      reellement supprimes par netem, cote serveur et cote client), joint
      dans le resume par bloc.

ATTRIBUTION DES PAQUETS A UNE CONNEXION
  Par FLUX (tcp.stream / udp.stream), pas par fenetre temporelle : comme les
  paquets client sont retardes par netem apres la fin du processus, les
  derniers paquets d'une connexion (ACK final, RST) tombent dans la fenetre
  de la connexion SUIVANTE. Le premier paquet d'un flux (SYN / Initial) est
  lui toujours dans la fenetre de sa propre connexion : le flux est rattache
  a l'execution dont la fenetre contient son premier paquet.

loss_evidence (par connexion)
  observed              : un indicateur de perte/retransmission est present
  suspected_unobserved  : aucun indicateur, mais app_ready depasse de plus de
                          max(--unobs-rtt-frac x RTT, --unobs-floor-ms) la
                          ligne de base du bloc (quantile --baseline-quantile
                          des app_ready du bloc) : perte probable non vue
  none                  : aucun indicateur, pas de surcout
  no_measure            : pas d'app_ready (timeout / echec)
  pn_undecodable        : QUIC, paquets serveur presents mais aucun dechiffre
                          (premier vol perdu, cles inutilisables) : trous
                          inobservables, a traiter comme suspect
  La ligne de base est un quantile bas du bloc lui-meme : si presque toutes
  les connexions d'un bloc subissent une perte, elle est sur-estimee.

USAGE
    python3 analyze_mechanism.py --root captures/ \\
        --out mechanism_connections.csv --summary mechanism_blocks.csv
    python3 analyze_mechanism.py --selftest      # test sur donnees synthetiques

PREREQUIS : tshark (teste avec 4.2.x, comme measure_timer_asymmetry.py).
"""

import argparse
import csv
import glob
import os
import re
import statistics
import subprocess
import sys
from bisect import bisect_right
from collections import defaultdict

FIELDS = [
    "frame.number", "frame.time_epoch", "ip.src", "ip.dst", "frame.len",
    "tcp.stream", "udp.stream", "tcp.len", "tcp.flags.syn",
    "tcp.analysis.retransmission", "tcp.analysis.fast_retransmission",
    "tcp.analysis.spurious_retransmission", "tcp.analysis.lost_segment",
    "tcp.analysis.out_of_order", "tcp.analysis.duplicate_ack",
    "quic.long.packet_type", "quic.frame_type",
    "quic.crypto.offset", "quic.crypto.length", "quic.packet_number",
    "arp.opcode",
]

EXEC_RE = re.compile(r"^Execution\s+(\d+)\s*-")
HS_RE = re.compile(r"Handshake duration:\s*([\d.]+|NaN)\s*ms")
APP_RE = re.compile(r"App-ready duration:\s*([\d.]+|NaN)\s*ms")
LABEL_RE = re.compile(
    r"^(?:simple_loss(?P<sl>[\d.]+)_delay(?P<sd>[\d.]+)ms"
    r"|lossonly_loss(?P<ll>[\d.]+)"
    r"|delayonly_delay(?P<dd>[\d.]+)ms"
    r"|(?P<ge>ge-(?:mild|severe)-\d)_delay(?P<gd>[\d.]+)ms"
    r"|(?P<plain>none|stable|unstable))"
    r"(?:_mtu(?P<mtu>\d+))?(?:_dir(?P<dir>c2s|both))?"
    # suffixes ajoutes par le Launcher : chaine realiste, padding, pcap, micro-lots
    r"(?P<chain>__chain2)?(?:__pad(?P<padb>\d+)b)?(?:__padto(?P<padto>\d+))?(?P<pcap>__pcap)?(?:__mb(?P<mb>\d+))?$"
)
GE_LOSS = {"1": 1.0, "2": 2.0, "5": 5.0}


def parse_label_extras(label):
    """Facteurs de design portes par les suffixes du label :
    (chain_depth, cert_pad_bytes, cert_pad_target_der, micro_batches)."""
    label = label.replace("__qmtu", "")  # suffixe QUIC_MTU_SYNC, independant de l'ordre
    m = LABEL_RE.match(label)
    if not m:
        return (None, None, None, None)
    g = m.groupdict()
    return (2 if g["chain"] else 1, int(g["padb"] or 0), int(g["padto"] or 0), int(g["mb"] or 1))

# Colonnes non numeriques ou constantes par bloc : exclues des medianes/moyennes
NON_STAT_COLS = {
    "protocol", "auth_mode", "label", "sig_alg", "kem", "block_index", "n_blocks",
    "conn_index", "loss_pct", "delay_ms_oneway", "loss_process", "mtu",
    "loss_direction", "loss_evidence", "baseline_app_ready_ms", "s2c_pn_mode",
    "round_index", "chain_depth", "cert_pad_bytes", "cert_pad_target_der", "micro_batches",
}


# ───────────────────────── utilitaires ─────────────────────────────────────
def truthy(v):
    return str(v).strip().lower() in ("1", "true")


def to_float(v, default=None):
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def to_int(v, default=None):
    f = to_float(v)
    return default if f is None else int(f)


def split_list(v):
    return [x for x in str(v).split(",") if x.strip() != ""]


def parse_label(label):
    """Retourne (loss_pct, delay_ms, loss_process, mtu, direction)."""
    label = label.replace("__qmtu", "")  # suffixe QUIC_MTU_SYNC, independant de l'ordre
    m = LABEL_RE.match(label)
    if not m:
        return (None, None, "?", 1500, "s2c")
    g = m.groupdict()
    mtu = int(g["mtu"]) if g["mtu"] else 1500
    direction = g["dir"] or "s2c"
    if g["sl"] is not None:
        return (float(g["sl"]), float(g["sd"]), "iid", mtu, direction)
    if g["ll"] is not None:
        return (float(g["ll"]), 0.0, "iid", mtu, direction)
    if g["dd"] is not None:
        return (0.0, float(g["dd"]), "none", mtu, direction)
    if g["ge"] is not None:
        loss = GE_LOSS.get(g["ge"].rsplit("-", 1)[1])
        return (loss, float(g["gd"]), g["ge"].rsplit("-", 1)[0], mtu, direction)
    return (None, 0.0, g["plain"], mtu, direction)


# ───────────────────────── tshark ──────────────────────────────────────────
def run_tshark(pcap, keylog, timeout=900):
    cmd = ["tshark", "-r", pcap]
    if keylog and os.path.isfile(keylog) and os.path.getsize(keylog) > 0:
        cmd += ["-o", f"tls.keylog_file:{keylog}"]
    cmd += ["-Y", "tcp.port==4433 or udp.port==4433 or arp", "-T", "fields",
            "-E", "separator=/t", "-E", "occurrence=a"]
    for f in FIELDS:
        cmd += ["-e", f]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        print(f"[WARN] tshark a depasse {timeout}s sur {pcap} (option --tshark-timeout).",
              file=sys.stderr)
        return ""
    if out.returncode != 0:
        print(f"[WARN] tshark a echoue sur {pcap}: {out.stderr[:300]!r}", file=sys.stderr)
        return ""
    return out.stdout


def parse_rows(text):
    rows = []
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        parts += [""] * (len(FIELDS) - len(parts))
        r = dict(zip(FIELDS, parts))
        t = to_float(r["frame.time_epoch"])
        if t is None:
            continue
        r["t"] = t
        r["len"] = int(to_float(r["frame.len"], 0))
        r["tcplen"] = int(to_float(r["tcp.len"], 0) or 0)
        if r["tcp.stream"].strip() != "":
            r["stream"] = "t" + r["tcp.stream"].strip()
        elif r["udp.stream"].strip() != "":
            r["stream"] = "u" + r["udp.stream"].strip()
        else:
            r["stream"] = None
        rows.append(r)
    return rows


# ───────────────────────── fenetres temporelles par connexion ─────────────
def load_windows(csv_path):
    """Lit conn_windows.csv (execution,t_start_epoch,t_end_epoch) -> liste
    de (execution:int, t_start:float, t_end:float) triee par t_start."""
    out = []
    with open(csv_path, newline="") as f:
        for row in csv.DictReader(f):
            ex = row.get("execution")
            ts = to_float(row.get("t_start_epoch"))
            te = to_float(row.get("t_end_epoch"))
            if ex is None or ts is None or te is None:
                continue
            try:
                out.append((int(ex), ts, te))
            except ValueError:
                continue
    out.sort(key=lambda w: w[1])
    return out


def split_rows_by_stream(rows, windows, slack=0.001):
    """Rattache chaque FLUX a l'execution dont la fenetre contient son
    premier paquet (SYN / Initial, emis apres T_START du processus et avant
    sa fin). Retourne ({execution: [rows]}, n_flux_sans_fenetre, n_warmup).

    n_warmup = flux dont le premier paquet precede la premiere fenetre :
    connexion d'echauffement non chronometree du client (WARMUP=1), attendue
    et sans warning.

    Pourquoi pas un decoupage temporel des paquets : les paquets client sont
    horodates apres le delai netem ; l'ACK final et le RST d'une connexion
    tombent donc apres T_END, dans la fenetre de la connexion suivante."""
    streams = defaultdict(list)
    for r in rows:
        if r["stream"] is not None:
            streams[r["stream"]].append(r)
    starts = [w[1] for w in windows]
    by_exec = defaultdict(list)
    unassigned = 0
    warmup = 0
    for rs in streams.values():
        rs.sort(key=lambda r: r["t"])
        t0 = rs[0]["t"]
        j = bisect_right(starts, t0 + slack) - 1
        if j < 0:
            warmup += 1
        elif t0 <= windows[j][2] + slack:
            by_exec[windows[j][0]].extend(rs)
        else:
            unassigned += 1
    for ex in by_exec:
        by_exec[ex].sort(key=lambda r: r["t"])
    return by_exec, unassigned, warmup


# ───────────────────────── metriques communes ──────────────────────────────
def common_metrics(rows, client_ip):
    t0 = rows[0]["t"]
    c2s = [r for r in rows if r["ip.src"] == client_ip]
    s2c = [r for r in rows if r["ip.src"] != client_ip]
    return t0, c2s, s2c, {
        "n_pkts": len(rows),
        "bytes_total": sum(r["len"] for r in rows),
        "pkts_c2s": len(c2s), "pkts_s2c": len(s2c),
        "bytes_c2s": sum(r["len"] for r in c2s),
        "bytes_s2c": sum(r["len"] for r in s2c),
        "capture_duration_ms": round((rows[-1]["t"] - t0) * 1000, 3),
    }


# ───────────────────────── TLS / TCP ───────────────────────────────────────
def metrics_tls(rows, client_ip):
    t0, c2s, s2c, m = common_metrics(rows, client_ip)

    def count(sub, *fields):
        return sum(1 for r in sub if any(truthy(r[f]) for f in fields))

    m["s2c_payload_segments"] = sum(1 for r in s2c if r["tcplen"] > 0)
    m["s2c_payload_bytes"] = sum(r["tcplen"] for r in s2c)
    first = next((r for r in s2c if r["tcplen"] > 0), None)
    m["t_first_s2c_payload_ms"] = round((first["t"] - t0) * 1000, 3) if first else None

    c2s_payload = [r for r in c2s if r["tcplen"] > 0]
    second = c2s_payload[1] if len(c2s_payload) > 1 else None
    m["t_client_second_payload_ms"] = round((second["t"] - t0) * 1000, 3) if second else None
    m["s2c_segments_before_client_reply"] = (
        sum(1 for r in s2c if r["tcplen"] > 0 and r["t"] < second["t"]) if second else None
    )

    retrans = ("tcp.analysis.retransmission", "tcp.analysis.fast_retransmission",
               "tcp.analysis.spurious_retransmission")
    for name, sub in (("s2c", s2c), ("c2s", c2s)):
        m[f"{name}_tcp_retransmissions"] = count(sub, *retrans)
        m[f"{name}_tcp_lost_segment_events"] = count(sub, "tcp.analysis.lost_segment")
        m[f"{name}_tcp_out_of_order"] = count(sub, "tcp.analysis.out_of_order")
        m[f"{name}_tcp_dup_acks"] = count(sub, "tcp.analysis.duplicate_ack")
    # SYN / SYN-ACK multiples : retransmission du handshake TCP, que tshark ne
    # signale pas toujours via tcp.analysis.retransmission.
    m["c2s_syn_packets"] = count(c2s, "tcp.flags.syn")
    m["s2c_synack_packets"] = count(s2c, "tcp.flags.syn")
    return m


# ───────────────────────── QUIC ────────────────────────────────────────────
def _spaces_of_row(r):
    """Liste de (espace, numero_de_paquet) pour un datagramme UDP (paquets
    coalesces). Un paquet a en-tete court (1-RTT) n'a pas de type long : la
    liste des numeros est alors plus longue d'un element que celle des types."""
    types = split_list(r["quic.long.packet_type"])
    pns = split_list(r["quic.packet_number"])
    kind = {"0": "initial", "2": "handshake"}
    labels = [kind.get(t.strip(), "other") for t in types]
    if len(pns) == len(labels) + 1:
        labels.append("1rtt")
    if len(pns) != len(labels) or not pns:
        return []
    out = []
    for lab, pn in zip(labels, pns):
        v = to_float(pn)
        if v is not None:
            out.append((lab, int(v)))
    return out


def pn_spaces(rows, client_ip):
    """{espace: ensemble de numeros de paquet} des paquets serveur."""
    seen = defaultdict(set)
    for r in rows:
        if r["ip.src"] == client_ip:
            continue
        for lab, pn in _spaces_of_row(r):
            seen[lab].add(pn)
    return seen


def pn_overlap(seen):
    """True si un meme numero apparait dans deux espaces differents : la pile
    numerote alors PAR ESPACE (RFC 9000 : chaque espace repart de 0)."""
    vals = [v for s_ in seen.values() for v in s_]
    return len(vals) != len(set(vals))


def infer_pn_mode(conn_seen):
    """Mode de numerotation d'une pile, par vote sur toutes les connexions
    d'une paire : "per_space" si des numeros se recouvrent entre espaces dans
    au moins 10 % des connexions, sinon "global" (un seul compteur partage
    par Initial/Handshake/1-RTT, comme aioquic et, a verifier, MsQuic).
    Calculer des trous par espace sur une pile a compteur global produit de
    FAUSSES pertes (observe sur du trafic aioquic reel)."""
    usable = [s_ for s_ in conn_seen if sum(len(v) for v in s_.values()) >= 2]
    if not usable:
        return "per_space"
    frac = sum(1 for s_ in usable if pn_overlap(s_)) / len(usable)
    return "per_space" if frac >= 0.10 else "global"


def metrics_quic(rows, client_ip, pn_mode="auto"):
    t0, c2s, s2c, m = common_metrics(rows, client_ip)

    def ftypes(r):
        out = []
        for x in split_list(r["quic.frame_type"]):
            try:
                out.append(int(x, 0))
            except ValueError:
                pass
        return out

    def types_long(r):
        return [x.strip() for x in split_list(r["quic.long.packet_type"])]

    # Paquets Initial/Handshake du serveur = "flight" d'authentification
    hs_rows = [r for r in s2c if set(types_long(r)) & {"0", "2"}]
    m["s2c_hs_space_datagrams"] = len(hs_rows)
    m["t_first_s2c_ms"] = round((s2c[0]["t"] - t0) * 1000, 3) if s2c else None
    m["t_last_s2c_hs_space_ms"] = round((hs_rows[-1]["t"] - t0) * 1000, 3) if hs_rows else None
    m["c2s_initial_datagrams"] = sum(1 for r in c2s if "0" in types_long(r))

    # Trous de numeros de paquet cote serveur = paquets perdus avant le client.
    # Une retransmission QUIC recoit un nouveau numero : meme une perte en
    # queue de flux cree un trou des que le paquet suivant arrive.
    seen = pn_spaces(rows, client_ip)
    decoded = sum(len(v) for v in seen.values())
    if pn_mode == "auto":
        pn_mode = "per_space" if pn_overlap(seen) else "global"
    m["s2c_pn_mode"] = pn_mode
    for lab in ("initial", "handshake", "1rtt"):
        m[f"s2c_lost_pn_{lab}"] = None
    if decoded == 0:
        m["s2c_lost_pn_total"] = None
        m["s2c_pn_decoded"] = 0
    elif pn_mode == "global":
        union = set().union(*seen.values())
        m["s2c_lost_pn_total"] = (max(union) + 1) - len(union)
        m["s2c_pn_decoded"] = decoded
    else:
        total = 0
        for lab in ("initial", "handshake", "1rtt"):
            if seen[lab]:
                lost = (max(seen[lab]) + 1) - len(seen[lab])
                m[f"s2c_lost_pn_{lab}"] = lost
                total += lost
            else:
                m[f"s2c_lost_pn_{lab}"] = 0
        m["s2c_lost_pn_total"] = total
        m["s2c_pn_decoded"] = decoded

    # Frames CRYPTO (taille et fragmentation du flight d'authentification)
    for name, sub in (("s2c", s2c), ("c2s", c2s)):
        frames = 0
        nbytes = 0
        for r in sub:
            n6 = sum(1 for t in ftypes(r) if t == 6)
            frames += n6
            nbytes += sum(int(to_float(x, 0)) for x in split_list(r["quic.crypto.length"]))
        m[f"{name}_crypto_frames"] = frames
        m[f"{name}_crypto_bytes"] = nbytes
        m[f"{name}_ping_frames"] = sum(1 for r in sub for t in ftypes(r) if t == 1)

    hd = next((r for r in s2c if 30 in ftypes(r)), None)   # HANDSHAKE_DONE = 0x1e
    m["t_handshake_done_ms"] = round((hd["t"] - t0) * 1000, 3) if hd else None
    return m


# ───────────────────────── indicateurs de perte ───────────────────────────
def loss_indicator_events(metrics, protocol):
    """Nombre d'indicateurs de perte/retransmission OBSERVES dans le pcap."""
    def g(k):
        v = metrics.get(k)
        return v if isinstance(v, (int, float)) else 0

    if protocol == "tls":
        return int(
            g("s2c_tcp_retransmissions") + g("s2c_tcp_lost_segment_events")
            + g("s2c_tcp_out_of_order")
            + g("c2s_tcp_retransmissions") + g("c2s_tcp_lost_segment_events")
            + g("c2s_tcp_out_of_order")
            + max(0, g("c2s_syn_packets") - 1) + max(0, g("s2c_synack_packets") - 1)
        )
    return int(g("s2c_lost_pn_total"))


def annotate_loss_evidence(out_rows, baseline_q=0.05, rtt_frac=0.5, floor_ms=20.0):
    """Ajoute baseline_app_ready_ms, recovery_excess_ms et loss_evidence."""
    groups = defaultdict(list)
    for r in out_rows:
        groups[(r["protocol"], r["auth_mode"], r["label"], r["sig_alg"], r["kem"],
                r["block_index"])].append(r)
    for rs in groups.values():
        vals = sorted(r["app_ready_ms"] for r in rs
                      if isinstance(r.get("app_ready_ms"), (int, float)))
        base = vals[int(baseline_q * (len(vals) - 1))] if vals else None
        rtt = 2.0 * (rs[0]["delay_ms_oneway"] or 0.0)
        thr = max(rtt_frac * rtt, floor_ms)
        for r in rs:
            r["baseline_app_ready_ms"] = round(base, 3) if base is not None else None
            app = r.get("app_ready_ms")
            if not isinstance(app, (int, float)) or base is None:
                r["recovery_excess_ms"] = None
                r["loss_evidence"] = "no_measure"
                continue
            r["recovery_excess_ms"] = round(app - base, 3)
            if (r["protocol"] == "quic" and r.get("s2c_pn_decoded") == 0
                    and (r.get("pkts_s2c") or 0) > 0):
                # Aucun paquet serveur dechiffre (ex. premier vol serveur perdu :
                # tshark ne connait plus la suite de chiffrement) : les trous de
                # numeros sont inobservables, la connexion ne doit pas passer
                # pour saine.
                r["loss_evidence"] = "pn_undecodable"
            elif r["loss_indicator_events"] > 0:
                r["loss_evidence"] = "observed"
            elif app - base > thr:
                r["loss_evidence"] = "suspected_unobserved"
            else:
                r["loss_evidence"] = "none"


# ───────────────────────── verite terrain qdisc ───────────────────────────
def load_qdisc(label_dir, b, n):
    """{(sig, kem, role): (paquets_emis, paquets_supprimes)} d'apres
    qdisc_stats_block<b>of<n>_seed*.csv ecrit par le launcher."""
    res = {}
    pattern = os.path.join(label_dir, f"qdisc_stats_block{b}of{n}_seed*.csv")
    for path in sorted(glob.glob(pattern)):
        with open(path, newline="") as f:
            for row in csv.DictReader(f):
                v = [to_int(row.get(k)) for k in
                     ("pkts_before", "dropped_before", "pkts_after", "dropped_after")]
                key = (row.get("sig_alg"), row.get("kem"), row.get("role"))
                if None in v:
                    res.setdefault(key, None)
                    continue
                d = (v[2] - v[0], v[3] - v[1])
                # Micro-lots : UNE ligne par tour et par role -> on SOMME les tours du bloc.
                prev = res.get(key)
                res[key] = d if prev is None else (prev[0] + d[0], prev[1] + d[1])
    return res


# ───────────────────────── logs de handshake ───────────────────────────────
def parse_log(path):
    """{execution: (handshake_ms|None, app_ready_ms|None)}
    Premiere valeur numerique conservee : une ligne NaN de secours qui suit
    une vraie mesure ne l'ecrase pas."""
    res = {}
    cur = None
    with open(path, errors="ignore") as f:
        for line in f:
            line = line.strip()
            m = EXEC_RE.match(line)
            if m:
                cur = int(m.group(1))
                res[cur] = [None, None]
                continue
            if cur is None:
                continue
            m = HS_RE.search(line)
            if m:
                if m.group(1) != "NaN" and res[cur][0] is None:
                    res[cur][0] = float(m.group(1))
            m = APP_RE.search(line)
            if m:
                if m.group(1) != "NaN" and res[cur][1] is None:
                    res[cur][1] = float(m.group(1))
    return {k: tuple(v) for k, v in res.items()}


# ───────────────────────── traitement d'un pcap ────────────────────────────
def analyze_pcap(pcap, protocol, keylog, text=None):
    """Metriques d'un pcap d'UNE connexion (utilise par l'autotest)."""
    if text is None:
        text = run_tshark(pcap, keylog)
    rows = parse_rows(text)
    if not rows:
        return None
    rows.sort(key=lambda r: r["t"])
    client_ip = rows[0]["ip.src"]
    if not client_ip:
        return None
    return metrics_tls(rows, client_ip) if protocol == "tls" else metrics_quic(rows, client_ip)


PATH_RE = re.compile(
    r"(?P<root>.*?)[/\\](?P<proto>tls|quic)[/\\](?P<auth>single|mutual)[/\\]"
    r"(?P<label>[^/\\]+)[/\\]pcap_perconn[/\\]block(?P<b>\d+)of(?P<n>\d+)(?:_mb(?P<r>\d+)of(?P<rn>\d+))?[/\\]"
    r"(?P<pair>[^/\\]+)[/\\]block\.pcap$"
)


def find_keylog(pdir, protocol, sig, kem):
    name = f"sslkeys_{'server' if protocol == 'tls' else 'client'}_{sig}_{kem}.log"
    p = os.path.join(pdir, name)
    if os.path.isfile(p):
        return p
    others = sorted(glob.glob(os.path.join(pdir, "sslkeys_*.log")))
    return others[0] if others else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root")
    ap.add_argument("--out", default="mechanism_connections.csv")
    ap.add_argument("--summary", default="mechanism_blocks.csv")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--tshark-timeout", type=int, default=900)
    ap.add_argument("--baseline-quantile", type=float, default=0.05)
    ap.add_argument("--unobs-rtt-frac", type=float, default=0.5)
    ap.add_argument("--unobs-floor-ms", type=float, default=20.0)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        return selftest()
    if not args.root:
        ap.error("--root requis (ou --selftest)")

    pcaps = sorted(glob.glob(os.path.join(args.root, "**", "pcap_perconn", "**", "block.pcap"),
                             recursive=True))
    if args.limit:
        pcaps = pcaps[: args.limit]
    print(f"[INFO] {len(pcaps)} capture(s) par paire (block.pcap) trouvees sous {args.root}", file=sys.stderr)

    out_rows = []
    qdisc_by_cell = {}
    n_pair_fail = 0
    n_conn_no_pkts = 0
    n_streams_unassigned = 0
    n_warmup_streams = 0
    for pcap in pcaps:
        m = PATH_RE.match(pcap.replace("\\", "/"))
        if not m:
            print(f"[WARN] chemin non reconnu : {pcap}", file=sys.stderr)
            continue
        g = m.groupdict()
        sig, kem = g["pair"].split("_", 1)
        loss, delay, process, mtu, direction = parse_label(g["label"])
        extras = parse_label_extras(g["label"])
        pdir = os.path.dirname(pcap)
        keylog = find_keylog(pdir, g["proto"], sig, kem)

        windows_csv = os.path.join(pdir, "conn_windows.csv")
        if not os.path.isfile(windows_csv):
            print(f"[WARN] conn_windows.csv absent pour {pdir} -- paire ignoree.", file=sys.stderr)
            n_pair_fail += 1
            continue
        windows = load_windows(windows_csv)
        if not windows:
            print(f"[WARN] conn_windows.csv vide pour {pdir} -- paire ignoree.", file=sys.stderr)
            n_pair_fail += 1
            continue

        text = run_tshark(pcap, keylog, args.tshark_timeout)
        rows = parse_rows(text)
        if not rows:
            print(f"[WARN] aucun paquet lisible dans {pcap} -- paire ignoree.", file=sys.stderr)
            n_pair_fail += 1
            continue

        by_exec, unassigned, warmup = split_rows_by_stream(rows, windows)
        n_streams_unassigned += unassigned
        n_warmup_streams += warmup
        if unassigned:
            print(f"[WARN] {unassigned} flux sans fenetre de connexion dans {pcap}", file=sys.stderr)

        # ARP (capture "port 4433 or arp") : verifie l'effet de resolution ARP
        # sur la 1re connexion. Avec WARMUP=1 les trames ARP precedent la 1re
        # fenetre ; avec WARMUP=0 elles tombent dans la fenetre de la connexion 1.
        arp_t = [r["t"] for r in rows if r["arp.opcode"].strip() != ""]
        first_start, first_end = windows[0][1], windows[0][2]
        extra = {
            "warmup_streams": warmup,
            "arp_frames_before_first_window": sum(1 for t in arp_t if t < first_start),
            "arp_frames_in_first_window": sum(1 for t in arp_t if first_start <= t <= first_end),
        }

        # Mode de numerotation QUIC de la pile (vote sur toutes les connexions)
        pair_pn_mode = "auto"
        if g["proto"] == "quic":
            seens = [pn_spaces(rs_, rs_[0]["ip.src"]) for rs_ in by_exec.values() if rs_]
            pair_pn_mode = infer_pn_mode(seens)
            print(f"[INFO] {g['pair']} bloc {g['b']} : numerotation QUIC serveur = {pair_pn_mode}",
                  file=sys.stderr)

        lp = os.path.join(g["root"], g["proto"], g["auth"], g["label"], "handshake_logs",
                          f"handshake_{g['proto']}_{g['auth']}_{sig}_{kem}_{g['label']}_"
                          f"block{g['b']}of{g['n']}"
                          f"{('_mb' + g['r'] + 'of' + g['rn']) if g['r'] else ''}.log")
        log = parse_log(lp) if os.path.isfile(lp) else {}
        if not log:
            print(f"[WARN] log introuvable ou vide : {lp}", file=sys.stderr)

        cell_key = (g["root"], g["proto"], g["auth"], g["label"], int(g["b"]), int(g["n"]))
        if cell_key not in qdisc_by_cell:
            label_dir = os.path.join(g["root"], g["proto"], g["auth"], g["label"])
            qdisc_by_cell[cell_key] = load_qdisc(label_dir, g["b"], g["n"])
        qd = qdisc_by_cell[cell_key]

        for execution, ts, te in windows:
            conn_rows = by_exec.get(execution)
            if not conn_rows:
                n_conn_no_pkts += 1
                continue
            client_ip = conn_rows[0]["ip.src"]
            metrics = (metrics_tls(conn_rows, client_ip) if g["proto"] == "tls"
                       else metrics_quic(conn_rows, client_ip, pair_pn_mode))
            hs, app = log.get(execution, (None, None))
            row = {
                "protocol": g["proto"], "auth_mode": g["auth"], "label": g["label"],
                "sig_alg": sig, "kem": kem,
                "block_index": int(g["b"]), "n_blocks": int(g["n"]), "conn_index": execution,
                "round_index": int(g["r"] or 1),
                "chain_depth": extras[0], "cert_pad_bytes": extras[1],
                "cert_pad_target_der": extras[2], "micro_batches": extras[3],
                "loss_pct": loss, "delay_ms_oneway": delay, "loss_process": process,
                "mtu": mtu, "loss_direction": direction,
                "handshake_ms": hs, "app_ready_ms": app,
            }
            row.update(metrics)
            row["loss_indicator_events"] = loss_indicator_events(metrics, g["proto"])
            row["_qdisc"] = (qd.get((sig, kem, "server_egress")),
                             qd.get((sig, kem, "client_egress")))
            row["_extra"] = extra
            out_rows.append(row)

    if not out_rows:
        print("[!] Aucune connexion analysee.")
        return 1

    annotate_loss_evidence(out_rows, args.baseline_quantile, args.unobs_rtt_frac,
                           args.unobs_floor_ms)

    cols = []
    for r in out_rows:
        for k in r:
            if k not in ("_qdisc", "_extra") and k not in cols:
                cols.append(k)
    with open(args.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(out_rows)
    print(f"[OK] {len(out_rows)} connexion(s) -> {args.out}  "
          f"({n_pair_fail} paire(s) illisible(s), {n_conn_no_pkts} connexion(s) sans paquet, "
          f"{n_streams_unassigned} flux sans fenetre, {n_warmup_streams} flux d'echauffement ecartes)")

    # Resume par bloc : unite d'inference independante (jamais la connexion)
    groups = defaultdict(list)
    for r in out_rows:
        groups[(r["protocol"], r["label"], r["sig_alg"], r["kem"], r["block_index"])].append(r)
    num_cols = [c for c in cols if c not in NON_STAT_COLS]
    sum_rows = []
    for (proto, label, sig, kem, b), rs in sorted(groups.items()):
        row = {"protocol": proto, "label": label, "sig_alg": sig, "kem": kem,
               "block_index": b, "n_conn": len(rs),
               "loss_pct": rs[0]["loss_pct"], "delay_ms_oneway": rs[0]["delay_ms_oneway"],
               "loss_process": rs[0]["loss_process"], "mtu": rs[0]["mtu"]}
        for c in num_cols:
            vals = [r[c] for r in rs if isinstance(r.get(c), (int, float))]
            row[f"{c}_median"] = round(statistics.median(vals), 3) if vals else None
            row[f"{c}_mean"] = round(statistics.mean(vals), 3) if vals else None
        ev = [r["loss_evidence"] for r in rs]
        row["baseline_app_ready_ms"] = rs[0]["baseline_app_ready_ms"]
        row["n_loss_observed"] = ev.count("observed")
        row["n_loss_suspected_unobserved"] = ev.count("suspected_unobserved")
        row["n_no_measure"] = ev.count("no_measure")
        row["n_pn_undecodable"] = ev.count("pn_undecodable")
        row["loss_indicator_events_sum"] = sum(r["loss_indicator_events"] for r in rs)
        srv, cli = rs[0]["_qdisc"]
        for tag, q in (("s2c", srv), ("c2s", cli)):
            row[f"qdisc_{tag}_sent"] = q[0] if q else None
            row[f"qdisc_{tag}_dropped"] = q[1] if q else None
            # Meme formule que le launcher : emis + supprimes au denominateur
            row[f"qdisc_{tag}_drop_pct"] = (
                round(100.0 * q[1] / (q[0] + q[1]), 3) if q and (q[0] + q[1]) > 0 else None)
        row.update(rs[0]["_extra"])
        sum_rows.append(row)
    with open(args.summary, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(sum_rows[0].keys()))
        w.writeheader()
        w.writerows(sum_rows)
    print(f"[OK] {len(sum_rows)} cellule(s) bloc -> {args.summary}")
    return 0


# ───────────────────────── auto-test ───────────────────────────────────────
T0 = 1000.0


def _line(rel=None, **kw):
    """Ligne tshark synthetique ; rel = temps en secondes depuis T0."""
    base = {f: "" for f in FIELDS}
    base.update(kw)
    if rel is not None:
        base["frame.time_epoch"] = f"{T0 + rel:.6f}"
    return "\t".join(base[f] for f in FIELDS)


def selftest():
    C, S = "10.0.0.2", "10.0.0.3"

    # TLS : ClientHello, segments serveur dont un trou (lost_segment) puis
    # remplissage (retransmission), reponse client, reponse applicative.
    tls = "\n".join([
        _line(0.000, **{"frame.number": "1", "ip.src": C, "frame.len": "74", "tcp.len": "0",
                        "tcp.stream": "0", "tcp.flags.syn": "1"}),
        _line(0.050, **{"frame.number": "2", "ip.src": S, "frame.len": "74", "tcp.len": "0",
                        "tcp.stream": "0", "tcp.flags.syn": "1"}),
        _line(0.051, **{"frame.number": "3", "ip.src": C, "frame.len": "1500", "tcp.len": "1448",
                        "tcp.stream": "0"}),
        _line(0.101, **{"frame.number": "4", "ip.src": S, "frame.len": "1500", "tcp.len": "1448",
                        "tcp.stream": "0"}),
        _line(0.102, **{"frame.number": "5", "ip.src": S, "frame.len": "1500", "tcp.len": "1448",
                        "tcp.stream": "0", "tcp.analysis.lost_segment": "1"}),
        _line(0.350, **{"frame.number": "6", "ip.src": S, "frame.len": "1500", "tcp.len": "1448",
                        "tcp.stream": "0", "tcp.analysis.retransmission": "1"}),
        _line(0.351, **{"frame.number": "7", "ip.src": C, "frame.len": "200", "tcp.len": "134",
                        "tcp.stream": "0"}),
        _line(0.401, **{"frame.number": "8", "ip.src": S, "frame.len": "300", "tcp.len": "234",
                        "tcp.stream": "0"}),
    ])
    m = analyze_pcap("x.pcap", "tls", None, text=tls)
    assert m["n_pkts"] == 8 and m["pkts_c2s"] == 3 and m["pkts_s2c"] == 5, m
    assert m["s2c_payload_segments"] == 4, m
    assert m["s2c_tcp_lost_segment_events"] == 1 and m["s2c_tcp_retransmissions"] == 1, m
    assert abs(m["t_first_s2c_payload_ms"] - 101.0) < 1e-3, m
    assert abs(m["t_client_second_payload_ms"] - 351.0) < 1e-3, m
    assert m["s2c_segments_before_client_reply"] == 3, m
    assert m["c2s_syn_packets"] == 1 and m["s2c_synack_packets"] == 1, m
    assert loss_indicator_events(m, "tls") == 2, m

    # QUIC : le serveur envoie Initial+Handshake (pn 0..), le paquet 1 du
    # serveur dans l'espace Handshake est perdu (trou), puis 1-RTT avec
    # HANDSHAKE_DONE (frame 30).
    quic = "\n".join([
        _line(0.000, **{"frame.number": "1", "ip.src": C, "frame.len": "1252", "udp.stream": "0",
                        "quic.long.packet_type": "0", "quic.frame_type": "6", "quic.crypto.offset": "0",
                        "quic.crypto.length": "1200", "quic.packet_number": "0"}),
        _line(0.050, **{"frame.number": "2", "ip.src": S, "frame.len": "1252", "udp.stream": "0",
                        "quic.long.packet_type": "0,2", "quic.frame_type": "2,6,6", "quic.crypto.offset": "0,0",
                        "quic.crypto.length": "90,900", "quic.packet_number": "0,0"}),
        _line(0.051, **{"frame.number": "3", "ip.src": S, "frame.len": "1252", "udp.stream": "0",
                        "quic.long.packet_type": "2", "quic.frame_type": "6", "quic.crypto.offset": "900",
                        "quic.crypto.length": "1100", "quic.packet_number": "2"}),
        _line(0.100, **{"frame.number": "4", "ip.src": C, "frame.len": "80", "udp.stream": "0",
                        "quic.long.packet_type": "2", "quic.frame_type": "2,6", "quic.crypto.offset": "0",
                        "quic.crypto.length": "36", "quic.packet_number": "0"}),
        _line(0.151, **{"frame.number": "5", "ip.src": S, "frame.len": "150", "udp.stream": "0",
                        "quic.frame_type": "30,8", "quic.packet_number": "0"}),
    ])
    q = analyze_pcap("y.pcap", "quic", None, text=quic)
    assert q["s2c_hs_space_datagrams"] == 2, q
    assert q["s2c_lost_pn_handshake"] == 1 and q["s2c_lost_pn_initial"] == 0 and q["s2c_lost_pn_total"] == 1, q
    assert q["s2c_crypto_frames"] == 3 and q["s2c_crypto_bytes"] == 90 + 900 + 1100, q
    assert abs(q["t_handshake_done_ms"] - 151.0) < 1e-3, q
    assert q["c2s_initial_datagrams"] == 1, q
    assert loss_indicator_events(q, "quic") == 1, q

    # Attribution par flux : 3 connexions, l'ACK final/RST client de chacune
    # (horodates apres le delai netem) tombe DANS la fenetre de la suivante.
    lines = []
    wins = []
    t = 0.0
    for i in range(1, 4):
        s = str(i - 1)
        lines += [
            _line(t + 0.050, **{"ip.src": C, "frame.len": "74", "tcp.len": "0", "tcp.stream": s, "tcp.flags.syn": "1"}),
            _line(t + 0.100, **{"ip.src": S, "frame.len": "74", "tcp.len": "0", "tcp.stream": s, "tcp.flags.syn": "1"}),
            _line(t + 0.250, **{"ip.src": C, "frame.len": "200", "tcp.len": "134", "tcp.stream": s}),
            _line(t + 0.300, **{"ip.src": S, "frame.len": "300", "tcp.len": "234", "tcp.stream": s}),
            _line(t + 0.352, **{"ip.src": C, "frame.len": "66", "tcp.len": "0", "tcp.stream": s}),  # apres T_END
        ]
        wins.append((i, T0 + t, T0 + t + 0.302))
        t += 0.306
    rows = parse_rows("\n".join(lines))
    by, unassigned, warm = split_rows_by_stream(rows, wins)
    assert unassigned == 0 and warm == 0, (unassigned, warm)
    for i in (1, 2, 3):
        assert len(by[i]) == 5 and sum(1 for r in by[i] if r["ip.src"] == C) == 3, (i, len(by[i]))

    # Flux d'echauffement : premier paquet AVANT la premiere fenetre -> ecarte
    # sans warning ; un flux apres la derniere fenetre reste "sans fenetre".
    wl = [_line(-0.200, **{"ip.src": C, "frame.len": "74", "tcp.stream": "9", "tcp.flags.syn": "1"}),
          _line(-0.150, **{"ip.src": S, "frame.len": "74", "tcp.stream": "9", "tcp.flags.syn": "1"}),
          _line(0.060, **{"ip.src": C, "frame.len": "74", "tcp.stream": "0", "tcp.flags.syn": "1"}),
          _line(5.000, **{"ip.src": C, "frame.len": "74", "tcp.stream": "7", "tcp.flags.syn": "1"})]
    by2, un2, warm2 = split_rows_by_stream(parse_rows("\n".join(wl)), [(1, T0, T0 + 0.3)])
    assert warm2 == 1 and un2 == 1 and len(by2[1]) == 1, (warm2, un2)

    # ARP : champ lu, ligne sans flux ignoree par l'attribution
    ar = parse_rows(_line(-0.5, **{"arp.opcode": "1", "frame.len": "42"}))
    assert ar[0]["arp.opcode"] == "1" and ar[0]["stream"] is None

    # QUIC a compteur de paquets GLOBAL (aioquic, trafic reel) : numeros
    # disjoints entre espaces -> aucune fausse perte ; un vrai trou est vu.
    def qrow(rel, src, types, pns, ftypes_, **kw):
        d = {"ip.src": src, "frame.len": "1252", "udp.stream": "0",
             "quic.long.packet_type": types, "quic.packet_number": pns, "quic.frame_type": ftypes_}
        d.update(kw)
        return _line(rel, **d)
    clean = parse_rows("\n".join([
        qrow(0.000, C, "0", "0", "6"),
        qrow(0.010, S, "0,2", "0,1", "2,6,6"),
        qrow(0.011, S, "", "2", "8"),
        qrow(0.020, S, "", "3", "30,8"),
    ]))
    mq = metrics_quic(clean, C)
    assert mq["s2c_pn_mode"] == "global" and mq["s2c_lost_pn_total"] == 0, mq
    gap = parse_rows("\n".join([
        qrow(0.000, C, "0", "0", "6"),
        qrow(0.010, S, "0,2", "0,1", "2,6,6"),
        qrow(0.020, S, "", "4", "30,8"),                      # 2 et 3 manquants
    ]))
    assert metrics_quic(gap, C)["s2c_lost_pn_total"] == 2
    assert infer_pn_mode([pn_spaces(clean, C)] * 5) == "global"
    per = parse_rows("\n".join([qrow(0.01, S, "0,2", "0,0", "2,6,6"), qrow(0.02, S, "", "0", "8")]))
    assert infer_pn_mode([pn_spaces(per, C)] * 5) == "per_space"

    # Classification loss_evidence
    def mk(app, ind=0, exe=1):
        return {"protocol": "tls", "auth_mode": "single", "label": "l", "sig_alg": "a", "kem": "k",
                "block_index": 1, "delay_ms_oneway": 50.0, "app_ready_ms": app,
                "loss_indicator_events": ind, "conn_index": exe}
    rs = [mk(312.5 + 0.01 * i, exe=i) for i in range(30)]
    rs += [mk(441.0, ind=1, exe=100), mk(2761.0, exe=101), mk(330.0, exe=102), mk(None, exe=103)]
    annotate_loss_evidence(rs)
    ev = {r["conn_index"]: r["loss_evidence"] for r in rs}
    assert ev[100] == "observed" and ev[101] == "suspected_unobserved", ev
    assert ev[102] == "none" and ev[103] == "no_measure" and ev[0] == "none", ev
    rq = [dict(mk(312.5), protocol="quic", s2c_pn_decoded=0, pkts_s2c=2, conn_index=7)]
    rq += [dict(mk(312.5 + 0.01 * i), protocol="quic", s2c_pn_decoded=3, pkts_s2c=2, conn_index=i)
           for i in range(10)]
    annotate_loss_evidence(rq)
    assert rq[0]["loss_evidence"] == "pn_undecodable" and rq[1]["loss_evidence"] == "none", rq[0]

    # Etiquettes
    assert parse_label("simple_loss2_delay25ms_mtu1280") == (2.0, 25.0, "iid", 1280, "s2c")
    assert parse_label("ge-mild-5_delay25ms")[0:3] == (5.0, 25.0, "ge-mild")
    assert parse_label("simple_loss1_delay25ms_dirboth")[4] == "both"
    assert parse_label("none")[2] == "none"
    # Suffixes du Launcher (chaine, padding, pcap, micro-lots) : NE DOIVENT PAS faire perdre loss/delay/mtu
    assert parse_label("simple_loss2_delay25ms_mtu1280__pcap") == (2.0, 25.0, "iid", 1280, "s2c")
    assert parse_label("ge-mild-5_delay50ms__mb2")[0:3] == (5.0, 50.0, "ge-mild")
    assert parse_label("simple_loss1_delay25ms__chain2__mb2")[0:2] == (1.0, 25.0)
    assert parse_label_extras("simple_loss1_delay25ms__chain2__mb2") == (2, 0, 0, 2)
    assert parse_label("simple_loss2_delay25ms_mtu1280__qmtu__pcap__mb2") == (2.0, 25.0, "iid", 1280, "s2c")
    assert parse_label_extras("simple_loss1_delay25ms__qmtu__chain2__mb2") == (2, 0, 0, 2)
    assert parse_label_extras("simple_loss2_delay25ms__padto8700__pcap") == (1, 0, 8700, 1)
    pm = PATH_RE.match("/r/quic/single/simple_loss2_delay25ms__pcap/pcap_perconn/block3of20_mb2of5/mldsa65_x448_mlkem768/block.pcap")
    assert pm and pm.group("b") == "3" and pm.group("r") == "2" and pm.group("rn") == "5", pm
    pm1 = PATH_RE.match("/r/tls/single/none__pcap/pcap_perconn/block3of20/mldsa65_hqc192/block.pcap")
    assert pm1 and pm1.group("r") is None, pm1
    # qdisc : les tours d'un meme bloc sont SOMMES
    import tempfile as _tf
    with _tf.TemporaryDirectory() as td:
        with open(os.path.join(td, "qdisc_stats_block1of4_seed9.csv"), "w") as qf:
            qf.write("timestamp,block_index,n_blocks,position,sig_alg,kem,role,pkts_before,dropped_before,pkts_after,dropped_after,effective_drop_pct\n")
            qf.write("t,1,4,1,s,k,server_egress,0,0,100,5,4.7\n")
            qf.write("t,1,4,5,s,k,server_egress,100,5,250,9,2.6\n")
        qq = load_qdisc(td, "1", "4")
        assert qq[("s", "k", "server_egress")] == (250, 9), qq

    # Log : une ligne NaN de secours ne doit pas ecraser une vraie mesure
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as tf:
        tf.write("Execution 1 - TLS Single\nHandshake duration: 12.5 ms\nApp-ready duration: 30.25 ms\n"
                 "Execution 2 - TLS Single\nHandshake duration: NaN ms  (client-side timeout after 150s)\n"
                 "App-ready duration: NaN ms  (client-side timeout after 150s)\n"
                 "Execution 3 - TLS Single\nHandshake duration: 9.0 ms\n"
                 "App-ready duration: NaN ms  (application request failed)\n"
                 "Handshake duration: NaN ms  (fallback)\nApp-ready duration: NaN ms  (fallback)\n")
    lg = parse_log(tf.name)
    os.unlink(tf.name)
    assert lg[1] == (12.5, 30.25) and lg[2] == (None, None) and lg[3] == (9.0, None), lg
    print("[SELFTEST] OK : TLS, QUIC (numerotation globale/par espace), flux, echauffement, ARP, loss_evidence, etiquettes, logs.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
