#!/usr/bin/env python3
"""
probe_structure.py -- sonde en LECTURE SEULE de la structure des donnees de la campagne.

Ne calcule AUCUN contraste signature PQ vs classique (pas d'estimation d'effet) : on ne
regarde que la structure (dossiers, colonnes, comptes, valeurs manquantes). Cela protege la
pre-inscription : les scripts d'analyse sont ecrits avant d'avoir vu les effets.
Ne lit pas le contenu des pcap. Stdlib uniquement. A lancer avec nice (campagne en cours) :

  nice -n 19 ionice -c3 python3 analysis_probe/probe_structure.py \
      [captures_v2] [campaign_state] [plans/plan_all.csv]

Sortie : analysis_probe/probe_<date>_<heure>.txt
"""
import collections
import csv
import re
import statistics
import sys
import time
import traceback
from pathlib import Path

ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else "captures_v2")
STATE = Path(sys.argv[2] if len(sys.argv) > 2 else "campaign_state")
PLAN = Path(sys.argv[3] if len(sys.argv) > 3 else "plans/plan_all.csv")
OUT = []


def P(*a):
    OUT.append(" ".join(str(x) for x in a))


def H(t):
    P("\n" + "=" * 10, t, "=" * 10)


def head(path, n=6, nb=4000, w=220):
    try:
        with open(path, "rb") as f:
            txt = f.read(nb).decode("utf-8", "replace")
        return [ln[:w] for ln in txt.splitlines()[:n]]
    except Exception as e:  # noqa: BLE001
        return ["<erreur lecture: %s>" % e]


def norm(name):
    return re.sub(r"\d+", "N", name)


FILES = []
PLAN_ROWS = []


def s1_plan():
    H("1. PLAN")
    if not PLAN.is_file():
        P("ABSENT :", PLAN)
        return
    with open(PLAN, newline="") as f:
        rows = list(csv.DictReader(f))
    PLAN_ROWS.extend(rows)
    P("fichier:", PLAN, "| lignes:", len(rows))
    if not rows:
        return
    cols = list(rows[0].keys())
    P("colonnes:", cols)
    for c in cols:
        vals = collections.Counter(r.get(c, "") for r in rows)
        if len(vals) <= 12:
            P("  %s: %s" % (c, dict(vals)))
        else:
            P("  %s: %d valeurs distinctes, ex: %s" % (c, len(vals), list(vals)[:4]))
    idk = "cell_id" if "cell_id" in cols else cols[0]
    seen = set()
    for r in rows:
        pre = r.get(idk, "").split("_")[0]
        if pre not in seen:
            seen.add(pre)
            P("  exemple [%s]: %s" % (pre, dict(r)))


def s2_state():
    H("2. ETAT DE LA CAMPAGNE (state.csv)")
    sp = STATE / "state.csv"
    if not sp.is_file():
        P("ABSENT :", sp)
        return
    with open(sp, newline="") as f:
        rows = list(csv.DictReader(f))
    P("lignes:", len(rows), "| colonnes:", list(rows[0].keys()) if rows else None)
    P("kind:", dict(collections.Counter(r.get("kind") for r in rows)))
    P("exit_code:", dict(collections.Counter(r.get("exit_code") for r in rows)))
    bad = [r for r in rows if r.get("exit_code") not in ("0", "", None)]
    P("lignes avec exit_code != 0:", len(bad))
    for r in bad[:20]:
        P("   ", dict(r))
    byb = collections.defaultdict(list)
    for r in rows:
        byb[r.get("block")].append(r)
    for b in sorted(byb, key=lambda x: int(x)):
        rs = byb[b]
        nc = sum(1 for r in rs if r.get("kind") == "cell")
        ns = sum(1 for r in rs if r.get("kind") == "sentinel")
        P("  bloc %s: %d cellules, %d sentinelles, %s -> %s" %
          (b, nc, ns, rs[0].get("timestamp"), rs[-1].get("timestamp")))
    P("contenu de", STATE, ":")
    for p in sorted(STATE.rglob("*"))[:80]:
        P("   ", p, p.stat().st_size if p.is_file() else "<dir>")


def s3_inventory():
    H("3. INVENTAIRE de " + str(ROOT))
    if not ROOT.is_dir():
        P("ABSENT :", ROOT)
        return
    P("entrees de premier niveau:", sorted(p.name for p in ROOT.iterdir()))
    FILES.extend(p for p in ROOT.rglob("*") if p.is_file())
    P("fichiers:", len(FILES), "| taille totale (Mo):", round(sum(p.stat().st_size for p in FILES) / 1e6, 1))
    P("extensions:", dict(collections.Counter(p.suffix or "<sans>" for p in FILES).most_common()))
    labels = collections.defaultdict(set)
    for d in ROOT.glob("*/*/*"):
        if d.is_dir():
            labels[(d.parts[-3], d.parts[-2])].add(d.name)
    P("dossiers proto/auth/<label> :")
    for k, v in sorted(labels.items()):
        P("   ", k, len(v), "labels ; exemples:", sorted(v)[:8])
    sent = sorted({str(p.relative_to(ROOT)) for p in FILES if "sentinel" in str(p).lower() or "sent_" in p.name})[:6]
    P("exemples de chemins 'sentinelle':", sent)
    kinds = {}
    for p in FILES:
        rel = p.relative_to(ROOT).parts
        if len(rel) == 4:
            key = ("<dans le dossier label>", norm(rel[3]))
        elif len(rel) > 4:
            key = (rel[3], p.suffix or "<sans>")
        else:
            key = ("<niveau<4>", norm(rel[-1]))
        k = kinds.setdefault(key, {"n": 0, "ex": []})
        k["n"] += 1
        if len(k["ex"]) < 2:
            k["ex"].append(str(p))
    P("types de fichiers (sous-dossier du label, extension) :")
    for key, v in sorted(kinds.items(), key=lambda kv: -kv[1]["n"]):
        P("   ", key, "n=%d" % v["n"], "ex:", v["ex"][0])
    H("4. EN-TETES D'UN EXEMPLE PAR TYPE (hors pcap)")
    for key, v in sorted(kinds.items(), key=lambda kv: -kv[1]["n"])[:40]:
        ex = v["ex"][0]
        if ex.endswith((".pcap", ".pcapng")):
            continue
        P("\n--", key, "|", ex)
        for ln in head(ex, 8):
            P("    ", ln)


LOGRE = re.compile(r"^handshake_(tls|quic)_(single|mutual)_(.+)_block(\d+)of(\d+)(?:_mb(\d+)of(\d+))?\.log$")
EX = re.compile(r"^Execution\s+(\d+)\s*-")
HS = re.compile(r"Handshake duration:\s*([\d.]+|NaN)\s*ms")
AP = re.compile(r"App-ready duration:\s*([\d.]+|NaN)\s*ms")


def s5_logs():
    H("5. LOGS handshake : coherence structurelle")
    logs = sorted(ROOT.glob("*/*/*/handshake_logs/*.log"))
    P("fichiers .log:", len(logs))
    if not logs:
        return
    agg = collections.defaultdict(lambda: collections.Counter())
    appvals = collections.defaultdict(list)
    n_exec_per_file = collections.Counter()
    unmatched, empty, dups = [], [], []
    shapes = collections.Counter()
    blocks_by_label = collections.defaultdict(set)
    rounds_by_label = collections.defaultdict(set)
    pairs_by_label = collections.defaultdict(set)
    for p in logs:
        proto, auth, label = p.parts[-5], p.parts[-4], p.parts[-3]
        m = LOGRE.match(p.name)
        if not m:
            unmatched.append(p.name)
            continue
        rest, b = m.group(3), int(m.group(4))
        blocks_by_label[label].add(b)
        rounds_by_label[label].add((m.group(6), m.group(7)))
        suffix = "_" + label
        pair = rest[:-len(suffix)] if rest.endswith(suffix) else "?" + rest
        pairs_by_label[label].add(pair)
        cur, seen, nex = None, set(), 0
        hs_ok = hs_nan = ap_ok = ap_nan = 0
        for ln in p.read_text(errors="ignore").splitlines():
            s = ln.strip()
            me = EX.match(s)
            if me:
                nex += 1
                cur = int(me.group(1))
                if cur in seen:
                    dups.append(p.name)
                seen.add(cur)
                continue
            mh, ma = HS.search(s), AP.search(s)
            if mh:
                if mh.group(1) == "NaN":
                    hs_nan += 1
                else:
                    hs_ok += 1
            if ma:
                if ma.group(1) == "NaN":
                    ap_nan += 1
                else:
                    ap_ok += 1
                    appvals[(proto, auth)].append(float(ma.group(1)))
            if not (mh or ma):
                shapes[re.sub(r"\d+(\.\d+)?", "N", s)[:70]] += 1
        if nex == 0:
            empty.append(p.name)
        n_exec_per_file[nex] += 1
        a = agg[(proto, auth)]
        a["files"] += 1
        a["executions"] += nex
        a["hs_ok"] += hs_ok
        a["hs_nan"] += hs_nan
        a["app_ok"] += ap_ok
        a["app_nan"] += ap_nan
    P("noms non reconnus par le motif attendu:", len(unmatched), unmatched[:8])
    P("fichiers sans aucune 'Execution':", len(empty), empty[:8])
    P("fichiers avec numeros d'execution dupliques:", len(set(dups)), sorted(set(dups))[:8])
    P("executions par fichier (nb executions -> nb fichiers):", dict(sorted(n_exec_per_file.items())))
    for k, a in sorted(agg.items()):
        v = appvals.get(k, [])
        ext = ""
        if v:
            ext = " | App-ready ms min/med/max = %.1f / %.1f / %.1f" % (min(v), statistics.median(v), max(v))
        P("  %s: %s%s" % (k, dict(a), ext))
    P("nb de labels:", len(blocks_by_label))
    P("nb de blocs distincts par label (valeur -> nb de labels):",
      dict(collections.Counter(len(v) for v in blocks_by_label.values())))
    P("tours (mb) vus par label (ex.):", {k: sorted(map(str, v)) for k, v in list(rounds_by_label.items())[:4]})
    P("nb de paires sig_kem par label (valeur -> nb de labels):",
      dict(collections.Counter(len(v) for v in pairs_by_label.values())))
    for k in list(pairs_by_label)[:8]:
        P("   label", k, "->", sorted(pairs_by_label[k])[:6])
    P("formes de lignes hors Execution/Handshake/App-ready (top 25) :")
    for s, n in shapes.most_common(25):
        P("   %6d  %s" % (n, s))


def s6_mapping():
    H("6. CORRESPONDANCE cell_id (plan) <-> dossier (label)")
    if not PLAN_ROWS:
        P("(plan non charge)")
        return
    idk = "cell_id" if "cell_id" in PLAN_ROWS[0] else list(PLAN_ROWS[0])[0]
    first = {}
    for r in PLAN_ROWS:
        first.setdefault(r[idk].split("_")[0], r[idk])
    ids = list(first.values())
    P("cell_id recherches:", ids)
    cands = [p for p in FILES if p.suffix in (".txt", ".json", ".csv", ".env", ".meta", ".md")
             and p.stat().st_size < 50_000
             and not {"handshake_logs", "pcap_perconn", "csv"} & set(p.parts)][:3000]
    if STATE.is_dir():
        cands += [p for p in STATE.rglob("*") if p.is_file() and p.stat().st_size < 3_000_000][:500]
    hits = collections.defaultdict(list)
    for p in cands:
        try:
            txt = p.read_text(errors="ignore")
        except Exception:  # noqa: BLE001
            continue
        for cid in ids:
            if cid in txt and len(hits[cid]) < 2:
                line = next((ln for ln in txt.splitlines() if cid in ln), "")
                hits[cid].append("%s :: %s" % (p, line[:200]))
    for cid in ids:
        P("  ", cid, "->", hits.get(cid) or "AUCUN fichier ne contient ce cell_id (le lien se fera par le label)")


def main():
    for fn in (s1_plan, s2_state, s3_inventory, s5_logs, s6_mapping):
        try:
            fn()
        except Exception:  # noqa: BLE001
            P("\n[ERREUR dans %s]" % fn.__name__)
            P(traceback.format_exc())
    out = Path("analysis_probe") / ("probe_%s.txt" % time.strftime("%Y%m%d_%H%M"))
    out.parent.mkdir(exist_ok=True)
    out.write_text("\n".join(OUT) + "\n")
    print("[OK] %s (%d lignes)" % (out, len(OUT)))


if __name__ == "__main__":
    main()
