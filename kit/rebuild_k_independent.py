#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""rebuild_k_independent.py -- regeneration INDEPENDANTE des estimations ponctuelles k_hat d'une famille S2/S3, a partir des journaux bruts.
N'importe pas analyse_S2.py (parseur, medianes et moyennes reecrits ici, bibliotheque standard seulement). Ne refait PAS le bootstrap.
Definition (PREREGISTRATION_S2.md section 5) : D_b(X, RTT) = mediane_b(app_ms | X) - mediane_b(app_ms | base) (meme signature de base, meme bloc, meme RTT) ;
k_b(X) = [D_b(X,150) - D_b(X,50)] / 100 ; k_hat(X) = moyenne des k_b sur les blocs ou les quatre medianes existent. Les cellules __pcap sont exclues ; les durees « NaN » sont des echecs et sont ignorees.
Usage : python3 kit/rebuild_k_independent.py --root captures_S3_PAD1 --pred seuil_S3/freeze_S3_PAD1 --cells analysis_S3_PAD1/S2_cells.csv [--metric app_ms|hs_ms]
Sortie : ecart maximal |k_hat(reconstruit) - k_hat(analyse)| et liste des cellules dont l'ecart depasse --tol (defaut 1e-9)."""
import argparse, csv, glob, json, os, re, statistics, sys

SIGS = ["secp384r1", "mldsa65", "ed25519", "mldsa44", "mldsa87", "secp521r1"]
FNAME = re.compile(r"^handshake_(tls|quic)_(single|mutual)_(.+)_block(\d+)of(\d+)(?:_mb\d+of\d+)?\.log$")


def num(s):
    return None if s == "NaN" else float(s)


def read_log(path, key):
    vals, cur_open = [], False
    pat = {"app_ms": "App-ready duration: ", "hs_ms": "Handshake duration: "}[key]
    with open(path, errors="replace") as f:
        cur = None
        for ln in f:
            ln = ln.rstrip("\n")
            if re.match(r"^Execution \S+ - (TLS|QUIC) (Single|Mutual)", ln):
                if cur_open:
                    vals.append(cur)
                cur, cur_open = None, True
            elif ln.startswith(pat):
                m = re.match(r"([0-9]+(?:\.[0-9]+)?|NaN)", ln[len(pat):])
                if m and cur_open:
                    cur = num(m.group(1))
        if cur_open:
            vals.append(cur)
    return vals


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True); ap.add_argument("--pred", required=True); ap.add_argument("--cells", required=True)
    ap.add_argument("--metric", default="app_ms", choices=["app_ms", "hs_ms"]); ap.add_argument("--tol", type=float, default=1e-9)
    a = ap.parse_args()
    const = json.load(open(os.path.join(a.pred, "constants_frozen.json")))
    (fam, f), = const["FAMILIES"].items()
    base_sig, proto, mtu = f["sig"], f["proto"], int(f["mtu"])
    # med[(sig, pad, rtt, block)] -> liste de durees valides (concatenation des micro-lots)
    raw = {}
    for ldir in sorted(glob.glob(os.path.join(a.root, proto, "*", "*"))):
        label = os.path.basename(ldir)
        if "__pcap" in label or "sentinel" in label or label.startswith("simple_loss") or re.search(r"loss\d", label):
            continue
        m = re.search(r"delay(\d+(?:\.\d+)?)ms", label)
        rtt = 2 * float(m.group(1)) if m else (0.0 if label.startswith("none") else None)
        mm = re.search(r"_mtu(\d+)", label); lm = int(mm.group(1)) if mm else 1500
        if rtt is None or lm != mtu:
            continue
        pm = re.search(r"__padto(\d+)", label); pad = int(pm.group(1)) if pm else 0
        for lf in sorted(glob.glob(os.path.join(ldir, "handshake_logs", "*.log"))):
            nm = FNAME.match(os.path.basename(lf))
            if not nm or nm.group(1) != proto:
                continue
            mid = nm.group(3)
            if mid.endswith("_" + label):
                mid = mid[: -(len(label) + 1)]
            sig = next((s for s in SIGS if mid.startswith(s + "_")), None)
            if sig is None or mid[len(sig) + 1:] != f["kem"]:
                continue
            blk = int(nm.group(4))
            vals = [v for v in read_log(lf, a.metric) if v is not None]
            raw.setdefault((sig, pad, rtt, blk), []).extend(vals)
    med = {k: statistics.median(v) for k, v in raw.items() if v}
    blocks = sorted({k[3] for k in med})

    def khat(sig, pad):
        ks = []
        for b in blocks:
            try:
                d = {r: med[(sig, pad, r, b)] - med[(base_sig, 0, r, b)] for r in (50.0, 150.0)}
            except KeyError:
                continue
            ks.append((d[150.0] - d[50.0]) / 100.0)
        return (sum(ks) / len(ks), len(ks)) if ks else (float("nan"), 0)

    cells = {(r["sig"], int(float(r["chain_target"]))): r for r in csv.DictReader(open(a.cells, encoding="utf-8")) if r["kind"] in ("pad", "bridge")}
    worst, bad, n = 0.0, [], 0
    for (sig, pad), r in sorted(cells.items(), key=lambda x: (x[0][1], x[0][0])):
        mine, nb = khat(sig, pad)
        ref = float(r["khat"]); n += 1
        d = abs(mine - ref) if mine == mine and ref == ref else float("inf")
        worst = max(worst, d if d != float("inf") else worst)
        if d > a.tol:
            bad.append((sig, pad, mine, ref, nb))
    print("famille %s, %d blocs lus, %d cellules comparees, ecart maximal |k_hat reconstruit - k_hat analyse| = %.3e" % (fam, len(blocks), n, worst))
    for b in bad:
        print("  ECART : %s %s reconstruit %.6f analyse %.6f (blocs %d)" % b)
    print("VERDICT :", "IDENTIQUE" if not bad else "%d cellule(s) differentes" % len(bad))
    sys.exit(0 if not bad else 1)


if __name__ == "__main__":
    main()
