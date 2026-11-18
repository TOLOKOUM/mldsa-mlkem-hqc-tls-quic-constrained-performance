#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""phase0_S3_check.py -- verifications de phase 0 de la campagne S3 (AUCUNE duree lue).
Entrees : CSV par connexion de quic_amp_audit_perconn.py (un par bras) + predictions du brouillon.
  P0-S3-1  decodage : >= 95 % des connexions de chaque bras validees et 0 paquet non dechiffre
  P0-S3-2  temoin : B_c = 2 440 o dans >= 90 % des connexions
  P0-S3-3  traitement : B_c = 3 660 o dans >= 90 % des connexions (part de 4 880 o rapportee)
  P0-S3-4  vol serveur inchange : cellules NON plafonnees du temoin (marge MsQuic >= 200 o) : |mediane S_chg(traitement) - mediane S_chg(temoin)| <= 50 o
  P0-S3-5  calage : --q-offset = 42 + mediane(S_chg - flight_a du brouillon) sur les cellules non plafonnees du traitement ; dispersion <= 150 o
"""
import argparse, collections, csv, re, statistics

def load(path):
    rows = []
    for r in csv.DictReader(open(path, encoding="utf-8")):
        p = r["pcap"]
        m = re.search(r"/([a-z0-9]+)_([a-z0-9_]+)/block\.pcap", p) or re.search(r"quic_single_([a-z0-9]+)_(.+?)_(?:delayonly|none)", p)
        pad = re.search(r"padto(\d+)", p)
        r["sig"], r["kem"] = (m.group(1), m.group(2)) if m else ("?", "?")
        r["pad"] = int(pad.group(1)) if pad else 0
        for k in ("Bc", "S_all", "S_chg_msquic", "margin_msquic", "undecrypted"):
            r[k] = int(float(r[k]))
        rows.append(r)
    return rows

def med(v):
    return statistics.median(v) if v else float("nan")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--control", required=True)
    ap.add_argument("--treat", required=True)
    ap.add_argument("--draft", required=True)
    ap.add_argument("--sig", default="secp384r1")
    a = ap.parse_args()
    C, T = load(a.control), load(a.treat)
    ok_all = True
    def flag(name, ok, txt):
        nonlocal ok_all
        ok_all &= bool(ok)
        print("[%s] %s : %s" % ("OK " if ok else "ECHEC", name, txt))
    for lab, R in (("temoin", C), ("traitement", T)):
        n = len(R)
        good = sum(1 for r in R if r["validated"] == "oui" and r["undecrypted"] == 0)
        bc = collections.Counter(r["Bc"] for r in R)
        print("%s : %d connexions ; Bc = %s ; decodees et validees : %d (%.1f %%)" % (lab, n, dict(sorted(bc.items())), good, 100.0 * good / max(n, 1)))
        flag("P0-S3-1 decodage (%s)" % lab, n and good / n >= 0.95, "%d/%d" % (good, n))
    fc = sum(1 for r in C if r["Bc"] == 2440) / max(len(C), 1)
    ft = sum(1 for r in T if r["Bc"] == 3660) / max(len(T), 1)
    f4 = sum(1 for r in T if r["Bc"] == 4880) / max(len(T), 1)
    flag("P0-S3-2 temoin Bc = 2 440", fc >= 0.90, "%.1f %%" % (100 * fc))
    flag("P0-S3-3 traitement Bc = 3 660", ft >= 0.90, "%.1f %% (4 880 o : %.1f %%)" % (100 * ft, 100 * f4))
    def cells(R):
        d = collections.defaultdict(list)
        for r in R:
            d[(r["sig"], r["kem"], r["pad"])].append(r)
        return d
    cc, ct = cells(C), cells(T)
    print("\ncellule (sig, kem, pad) | temoin: n, Bc, S_chg med, marge MsQuic | traitement: n, Bc, S_chg med, marge MsQuic")
    diffs = []
    for k in sorted(set(cc) | set(ct)):
        c, t = cc.get(k, []), ct.get(k, [])
        s = "%-32s | " % (k,)
        s += "%2d %s %6.0f %6.0f | " % (len(c), "/".join(sorted({str(r['Bc']) for r in c})), med([r["S_chg_msquic"] for r in c]), med([r["margin_msquic"] for r in c])) if c else "- | "
        s += "%2d %s %6.0f %6.0f" % (len(t), "/".join(sorted({str(r['Bc']) for r in t})), med([r["S_chg_msquic"] for r in t]), med([r["margin_msquic"] for r in t])) if t else "-"
        print(s)
        if c and t and med([r["margin_msquic"] for r in c]) >= 200:
            diffs.append((k, med([r["S_chg_msquic"] for r in t]) - med([r["S_chg_msquic"] for r in c])))
    bad = [(k, d) for k, d in diffs if abs(d) > 50]
    flag("P0-S3-4 vol serveur inchange (cellules non plafonnees du temoin)", diffs and not bad,
         "ecarts de mediane : %s" % ", ".join("%s=%+.0f" % (k[2], d) for k, d in diffs))
    pred = {}
    for r in csv.DictReader(open(a.draft, encoding="utf-8")):
        if r["kind"] in ("base", "pad") and r["sig"] == a.sig:
            pred[int(float(r["chain_target"]))] = float(r["flight_a"])
    gaps = []
    for k, rs in ct.items():
        if k[0] == a.sig and k[2] > 0 and k[2] in pred and med([r["margin_msquic"] for r in rs]) >= 200:   # base exclue : sa chaine reelle n'est pas une chaine remplie
            gaps.append((k[2], med([r["S_chg_msquic"] for r in rs]) - pred[k[2]]))
    if gaps:
        g = [x[1] for x in gaps]
        q = 42 + med(g)
        flag("P0-S3-5 calage", max(g) - min(g) <= 150,
             "S_chg - flight_a(brouillon) par taille : %s ; dispersion %.0f o ; q-offset propose = %.0f" % (", ".join("%d:%+.0f" % x for x in sorted(gaps)), max(g) - min(g), q))
        modal = collections.Counter(r["Bc"] for r in T).most_common(1)[0][0]
        print("\n=> ARGUMENTS A DONNER AU GEL : --quic-dgram 1220 --bc x448_mlkem768=%d --amp-sub 28 --q-offset %.0f   (temoin : --bc x448_mlkem768=2440)" % (modal, q))
    else:
        flag("P0-S3-5 calage", False, "aucune cellule non plafonnee dans le traitement")
    print("\nVERDICT PHASE 0 : %s" % ("TOUS LES CRITERES SATISFAITS" if ok_all else "AU MOINS UN CRITERE NON SATISFAIT : ne pas geler, envoyer cette sortie"))

if __name__ == "__main__":
    main()
