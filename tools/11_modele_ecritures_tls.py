#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""11_modele_ecritures_tls.py -- PHASE 5b : le decoupage TCP du vol serveur TLS est explique par le tampon d'ecriture d'OpenSSL.

Constat (pcap reels, 10_experiences_naturelles.py section 5) : le vol TLS ML-DSA-65 de 10 215 o part en 3 ecritures de 4 096, 4 096 et
2 023 o (segments 1448 x2 + 1200 | 1448 x2 + 1200 | 1448 + 575 ; a MTU 1280 : 1228 x3 + 412 | 1228 x3 + 412 | 1228 + 795). Le 1er segment est
plein : le ServerHello n'est PAS ecrit a part. Le vol ECDSA rempli (8 700 o) part en 4 096, 5 912 et 207 o. Ce profil est celui du tampon
d'ecriture d'OpenSSL (BIO_f_buffer, 4 096 o) :
   - chaque enregistrement TLS est ajoute au tampon ; si le tampon ne peut le contenir, il est rempli jusqu'a 4 096 o puis vide (1 ecriture) ;
   - le reste de l'enregistrement est ecrit directement s'il fait au moins 4 096 o, sinon recopie dans le tampon ;
   - le tampon est vide en fin de vol.
Les enregistrements du vol (octets) sont reconstitues exactement : ServerHello 95 + partage serveur ; ChangeCipherSpec 6 ; EncryptedExtensions 28 ;
Certificate = chaine + 30 + 5 x nb_certificats ; CertificateVerify = signature + 30 ; Finished 74 (SHA-384). Ils redonnent 10 215 o (ML-DSA-65 et ECDSA
rempli) a l'octet pres.
Chaque ecriture est emise tant que la fenetre initiale (10 segments) est ouverte : son dernier segment est PARTIEL (ce qui consomme un segment de
fenetre pour moins d'un MSS). Les octets en attente une fois la fenetre epuisee sont, eux, regroupes en segments pleins.

Ce script (a) verifie que le modele reproduit les sequences de segments observees (p5_segments.csv de 10) ; (b) predit k pour les 21 paires TLS
avec ce mecanisme et le compare a k observe (p3_k_pred_vs_obs.csv de 07) ; (c) compare aux variantes 'octets' et 'deux ecritures' de 07.
TRANSPARENCE : le mecanisme est deduit des pcap de x448_mlkem768 (un seul KEM, trois signatures), pas des k observes ; son extension aux autres
KEM/niveaux repose sur l'hypothese que la meme pile (OpenSSL, SHA-384, ChangeCipherSpec de compatibilite) est utilisee partout.

Usage : python3 tools/11_modele_ecritures_tls.py --phase3 analysis_v2/phase3 [--segments analysis_v2/phase5/p5_segments.csv] [--out analysis_v2/phase5]
"""
from __future__ import annotations
import argparse, importlib.util, math, os, re, sys, warnings
import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")
HERE = os.path.dirname(os.path.abspath(__file__))
REP: list[str] = []
BUF = 4096
RTT_PROFILS = (125.02, 167.04)


def log(msg=""):
    print(msg, flush=True)
    REP.append(str(msg))


def load_mod(fname, name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, fname))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ------------------------------------------------------------------------------------------------ modele
def records(p3, kem, sig, chain_bytes, depth=1, hash_len=48):
    """Enregistrements TLS du vol serveur (octets, en-tete de 5 o compris), dans l'ordre d'emission."""
    _, ss = p3.kem_shares(kem)
    return [95 + ss,                              # ServerHello
            6,                                    # ChangeCipherSpec (mode de compatibilite)
            28,                                   # EncryptedExtensions (chiffre)
            chain_bytes + 30 + 5 * depth,         # Certificate
            p3.SIG_BYTES[sig] + 30,               # CertificateVerify
            5 + 4 + hash_len + 1 + 16]            # Finished


def bio_writes(recs, buf=None):
    """Ecritures sur le socket produites par le tampon d'ecriture (BIO_f_buffer) pour la suite d'enregistrements."""
    buf = buf or BUF
    writes, fill = [], 0
    for r in recs:
        inl = r
        if buf - fill >= inl:
            fill += inl
            continue
        if buf - fill > 0:                        # remplir le tampon, puis le vider
            inl -= buf - fill
            fill = buf
        if fill > 0:
            writes.append(fill)
            fill = 0
        if inl >= buf:                            # ecriture directe du reste
            writes.append(inl)
            inl = 0
        fill = inl
    if fill > 0:
        writes.append(fill)
    return writes


def tcp_first_window(writes, mss, iw=10):
    """-> (segments emis dans la fenetre initiale, octets en attente). Une ecriture emet des segments pleins puis un segment partiel
    tant que la fenetre est ouverte ; une fois fermee, tout est mis en attente (segmentation ulterieure en segments pleins)."""
    seg, q = [], 0
    for w in writes:
        if len(seg) < iw and q == 0:
            segs = [mss] * (w // mss) + ([w % mss] if w % mss else [])
            room = iw - len(seg)
            seg += segs[:room]
            if len(segs) > room:
                q += w - sum(segs[:room])
        else:
            q += w
    return seg, q


def rounds_bio(p3, kem, sig, chain_bytes, mss=1448, iw=10, depth=1):
    recs = records(p3, kem, sig, chain_bytes, depth)
    w = bio_writes(recs)
    seg, q = tcp_first_window(w, mss, iw)
    s_eff = len(seg) + (math.ceil(q / mss) if q else 0)
    return p3.rounds_needed(s_eff, iw, iw), s_eff, w, seg, sum(recs)


def rle(seq):
    out, i = [], 0
    while i < len(seq):
        j = i
        while j < len(seq) and seq[j] == seq[i]:
            j += 1
        out.append("%d" % seq[i] if j - i == 1 else "%dx%d" % (seq[i], j - i))
        i = j
    return ",".join(out)


def parse_rle(s):
    out = []
    for t in str(s).split(","):
        if "x" in t:
            a, b = t.split("x")
            out += [int(a)] * int(b)
        else:
            out.append(int(t))
    return out


# ------------------------------------------------------------------------------------------------ (a) validation sur les sequences observees
def validate(p3, chain, seg_csv, out):
    log("=== (a) LE MODELE D'ECRITURES REPRODUIT-IL LES SEQUENCES DE SEGMENTS OBSERVEES (pcap reels) ? ===")
    if not seg_csv or not os.path.exists(seg_csv):
        log("    (p5_segments.csv introuvable : --segments)")
        return None
    s = pd.read_csv(seg_csv)
    s = s[s.proto == "tls"]
    rows = []
    for _, x in s.iterrows():
        sig, kem = x.pair.split("_", 1)
        padded = "padto8700" in x.label
        mss = 1228 if "mtu1280" in x.label else 1448
        ch = 8700 if padded else chain[sig]
        rd, s_eff, w, seg, tot = rounds_bio(p3, kem, sig, ch, mss)
        obs = parse_rle(x.sequence_modale)
        # la signature ECDSA DER varie de quelques octets d'un flux a l'autre (r, s sans octet de tete) -> tolerance de 3 o par element
        ok = len(seg) == len(obs) and all(abs(a - b) <= 3 for a, b in zip(seg, obs))
        exact = len(seg) == len(obs) and all(a == b for a, b in zip(seg, obs))
        rows.append(dict(label=x.label, pair=x.pair, mss=mss, ecritures_modele="+".join(map(str, w)), sequence_modele=rle(seg),
                         sequence_observee=x.sequence_modale, part_flux_sequence_observee=x.part_flux_sequence_modale,
                         identique=ok, exacte=exact, octets_modele=tot, octets_observes=x.octets_vol_modal))
        log("    %-52s %-24s modele : %-42s observe : %-42s %s" % (x.label[-52:], x.pair, rle(seg), x.sequence_modale, ("IDENTIQUE" if exact else "IDENTIQUE a 3 o pres" if ok else "DIFFERENT")))
        log("    %-52s %-24s ecritures du modele : %s (octets %d contre %d observes)" % ("", "", "+".join(map(str, w)), tot, x.octets_vol_modal))
    r = pd.DataFrame(rows)
    log("    -> %d / %d cellules reproduites exactement, %d / %d a 3 o pres (la longueur DER d'une signature ECDSA varie de quelques octets)." % (
        int(r.exacte.sum()), len(r), int(r.identique.sum()), len(r)))
    for _, x in r.iterrows():
        n = len(parse_rle(x.sequence_modele))
        if n >= 10:
            log("    NB : %s %s remplit EXACTEMENT la fenetre initiale (%d segments sur 10) et ne bascule pas (k observe ~ 0) : un segment de plus => k = 1." % (
                x.label[-40:], x.pair, n))
    log("    Le 1er segment plein et le segment partiel a la fin de chaque ecriture sont reproduits sans parametre ajuste.")
    r.to_csv(os.path.join(out, "p5b_segments_validation.csv"), index=False)
    return r


# ------------------------------------------------------------------------------------------------ (b) k predit contre k observe
def load_obs(path):
    d = pd.read_csv(path)
    km = [c for c in d.columns if re.fullmatch(r"k\d+", c)]
    kd = [c + "_med" for c in km]
    obs = {}
    for _, r in d.iterrows():
        obs[(r.proto, r.level, r.kem)] = dict(mean=np.array([r[c] for c in km], float), med=np.array([r[c] for c in kd], float))
    return obs


def verdict(kp, ks):
    dev = float(np.max(np.abs(np.asarray(ks, float) - kp)))
    return "conforme" if dev <= 0.25 else ("partiel" if dev <= 0.75 else "infirme")


def compare(p3, chain, phase3, tau_tls, out):
    log("\n=== (b) k PREDIT PAR LE MODELE D'ECRITURES CONTRE k OBSERVE (21 paires TLS, estimateur MEDIAN par bloc, profils RTT 125 / 167) ===")
    obs = load_obs(os.path.join(phase3, "p3_k_pred_vs_obs.csv"))
    rows = []
    for lv in ("L1", "L3", "L5"):
        cl, ml = p3.CLASSICAL_OF[lv], p3.MLDSA_OF[lv]
        for kem in p3.KEMS[lv]:
            rc, sc, wc, _, bc = rounds_bio(p3, kem, cl, chain[cl])
            rm, sm, wm, _, bm = rounds_bio(p3, kem, ml, chain[ml])
            kb = p3.tls_rounds(kem, ml, chain, "bytes")[0] - p3.tls_rounds(kem, cl, chain, "bytes")[0]
            kw = p3.tls_rounds(kem, ml, chain, "writes")[0] - p3.tls_rounds(kem, cl, chain, "writes")[0]
            ko = obs[("tls", lv, kem)]["med"]
            kbio = rm - rc
            # recouvrement du calcul client HQC-192 : k apparent = 1 - T / RTT (T mesure sans perte sur fx)
            kbio_tau = [kbio * max(0.0, 1.0 - tau_tls / r) if (kbio and "hqc192" in kem) else float(kbio) for r in RTT_PROFILS]
            rows.append(dict(level=lv, kem=kem, marge_segments_mldsa=sm - 10, segments_classique=sc, segments_mldsa=sm, octets_classique=bc, octets_mldsa=bm,
                             R_cl=rc, R_ml=rm, k_octets=kb, k_deux_ecritures=kw, k_ecritures_bio=kbio,
                             k_obs_125=ko[0], k_obs_167=ko[1], verdict_octets=verdict(kb, ko), verdict_deux_ecritures=verdict(kw, ko),
                             verdict_bio=verdict(kbio, ko), verdict_bio_tau=verdict_tau(kbio_tau, ko)))
    r = pd.DataFrame(rows)
    triv = {k: verdict(0, obs[("tls",) + k]["med"]) for k in [(a, b) for a, b in zip(r.level, r.kem)]}
    r["trivial_conforme"] = [triv[(a, b)] == "conforme" for a, b in zip(r.level, r.kem)]
    r["informative"] = ~r.trivial_conforme
    log("    %-3s %-16s %5s %5s %7s %7s | k : %-6s %-6s %-6s | obs 125/167    | verdicts : octets / 2 ecritures / BIO / BIO+T" % (
        "niv", "KEM", "seg.cl", "seg.ML", "oct.cl", "oct.ML", "octets", "2 ecr.", "BIO"))
    for _, x in r.iterrows():
        log("    %-3s %-16s %5d %5d %7d %7d | k : %-6d %-6d %-6d | %5.2f / %5.2f | %s / %s / %s / %s%s" % (
            x.level, x.kem, x.segments_classique, x.segments_mldsa, x.octets_classique, x.octets_mldsa, x.k_octets, x.k_deux_ecritures, x.k_ecritures_bio,
            x.k_obs_125, x.k_obs_167, x.verdict_octets, x.verdict_deux_ecritures, x.verdict_bio, x.verdict_bio_tau, "   <-- informative" if x.informative else ""))
    log("")
    for nm, col in (("octets seuls (07)", "verdict_octets"), ("deux ecritures (07, post hoc)", "verdict_deux_ecritures"),
                    ("ecritures BIO (mecanisme deduit des pcap)", "verdict_bio"), ("ecritures BIO + recouvrement T (HQC-192)", "verdict_bio_tau")):
        a = r[col].value_counts()
        b = r[r.informative][col].value_counts()
        log("    %-46s 21 paires : %d conformes / %d partiels / %d infirmes   | %d informatives : %d / %d / %d" % (
            nm, a.get("conforme", 0), a.get("partiel", 0), a.get("infirme", 0), int(r.informative.sum()),
            b.get("conforme", 0), b.get("partiel", 0), b.get("infirme", 0)))
    fr = r[r.marge_segments_mldsa.abs() <= 1]
    log("\n    Paires a +-1 segment de la limite de 10 (predictions fragiles) : %s" % (", ".join("%s %s (%d segments)" % (x.level, x.kem, x.segments_mldsa) for _, x in fr.iterrows()) or "aucune"))
    ch = r[(r.k_octets != r.k_ecritures_bio) | (r.k_deux_ecritures != r.k_ecritures_bio)]
    log("\n    Paires ou les trois modeles divergent : %s" % (", ".join("%s %s (octets %d / 2 ecr. %d / BIO %d ; observe %.2f-%.2f)" % (
        x.level, x.kem, x.k_octets, x.k_deux_ecritures, x.k_ecritures_bio, x.k_obs_125, x.k_obs_167) for _, x in ch.iterrows()) or "aucune"))
    log("    Lecture : si le modele BIO reproduit les paires proches du seuil (TLS L5 ML-KEM-1024 : 13 914 / 14 047 o contre 14 480 o) SANS avoir ete ajuste sur elles,")
    log("    la correction 'deux ecritures' (post hoc) est remplacee par un mecanisme observe sur pcap : chaque ecriture consomme un segment de fenetre partiel.")
    r.to_csv(os.path.join(out, "p5b_k_pred_ecritures.csv"), index=False)
    return r


def verdict_tau(kp_list, ko):
    dev = max(abs(a - b) for a, b in zip(kp_list, ko))
    return "conforme" if dev <= 0.25 else ("partiel" if dev <= 0.75 else "infirme")


def natural(p3, chain, out):
    log("\n=== (c) CELLULES NATURELLES TLS (chaine a 2 niveaux, x448_mlkem768 / hqc192) : vols predits par le modele d'ecritures ===")
    rows = []
    for kem in ("x448_mlkem768", "hqc192"):
        rc, sc, wc, _, bc = rounds_bio(p3, kem, "secp384r1", 903, depth=2)
        rm, sm, wm, _, bm = rounds_bio(p3, kem, "mldsa65", 11032, depth=2)
        log("    %-14s classique : ecritures %s, segments %d, tours %d | ML-DSA : ecritures %s, segments %d, tours %d | k = %d" % (
            kem, "+".join(map(str, wc)), sc, rc, "+".join(map(str, wm)), sm, rm, rm - rc))
        rows.append(dict(kem=kem, k=rm - rc, ecritures_ml="+".join(map(str, wm)), segments_ml=sm, segments_cl=sc))
    pd.DataFrame(rows).to_csv(os.path.join(out, "p5b_chain2.csv"), index=False)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--phase3", default="analysis_v2/phase3")
    ap.add_argument("--segments", default=None)
    ap.add_argument("--out", default="analysis_v2/phase5")
    ap.add_argument("--manifest", default=None)
    ap.add_argument("--buf", type=int, default=4096, help="taille du tampon d'ecriture (test de falsification : 4096 attendu)")
    ap.add_argument("--tau-tls", type=float, default=38.9, help="recouvrement HQC-192 en TLS mesure sans perte (10 section 1)")
    a = ap.parse_args()
    global BUF
    BUF = a.buf
    os.makedirs(a.out, exist_ok=True)
    p3 = load_mod("07_threshold_model.py", "p3_threshold")
    chain = p3.chain_sizes(a.manifest)
    seg_csv = a.segments or os.path.join(a.out, "p5_segments.csv")
    log("PHASE 5b -- modele d'ecritures TLS (tampon d'ecriture OpenSSL de %d o). Chaines : %s" % (BUF, {k: chain[k] for k in ("secp384r1", "mldsa65")}))
    validate(p3, chain, seg_csv, a.out)
    compare(p3, chain, a.phase3, a.tau_tls, a.out)
    natural(p3, chain, a.out)
    with open(os.path.join(a.out, "p5b_report.txt"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(REP))
    log("\nTermine -> %s" % a.out)


if __name__ == "__main__":
    main()
