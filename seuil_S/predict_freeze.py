#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""predict_freeze.py -- PREDICTIONS FIGEES de la campagne « franchissement de seuil » (campagne S).

A executer, et son resultat COMMITE + HORODATE, AVANT le premier bloc de mesure (voir PREREGISTRATION_S.md).
Aucune donnee de temps n'est lue : le script ne depend que (i) des constantes physiques/logicielles ci-dessous, (ii) des deux modules
de modele deja ecrits et figes (07_threshold_model.py, 11_modele_ecritures_tls.py) dont l'empreinte sha256 est consignee.

CE QUI EST PREDIT, POUR CHAQUE CELLULE (famille, taille de chaine ECDSA/Ed25519 rembourree X, RTT quelconque) :
    k = (nombre d'allers-retours du vol serveur avec chaine de X octets) - (nombre avec la chaine de base non rembourree)
TLS/TCP  : deux regles rivales, ecrites avant les donnees
    R_octets : vol en octets F ; segments = ceil(F / MSS) ; fenetre initiale 10 segments (doublement ensuite)
    R_ecritures (« BIO ») : le vol part en ecritures produites par le tampon d'ecriture d'OpenSSL (4 096 o) ; le dernier segment de chaque
              ecriture est partiel et consomme un segment de fenetre (mecanisme deduit des pcap x448_mlkem768 de la campagne v2)
QUIC     : deux regles rivales
    R_amp  : premiere salve = min(3 x octets Initial client, W0 = 12 520 o), puis doublement de W0
    R_cwnd : la limite anti-amplification n'agit pas : premiere salve = W0 (RFC 9002, 10 datagrammes de 1 252 o)
Rival trivial : TLS k=0, QUIC k=1 des que X > base (reference seulement).

Sorties (dans --out) : predictions_frozen.csv, thresholds_frozen.csv, constants_frozen.json, SHA256SUMS_frozen.txt
Usage : python3 predict_freeze.py --tools /chemin/vers/tools --out freeze_S
"""
from __future__ import annotations
import argparse, hashlib, importlib.util, json, math, os, sys

# ------------------------------------------------------------------------------------------------ grille FIGEE
# chain_target = valeur de CERT_PAD_TARGET_DER (octets DER de la chaine de certificats, feuille remplie) ; 0 = chaine de base non remplie.
BASE_CHAIN = {"secp384r1": 430, "ed25519": 304}
FAMILIES = {
    "TLS_1500": dict(proto="tls", sig="secp384r1", kem="x448_mlkem768", mtu=1500, bridge="mldsa65",
                     sizes=[6000, 9100, 10000, 11300, 11650, 12200, 12500, 12800, 13150, 16000, 28000, 41400, 41800, 42100, 46000],
                     pcap=[10000, 11300, 11650, 12800, 13150, 41400, 41800]),
    "TLS_1280": dict(proto="tls", sig="secp384r1", kem="x448_mlkem768", mtu=1280, bridge="mldsa65",
                     sizes=[8600, 9100, 9500, 10000, 10600, 10950], pcap=[9100, 10000, 10600]),
    "QUIC_A":   dict(proto="quic", sig="secp384r1", kem="x448_mlkem768", mtu=1500, bridge="mldsa65",
                     sizes=[3000, 5400, 5950, 7500, 9500, 10200, 10900, 14000, 29400, 30300, 32500, 35100],
                     pcap=[5400, 5950, 9500, 10900, 29400, 30300]),
    "QUIC_B":   dict(proto="quic", sig="ed25519", kem="x25519_mlkem512", mtu=1500, bridge="mldsa44",
                     sizes=[1500, 2150, 2800, 5000, 8000, 10500, 11400, 14000, 26200, 27100, 31000, 35500],
                     pcap=[2150, 2800, 8000, 11400]),
}
RTTS = [50, 150]            # RTT (ms) des cellules de mesure ; les cellules pcap n'existent qu'a 50 ms
TOL_K = 0.25                # tolerance de classement (comme en v2)
MARGIN_MIN = {"tls": 60, "quic": 150}   # marge minimale (octets de chaine) entre chaque cellule et la frontiere la plus proche de CHAQUE regle
STEP = 1                    # pas (octets) du balayage de marges


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


class Model:
    def __init__(self, tools):
        sys.path.insert(0, tools)
        self.p3 = load(os.path.join(tools, "07_threshold_model.py"), "p3_threshold")
        self.m11 = load(os.path.join(tools, "11_modele_ecritures_tls.py"), "m11_writes")
        self.tools = tools

    # ---------------- TLS
    REC_MAX = 16384          # RFC 8446 s5.1 : charge utile maximale d'un enregistrement TLS 1.3
    REC_OVH = 5 + 1 + 16     # en-tete 5 o + type interne 1 o + etiquette AEAD 16 o, par enregistrement supplementaire
    split_records = True     # calage de phase 0 (mesure : +43,5 o a 46 000 o = 2 enregistrements supplementaires)

    def records(self, kem, sig, chain):
        """Enregistrements du vol serveur ; le message Certificate de plus de 16 384 o est fragmente en enregistrements <= 16 384 o."""
        recs = list(self.m11.records(self.p3, kem, sig, chain))
        if not self.split_records:
            return recs
        out = []
        for i, r in enumerate(recs):
            if i == 3:                                   # Certificate
                plain = r - 5 - 16                       # charge utile en clair, type interne compris
                n = max(1, math.ceil(plain / (self.REC_MAX + 1)))
                if n > 1:
                    first = r + (n - 1) * self.REC_OVH
                    sizes = [self.REC_MAX + 1 + 5 + 16] * (n - 1)
                    sizes.append(first - sum(sizes))
                    out.extend(sizes)
                    continue
            out.append(r)
        return out

    def tls_flight(self, kem, sig, chain, mss):
        recs = self.records(kem, sig, chain)
        return sum(recs)

    def tls_octets(self, kem, sig, chain, mss):
        F = self.tls_flight(kem, sig, chain, mss)
        segs = math.ceil(F / mss)
        r = self.p3.rounds_needed(segs, 10, 10)
        fw_seg = min(10, segs)
        fw_bytes = min(F, 10 * mss)
        return dict(F=F, segs=segs, rounds=r, fw_seg=fw_seg, fw_bytes=fw_bytes)

    def tls_bio(self, kem, sig, chain, mss):
        recs = self.records(kem, sig, chain)
        w = self.m11.bio_writes(recs)
        seg, q = self.m11.tcp_first_window(w, mss, 10)
        s_eff = len(seg) + (math.ceil(q / mss) if q else 0)
        r = self.p3.rounds_needed(s_eff, 10, 10)
        return dict(F=sum(recs), segs=s_eff, rounds=r, fw_seg=len(seg), fw_bytes=sum(seg), writes="+".join(map(str, w)))

    # ---------------- QUIC
    bc_override: dict = {}
    q_offset = 0.0      # octets additifs au vol serveur QUIC (calage de phase 0)
    amp_sub = 0         # octets retranches a 3 x B_c : plafond mesure de la salve 1 (calage de phase 0)

    def _quic(self, kem, sig, chain, rule):
        p3 = self.p3
        cs, ss = p3.kem_shares(kem)
        c_bytes = self.bc_override.get(kem) or math.ceil((p3.CH_BASE + cs) / p3.CH_CAP) * p3.QUIC_DGRAM
        s = p3.RHO_QUIC * (p3.SH_FIX + ss + (p3.A_TLS - p3.SH_FIX) + chain + p3.SIG_BYTES[sig]) + self.q_offset
        b1 = min(3 * c_bytes - self.amp_sub, p3.QUIC_IW) if rule == "amp" else p3.QUIC_IW
        return dict(F=s, rounds=p3.rounds_needed(s, b1, p3.QUIC_IW), burst=b1, bc=c_bytes)

    def quic_amp(self, kem, sig, chain):
        return self._quic(kem, sig, chain, "amp")

    def quic_cwnd(self, kem, sig, chain):
        return self._quic(kem, sig, chain, "cwnd")

    def rule_rounds(self, fam, rule, chain, sig=None):
        f = FAMILIES[fam]
        sig = sig or f["sig"]
        if f["proto"] == "tls":
            mss = f["mtu"] - 52
            return (self.tls_octets if rule == "octets" else self.tls_bio)(f["kem"], sig, chain, mss)
        return (self.quic_amp if rule == "amp" else self.quic_cwnd)(f["kem"], sig, chain)


RULES = {"tls": ("octets", "bio"), "quic": ("amp", "cwnd")}


def margin(M, fam, rule, chain, span=1500):
    """Distance minimale (octets de chaine) a un changement de rounds de cette regle."""
    r0 = M.rule_rounds(fam, rule, chain)["rounds"]
    best = span + 1
    for d in range(1, span + 1, STEP):
        for c in (chain - d, chain + d):
            if c < 100:
                continue
            if M.rule_rounds(fam, rule, c)["rounds"] != r0:
                return d
    return best


def r50(x):
    return int(round(x / 50.0) * 50)


def threshold(M, fam, rule, step):
    base = BASE_CHAIN[FAMILIES[fam]["sig"]]
    b0 = M.rule_rounds(fam, rule, base)["rounds"]
    for c in range(base, 80001):
        if M.rule_rounds(fam, rule, c)["rounds"] - b0 >= step:
            return c
    raise RuntimeError("seuil introuvable")


def auto_quic_sizes(M):
    """Les tailles QUIC sont DEDUITES des seuils calcules avec les constantes de phase 0 (decalages fixes en octets de chaine)."""
    for fam in ("QUIC_A", "QUIC_B"):
        t1a, t1c = threshold(M, fam, "amp", 1), threshold(M, fam, "cwnd", 1)
        t2a, t2c = threshold(M, fam, "amp", 2), threshold(M, fam, "cwnd", 2)
        sizes = [0.5 * t1a, t1a - 350, t1a + 250, t1a + 0.4 * (t1c - t1a), t1c - 1000, t1c - 350, t1c + 350, t1c + 3500,
                 t2a - 450, t2a + 450, 0.5 * (t2a + t2c), t2c + 400]
        sizes = sorted(set(r50(x) for x in sizes))
        FAMILIES[fam]["sizes"] = sizes
        FAMILIES[fam]["pcap"] = [r50(x) for x in (t1a - 350, t1a + 250, t1c - 1000, t1c + 350, t2a - 450, t2a + 450)][: (6 if fam == "QUIC_A" else 4)]
        FAMILIES[fam]["thresholds_model"] = dict(amp1=t1a, cwnd1=t1c, amp2=t2a, cwnd2=t2c)


def build(M):
    rows = []
    for fam, f in FAMILIES.items():
        proto, sig, kem = f["proto"], f["sig"], f["kem"]
        ra, rb = RULES[proto]
        base = BASE_CHAIN[sig]
        b_a, b_b = M.rule_rounds(fam, ra, base), M.rule_rounds(fam, rb, base)
        assert b_a["rounds"] == 1 and b_b["rounds"] == 1, (fam, "la base doit tenir en un tour", b_a, b_b)
        cells = [(0, "base")] + [(x, "pad") for x in f["sizes"]]
        for X, kind in cells:
            ch = base if X == 0 else X
            a, b = M.rule_rounds(fam, ra, ch), M.rule_rounds(fam, rb, ch)
            ka, kb = a["rounds"] - b_a["rounds"], b["rounds"] - b_b["rounds"]
            row = dict(family=fam, proto=proto, sig=sig, kem=kem, mtu=f["mtu"], chain_target=X, kind=kind,
                       flight_a=round(a["F"], 1), flight_b=round(b["F"], 1),
                       rule_a=ra, rule_b=rb, rounds_a=a["rounds"], rounds_b=b["rounds"], k_a=ka, k_b=kb,
                       disc=int(ka != kb), k_max=max(ka, kb), tier=("primary" if max(ka, kb) <= 1 else "secondary"),
                       k_trivial=(0 if proto == "tls" else int(X > 0)), pcap_cell=int(X in f["pcap"]))
            if proto == "tls":
                row.update(fw_seg_a=a["fw_seg"], fw_seg_b=b["fw_seg"], fw_bytes_a=a["fw_bytes"], fw_bytes_b=b["fw_bytes"],
                           segs_a=a["segs"], segs_b=b["segs"], writes_b=b["writes"], quic_burst_a="", quic_burst_b="", quic_bc="")
            else:
                row.update(fw_seg_a="", fw_seg_b="", fw_bytes_a="", fw_bytes_b="", segs_a="", segs_b="", writes_b="",
                           quic_burst_a=a["burst"], quic_burst_b=b["burst"], quic_bc=a["bc"])
            if X > 0:
                row["margin_a"], row["margin_b"] = margin(M, fam, ra, X), margin(M, fam, rb, X)
            else:
                row["margin_a"] = row["margin_b"] = ""
            rows.append(row)
        # pont : signature post-quantique de meme niveau, chaine d'origine (aucun remplissage)
        br = f["bridge"]
        bb = M.rule_rounds(fam, ra, M.p3.CHAIN_DEFAULT[br], sig=br), M.rule_rounds(fam, rb, M.p3.CHAIN_DEFAULT[br], sig=br)
        ka, kb = bb[0]["rounds"] - b_a["rounds"], bb[1]["rounds"] - b_b["rounds"]
        rows.append(dict(family=fam, proto=proto, sig=br, kem=kem, mtu=f["mtu"], chain_target=0, kind="bridge",
                         flight_a=round(bb[0]["F"], 1), flight_b=round(bb[1]["F"], 1), rule_a=ra, rule_b=rb,
                         rounds_a=bb[0]["rounds"], rounds_b=bb[1]["rounds"], k_a=ka, k_b=kb, disc=int(ka != kb),
                         k_max=max(ka, kb), tier="bridge", k_trivial=(0 if proto == "tls" else 1), pcap_cell=0,
                         margin_a="", margin_b=""))
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tools", required=True, help="dossier contenant 07_threshold_model.py, 11_modele_ecritures_tls.py et pq_common.py")
    ap.add_argument("--out", default="freeze_S")
    ap.add_argument("--quic-dgram", type=int, default=None, help="charge utile d'un datagramme QUIC (octets), mesuree en phase 0 ; W0 = 10 x cette valeur")
    ap.add_argument("--rho-quic", type=float, default=None, help="surcout QUIC / TLS (octets recus), mesure en phase 0")
    ap.add_argument("--q-offset", type=float, default=0.0, help="octets additifs au vol serveur QUIC (mediane de burst1 - vol predit, cellules remplies non plafonnees, phase 0)")
    ap.add_argument("--amp-sub", type=int, default=0, help="octets retranches a 3 x B_c (plafond mesure de la salve 1 = 3 x B_c - N, phase 0)")
    ap.add_argument("--bc", action="append", help="KEM=octets du premier vol client QUIC mesure en phase 0 (ex. x448_mlkem768=2440), repetable")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    M = Model(os.path.abspath(a.tools))
    if a.quic_dgram:
        M.p3.QUIC_DGRAM = a.quic_dgram
        M.p3.QUIC_IW = 10 * a.quic_dgram          # RFC 9002 : fenetre initiale = 10 datagrammes (MDS <= 1 472 o)
    if a.rho_quic:
        M.p3.RHO_QUIC = a.rho_quic
    M.q_offset = a.q_offset
    M.amp_sub = a.amp_sub
    for kv in a.bc or []:
        k, v = kv.split("=")
        M.bc_override[k] = int(v)
    auto_quic_sizes(M)
    rows = build(M)
    import pandas as pd
    df = pd.DataFrame(rows)

    # ---- controles de conception (echec = grille a corriger AVANT gel)
    bad = []
    for _, r in df[df.kind == "pad"].iterrows():
        need = MARGIN_MIN[r.proto]
        if r.margin_a < need or r.margin_b < need:
            bad.append((r.family, r.chain_target, r.margin_a, r.margin_b))
    assert not bad, "marges insuffisantes : %s" % bad
    if not a.quic_dgram and not a.rho_quic and not a.bc and not a.q_offset and not a.amp_sub:
        for _, r in df[(df.proto == "quic") & (df.kind == "pad")].iterrows():
            c = dict(M.p3.CHAIN_DEFAULT); c[r.sig] = int(r.chain_target)
            assert M.p3.quic_rounds(r.kem, r.sig, c)[0] == r.rounds_a, ("incoherence regle amp", r.family, r.chain_target)
    # coherence avec le code d'origine (07) pour la regle « octets » a MTU 1500
    for _, r in df[(df.family == "TLS_1500") & (df.kind == "pad")].iterrows():
        c = dict(M.p3.CHAIN_DEFAULT); c["secp384r1"] = int(r.chain_target)
        ref = M.p3.tls_rounds("x448_mlkem768", "secp384r1", c, "bytes")[0]
        assert ref == r.rounds_a, ("incoherence regle octets", r.chain_target, ref, r.rounds_a)
    df.to_csv(os.path.join(a.out, "predictions_frozen.csv"), index=False)

    # ---- seuils predits (premiere taille de chaine pour laquelle chaque regle predit k >= 1, puis k >= 2), balayage a 1 octet
    th = []
    for fam, f in FAMILIES.items():
        ra, rb = RULES[f["proto"]]
        for rule in (ra, rb):
            base_r = M.rule_rounds(fam, rule, BASE_CHAIN[f["sig"]])["rounds"]
            found = {}
            nonmono = 0
            prev_k = 0
            for c in range(BASE_CHAIN[f["sig"]], 60001):
                x = M.rule_rounds(fam, rule, c)
                k = x["rounds"] - base_r
                if k < prev_k:
                    nonmono += 1
                prev_k = max(prev_k, k)
                for step in (1, 2):
                    if k >= step and step not in found:
                        found[step] = (c, x["F"])
            for step, (c, F) in sorted(found.items()):
                th.append(dict(family=fam, rule=rule, step=step, chain_threshold=c, flight_threshold=round(F, 1), nonmonotone_points=nonmono))
    pd.DataFrame(th).to_csv(os.path.join(a.out, "thresholds_frozen.csv"), index=False)

    const = dict(
        MSS_1500=1448, MSS_1280=1228, TCP_IW_SEGMENTS=10, BIO_BUFFER=M.m11.BUF, TLS_A=M.p3.A_TLS, SH_FIX=M.p3.SH_FIX,
        QUIC_DGRAM=M.p3.QUIC_DGRAM, QUIC_W0=M.p3.QUIC_IW, RHO_QUIC=M.p3.RHO_QUIC, CH_BASE=M.p3.CH_BASE, CH_CAP=M.p3.CH_CAP,
        KEM_SHARE=M.p3.KEM_SHARE, SIG_BYTES=M.p3.SIG_BYTES, CHAIN_DEFAULT=M.p3.CHAIN_DEFAULT, BASE_CHAIN=BASE_CHAIN,
        FAMILIES={k: {kk: vv for kk, vv in v.items()} for k, v in FAMILIES.items()}, RTTS=RTTS, TOL_K=TOL_K, MARGIN_MIN=MARGIN_MIN,
        source_sha256={n: sha256(os.path.join(a.tools, n)) for n in ("07_threshold_model.py", "11_modele_ecritures_tls.py", "pq_common.py")
                       if os.path.exists(os.path.join(a.tools, n))},
        this_script_sha256=sha256(os.path.abspath(__file__)),
        phase0_overrides=dict(quic_dgram=a.quic_dgram, rho_quic=a.rho_quic, bc=a.bc, q_offset=a.q_offset, amp_sub=a.amp_sub))
    with open(os.path.join(a.out, "constants_frozen.json"), "w") as f:
        json.dump(const, f, indent=1, sort_keys=True)
    with open(os.path.join(a.out, "SHA256SUMS_frozen.txt"), "w") as f:
        for n in ("predictions_frozen.csv", "thresholds_frozen.csv", "constants_frozen.json"):
            f.write("%s  %s\n" % (sha256(os.path.join(a.out, n)), n))

    # ---- resume lisible
    pd.set_option("display.width", 250, "display.max_rows", 500)
    print("=== PREDICTIONS FIGEES : %d cellules (grille) ===" % len(df))
    for fam in FAMILIES:
        d = df[df.family == fam]
        print("\n--- %s (%s, %s, %s, MTU %d) : regles %s / %s ---" % (fam, FAMILIES[fam]["proto"], FAMILIES[fam]["sig"], FAMILIES[fam]["kem"],
                                                                      FAMILIES[fam]["mtu"], d.rule_a.iloc[0], d.rule_b.iloc[0]))
        print(d[["kind", "sig", "chain_target", "flight_a", "flight_b", "k_a", "k_b", "disc", "tier", "margin_a", "margin_b", "pcap_cell"]].to_string(index=False))
    n_disc = int(df[(df.kind == "pad") & (df.disc == 1)].shape[0])
    print("\nCellules de mesure remplies : %d ; discriminantes (k_a != k_b) : %d ; bridge : %d" % (
        (df.kind == "pad").sum(), n_disc, (df.kind == "bridge").sum()))
    print("Empreintes : voir %s/SHA256SUMS_frozen.txt" % a.out)


if __name__ == "__main__":
    main()
