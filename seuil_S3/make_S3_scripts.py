#!/usr/bin/env python3
# Cree seuil_S3/predict_freeze_S3.py et seuil_S3/make_plan_S3.py a partir des scripts GELES de S2 (qui ne sont pas modifies).
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__)); S2 = os.path.join(os.path.dirname(HERE), "seuil_S2")
def sub(s, o, n, label):
    c = s.count(o)
    if c != 1: sys.exit("ANCRE %s: %d occurrences" % (label, c))
    return s.replace(o, n)
t = open(os.path.join(S2, "predict_freeze_S2_quicc.py"), encoding="utf-8").read()
t = sub(t, '''    "QUIC_C":   dict(proto="quic", sig="ed25519", kem="hqc128", mtu=1500, bridge="mldsa44", iw=None,
                     intervention="partage de cle client HQC-128 (B_c attendu : 3 datagrammes)"),
}''', '''    "QUIC_C":   dict(proto="quic", sig="ed25519", kem="hqc128", mtu=1500, bridge="mldsa44", iw=None,
                     intervention="partage de cle client HQC-128 (B_c attendu : 3 datagrammes)"),
    # --- S3 : B_c varie par une extension ClientHello privee (CH_PAD_BYTES), meme KEM, meme signature, meme chaine, meme vol serveur
    "QUIC_PAD1": dict(proto="quic", sig="secp384r1", kem="x448_mlkem768", mtu=1500, bridge="mldsa65", iw=None,
                     intervention="remplissage du ClientHello (CH_PAD_BYTES) : B_c attendu 3 datagrammes, meme vol serveur"),
    "QUIC_PAD0": dict(proto="quic", sig="secp384r1", kem="x448_mlkem768", mtu=1500, bridge="mldsa65", iw=None,
                     intervention="temoin sans remplissage (B_c = 2 440 o), meme binaire MsQuic"),
}''', "fam")
t = sub(t, 'MAX_CHAIN = {"TLS_IW4": 20000, "TLS_IW20": 46000, "QUIC_C": 12000}', 'MAX_CHAIN = {"TLS_IW4": 20000, "TLS_IW20": 46000, "QUIC_C": 12000, "QUIC_PAD1": 12500, "QUIC_PAD0": 12500}', "max")
t = sub(t, '    ap.add_argument("--max-chain", type=int, default=None)\n', '    ap.add_argument("--max-chain", type=int, default=None)\n    ap.add_argument("--sizes", default=None, help="tailles de chaine imposees (liste separee par des virgules) : sert a donner au temoin QUIC_PAD0 les memes cellules que QUIC_PAD1")\n', "arg")
t = sub(t, '    f["sizes"] = choose_sizes(M, fam, ra, rb, extra)\n', '    f["sizes"] = choose_sizes(M, fam, ra, rb, extra)\n    if a.sizes:\n        f["sizes"] = sorted(int(x) for x in a.sizes.split(","))\n', "sizes")
open(os.path.join(HERE, "predict_freeze_S3.py"), "w", encoding="utf-8").write(t)
m = open(os.path.join(S2, "make_plan_S2.py"), encoding="utf-8").read()
open(os.path.join(HERE, "make_plan_S3.py"), "w", encoding="utf-8").write(m)
print("OK : predict_freeze_S3.py, make_plan_S3.py crees")
