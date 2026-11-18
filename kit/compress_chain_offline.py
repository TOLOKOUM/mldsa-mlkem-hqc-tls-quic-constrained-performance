#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""compress_chain_offline.py -- compression hors ligne de la chaine EXACTE envoyee par le serveur (revue du 15/11/2026, point 7).
Construit le message Certificate de TLS 1.3 (RFC 8446 s.4.4.2 : contexte vide, puis pour chaque certificat : longueur sur 3 octets,
DER, longueur d'extensions sur 2 octets = 0) a partir de fichiers PEM (feuille d'abord), puis compresse avec zlib (RFC 8879 algo 1),
Brotli (2) et Zstandard (3). Modules python 'brotli' et 'zstandard' si presents, sinon binaires 'brotli' / 'zstd'.
Usage : python3 compress_chain_offline.py leaf.pem [intermediate.pem ...]   (ou un seul fichier PEM contenant la chaine)
"""
import sys, zlib, subprocess, base64, re, shutil

def pem_certs(path):
    t = open(path).read()
    return [base64.b64decode("".join(b.split())) for b in re.findall(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", t, re.S)]

def msg(ders):
    body = b"".join(len(d).to_bytes(3, "big") + d + b"\x00\x00" for d in ders)
    return b"\x00" + len(body).to_bytes(3, "big") + body       # contexte vide (1 octet de longueur 0) + liste

def comp(name, data):
    if name == "zlib": return len(zlib.compress(data, 9))
    if name == "brotli":
        try:
            import brotli; return len(brotli.compress(data, quality=11))
        except ImportError:
            if shutil.which("brotli"): return len(subprocess.run(["brotli", "-c", "-q", "11"], input=data, capture_output=True).stdout)
    if name == "zstd":
        try:
            import zstandard; return len(zstandard.ZstdCompressor(level=19).compress(data))
        except ImportError:
            if shutil.which("zstd"): return len(subprocess.run(["zstd", "-c", "-19"], input=data, capture_output=True).stdout)
    return None

if __name__ == "__main__":
    ders = [d for f in sys.argv[1:] for d in pem_certs(f)]
    if not ders: sys.exit("aucun certificat PEM lu")
    m = msg(ders)
    print("certificats : %d ; message Certificate : %d octets" % (len(ders), len(m)))
    for n in ("zlib", "brotli", "zstd"):
        c = comp(n, m); print("%-7s %s" % (n, "indisponible" if c is None else "%d octets (gain %+d)" % (c, len(m) - c)))
