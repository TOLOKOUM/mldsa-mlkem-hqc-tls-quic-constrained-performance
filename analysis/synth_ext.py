#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""synth_ext.py -- DONNEES SYNTHETIQUES pour tester le pipeline d'analyse 13_analyse_extensions.py.

*** CE NE SONT PAS DES MESURES. *** Les valeurs sortent d'un modele simple (voir plus bas) et ne prouvent RIEN sur le
protocole : elles servent uniquement a verifier (1) que l'analyseur lit le format reel des journaux, (2) que les verdicts
PASS/FAIL/INCONCLUSIF sont correctement calcules, (3) qu'une hypothese FAUSSE est bien detectee.
Scenarios :
  h0        le monde se comporte comme les predictions enregistrees  -> l'analyse doit conclure PASS
  falsify   le monde viole trois predictions (QUIC reprise garde la penalite ML-DSA ; ML-DSA compressible a 35 % ;
            serveur MT 40 % plus lent que le serveur stock) -> l'analyse doit conclure FAIL sur ces predictions.
Usage : python3 synth_ext.py --out /tmp/synth_h0 --scenario h0 [--blocks 20]
"""
import argparse, os, math
import numpy as np

KEM_CT = {"x448_mlkem768": 1144, "hqc192": 9034}          # octets KEM dans le vol serveur
KEM_SRV_MS = {"x448_mlkem768": 13.5, "hqc192": 51.0}       # CPU serveur par handshake
KEM_CLI_MS = {"x448_mlkem768": 34.0, "hqc192": 85.0}
CERT_PLAIN = {("ecdsa", 1): 444, ("ecdsa", 2): 923, ("mldsa", 1): 5507, ("mldsa", 2): 11050}
CV = {"ecdsa": 112, "mldsa": 3317}
BASE = 221
CERT_COMP = {("ecdsa", 1): {"zlib": 440}, ("ecdsa", 2): {"zlib": 769, "brotli": 739}}
PAD_COMP = {"zlib": 523, "brotli": 540}
SIG_SRV_MS = {"ecdsa": 1.0, "mldsa": 0.6}
SIG_CLI_MS = {"ecdsa": 1.5, "mldsa": 0.3}
TLS_IW, QUIC_CAP, QUIC_DBL = 14480, 8804, 12520


def fmt_delay(rtt):
    d = rtt / 2.0
    return ("%g" % d)


def label(rtt, loss=0, chain=1, padto=0, comp="", res=False, load=None):
    if loss > 0:
        l = "simple_loss%g_delay%sms" % (loss, fmt_delay(rtt))
    elif rtt == 0:
        l = "none"
    else:
        l = "delayonly_delay%sms" % fmt_delay(rtt)
    if chain == 2: l += "__chain2"
    if padto: l += "__padto%d" % padto
    if comp: l += "__comp" + comp
    if res: l += "__res"
    if load:
        srv, conc, secs = load
        l += "__load_%s_srv1cpu" % srv
        if conc != "1 2 4 8 16 32": l += "__c" + conc.replace(" ", "-")
        if secs != 20: l += "__w%ds" % secs
    return l


def flight(proto, sig, kem, chain, padto, comp, resumed, scen):
    s = "ecdsa" if sig == "secp384r1" else "mldsa"
    if resumed:
        return 1329 + KEM_CT[kem] - 1144, 0, 0, 0
    if padto:
        plain = padto + 13
    else:
        plain = CERT_PLAIN[(s, chain)]
    rx = BASE + KEM_CT[kem] + plain + CV[s]
    cc = 0; ctype = 11
    if comp not in ("", "none"):
        if padto:
            cc = PAD_COMP.get(comp, 0)
        elif s == "ecdsa":
            cc = CERT_COMP.get((s, chain), {}).get(comp, 0)
        elif scen == "falsify":
            cc = int(0.65 * plain)                       # hypothese fausse : ML-DSA serait compressible
        if cc:
            rx -= plain - cc; ctype = 25
    return rx, ctype, cc if cc else 0, plain


def kround(proto, rx_srv):
    if proto == "tls":
        return 1 if rx_srv > TLS_IW else 0
    if rx_srv <= QUIC_CAP: return 0
    return 1 if rx_srv <= QUIC_CAP + QUIC_DBL else 2


def conn_times(rng, proto, rtt, sig, kem, flight_bytes, resumed, scen, bf, boff):
    s = "ecdsa" if sig == "secp384r1" else "mldsa"
    srv = KEM_SRV_MS[kem] + (0 if resumed else SIG_SRV_MS[s]); cli = KEM_CLI_MS[kem] + (0 if resumed else SIG_CLI_MS[s])
    fl = flight_bytes
    if scen == "falsify" and resumed and proto == "quic" and s == "mldsa":
        fl = 10191                                        # hypothese fausse : la reprise QUIC ML-DSA envoie encore le vol complet (penalite conservee)
    k = kround(proto, fl)
    base_rt = (2 if proto == "tls" else 1)
    hs = (base_rt + k) * rtt + srv + cli
    app = hs + rtt + 0.4
    z = rng.lognormal(0, 0.03)
    return (hs * z * bf + boff), (app * z * bf + boff)


def write_conn_log(path, proto, entries):
    with open(path, "w") as f:
        for i, e in enumerate(entries, 1):
            f.write("Execution %d - %s Single\n" % (i, proto.upper()))
            if e.get("mode"): f.write("Mode: %s\n" % e["mode"])
            if e.get("ticket_in"): f.write("Ticket-in: %s\n" % e["ticket_in"])
            f.write("App-bytes: 100\nResumed: %d\nRx-bytes: %d\nTx-bytes: %d\n" % (e["resumed"], e["rx"], e["tx"]))
            if proto == "tls" and e.get("ctype") is not None:
                f.write("CertMsg: type=%d len_comp=%d len_plain=%d\n" % (e["ctype"], e["cc"], e["cp"]))
            f.write("Handshake duration: %.2f ms\nApp-ready duration: %.2f ms\n" % (e["hs"], e["app"]))


def gen_conn_cells(root, rng, nblocks, scen, kind):
    PAIRS = [(s, k) for s in ("secp384r1", "mldsa65") for k in ("x448_mlkem768", "hqc192")]
    PAIRS_E = [("secp384r1", k) for k in ("x448_mlkem768", "hqc192")]
    cells = []
    if kind == "resume":
        for proto in ("tls", "quic"):
            for rtt in (0, 50, 100, 150): cells.append(dict(proto=proto, rtt=rtt, loss=0, lab=label(rtt, res=True), pairs=PAIRS, res=True))
            for L in (1, 2, 5): cells.append(dict(proto=proto, rtt=50, loss=L, lab=label(50, loss=L, res=True), pairs=PAIRS, res=True))
    if kind == "comp":
        for proto in ("tls", "quic"):
            for rtt in (0, 50):
                for alg in ("none", "zlib", "brotli"):
                    cells.append(dict(proto=proto, rtt=rtt, loss=0, lab=label(rtt, comp=alg), pairs=PAIRS, comp=alg, chain=1))
                    cells.append(dict(proto=proto, rtt=rtt, loss=0, lab=label(rtt, chain=2, comp=alg), pairs=PAIRS, comp=alg, chain=2))
                    for T in (8700, 16000):
                        cells.append(dict(proto=proto, rtt=rtt, loss=0, lab=label(rtt, padto=T, comp=alg), pairs=PAIRS_E, comp=alg, chain=1, padto=T))
    for blk in range(1, nblocks + 1):
        bf = rng.normal(1.0, 0.012); boff = rng.normal(0, 0.25)
        for c in cells:
            proto = c["proto"]
            ldir = os.path.join(root, proto, "single", c["lab"], "handshake_logs"); os.makedirs(ldir, exist_ok=True)
            for sig, kem in c["pairs"]:
                for mb in (1, 2):
                    ents = []
                    for i in range(1, 11):
                        idx = (mb - 1) * 10 + i
                        resumed = c.get("res", False) and (idx % 2 == 0)
                        rx, ctype, cc, cp = flight(proto, sig, kem, c.get("chain", 1), c.get("padto", 0), c.get("comp", ""), resumed, scen)
                        hs, app = conn_times(rng, proto, c["rtt"] + 0.0, sig, kem, rx, resumed, scen, bf, boff)
                        # perte : on ajoute un terme lineaire en perte, plus grand quand le vol est grand (QUIC) -- modele jouet
                        if c["loss"]:
                            extra = c["loss"] * (0.9 if proto == "quic" else 0.5) * (1 + rx / 9000.0) * (0.35 if resumed else 1.0)
                            hs += extra; app += extra
                        e = dict(rx=int(rx + rng.integers(-1, 2)), tx=1613 + (271 if resumed else 0), resumed=int(resumed), hs=hs, app=app,
                                 ctype=ctype if proto == "tls" else None, cc=cc, cp=cp)
                        if c.get("res"):
                            e["mode"] = "resumed" if resumed else "full"
                            if resumed: e["ticket_in"] = "loaded"
                        ents.append(e)
                    fn = "handshake_%s_single_%s_%s_%s_block%dof%d_mb%dof2.log" % (proto, sig, kem, c["lab"], blk, nblocks, mb)
                    write_conn_log(os.path.join(ldir, fn), proto, ents)


def gen_load(root, rng, nblocks, scen):
    PAIRS = [(s, k) for s in ("secp384r1", "mldsa65") for k in ("x448_mlkem768", "hqc192")]
    levels_all = [1, 2, 4, 8, 16, 32]
    cells = []
    for rtt in (0, 50):
        cells.append(("tls", "mt", rtt, levels_all, 20)); cells.append(("quic", "quic", rtt, levels_all, 20))
        cells.append(("tls", "stock", rtt, [1], 20)); cells.append(("tls", "mt", rtt, [1], 20))
    cal = {}
    for blk in range(1, nblocks + 1):
        bf = rng.normal(1.0, 0.012)
        for proto, srv, rtt, levels, secs in cells:
            conc_s = " ".join(str(x) for x in levels)
            lab = label(rtt, load=(srv if srv != "quic" else "stock", conc_s if len(levels) < 6 else "1 2 4 8 16 32", secs))   # QUIC : TLS_SERVER garde sa valeur par defaut (stock)
            ldir = os.path.join(root, proto, "single", lab, "handshake_logs"); os.makedirs(ldir, exist_ok=True)
            for sig, kem in PAIRS:
                s = "ecdsa" if sig == "secp384r1" else "mldsa"
                Ssrv = (KEM_SRV_MS[kem] + SIG_SRV_MS[s] + (9.0 if proto == "quic" else 0.0)) * rng.normal(1.0, 0.01)
                if scen == "falsify" and proto == "tls" and srv == "mt": Ssrv *= 1.40
                Scli = KEM_CLI_MS[kem] + SIG_CLI_MS[s] + (30.0 if proto == "quic" else 0.0)
                rx, _, _, _ = flight(proto, sig, kem, 1, 0, "", False, scen)
                _, app0 = conn_times(np.random.default_rng(1), proto, float(rtt), sig, kem, rx, False, scen, 1.0, 0.0)
                Z = 35.0 if proto == "tls" else 60.0
                R0 = app0
                Rcyc0 = R0 + Z
                order = list(rng.permutation(levels))
                t = 1_793_000_000_000 + blk * 10_000_000
                lines, srv_trace, cli_trace = [], [], []
                nproc = 8
                lines.append('LOADMETA nproc=%d load_seconds=%d trim_s=2 timeout_s=30 levels="%s" kem=%s sig=%s proto=%s' % (nproc, secs, conc_s, kem, sig, proto))
                segs = []
                for k, c in enumerate(order, 1):
                    p = 8.0
                    X = 1000.0 / ((Rcyc0 / c) ** p + (Ssrv * 1.02) ** p) ** (1.0 / p)
                    R = max(R0, 1000.0 * c / X - Z) if X > 0 else R0
                    t0, t1 = t, t + secs * 1000
                    lines.append("LEVEL conc=%d t_start=%d t_end=%d order=%d" % (c, t0, t1, k))
                    n = int(X * secs)
                    ts = np.sort(rng.uniform(t0 + 100, t1 + 50, size=n))
                    nf = 0
                    for tt in ts:
                        okc = 1
                        if c >= 32 and rng.uniform() < 0.004: okc = 0
                        app = R * rng.lognormal(0, 0.08) * bf
                        lines.append("LOADCONN conc=%d worker=1 t_end=%d ok=%d hs_ms=%s app_ms=%s rx=%d" % (c, tt, okc, "%.2f" % (0.95 * app) if okc else "NaN", "%.2f" % app if okc else "NaN", rx))
                        nf += 1 - okc
                    lines.append("LEVELEND conc=%d n_conn=%d n_fail=%d" % (c, n, nf))
                    segs.append((t0, t1, X, Ssrv, Scli))
                    t = t1 + 3000
                lines.append("LOADDONE")
                fn = "handshake_%s_single_%s_%s_%s_block%dof%d.log" % (proto, sig, kem, lab, blk, nblocks)
                open(os.path.join(ldir, fn), "w").write("\n".join(lines) + "\n")
                # traces CPU (toutes les 0,5 s), constantes par morceaux
                tdir = os.path.join(root, proto, "single", lab, "load_traces", "block%dof%d" % (blk, nblocks), "%s_%s" % (sig, kem)); os.makedirs(tdir, exist_ok=True)
                T0, T1 = 1_793_000_000_000 + blk * 10_000_000 - 3000, t + 3000
                grid = np.arange(T0, T1, 500)
                su, cu = np.zeros(len(grid)), np.zeros(len(grid))
                for (a, b, X, Ss, Sc) in segs:
                    m = (grid >= a) & (grid < b)
                    su[m] = min(1.0, X * Ss / 1000.0) + 0.02; cu[m] = X * Sc / 1000.0 + 0.05
                scum = np.cumsum(su * 0.5 * 1e6); ccum = np.cumsum(cu * 0.5 * 1e6)
                for nm, cum in (("srv", scum), ("cli", ccum)):
                    with open(os.path.join(tdir, "%s_cpu_trace.csv" % nm), "w") as f:
                        f.write("t_epoch,cpu_usec\n")
                        for g, v in zip(grid, cum): f.write("%.3f,%d\n" % (g / 1000.0, v))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True); ap.add_argument("--scenario", default="h0", choices=["h0", "falsify"])
    ap.add_argument("--blocks", type=int, default=20); ap.add_argument("--seed", type=int, default=7)
    a = ap.parse_args()
    rng = np.random.default_rng(a.seed)
    os.makedirs(a.out, exist_ok=True)
    gen_conn_cells(a.out, rng, a.blocks, a.scenario, "resume")
    gen_conn_cells(a.out, rng, a.blocks, a.scenario, "comp")
    gen_load(a.out, rng, a.blocks, a.scenario)
    open(os.path.join(a.out, "SYNTHETIQUE.txt"), "w").write("Donnees SYNTHETIQUES (scenario %s) : test du pipeline uniquement. Ne rien en conclure.\n" % a.scenario)
    print("ecrit dans", a.out)


if __name__ == "__main__":
    main()
