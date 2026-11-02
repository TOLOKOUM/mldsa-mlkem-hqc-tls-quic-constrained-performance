#!/usr/bin/env python3
"""
ab_tcpdump_effect.py -- analyse du protocole A/B de ab_tcpdump_effect.sh.

Question : l'instrumentation mecanistique (tcpdump + journal de cles) change-t-
elle les durees mesurees (handshake_ms, app_ready_ms) ?

Unite statistique : la PAIRE de blocs adjacents (un bloc instrumente, un bloc
plain), jamais la connexion. Pour chaque paire p et chaque metrique :
    d_p = mediane(bloc instrumente) - mediane(bloc plain)
Medianes (et non moyennes) : la queue de pertes domine les moyennes.

Sorties par metrique :
  - Hodges-Lehmann (mediane des moyennes de Walsh des d_p) : estimation robuste
    de l'effet de l'instrumentation, en ms et en % de la mediane "plain" ;
  - IC95 bootstrap sur les paires (graine fixe) ;
  - p-valeur exacte de sign-flip bilaterale sur la somme des d_p (2^P cas) ;
  - effet d'ordre : moyenne des d_p pour "instrumente d'abord" vs "plain
    d'abord" ;
  - verdict d'equivalence : l'IC95 tient-il dans +/- marge ? (--margin-pct,
    defaut 2 % de la mediane plain, ou --margin-ms en absolu).
Avec P paires, la plus petite p exacte est 2/2^P (P=10 : 0,002). Un IC par
bootstrap sur P=10 paires est grossier : le verdict "equivalent" demande que
l'IC ET l'estimation soient dans la marge ; en cas de doute, ajouter des paires.

USAGE
    python3 ab_tcpdump_effect.py --root captures --plan ab_tcpdump_plan_none_seed424242.csv
    python3 ab_tcpdump_effect.py --selftest
"""

import argparse
import csv
import itertools
import os
import random
import re
import statistics
import sys
import tempfile

EXEC_RE = re.compile(r"^Execution\s+(\d+)\s*-")
HS_RE = re.compile(r"Handshake duration:\s*([\d.]+|NaN)\s*ms")
APP_RE = re.compile(r"App-ready duration:\s*([\d.]+|NaN)\s*ms")
LABEL_FIELDS = ("hs", "app")


def parse_log(path):
    """{execution: [handshake_ms|None, app_ready_ms|None]} ; premiere valeur
    numerique conservee (un marqueur NaN de secours ne l'ecrase pas)."""
    res, cur = {}, None
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
            for k, rx in ((0, HS_RE), (1, APP_RE)):
                m = rx.search(line)
                if m and m.group(1) != "NaN" and res[cur][k] is None:
                    res[cur][k] = float(m.group(1))
    return res


def label_of(profile, loss, delay):
    """Meme logique que le launcher pour les profils usuels. Pour les autres
    profils, passer --label explicitement."""
    if profile == "none":
        return "none"
    if profile == "simple":
        return f"simple_loss{loss}_delay{delay}ms"
    if profile == "delay-only":
        return f"delayonly_delay{delay}ms"
    if profile == "loss-only":
        return f"lossonly_loss{loss}"
    if profile.startswith("ge-"):
        return f"{profile}_delay{delay}ms"
    return profile


def wilcoxon_hl(d):
    """Hodges-Lehmann : mediane des moyennes de Walsh (i <= j)."""
    w = [(d[i] + d[j]) / 2.0 for i in range(len(d)) for j in range(i, len(d))]
    return statistics.median(w)


def signflip_p(d):
    """p exacte bilaterale du test de sign-flip sur la somme des d."""
    obs = abs(sum(d))
    n = len(d)
    if n > 22:
        raise ValueError("trop de paires pour l'enumeration exacte")
    ge = 0
    for signs in itertools.product((1, -1), repeat=n):
        if abs(sum(s * x for s, x in zip(signs, d))) >= obs - 1e-12:
            ge += 1
    return ge / (2 ** n)


def bootstrap_ci(d, n_boot=10000, seed=12345, stat=wilcoxon_hl):
    rng = random.Random(seed)
    n = len(d)
    vals = sorted(stat([d[rng.randrange(n)] for _ in range(n)]) for _ in range(n_boot))
    return vals[int(0.025 * n_boot)], vals[int(0.975 * n_boot) - 1]


def analyze(block_stats, plan, margin_pct=2.0, margin_ms=None):
    """block_stats[b] = {"hs": mediane, "app": mediane} ; plan = lignes du plan.
    Retourne une liste de dicts de resultats (un par metrique)."""
    pairs = {}
    for r in plan:
        p = int(r["pair_index"])
        pairs.setdefault(p, {})[r["arm"]] = int(r["block_index"])
    out = []
    for key, name in (("hs", "handshake_ms"), ("app", "app_ready_ms")):
        d, plain_vals, order_first_instr, order_first_plain = [], [], [], []
        used = 0
        for p, arms in sorted(pairs.items()):
            bi, bp = arms.get("instrumented"), arms.get("plain")
            if bi is None or bp is None:
                continue
            si, sp = block_stats.get(bi), block_stats.get(bp)
            if not si or not sp or si.get(key) is None or sp.get(key) is None:
                continue
            diff = si[key] - sp[key]
            d.append(diff)
            plain_vals.append(sp[key])
            used += 1
            (order_first_instr if bi < bp else order_first_plain).append(diff)
        if len(d) < 2:
            out.append({"metric": name, "n_pairs": len(d), "verdict": "donnees insuffisantes"})
            continue
        hl = wilcoxon_hl(d)
        lo, hi = bootstrap_ci(d)
        base = statistics.median(plain_vals)
        margin = margin_ms if margin_ms is not None else abs(base) * margin_pct / 100.0
        p_val = signflip_p(d)
        if lo >= -margin and hi <= margin and abs(hl) <= margin:
            verdict = f"equivalent (IC95 dans +/-{margin:.2f} ms)"
        elif lo > 0 or hi < 0:
            verdict = "effet detecte (IC95 exclut 0)"
        else:
            verdict = f"indetermine (IC95 deborde de +/-{margin:.2f} ms et inclut 0)"
        out.append({
            "metric": name, "n_pairs": len(d),
            "plain_median_ms": round(base, 3),
            "hl_effect_ms": round(hl, 3), "hl_effect_pct": round(100.0 * hl / base, 2) if base else None,
            "ci95_lo_ms": round(lo, 3), "ci95_hi_ms": round(hi, 3),
            "signflip_p": round(p_val, 5), "margin_ms": round(margin, 3),
            "mean_d_instr_first": round(statistics.mean(order_first_instr), 3) if order_first_instr else None,
            "mean_d_plain_first": round(statistics.mean(order_first_plain), 3) if order_first_plain else None,
            "min_d_ms": round(min(d), 3), "max_d_ms": round(max(d), 3),
            "verdict": verdict,
        })
    return out


def load_block_stats(root, plan, label_override=None):
    stats = {}
    for r in plan:
        b, n = int(r["block_index"]), int(r["n_blocks"])
        proto, auth, profile = r["protocol"], r["auth_mode"], r["profile"]
        sig, kem = r["sig_kem"].split("_", 1)
        # sig_kem est "sig_kem" avec '_' possible dans le nom du KEM : le nom
        # de la signature n'en contient pas.
        label = label_override or r.get("label") or label_of(profile, r.get("loss", "0"), r.get("delay", "0"))
        path = os.path.join(root, proto, auth, label, "handshake_logs",
                            f"handshake_{proto}_{auth}_{sig}_{kem}_{label}_block{b}of{n}.log")
        if not os.path.isfile(path):
            print(f"[WARN] log absent : {path}", file=sys.stderr)
            continue
        log = parse_log(path)
        hs = [v[0] for v in log.values() if v[0] is not None]
        app = [v[1] for v in log.values() if v[1] is not None]
        n_fail = sum(1 for v in log.values() if v[0] is None or v[1] is None)
        stats[b] = {"hs": statistics.median(hs) if hs else None,
                    "app": statistics.median(app) if app else None,
                    "n": len(log), "n_fail": n_fail}
    return stats


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default="captures")
    ap.add_argument("--plan")
    ap.add_argument("--label", help="surcharge le label du dossier (profils non standard)")
    ap.add_argument("--margin-pct", type=float, default=2.0)
    ap.add_argument("--margin-ms", type=float, default=None)
    ap.add_argument("--out", default="ab_tcpdump_effect_results.csv")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if not a.plan:
        ap.error("--plan requis (ou --selftest)")
    with open(a.plan, newline="") as f:
        plan = list(csv.DictReader(f))
    stats = load_block_stats(a.root, plan, a.label)
    res = analyze(stats, plan, a.margin_pct, a.margin_ms)
    n_fail = sum(s["n_fail"] for s in stats.values())
    print(f"[INFO] {len(stats)}/{len(plan)} blocs lus ; {n_fail} connexion(s) sans mesure complete (exclues des medianes)")
    cols = []
    for r in res:
        for k in r:
            if k not in cols:
                cols.append(k)
    with open(a.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(res)
    for r in res:
        print(f"\n== {r['metric']} ({r['n_pairs']} paires)")
        for k, v in r.items():
            if k not in ("metric", "n_pairs"):
                print(f"   {k:22s} {v}")
    print(f"\n[OK] resultats -> {a.out}")
    return 0


def selftest():
    rng = random.Random(7)

    def run(effect_ms, label="none"):
        tmp = tempfile.mkdtemp()
        plan = []
        n_pairs, n_blocks = 10, 20
        b = 0
        for p in range(1, n_pairs + 1):
            arms = ("instrumented", "plain") if p % 2 else ("plain", "instrumented")
            for arm in arms:
                b += 1
                plan.append({"block_index": str(b), "n_blocks": str(n_blocks), "pair_index": str(p),
                             "arm": arm, "per_conn_pcap": "1" if arm == "instrumented" else "0",
                             "protocol": "tls", "auth_mode": "single", "profile": "none",
                             "sig_kem": "mldsa65_x448_mlkem768"})
                d = os.path.join(tmp, "tls", "single", label, "handshake_logs")
                os.makedirs(d, exist_ok=True)
                drift = 0.05 * b        # derive lente, equilibree par l'alternance
                with open(os.path.join(d, f"handshake_tls_single_mldsa65_x448_mlkem768_{label}_block{b}of{n_blocks}.log"), "w") as f:
                    for i in range(1, 26):
                        hs = 11.0 + drift + rng.gauss(0, 0.3) + (effect_ms if arm == "instrumented" else 0)
                        f.write(f"Execution {i} - TLS Single\\nHandshake duration: {hs:.2f} ms\\nApp-ready duration: {hs + 101.4:.2f} ms\\n".replace("\\n", "\n"))
        return load_block_stats(tmp, plan), plan

    st, plan = run(0.0)
    r0 = analyze(st, plan, margin_ms=1.0)[0]
    assert r0["n_pairs"] == 10 and r0["verdict"].startswith("equivalent"), r0
    st, plan = run(2.0)
    r1 = analyze(st, plan, margin_ms=1.0)[0]
    assert r1["verdict"].startswith("effet detecte") and 1.5 < r1["hl_effect_ms"] < 2.5 and r1["signflip_p"] < 0.01, r1
    assert abs(signflip_p([1.0, 1.0, 1.0, 1.0]) - 2 / 16) < 1e-12
    assert abs(wilcoxon_hl([1.0, 2.0, 3.0]) - 2.0) < 1e-12
    print("[SELFTEST] OK : equivalence (effet nul), detection (effet 2 ms), sign-flip exact, Hodges-Lehmann.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
