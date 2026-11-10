import os, re, sys, glob, collections, statistics as st
d = sys.argv[1]
kv = re.compile(r"(\w+)=(\S+)")
A = collections.defaultdict(lambda: dict(ok=[], fl=[], app=[], blocks=set()))
nfiles = 0
for p in sorted(glob.glob(os.path.join(d, "handshake_quic_single_*.log"))):
    m = re.search(r"single_(secp384r1|mldsa65)_(.+?)_none__.*block(\d+)of", os.path.basename(p))
    if not m: continue
    sig, kem, blk = m.group(1), m.group(2), int(m.group(3)); nfiles += 1
    trim = 2000.0; lvl = None; W = collections.defaultdict(list)
    for line in open(p, errors="replace"):
        if line.startswith("LOADMETA"):
            t = dict(kv.findall(line)); trim = 1000.0 * float(t.get("trim_s", 2))
        elif line.startswith("LEVEL "):
            t = dict(kv.findall(line)); lvl = (int(t["conc"]), float(t["t_start"]), float(t["t_end"]))
        elif line.startswith("LOADCONN") and lvl:
            t = dict(kv.findall(line))
            if int(t["conc"]) != lvl[0]: continue
            try: W[(lvl, int(t["worker"]))].append((float(t["t_end"]), int(t["ok"]), t["app_ms"]))
            except (KeyError, ValueError): pass
    for (lv, w), L in W.items():
        L.sort(); c, ts, te = lv
        for (t0, _, _), (t1, ok, app) in zip(L, L[1:]):
            if not (ts + trim <= t1 <= te - trim): continue
            a = A[(sig, kem, c)]; a["blocks"].add(blk)
            dur = t1 - t0
            if ok == 1:
                a["ok"].append(dur)
                try: a["app"].append(float(app))
                except ValueError: pass
            else: a["fl"].append(dur)
print(f"{nfiles} fichiers lus\n")
q = lambda v, p: sorted(v)[min(len(v) - 1, int(p * len(v)))]
print("durée d'une tentative = écart entre deux t_end consécutifs d'un même worker (ms, fenêtre mesurée, 1re tentative de chaque worker exclue)")
print("sig        kem            c  | n_ok    n_échec échec% | réussies : écart moyen / app_ms moyen | échecs : moyenne  p10   médiane  p90   max | <0,1s 0,1-0,3 0,3-1 1-5 5-30 >=30 (s)")
for k in sorted(A):
    a = A[k]; sig, kem, c = k
    if c < 16 or not a["fl"]: continue
    fl, ok = a["fl"], a["ok"]; n = len(fl) + len(ok)
    bins = [0.1, 0.3, 1, 5, 30]; cnt = [0] * 6
    for x in fl:
        i = 0
        while i < 5 and x / 1000.0 >= bins[i]: i += 1
        cnt[i] += 1
    print(f"{sig:10s} {kem:14s} {c:3d} | {len(ok):6d} {len(fl):6d} {100*len(fl)/n:6.2f} | {st.mean(ok):8.0f} / {st.mean(a['app']):8.0f} | {st.mean(fl):8.0f} {q(fl,.1):6.0f} {st.median(fl):7.0f} {q(fl,.9):6.0f} {max(fl):6.0f} | " + " ".join(f"{x:5d}" for x in cnt))
