import csv, sys, random, statistics as st, collections
src = sys.argv[1]
out = sys.argv[2] if len(sys.argv) > 2 else "little_B3_niveaux.csv"
rows = list(csv.DictReader(open(src, newline="", encoding="utf-8")))
def f(x):
    try: return float(x)
    except (TypeError, ValueError): return None
print(f"{len(rows)} lignes ; colonnes : {list(rows[0].keys())}")
print("exemple :", {k: rows[0][k] for k in ("arm","proto","tls_server","sig","kem","block","conc","n","n_ok","X","fail","app_mean","app_med")})
G = collections.defaultdict(list)
chk = []
for r in rows:
    c, n, nok, X, am = f(r["conc"]), f(r["n"]), f(r["n_ok"]), f(r["X"]), f(r["app_mean"])
    if None in (c, n, nok, X, am) or nok <= 0 or X <= 0: continue
    nf = n - nok
    win = nok / X
    Xt = n / win
    Xf = nf / win
    Rs = am
    Rnaive = c * 1000.0 / X
    Rall = c * 1000.0 / Xt
    Rf = (c * 1000.0 - X * Rs) / Xf if nf > 0 else None
    G[(r["proto"], r["tls_server"], r["sig"], r["kem"], int(c))].append(
        dict(n=n, nok=nok, nf=nf, X=X, Xt=Xt, Rs=Rs, Rn=Rnaive, Ra=Rall, Rf=Rf, win=win, fail=f(r["fail"])))
    chk.append((win, nf, f(r["fail"]), n))
w = [a[0] for a in chk]
print(f"fenêtre implicite n_ok/X : min {min(w):.2f} s, médiane {st.median(w):.2f} s, max {max(w):.2f} s")
dif = [abs(a[1]/a[3] - a[2]) for a in chk if a[2] is not None and a[2] <= 1.0]
if dif: print(f"colonne 'fail' = fraction (n-n_ok)/n ? écart max {max(dif):.4f} (0 => oui)")
dif2 = [abs(a[1] - a[2]) for a in chk if a[2] is not None and a[2] > 1.0]
if dif2: print(f"colonne 'fail' = nombre (n-n_ok) ? écart max {max(dif2):.4f} (0 => oui)")
random.seed(20261110)
def boot(v):
    v = [x for x in v if x is not None]
    if len(v) < 2: return (float("nan"),)*2
    m = sorted(sum(random.choices(v, k=len(v)))/len(v) for _ in range(4000))
    return m[100], m[3899]
def mean(v):
    v = [x for x in v if x is not None]; return sum(v)/len(v) if v else float("nan")
hdr = ["proto","serveur","sig","kem","c","blocs","tentatives/bloc","echecs/bloc","echec_%","X_reussis","X_toutes","Rs_ms","R_c/X_ms (article)","R_c/Xtot_ms (Little)","ecart_%","Rf_implicite_ms","Rf_lo","Rf_hi"]
res = []
for k in sorted(G):
    b = G[k]
    m = lambda key: mean([x[key] for x in b])
    nf, n = m("nf"), m("n")
    rf = [x["Rf"] for x in b]
    lo, hi = boot(rf) if nf > 0 else (float("nan"),)*2
    ra, rn = m("Ra"), m("Rn")
    res.append([*k[:4], k[4], len(b), round(n,1), round(nf,2), round(100*nf/n,2), round(m("X"),2), round(m("Xt"),2),
                round(m("Rs"),2), round(rn,2), round(ra,2), round(100*(rn/ra-1),2),
                round(mean(rf),1) if nf > 0 else "", round(lo,1) if nf > 0 else "", round(hi,1) if nf > 0 else ""])
with open(out, "w", newline="") as fh:
    w_ = csv.writer(fh); w_.writerow(hdr); w_.writerows(res)
print(f"\n{out} écrit ({len(res)} lignes). Niveaux avec échecs :\n")
print("proto serveur sig kem c | échec% | Rs(ms) | c/X (article) | c/Xtot (Little) | écart% | Rf implicite [IC95 blocs]")
for r in res:
    if r[7] and r[7] > 0:
        print(f"{r[0]:5s} {str(r[1]):6s} {r[2]:10s} {r[3]:14s} c={r[4]:<3d}| {r[8]:6.2f} | {r[11]:8.2f} | {r[12]:9.2f} | {r[13]:9.2f} | {r[14]:6.2f} | {r[15]} [{r[16]} ; {r[17]}]")
