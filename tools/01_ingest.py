#!/usr/bin/env python3
"""01_ingest.py -- Phase 1a : ingestion complete de captures_v2 en tables propres + audit de completude.

N'estime AUCUN effet. Produit (dans --out) :
  conn.csv.gz          1 ligne / connexion (app_ms, hs_ms, echec, facteurs de conception, covariables de visite)
  visits.csv           1 ligne / visite (paire x tour x bloc x cellule) : horodatage, thermique, qdisc, CPU/memoire
  manifests.csv        1 ligne / (cellule, bloc) : configuration reellement appliquee
  audit_completeness.csv  attendu vs trouve par (cellule, bloc, paire, tour)
  audit_state.csv      cellules interrompues (exit != 0 / 98) et leur re-execution
  ingest_report.txt    synthese lisible

USAGE : python3 01_ingest.py --root captures_v2 --state campaign_state/state.csv --plan plans/plan_all.csv --out analysis_v2
"""
from __future__ import annotations
import argparse, csv, re, sys
from pathlib import Path
import numpy as np
import pandas as pd
from pq_common import (ALL_PAIRS, SIGS, N_BLOCKS, kem_info, plan_label, parse_label, family_of)

EXEC_RE = re.compile(r"^Execution\s+(\d+)\s*-\s*(.+?)\s*$")
HS_RE = re.compile(r"Handshake duration:\s*([\d.]+|NaN)\s*ms")
APP_RE = re.compile(r"App-ready duration:\s*([\d.]+|NaN)\s*ms(?:\s*\((.*)\))?")
BYTES_RE = re.compile(r"App-bytes:\s*(\d+)")
WARM_RE = re.compile(r"Warm-up:\s*(\d+)")
TMO_RE = re.compile(r"timeout budget:\s*(\d+)\s*s")
OFFL_RE = re.compile(r"^offload\[pair=(.+?)\]\[(.+?)\]=(.*)$")
TAIL_RE = re.compile(r"_block(\d+)of(\d+)(?:_mb(\d+)of(\d+))?$")
CANON = {f"{s}|{k.lower()}": (s, k) for s, k in ALL_PAIRS}


def f2(v):
    return np.nan if v == "NaN" else float(v)


def parse_log(path: Path):
    ex, cur, warm, tmo = [], None, None, None
    with open(path, errors="ignore") as fh:
        for ln in fh:
            c = ln[0:1]
            if c == "E":
                m = EXEC_RE.match(ln)
                if m:
                    cur = dict(exec=int(m.group(1)), hs=np.nan, app=np.nan, nbytes=np.nan, fail_reason="",
                               n_hs=0, n_app=0)
                    ex.append(cur)
                    continue
            elif c == "H" and cur is not None:
                m = HS_RE.search(ln)
                if m:
                    cur["hs"] = f2(m.group(1)); cur["n_hs"] += 1; continue
                m = TMO_RE.search(ln)
                if m:
                    tmo = int(m.group(1)); continue
            elif c == "H":
                m = TMO_RE.search(ln)
                if m:
                    tmo = int(m.group(1)); continue
            elif c == "A" and cur is not None:
                m = APP_RE.search(ln)
                if m:
                    cur["app"] = f2(m.group(1)); cur["n_app"] += 1; cur["fail_reason"] = (m.group(2) or "").strip(); continue
                m = BYTES_RE.search(ln)
                if m:
                    cur["nbytes"] = int(m.group(1)); continue
            elif c == "W":
                m = WARM_RE.match(ln)
                if m:
                    warm = int(m.group(1))
    return ex, warm, tmo


def parse_name(fname, proto, auth, label):
    stem = fname[:-4]
    m = TAIL_RE.search(stem)
    if not m:
        return None
    head = stem[:m.start()]
    pre, suf = f"handshake_{proto}_{auth}_", f"_{label}"
    if not (head.startswith(pre) and head.endswith(suf)):
        return None
    mid = head[len(pre):len(head) - len(suf)]
    if "_" not in mid:
        return None
    sig, kem = mid.split("_", 1)
    can = CANON.get(f"{sig}|{kem.lower()}")
    if can is None:
        return None
    return dict(block=int(m.group(1)), n_blocks=int(m.group(2)), round=int(m.group(3) or 1),
                n_rounds=int(m.group(4) or 1), sig=can[0], kem=can[1])


def read_plan(path):
    with open(path, newline="") as fh:
        rows = list(csv.DictReader(fh))
    out, seen = {}, {}
    for r in rows:
        env = dict(kv.split("=", 1) for kv in (r.get("extra_env") or "").split(";") if "=" in kv)
        lab = plan_label(r)
        pairs = [tuple(p.split("|")) for p in r["only_pairs"].split(";") if p] or list(ALL_PAIRS)
        key = (r["protocol"], r["auth"], lab)
        if key in seen:
            print(f"[ERREUR] collision de label : {key} <- {seen[key]} et {r['cell_id']}", file=sys.stderr)
        seen[key] = r["cell_id"]
        out[key] = dict(cell_id=r["cell_id"], total_runs=int(r["total_runs"]), pairs=pairs,
                        n_rounds=int(env.get("MICRO_BATCHES", "1") or 1), family=family_of(r["cell_id"]))
    return out


def read_env_like(path: Path, lab):
    df = pd.read_csv(path)
    for k, v in lab.items():
        df[k] = v
    return df


def collect_side_tables(root: Path):
    env, qd, res, man = [], [], [], []
    for pdir in sorted(root.glob("*/*/*")):
        if not pdir.is_dir():
            continue
        proto, auth, label = pdir.parts[-3:]
        lab = dict(proto=proto, auth=auth, label=label)
        for f in pdir.glob("env_metadata_block*.csv"):
            env.append(read_env_like(f, lab))
        for f in pdir.glob("qdisc_stats_block*.csv"):
            qd.append(read_env_like(f, lab))
        for f in (pdir / "resource_usage").glob("*.csv"):
            d = read_env_like(f, lab).drop(columns=["network_profile"], errors="ignore")
            res.append(d)
        for f in pdir.glob("block_manifest_block*.log"):
            d = dict(lab); d["file"] = f.name; offs = {}
            for ln in f.read_text(errors="ignore").splitlines():
                if ln.startswith("cpu_model="):
                    d["cpu_model"] = ln.split("=", 1)[1]; continue
                mo = OFFL_RE.match(ln)
                if mo:   # offload[pair=SIG|KEM][conteneur]=tcp-segmentation-offload: off generic-... : on [fixed] ...
                    offs.setdefault(mo.group(2), set()).add(" ".join(mo.group(3).split()))
                    continue
                if ln.startswith(("netem[", "neighbors[", "tcp_isolation[", "tcp_metrics_entries[")):
                    continue
                for tok in ln.split():
                    if "=" in tok:
                        k, v = tok.split("=", 1)
                        if "[" not in k and k not in ("block", "round", "sig"):
                            d.setdefault(k, v)
            for cont, fs in offs.items():
                d[f"offload_{cont}"] = " | ".join(sorted(fs))
            man.append(d)
    cat = lambda L: pd.concat(L, ignore_index=True) if L else pd.DataFrame()
    return cat(env), cat(qd), cat(res), pd.DataFrame(man)


def dedup_occ(df, keys, n_rounds_of, tcol="timestamp"):
    """Numerote les occurrences d'une meme paire dans (cellule, bloc) par ordre chronologique.
    Si plus d'occurrences que de tours (cellule interrompue puis relancee), garde les DERNIERES (la relance)."""
    df = df.copy()
    df["_t"] = pd.to_datetime(df[tcol], utc=True, format="ISO8601")
    df = df.sort_values(["_t"], kind="stable")
    g = df.groupby(keys, sort=False)
    df["_c"], df["_n"] = g.cumcount(), g[keys[0]].transform("size")
    nr = df.apply(lambda r: n_rounds_of.get((r["proto"], r["auth"], r["label"]), 1), axis=1)
    df["_extra"] = (df["_n"] - nr).clip(lower=0)
    df["round"] = df["_c"] - df["_extra"] + 1
    sup = df["round"] < 1
    return df[~sup].drop(columns=["_c", "_n", "_extra"]), int(sup.sum())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True, type=Path)
    ap.add_argument("--state", type=Path, default=None)
    ap.add_argument("--plan", required=True, type=Path)
    ap.add_argument("--out", default=Path("analysis_v2"), type=Path)
    a = ap.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    rep = []
    P = lambda s="": (print(s), rep.append(s))

    plan = read_plan(a.plan)
    P(f"plan : {len(plan)} cellules ({sum(1 for v in plan.values())} labels uniques)")

    # ---------------------------------------------------------------- 1. logs de handshake
    rows, unmatched, vis_exec = [], [], []
    files = sorted(a.root.glob("*/*/*/handshake_logs/handshake_*.log"))
    P(f"fichiers de log : {len(files)}")
    for i, f in enumerate(files):
        proto, auth, label = f.parts[-5:-2]
        meta = parse_name(f.name, proto, auth, label)
        if meta is None:
            unmatched.append(str(f)); continue
        ex, warm, tmo = parse_log(f)
        for e in ex:
            rows.append((proto, auth, label, meta["block"], meta["round"], meta["n_rounds"], meta["sig"], meta["kem"],
                         e["exec"], e["hs"], e["app"], e["nbytes"], e["fail_reason"], e["n_hs"], e["n_app"], warm, tmo))
        vis_exec.append((proto, auth, label, meta["block"], meta["round"], meta["sig"], meta["kem"], len(ex), f.name))
        if (i + 1) % 5000 == 0:
            print(f"   ... {i + 1}/{len(files)}")
    conn = pd.DataFrame(rows, columns=["proto", "auth", "label", "block", "round", "n_rounds", "sig", "kem", "exec", "hs_ms",
                                       "app_ms", "app_bytes", "fail_reason", "n_hs_lines", "n_app_lines", "warmup", "timeout_s"])
    if unmatched:
        P(f"[!] {len(unmatched)} logs au nom non reconnu (ignores) : {unmatched[:3]} ...")
    dupkey = ["proto", "auth", "label", "block", "round", "sig", "kem", "exec"]
    nd = int(conn.duplicated(dupkey).sum())
    if nd:
        P(f"[!] {nd} executions dupliquees (meme cle) -> on garde la derniere"); conn = conn.drop_duplicates(dupkey, keep="last")

    # ---------------------------------------------------------------- 2. tables annexes
    env, qd, res, man = collect_side_tables(a.root)
    if len(man):
        man["block"] = pd.to_numeric(man["block_index"], errors="coerce")
        man = man.sort_values("file").drop_duplicates(["proto", "auth", "label", "block"], keep="last")
        kmap = man[["proto", "auth", "label", "block", "kernel"]]
    else:
        kmap = pd.DataFrame(columns=["proto", "auth", "label", "block", "kernel"])
    n_rounds_of = conn.groupby(["proto", "auth", "label"])["n_rounds"].max().to_dict()
    ks = ["proto", "auth", "label", "block_index", "sig_alg", "kem"]
    env, s1 = dedup_occ(env, ks + ["event"], n_rounds_of)
    visit_env = []
    for (proto, auth, label, blk, sig, kem, rnd), g in env.groupby(ks + ["round"], sort=False):
        b = g[g.event == "before"].iloc[0] if (g.event == "before").any() else None
        af = g[g.event == "after"].iloc[0] if (g.event == "after").any() else None
        visit_env.append(dict(proto=proto, auth=auth, label=label, block=int(blk), sig=sig, kem=kem, round=int(rnd),
                              position=(b if b is not None else af)["position"],
                              t_before=b["_t"] if b is not None else pd.NaT, t_after=af["_t"] if af is not None else pd.NaT,
                              temp_b=b["cpu_temp_c"] if b is not None else np.nan, temp_a=af["cpu_temp_c"] if af is not None else np.nan,
                              mhz_b=b["cpu_mhz_mean"] if b is not None else np.nan, mhz_a=af["cpu_mhz_mean"] if af is not None else np.nan,
                              load_b=b["load1"] if b is not None else np.nan, load_a=af["load1"] if af is not None else np.nan,
                              governor=(b if b is not None else af)["governor"], no_turbo=(b if b is not None else af)["no_turbo"]))
    ve = pd.DataFrame(visit_env)
    # qdisc : une ligne / role / visite
    if len(qd):
        qd, s2 = dedup_occ(qd.rename(columns={"sig_alg": "sig_alg"}), ["proto", "auth", "label", "block_index", "sig_alg", "kem", "role"], n_rounds_of)
        qd["d_pkts"] = qd["pkts_after"] - qd["pkts_before"]; qd["d_drop"] = qd["dropped_after"] - qd["dropped_before"]
        pv = qd.pivot_table(index=["proto", "auth", "label", "block_index", "sig_alg", "kem", "round"], columns="role",
                            values=["d_pkts", "d_drop", "effective_drop_pct"], aggfunc="first")
        pv.columns = [f"{'srv' if r.startswith('server') else 'cli'}_{v}" for v, r in pv.columns]
        pv = pv.reset_index().rename(columns={"block_index": "block", "sig_alg": "sig"})
        ve = ve.merge(pv, on=["proto", "auth", "label", "block", "sig", "kem", "round"], how="left")
    if len(res):
        res, s3 = dedup_occ(res, ["proto", "auth", "label", "block_index", "sig_alg", "kem", "role"], n_rounds_of)
        pr = res.pivot_table(index=["proto", "auth", "label", "block_index", "sig_alg", "kem", "round"], columns="role",
                             values=["cpu_usec_per_handshake", "mem_peak_bytes"], aggfunc="first")
        pr.columns = [f"{'srv' if r == 'server' else 'cli'}_{'cpu_us' if v.startswith('cpu') else 'mem_b'}" for v, r in pr.columns]
        pr = pr.reset_index().rename(columns={"block_index": "block", "sig_alg": "sig"})
        ve = ve.merge(pr, on=["proto", "auth", "label", "block", "sig", "kem", "round"], how="left")
    for side in ("srv", "cli"):   # perte reellement appliquee par netem : le compteur "pkts" exclut les paquets perdus
        if f"{side}_d_drop" in ve:
            ve[f"{side}_loss_real_pct"] = 100.0 * ve[f"{side}_d_drop"] / (ve[f"{side}_d_drop"] + ve[f"{side}_d_pkts"]).replace(0, np.nan)
    ve = ve.merge(kmap, on=["proto", "auth", "label", "block"], how="left")
    P(f"visites (env_metadata) : {len(ve)} | occurrences ecartees (cellules relancees) env={s1}")

    # ordre dans le bloc pour chaque (cellule, bloc) et temps absolu
    ve = ve.sort_values("t_before")
    ve["visit_seq"] = ve.groupby(["proto", "auth", "label", "block"]).cumcount() + 1
    t0 = ve["t_before"].min()
    ve["t_h"] = (ve["t_before"] - t0).dt.total_seconds() / 3600
    ve["dur_s"] = (ve["t_after"] - ve["t_before"]).dt.total_seconds()
    bstart = ve.groupby("block")["t_before"].transform("min")
    ve["t_in_block_h"] = (ve["t_before"] - bstart).dt.total_seconds() / 3600

    # ---------------------------------------------------------------- 3. facteurs de conception + fusion
    lab_tab = []
    for (proto, auth, label) in conn[["proto", "auth", "label"]].drop_duplicates().itertuples(index=False):
        d = parse_label(label)
        if d is None:
            P(f"[!] label non reconnu : {label}"); d = {}
        pl = plan.get((proto, auth, label))
        if d.get("sentinel"):
            cid, fam = f"sent_{proto}", "sentinel"
        elif pl:
            cid, fam = pl["cell_id"], pl["family"]
        else:
            cid, fam = "UNPLANNED", "unplanned"; P(f"[!] label absent du plan : {proto}/{auth}/{label}")
        lab_tab.append(dict(proto=proto, auth=auth, label=label, cell_id=cid, family=fam, **d))
    lab_tab = pd.DataFrame(lab_tab)
    conn = conn.merge(lab_tab, on=["proto", "auth", "label"], how="left")
    conn["level"] = conn["sig"].map(lambda s: SIGS[s][0]); conn["sig_class"] = conn["sig"].map(lambda s: SIGS[s][1])
    ki = conn["kem"].map(kem_info)
    conn["kem_family"] = ki.map(lambda t: t[0]); conn["kem_form"] = ki.map(lambda t: t[1])
    conn["pair"] = conn["sig"] + "|" + conn["kem"]
    conn["fail"] = conn["app_ms"].isna().astype(int)
    conn["fail_reason"] = conn["fail_reason"].fillna("")
    conn.loc[(conn.fail == 1) & (conn.fail_reason == ""), "fail_reason"] = "unspecified"
    conn["fail_kind"] = np.where(conn.fail == 0, "", np.where(conn.fail_reason.str.contains("timeout after"), "timeout_budget", "other"))
    conn["hs_completed"] = conn["hs_ms"].notna().astype(int)
    vcols = [c for c in ve.columns if c not in ("t_before", "t_after")]
    conn = conn.merge(ve[["proto", "auth", "label", "block", "sig", "kem", "round"] + [c for c in vcols if c not in
                      ("proto", "auth", "label", "block", "sig", "kem", "round")]],
                      on=["proto", "auth", "label", "block", "sig", "kem", "round"], how="left")
    n_nov = int(conn["visit_seq"].isna().sum())
    if n_nov:
        P(f"[!] {n_nov} connexions sans visite env_metadata correspondante")

    # ---------------------------------------------------------------- 4. audit de completude
    vx = pd.DataFrame(vis_exec, columns=["proto", "auth", "label", "block", "round", "sig", "kem", "n_found", "file"])
    exp = []
    for (proto, auth, label), pl in plan.items():
        for blk in range(1, N_BLOCKS + 1):
            for (s, k) in pl["pairs"]:
                for r in range(1, pl["n_rounds"] + 1):
                    exp.append((proto, auth, label, pl["cell_id"], blk, r, s, k, pl["total_runs"] // N_BLOCKS // pl["n_rounds"]))
    exp = pd.DataFrame(exp, columns=["proto", "auth", "label", "cell_id", "block", "round", "sig", "kem", "n_expected"])
    aud = exp.merge(vx.drop(columns="file"), on=["proto", "auth", "label", "block", "round", "sig", "kem"], how="outer", indicator=True)
    aud["n_found"] = aud["n_found"].fillna(0).astype(int)
    aud["status"] = np.where(aud["_merge"] == "left_only", "MANQUANT", np.where(aud["_merge"] == "right_only", "HORS_PLAN",
                      np.where(aud["n_found"] < aud["n_expected"], "INCOMPLET", np.where(aud["n_found"] > aud["n_expected"], "EN_TROP", "ok"))))
    aud = aud.drop(columns="_merge")
    lt = lab_tab.set_index(["proto", "auth", "label"])
    for i in aud.index[aud.cell_id.isna()]:
        k = (aud.at[i, "proto"], aud.at[i, "auth"], aud.at[i, "label"])
        aud.at[i, "cell_id"] = lt.loc[k, "cell_id"] if k in lt.index else "?"
    is_sent = aud["cell_id"].astype(str).str.startswith("sent_")
    sent_n = aud[is_sent].groupby("cell_id")["n_found"].agg(lambda s: s.mode().iat[0])
    for cid, nmode in sent_n.items():  # sentinelles : attendu = mode observe (pas de plan explicite)
        m = is_sent & (aud.cell_id == cid)
        aud.loc[m, "n_expected"] = nmode
        aud.loc[m, "status"] = np.where(aud.loc[m, "n_found"] == nmode, "ok", np.where(aud.loc[m, "n_found"] < nmode, "INCOMPLET", "EN_TROP"))
    aud.to_csv(a.out / "audit_completeness.csv", index=False)
    P("\n=== COMPLETUDE (visites paire x tour x bloc x cellule) ===")
    for st, n in aud["status"].value_counts().items():
        P(f"   {st:10s} {n}")
    bad = aud[aud.status != "ok"]
    if len(bad):
        P(bad.groupby(["cell_id", "status"]).size().rename("n_visites").reset_index().head(40).to_string(index=False))

    # ---------------------------------------------------------------- 5. etat de campagne
    if a.state and Path(a.state).exists():
        st = pd.read_csv(a.state)
        st["ts"] = pd.to_datetime(st["timestamp"], utc=True, format="ISO8601")
        cells = st[st.kind.isin(["cell", "sentinel"])].copy()
        cells["key"] = cells["cell_id"].astype(str) + "|" + cells["visit"].fillna("").astype(str)
        out = []
        for (blk, key), g in cells.groupby(["block", "key"]):
            g = g.sort_values("ts")
            if (g.exit_code != 0).any():
                last = g.iloc[-1]
                cid = key.split("|")[0]
                bad_n = int(((aud.cell_id == cid) & (aud.block == blk) & (aud.status != "ok")).sum()) if not cid.startswith("sent_") else np.nan
                out.append(dict(block=blk, cell_id=cid, visit=key.split("|")[1], codes=";".join(map(str, g.exit_code)),
                                n_attempts=len(g), last_code=int(last.exit_code), visites_non_ok_apres=bad_n))
        so = pd.DataFrame(out)
        so.to_csv(a.out / "audit_state.csv", index=False)
        P("\n=== CELLULES INTERROMPUES (state.csv) ===")
        P(so.to_string(index=False) if len(so) else "aucune")
        P(f"code 98 (suspension) : {int((st.exit_code == 98).sum())} visite(s)")
        if int((st.exit_code == 98).sum()):
            P("   >>> a EXCLURE ou refaire :\n" + st[st.exit_code == 98][["block", "kind", "cell_id", "visit"]].to_string(index=False))

    # ---------------------------------------------------------------- 6. ecritures
    man.to_csv(a.out / "manifests.csv", index=False)
    ve.to_csv(a.out / "visits.csv", index=False)
    conn = conn.sort_values(["proto", "auth", "cell_id", "block", "visit_seq", "exec"])
    conn.to_csv(a.out / "conn.csv.gz", index=False, compression="gzip")
    P(f"\nconnexions : {len(conn)} | echecs (app NaN) : {int(conn.fail.sum())} | cellules : {conn.cell_id.nunique()} | blocs : {conn.block.nunique()}")
    (a.out / "ingest_report.txt").write_text("\n".join(rep))
    P(f"[OK] {a.out}/conn.csv.gz, visits.csv, manifests.csv, audit_*.csv, ingest_report.txt")


if __name__ == "__main__":
    main()
