#!/usr/bin/env python3
"""02_qc.py -- Phase 1b : controles qualite SANS estimer de contraste signature classique vs ML-DSA.

Sections : A integrite de la mesure | B configuration appliquee (manifestes, offloads, noyau) | C environnement |
D verite-terrain netem (+ D2 exposition reelle a la perte par protocole / classe de signature / KEM) |
E randomisation | F derive (sentinelles, tendance) | G effets de nuisance | H heterogeneite entre blocs | I tcpdump.
Produit qc_report.txt, qc_*.csv, visit_flags.csv (regles d'exclusion PRE-SPECIFIEES, appliquees avant tout contraste).

USAGE : python3 02_qc.py --ana analysis_v2 --root captures_v2 --state campaign_state/state.csv
"""
from __future__ import annotations
import argparse, re
from pathlib import Path
import numpy as np
import pandas as pd
from scipy import stats
from pq_common import N_BLOCKS, paired_summary, holm, fe_slope, pct, boot_ci

# --- Regles d'exclusion PRE-SPECIFIEES (ecrites avant toute estimation d'effet) ---
HARD = ["code98", "config_mismatch", "governor_or_turbo", "offload_active", "missing_visit_meta"]  # exclues (analyse primaire)
SOFT = ["duration_outlier", "warmup_timeout", "thermal_hot", "load_high", "qdisc_zero_loss_violation", "kernel_minor"]  # sensibilite
EXTREME_FACTOR = 10.0   # un succes > 10x la mediane de sa paire-cellule est liste (jamais supprime)
OFF_FEATS = ("tcp-segmentation-offload", "generic-segmentation-offload", "generic-receive-offload", "tx-udp-segmentation")


def cp_ci(k, n, a=0.05):
    if n == 0:
        return (np.nan, np.nan)
    lo = 0.0 if k == 0 else stats.beta.ppf(a / 2, k, n - k + 1)
    hi = 1.0 if k == n else stats.beta.ppf(1 - a / 2, k + 1, n - k)
    return lo, hi


def ratio_ci(g, B=3000, seed=1):
    """perte realisee / perte nominale (rapport de sommes), IC95% par bootstrap de BLOCS. g : colonnes block, d, t, nl."""
    agg = g.groupby("block")[["d", "t", "nl"]].sum()
    f = lambda a: 100.0 * a["d"].sum() / a["t"].sum() / (a["nl"].sum() / a["t"].sum())
    rng = np.random.default_rng(seed)
    est = [f(agg.iloc[rng.integers(0, len(agg), len(agg))]) for _ in range(B)]
    return f(agg), float(np.quantile(est, .025)), float(np.quantile(est, .975))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ana", required=True, type=Path)
    ap.add_argument("--root", type=Path, default=None)
    ap.add_argument("--state", type=Path, default=None)
    a = ap.parse_args()
    rep = []
    P = lambda s="": (print(s), rep.append(str(s)))
    gate, notes = [], []   # gate : bloquant ; notes : a documenter dans l'article

    conn = pd.read_csv(a.ana / "conn.csv.gz", low_memory=False)
    vis = pd.read_csv(a.ana / "visits.csv")
    man = pd.read_csv(a.ana / "manifests.csv", low_memory=False) if (a.ana / "manifests.csv").exists() else pd.DataFrame()
    aud = pd.read_csv(a.ana / "audit_completeness.csv")
    vk = ["proto", "auth", "label", "block", "sig", "kem", "round"]
    kk = ["proto", "auth", "label", "block"]
    conn["fail_reason"] = conn["fail_reason"].fillna("")
    if "hs_completed" not in conn:
        conn["hs_completed"] = conn["hs_ms"].notna().astype(int)
    if "fail_kind" not in conn:
        conn["fail_kind"] = np.where(conn.fail == 0, "", np.where(conn.fail_reason.str.contains("timeout after"), "timeout_budget", "other"))
    if len(man):
        man["block"] = pd.to_numeric(man["block_index"], errors="coerce")
        if "kernel" not in vis.columns:
            vis = vis.merge(man[kk + ["kernel"]].drop_duplicates(kk), on=kk, how="left")
        if "kernel" not in conn.columns:
            conn = conn.merge(man[kk + ["kernel"]].drop_duplicates(kk), on=kk, how="left")

    # ------------------------------------------------------------------ A. integrite de la mesure
    P("=" * 78 + "\nA. INTEGRITE DE LA MESURE\n" + "=" * 78)
    nonok = aud[aud.status != "ok"]
    P(f"visites attendues/trouvees non conformes : {len(nonok)} (voir audit_completeness.csv)")
    if len(nonok):
        gate.append(f"{len(nonok)} visites incompletes/manquantes")
    ok = conn[conn.fail == 0]
    bad_bytes = ok[ok.app_bytes != 100]
    P(f"succes avec App-bytes != 100 : {len(bad_bytes)}")
    if len(bad_bytes):
        gate.append("App-bytes != 100"); P(bad_bytes.groupby("cell_id").size().to_string())
    P(f"execution avec lignes Handshake/App-ready multiples : {int(((conn.n_hs_lines > 1) | (conn.n_app_lines > 1)).sum())} | sans ligne App-ready : {int((conn.n_app_lines == 0).sum())}")
    rev = ok[(ok.hs_ms > ok.app_ms + 1e-6)]
    P(f"succes avec Handshake > App-ready (incoherent) : {len(rev)}")
    P(f"warm-up distincts : {[int(x) for x in sorted(conn.warmup.dropna().unique())]} | budget timeout (s) : {[int(x) for x in sorted(conn.timeout_s.dropna().unique())]}")
    g = conn.groupby(["cell_id"]).agg(n=("fail", "size"), k=("fail", "sum")).reset_index()
    g[["cp_lo", "cp_hi"]] = [cp_ci(int(k), int(n)) for k, n in zip(g.k, g.n)]
    g["rate_pct"] = 100 * g.k / g.n
    g.to_csv(a.ana / "qc_failures_by_cell.csv", index=False)
    P(f"\nechecs (App-ready NaN) : {int(g.k.sum())}/{int(g.n.sum())} = {100*g.k.sum()/g.n.sum():.4f}% | cellules avec >=1 echec : {int((g.k>0).sum())}/{len(g)}")
    P(g.sort_values("rate_pct", ascending=False).head(6).to_string(index=False, float_format=lambda x: f"{x:.3f}"))
    fl = conn[conn.fail == 1].copy(); fl["raison"] = fl.fail_reason.replace("", "(vide)")
    ft = fl.groupby(["proto", "auth", "raison", "hs_completed"]).size().rename("n").reset_index()
    ft.to_csv(a.ana / "qc_failures_by_reason.csv", index=False)
    P("\nechecs par protocole / raison / handshake abouti (1) ou non (0) :")
    P(ft.to_string(index=False))
    n_other = int((fl.fail_kind != "timeout_budget").sum())
    if n_other:
        notes.append(f"{n_other} echecs NE SONT PAS des expirations du budget de 150 s (raison absente/autre) : leur duree reelle est inconnue "
                     f"-> RMST/completion en phase 2 (pas de latence conditionnelle) ; a decrire dans l'article")
    med = ok.groupby(["cell_id", "pair"])["app_ms"].transform("median")
    ext = ok[ok.app_ms > EXTREME_FACTOR * med]
    ext_t = ext.groupby(["proto", "cell_id"]).agg(n=("app_ms", "size"), max_ms=("app_ms", "max")).reset_index()
    P(f"\nsucces > {EXTREME_FACTOR:.0f}x la mediane de leur paire-cellule : {len(ext)} (conserves) | par protocole : {ext.groupby('proto').size().to_dict()}")
    P(f"succes > 10 s : {ok[ok.app_ms > 1e4].groupby('proto').size().to_dict()} | > 60 s : {ok[ok.app_ms > 6e4].groupby('proto').size().to_dict()} | max (ms) : {ok.groupby('proto').app_ms.max().round(0).to_dict()}")
    if len(ext):
        P(ext_t.sort_values("max_ms", ascending=False).head(6).to_string(index=False))
    ext.to_csv(a.ana / "qc_extreme_values.csv", index=False)

    # ------------------------------------------------------------------ B. configuration appliquee
    P("\n" + "=" * 78 + "\nB. CONFIGURATION REELLEMENT APPLIQUEE (manifestes) vs PREVUE (labels / plan)\n" + "=" * 78)
    mism = pd.DataFrame(); off_bad = pd.DataFrame()
    if len(man):
        exp = conn.groupby(kk).agg(mtu=("mtu", "first"), loss_dir=("loss_dir", "first"), mb=("mb", "first"), n_exec=("exec", "size"),
                                   n_rounds=("n_rounds", "first"), npairs=("pair", "nunique"), family=("family", "first")).reset_index()
        mm = man.drop(columns=[c for c in ("mtu", "loss_dir") if c in man.columns]).rename(columns={"loss_direction": "loss_dir_man"})
        m = exp.merge(mm.assign(mtu_man=pd.to_numeric(man["mtu"], errors="coerce")), on=kk, how="left")
        m["bad_mtu"] = m["mtu"] != m["mtu_man"]
        m["bad_dir"] = m["loss_dir"] != m["loss_dir_man"]
        m["bad_mb"] = pd.to_numeric(m["micro_batches"], errors="coerce") != m["n_rounds"]
        m["bad_runs"] = (pd.to_numeric(m["runs_this_block"], errors="coerce") != m["n_exec"] / m["npairs"].clip(lower=1)) & (m["family"] != "sentinel")
        for c, v in (("rate_mbit", "100"), ("netem_limit", "1000"), ("governor", "performance"), ("no_turbo", "1"), ("offload_off", "1"), ("udp_gso", "0")):
            if c in m:
                m[f"bad_{c}"] = m[c].astype(str) != v
        # etat reel des offloads journalise par le Launcher (ethtool -k) ; "on [fixed]" = non modifiable
        offc = [c for c in m.columns if c.startswith("offload_") and c != "offload_off"]
        if offc:
            txt = m[offc].fillna("").astype(str).agg(" | ".join, axis=1)
            on_mod = txt.str.contains(r"(?:%s): on(?! \[fixed\])" % "|".join(OFF_FEATS))
            on_fix = txt.str.contains(r"(?:%s): on \[fixed\]" % "|".join(OFF_FEATS))
            m["bad_offload_on"] = on_mod
            P(f"   offloads reellement actifs (modifiables) : {int(on_mod.sum())} cellule-blocs | actifs NON modifiables [fixed] : {int(on_fix.sum())} | etats distincts : {txt.nunique()}")
            if on_fix.any():
                notes.append("offload(s) actif(s) mais [fixed] (non desactivables) : la perte netem peut s'appliquer par super-paquet -> voir D2")
            off_bad = m[on_mod][kk]
        else:
            P("   (colonnes offload_* absentes des manifestes : relancer 01_ingest.py pour verifier l'etat reel de TSO/GSO/GRO)")
        bc = [c for c in m.columns if c.startswith("bad_")]
        m["any_bad"] = m[bc].any(axis=1) | m["kernel"].isna()
        for c in bc + ["any_bad"]:
            P(f"   {c:18s} {int(m[c].sum())}")
        P(f"   cpusets distincts serveur/client : {m.server_cpuset.nunique()}/{m.client_cpuset.nunique()} | modeles CPU : {m.cpu_model.nunique()} | images Docker : {m['image_id'].nunique() if 'image_id' in m else 'NA'}")
        mism = m[m.any_bad][kk + bc]
        mism.to_csv(a.ana / "qc_config_mismatch.csv", index=False)
        if len(mism):
            gate.append(f"{len(mism)} (cellule,bloc) dont la config ne correspond pas")
        # noyau
        kc = man.groupby("kernel").agg(cell_blocs=("block", "size"), bloc_min=("block", "min"), bloc_max=("block", "max"), debut=("timestamp_start", "min"), fin=("timestamp_start", "max")).reset_index()
        P("\n   noyaux Linux rencontres :"); P(kc.to_string(index=False))
    else:
        P("   (pas de manifestes)")

    # ------------------------------------------------------------------ C. environnement
    P("\n" + "=" * 78 + "\nC. ENVIRONNEMENT : gouverneur, turbo, thermique, charge, suspension, noyau\n" + "=" * 78)
    P(f"gouverneur : {vis.governor.value_counts().to_dict()} | no_turbo : {vis.no_turbo.value_counts().to_dict()}")
    pw = vis[vis.governor != "performance"]
    if len(pw):
        P("visites hors gouverneur 'performance' (par bloc / cellule) :"); P(pw.groupby(["block", "proto", "label"]).size().rename("visites").reset_index().to_string(index=False))
    P(f"temperature CPU (C) avant visite : min {vis.temp_b.min():.0f} / med {vis.temp_b.median():.0f} / p95 {vis.temp_b.quantile(.95):.0f} / max {vis.temp_b.max():.0f}")
    P(f"frequence moyenne (MHz) : min {vis.mhz_b.min():.0f} / med {vis.mhz_b.median():.0f} / max {vis.mhz_b.max():.0f}")
    P(f"load1 avant visite : med {vis.load_b.median():.2f} / p95 {vis.load_b.quantile(.95):.2f} / max {vis.load_b.max():.2f} | visites load1>4 : {int((vis.load_b > 4).sum())}")
    # surcout = duree de la visite - somme des latences mesurees : isole suspension / blocage du bruit de retransmission
    ca = conn.assign(app_s=conn.app_ms.fillna(conn.timeout_s * 1000.0) / 1000.0).groupby(vk).agg(sum_app=("app_s", "sum"), n_exec=("exec", "size")).reset_index()
    vis = vis.merge(ca, on=vk, how="left")
    vis["overhead_s"] = vis.dur_s - vis.sum_app
    vis["ovh_exec"] = vis.overhead_s / vis.n_exec
    grp = vis.groupby(["proto", "auth", "label", "sig", "kem", "round"])["ovh_exec"]
    vis["ovh_med"] = grp.transform("median")
    vis["ovh_mad"] = grp.transform(lambda s: np.median(np.abs(s - s.median())) + 1e-3)
    vis["z_ovh"] = (vis.ovh_exec - vis.ovh_med) / (1.4826 * vis.ovh_mad)
    to_s = float(conn.timeout_s.max())
    vis["f_warm"] = (vis.overhead_s >= 0.8 * to_s) & (vis.z_ovh > 8)
    vis["f_dur"] = (vis.z_ovh > 8) & (vis.ovh_exec > vis.ovh_med + 2.0) & ~vis.f_warm
    P(f"visites avec surcout inexplique ~ budget de timeout ({to_s:.0f} s) = connexion de warm-up expiree, hors mesure : {int(vis.f_warm.sum())}")
    P(f"visites avec autre surcout inexplique (>2 s/exec, z>8) = suspension / blocage probables : {int(vis.f_dur.sum())}")
    vis["f_hot"] = vis.temp_b > vis.temp_b.quantile(.99)
    vis["f_load"] = vis.load_b > vis.load_b.quantile(.99)
    code98 = pd.DataFrame()
    if a.state and Path(a.state).exists():
        st = pd.read_csv(a.state); code98 = st[st.exit_code == 98]
    P(f"visites code 98 (suspension) : {len(code98)}")
    # noyau minoritaire dans les blocs mixtes
    vis["f_kern"] = False; kern_block = None
    if "kernel" in vis and vis.kernel.nunique() > 1:
        modal = vis.kernel.value_counts().index[0]
        mixed = vis.groupby("block").kernel.nunique(); mixed = mixed[mixed > 1].index.tolist()
        vis["f_kern"] = (vis.kernel != modal).values
        P(f"\nchangement de noyau en cours de campagne : noyau majoritaire {modal}; {int(vis.f_kern.sum())} visites sous un autre noyau (blocs mixtes : {mixed})")
        if mixed:
            cv_ = conn[(conn.fail == 0) & (conn.family != "sentinel")].groupby(vk + ["cell_id", "pair", "kernel"], dropna=False)["app_ms"].median().reset_index()
            cv_["ly"] = np.log(cv_.app_ms); cv_["cp"] = cv_.cell_id + "|" + cv_.pair + "|" + cv_["round"].astype(str)
            ref = cv_[~cv_.block.isin(mixed)].groupby("cp").ly.mean().rename("ref")
            mx = cv_[cv_.block.isin(mixed)].merge(ref, on="cp"); mx["res"] = mx.ly - mx.ref
            cell = mx.groupby(["cell_id", mx.kernel != modal]).res.mean().reset_index(); cell.columns = ["cell_id", "minor", "res"]
            x1, x0 = cell[cell.minor].res.values, cell[~cell.minor].res.values
            if len(x1) >= 5 and len(x0) >= 5:
                rng = np.random.default_rng(1)
                bs = [rng.choice(x1, len(x1)).mean() - rng.choice(x0, len(x0)).mean() for _ in range(5000)]
                dlt = x1.mean() - x0.mean()
                P(f"   effet du noyau minoritaire sur le niveau de latence (blocs mixtes, residu log vs blocs non mixtes, bootstrap par cellule) : "
                  f"{pct(dlt):+.2f}% IC95% [{pct(np.quantile(bs, .025)):+.2f}, {pct(np.quantile(bs, .975)):+.2f}] (n_min={len(x1)} cellules, n_maj={len(x0)})")
                P("   le noyau est constant a l'interieur d'une cellule-bloc : les contrastes ENTRE paires d'une meme cellule restent comparables ; "
                  "covariable 'kernel' obligatoire, sensibilite en excluant les cellule-blocs au noyau minoritaire")
            notes.append(f"changement de noyau ({modal} -> autre) dans le(s) bloc(s) {mixed}: covariable + sensibilite; desactiver unattended-upgrades pour toute campagne future")

    # ------------------------------------------------------------------ D. verite-terrain netem
    P("\n" + "=" * 78 + "\nD. PERTE REELLE (qdisc netem) vs PERTE NOMINALE  [serveur=s2c ; client=c2s ; perte = pertes/(paquets envoyes + pertes)]\n" + "=" * 78)
    meta = conn.drop_duplicates(["proto", "auth", "label"])[["proto", "auth", "label", "cell_id", "family", "loss_nom", "process", "loss_dir", "rtt"]]
    vv = vis.merge(meta, on=["proto", "auth", "label"], how="left"); vv = vv[vv.family != "sentinel"].copy()
    rows, long = [], []
    for (cid, proc, nom, ldir, pr), gg in vv.groupby(["cell_id", "process", "loss_nom", "loss_dir", "proto"]):
        for side, lab in (("srv", "s2c"), ("cli", "c2s")):
            active = ldir == "both" or ldir == lab
            exp_loss = nom if active else 0.0
            d_, p_ = gg[f"{side}_d_drop"], gg[f"{side}_d_pkts"]
            sb = pd.DataFrame({"block": gg.block, "d": d_, "t": d_ + p_}).groupby("block").sum()
            byb = 100.0 * sb.d / sb.t.clip(lower=1)
            lo, hi = boot_ci(byb.values, B=4000)
            rows.append(dict(cell_id=cid, proto=pr, process=proc, side=lab, nominal_pct=exp_loss, observed_pct=100.0 * d_.sum() / max(d_.sum() + p_.sum(), 1),
                             ci_lo=lo, ci_hi=hi, drops=int(d_.sum()), pkts=int(p_.sum())))
            if active and exp_loss > 0:
                long.append(pd.DataFrame({"block": gg.block.values, "d": d_.values, "t": (d_ + p_).values, "nl": exp_loss * (d_ + p_).values,
                                          "proto": pr, "process": proc, "side": lab, "sig": gg.sig.values, "kem": gg.kem.values, "rtt": gg.rtt.values}))
    nd = pd.DataFrame(rows); nd["inside_ci"] = (nd.nominal_pct >= nd.ci_lo) & (nd.nominal_pct <= nd.ci_hi)
    nd["zero_violation"] = (nd.nominal_pct == 0) & (nd.drops > 0)
    nd["rel_dev"] = np.where(nd.nominal_pct > 0, (nd.observed_pct - nd.nominal_pct) / nd.nominal_pct.replace(0, np.nan), np.nan)
    nd["off_nominal"] = (nd.nominal_pct > 0) & ~nd.inside_ci & (nd.rel_dev.abs() > 0.15)
    nd.to_csv(a.ana / "qc_netem_truth.csv", index=False)
    P(f"cellule-cotes avec perte nominale 0 mais pertes observees > 0 : {int(nd.zero_violation.sum())}")
    P(f"cellule-cotes avec perte nominale > 0 : {int((nd.nominal_pct>0).sum())} | nominal hors IC95% bootstrap(blocs) : {int(((nd.nominal_pct>0)&~nd.inside_ci).sum())} | ecart > 15% : {int(nd.off_nominal.sum())}")
    offp = nd[nd.off_nominal].groupby("proto").size().to_dict()
    P(f"   ecart > 15% par protocole : {offp}")
    if int(nd.zero_violation.sum()):
        gate.append(f"{int(nd.zero_violation.sum())} cellule-cotes avec pertes netem alors que nominal=0")
    bad_z = vv.merge(nd[nd.zero_violation][["cell_id"]].drop_duplicates(), on="cell_id")
    vis["f_qz"] = False
    if len(bad_z):
        vis.loc[vis.set_index(["proto", "auth", "label"]).index.isin(bad_z.set_index(["proto", "auth", "label"]).index) &
                ((vis.srv_d_drop > 0) | (vis.cli_d_drop > 0)).values, "f_qz"] = True

    P("\n" + "-" * 78 + "\nD2. EXPOSITION REELLE A LA PERTE : rapport perte realisee / perte nominale (1.00 = perte par paquet conforme)\n" + "-" * 78)
    shortfall = False
    if long:
        LG = pd.concat(long, ignore_index=True)
        LG["sig_class"] = np.where(LG.sig.str.startswith("mldsa"), "pqc", "classical")
        LG["kem_family"] = np.where(LG.kem.str.contains("hqc"), "hqc", np.where(LG.kem.str.contains("mlkem"), "mlkem", "classical"))
        out = []
        for keys in (["proto"], ["proto", "process"], ["proto", "side"], ["proto", "sig_class"], ["proto", "kem_family"], ["proto", "rtt"]):
            for k, gg in LG.groupby(keys):
                k = k if isinstance(k, tuple) else (k,)
                r, lo, hi = ratio_ci(gg)
                out.append(dict(decoupage="+".join(keys), proto=k[0], niveau=str(k[1]) if len(k) > 1 else "toutes", ratio=r, lo=lo, hi=hi, visites=len(gg)))
        ex = pd.DataFrame(out); ex.to_csv(a.ana / "qc_netem_exposure.csv", index=False)
        P("(toutes cellules a perte nominale > 0 ; table complete, y compris par RTT et par cote, dans qc_netem_exposure.csv)")
        P(ex[ex.decoupage.isin(["proto", "proto+process", "proto+sig_class", "proto+kem_family"])].to_string(index=False, float_format=lambda x: f"{x:.3f}"))
        rq = LG[LG.proto == "quic"]; rt = LG[LG.proto == "tls"]
        if len(rq) and len(rt):
            qr, ql, qh = ratio_ci(rq); tr, tl, th = ratio_ci(rt)
            P(f"\nQUIC : {qr:.3f} [{ql:.3f}, {qh:.3f}] | TLS : {tr:.3f} [{tl:.3f}, {th:.3f}]")
            shortfall = (th < 0.95) and (qr >= 0.90) and (tr < qr - 0.05)
            if shortfall:
                tc = rt
                c1 = ratio_ci(tc[tc.sig_class == "classical"]); c2 = ratio_ci(tc[tc.sig_class == "pqc"])
                size_dep = c2[2] < c1[1]
                P(f"   TLS classique {c1[0]:.3f} [{c1[1]:.3f}, {c1[2]:.3f}] vs TLS ML-DSA {c2[0]:.3f} [{c2[1]:.3f}, {c2[2]:.3f}] -> "
                  f"{'DEPEND de la taille du vol (IC disjoints)' if size_dep else 'pas de dependance nette a la classe de signature (IC qui se recouvrent)'}")
                P("   DIAGNOSTIC : la perte effectivement appliquee aux paquets TLS est inferieure au nominal alors que celle de QUIC est conforme."
                  + (" Le deficit croit avec la taille des messages : profil compatible avec une perte decidee par SUPER-PAQUET (segmentation TCP non desactivee)"
                     " et comptee par segment. A verifier (ethtool -k sur l'interface portant netem, taille des trames emises cote serveur)." if size_dep else ""))
                gate.append("deficit de perte specifique a TLS" + (" et dependant de la taille du vol (exposition a la perte differente entre classique et ML-DSA)" if size_dep else "")
                            + " : perte nominale != perte appliquee ; contraste entre protocoles 'a perte egale' NON valide en l'etat")
    n_off_other = int(nd[nd.off_nominal & (nd.proto == "quic")].shape[0]) if shortfall else int(nd.off_nominal.sum())
    if n_off_other:
        gate.append(f"{n_off_other} cellule-cotes dont la perte netem observee s'ecarte de >15% du nominal (hors IC)")

    # ------------------------------------------------------------------ E. randomisation
    P("\n" + "=" * 78 + "\nE. RANDOMISATION : les classes de signature sont-elles equilibrees en rang de visite ?\n" + "=" * 78)
    cv = conn.drop_duplicates(vk)[vk + ["cell_id", "family", "sig_class", "visit_seq", "pair"]]
    cv = cv[cv.family != "sentinel"]
    out = []
    for cid, gg in cv.groupby("cell_id"):
        d = []
        for blk, b in gg.groupby("block"):
            if b.sig_class.nunique() == 2:
                d.append(b[b.sig_class == "pqc"].visit_seq.mean() - b[b.sig_class == "classical"].visit_seq.mean())
        if len(d) >= 3:
            s = paired_summary(d); out.append(dict(cell_id=cid, n_blocks=s["n"], mean_rank_diff=s["mean"], p=s["p"]))
    ed = pd.DataFrame(out)
    if len(ed):
        ed["p_holm"] = holm(ed.p.values); ed.to_csv(a.ana / "qc_randomisation_balance.csv", index=False)
        P(f"cellules testees : {len(ed)} | p_Holm < 0.05 : {int((ed.p_holm<.05).sum())} (attendu ~0 sous randomisation) | p brut < 0.05 : {int((ed.p<.05).sum())} (attendu ~{.05*len(ed):.1f})")
        P(ed.sort_values("p").head(4).to_string(index=False, float_format=lambda x: f"{x:.4f}"))
        if (ed.p_holm < .05).any():
            gate.append("desequilibre de rang sig_class (randomisation suspecte)")
    # enchainement : l'attendu sous permutation sans remise d'un tour (n_c classiques, n_p ML-DSA) est
    # (n_c(n_c-1)+n_p(n_p-1)) / (n(n-1)) par paire de voisins, PAS 0.5 ; on compare a cette valeur.
    cv = cv.sort_values(["cell_id", "block", "round", "visit_seq"])
    cv["prev"] = cv.groupby(["cell_id", "block", "round"])["sig_class"].shift()
    x = cv.dropna(subset=["prev"])
    grp = cv.groupby(["cell_id", "block", "round"]).sig_class.agg(nc=lambda s: (s == "classical").sum(), npq=lambda s: (s == "pqc").sum()).reset_index()
    grp["n"] = grp.nc + grp.npq; grp = grp[grp.n > 1]
    grp["adj"] = grp.n - 1; grp["exp_same"] = (grp.nc * (grp.nc - 1) + grp.npq * (grp.npq - 1)) / (grp.n * (grp.n - 1))
    obs = (x.prev == x.sig_class).mean(); expd = float((grp.exp_same * grp.adj).sum() / grp.adj.sum())
    se = np.sqrt(expd * (1 - expd) / len(x))
    P(f"\nenchainement sig_class(i-1)==sig_class(i) : observe {obs:.3f} vs attendu sous permutation {expd:.3f} (ecart {obs-expd:+.3f}, ~{(obs-expd)/se:+.1f} ecarts-types binomiaux)")
    if abs(obs - expd) > 4 * se:
        gate.append("enchainement des classes de signature different de l'attendu sous randomisation")

    # ------------------------------------------------------------------ F. derive
    P("\n" + "=" * 78 + "\nF. DERIVE TEMPORELLE (sentinelles : meme paire, 3 visites par bloc)\n" + "=" * 78)
    s = conn[(conn.family == "sentinel") & (conn.fail == 0)].copy(); s["ly"] = np.log(s.app_ms)
    sv = s.groupby(["proto", "block", "sentinel", "pair"])["ly"].median().unstack("sentinel")
    drift_rows = []
    for (pr, pair), gg in sv.groupby(["proto", "pair"]):
        for tag in ("mid", "post"):
            d = (gg[tag] - gg["pre"]).dropna().values
            r = paired_summary(d); drift_rows.append(dict(proto=pr, pair=pair, contrast=f"{tag}-pre", n_blocks=r["n"], pct_change=pct(r["mean"]),
                                                          lo=pct(r["lo"]), hi=pct(r["hi"]), p=r["p"], hl_pct=pct(r["hl"])))
    dr = pd.DataFrame(drift_rows)
    if len(dr):
        dr["p_holm"] = holm(dr.p.fillna(1).values)
        dr.to_csv(a.ana / "qc_sentinel_drift.csv", index=False)
        P("derive intra-bloc, moyenne des differences par bloc en % (IC95% bootstrap par blocs, p exact sign-flip, Holm sur les 8 tests) :")
        P(dr.to_string(index=False, float_format=lambda x: f"{x:.3f}"))
    cvis = conn[(conn.fail == 0) & (conn.family != "sentinel")].groupby(vk + ["cell_id", "t_h", "visit_seq", "t_in_block_h", "temp_b", "pair"], dropna=False)["app_ms"].median().reset_index()
    cvis["ly"] = np.log(cvis.app_ms); cvis["cp"] = cvis.cell_id + "|" + cvis.pair + "|" + cvis["round"].astype(str)
    cvis["t_frac"] = cvis.t_in_block_h / cvis.groupby("block").t_in_block_h.transform("max").clip(lower=1e-9)
    cvis["day"] = cvis.block.astype(float)
    r = fe_slope(cvis.ly.values, cvis.day.values, [cvis.cp.values], cvis.block.values)
    P(f"\ntendance inter-blocs (toutes cellules, effets fixes cellule x paire x tour) : {pct(r['b']):+.3f} % par bloc  IC95% [{pct(r['lo']):+.3f}, {pct(r['hi']):+.3f}]  p={r['p']:.3g} (G={r['G']}) "
      f"=> cumul sur {N_BLOCKS - 1} blocs ~ {pct(r['b'] * (N_BLOCKS - 1)):+.2f}%")

    # ------------------------------------------------------------------ G. nuisance
    P("\n" + "=" * 78 + "\nG. EFFETS DE NUISANCE (rang de visite, temperature) -- covariables du modele, pas des resultats\n" + "=" * 78)
    nrows = []
    cvis["fam"] = cvis.cell_id.str.split("_").str[0]
    cvis["rank_frac"] = cvis.visit_seq / cvis.groupby(["cell_id", "block"]).visit_seq.transform("max").clip(lower=1)
    groups = [("tous", cvis)] + [(fam, gg) for fam, gg in cvis.groupby("fam") if len(gg) >= 300]
    for fam, gg in groups:
        for var, lab in (("rank_frac", "dernier vs premier rang de visite (rang/rang_max)"), ("t_frac", "fin vs debut de bloc (temps)"), ("temp_b", "par degre C")):
            xx = gg.dropna(subset=[var])
            if len(xx) > 50 and xx[var].nunique() > 2:
                r = fe_slope(xx.ly.values, xx[var].values, [xx.cp.values, xx.block.values], xx.block.values)
                nrows.append(dict(famille=fam, covariable=lab, pct_effect=pct(r["b"]), lo=pct(r["lo"]), hi=pct(r["hi"]), p=r["p"], n=r["n"]))
    nu = pd.DataFrame(nrows)
    if len(nu):
        nu["p_holm"] = holm(nu.p.fillna(1).values); nu.to_csv(a.ana / "qc_nuisance.csv", index=False)
        P(nu.to_string(index=False, float_format=lambda x: f"{x:.4f}"))

    # ------------------------------------------------------------------ H. heterogeneite inter-blocs
    P("\n" + "=" * 78 + "\nH. HETEROGENEITE ENTRE BLOCS (justifie le bloc comme unite d'inference)\n" + "=" * 78)
    cv2 = cvis.copy(); cv2["res"] = cv2.ly - cv2.groupby("cp").ly.transform("mean")
    bm = cv2.groupby(["cell_id", "block"]).res.mean().reset_index()
    icc_rows = []
    for cid, gg in bm.groupby("cell_id"):
        sb = gg.res.var(ddof=1)
        within = cv2[cv2.cell_id == cid].groupby(["cp"]).ly.std().mean() ** 2
        n_per = cv2[cv2.cell_id == cid].groupby("block").size().mean()
        icc_rows.append(dict(cell_id=cid, sd_between_blocks_pct=100 * np.sqrt(max(sb - within / max(n_per, 1), 0)), sd_within_pct=100 * np.sqrt(within)))
    ic = pd.DataFrame(icc_rows)
    ic.to_csv(a.ana / "qc_block_heterogeneity.csv", index=False)
    P(f"ecart-type entre blocs (moyenne des cellules) : {ic.sd_between_blocks_pct.mean():.2f}% | intra-bloc/visite : {ic.sd_within_pct.mean():.2f}%")
    P("   -> l'inference DOIT se faire au niveau bloc (sign-flip / bootstrap de blocs / effet aleatoire), jamais sur les connexions poolees.")

    # ------------------------------------------------------------------ I. pertes de capture
    if a.root:
        drops = []
        for f in a.root.glob("*/*/*/pcap_perconn/*/*/tcpdump.err"):
            m_ = re.search(r"(\d+) packets dropped by kernel", f.read_text(errors="ignore"))
            drops.append(int(m_.group(1)) if m_ else -1)
        P("\n" + "=" * 78 + f"\nI. CAPTURES tcpdump : {len(drops)} fichiers | pertes noyau > 0 : {sum(d>0 for d in drops)} | illisibles : {sum(d<0 for d in drops)}\n" + "=" * 78)
        if sum(d > 0 for d in drops):
            gate.append("paquets perdus par tcpdump")

    # ------------------------------------------------------------------ drapeaux de visite
    f = vis[vk].copy()
    f["code98"] = False
    if len(code98):
        key98 = set(zip(code98.block.astype(int), code98.cell_id.astype(str)))
        cid_of = conn.drop_duplicates(["proto", "auth", "label"]).set_index(["proto", "auth", "label"]).cell_id
        f["code98"] = [(b, cid_of.get((p, a_, l))) in key98 for p, a_, l, b in zip(f.proto, f.auth, f.label, f.block)]
    f["config_mismatch"] = False
    if len(mism):
        km = set(zip(mism.proto, mism.auth, mism.label, mism.block)); f["config_mismatch"] = [k in km for k in zip(f.proto, f.auth, f.label, f.block)]
    f["offload_active"] = False
    if len(off_bad):
        ko = set(zip(off_bad.proto, off_bad.auth, off_bad.label, off_bad.block)); f["offload_active"] = [k in ko for k in zip(f.proto, f.auth, f.label, f.block)]
    f["governor_or_turbo"] = ((vis.governor != "performance") | (vis.no_turbo != 1)).values
    f["missing_visit_meta"] = vis.t_h.isna().values
    f["duration_outlier"] = vis.f_dur.values; f["warmup_timeout"] = vis.f_warm.values
    f["thermal_hot"] = vis.f_hot.values; f["load_high"] = vis.f_load.values
    f["qdisc_zero_loss_violation"] = vis.f_qz.values; f["kernel_minor"] = vis.f_kern.values
    f["hard_excluded"] = f[HARD].any(axis=1); f["soft_flagged"] = f[SOFT].any(axis=1)
    f.to_csv(a.ana / "visit_flags.csv", index=False)
    P("\n" + "=" * 78 + "\nDRAPEAUX DE VISITE (regles pre-specifiees)\n" + "=" * 78)
    for c in HARD + SOFT:
        P(f"   {c:28s} {int(f[c].sum()):6d}   [{'EXCLUE' if c in HARD else 'sensibilite'}]")
    P(f"visites exclues de l'analyse primaire : {int(f.hard_excluded.sum())}/{len(f)} | a signaler en sensibilite : {int(f.soft_flagged.sum())}")
    if f.hard_excluded.sum():
        ex_cells = f[f.hard_excluded].groupby(["proto", "label", "block"]).size().rename("visites").reset_index()
        notes.append(f"{int(f.hard_excluded.sum())} visites exclues par regle dure, soit {len(ex_cells)} cellule-bloc(s) entier(s) : "
                     + "; ".join(f"{r.proto}/{r.label} bloc {r.block}" for r in ex_cells.itertuples()))

    P("\n" + "#" * 78)
    P("PORTE QUALITE : " + ("PASS -- aucune alerte bloquante" if not gate else "A TRAITER AVANT TOUT CONTRASTE :"))
    for g_ in gate:
        P("   - " + g_)
    if notes:
        P("A DOCUMENTER (non bloquant) :")
        for n_ in notes:
            P("   * " + n_)
    (a.ana / "qc_report.txt").write_text("\n".join(rep))
    print(f"[OK] {a.ana}/qc_report.txt + qc_*.csv + visit_flags.csv")


if __name__ == "__main__":
    main()
