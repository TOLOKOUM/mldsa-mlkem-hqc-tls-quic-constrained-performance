#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fig_v2.py -- figures de la campagne v2 (captures_v2 : 20 blocs, 137 cellules, conn.csv.gz + tableaux p2_/p3_).
Chaque fonction est enregistree avec @figure(campagne, FID, slug, entrees) et renvoie une liste de Variant.
Les etiquettes de figure sont en anglais (langue de l'article) ; les commentaires en francais."""
from __future__ import annotations
import numpy as np
import pandas as pd
import matplotlib
import matplotlib.ticker
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D

from figkit import (figure, Variant, boot_blocks, paired_block_stat, clopper_pearson, panel_letter, rng_fixed,
                    kem_family_of, PS)

LEVELS = PS.SECURITY_LEVEL_ORDER
SIGS_BY_LEVEL = {"L1": ("ed25519", "mldsa44"), "L3": ("secp384r1", "mldsa65"), "L5": ("secp521r1", "mldsa87")}
BASE_KEM = {"L1": "P-256", "L3": "P-384", "L5": "P-521"}
PROFILE_BY_LOSS = {0.0: "ideal", 1.3: "moderate", 1.5833: "degraded"}
PROFILE_LABEL = {"ideal": "Ideal (RTT 0)", "moderate": "Moderate (RTT 125 ms, 1.3 % loss)", "degraded": "Degraded (RTT 167 ms, 1.58 % loss)"}
PROTO_AUTH = [("tls", "single"), ("tls", "mutual"), ("quic", "single")]
SIGCLASS_LABEL = {"classical": "classical signature", "pqc": "ML-DSA signature"}


def prep(ctx):
    if hasattr(ctx, "_v2prep"):
        return ctx._v2prep
    d = ctx.df("v2_conn").copy()
    d["ok"] = (d["fail"] == 0) & d["hs_ms"].notna()
    d["kfam"] = [kem_family_of(k) for k in d["kem"]]
    d["profile"] = np.where(d["family"] == "main", d["loss_nom"].map(PROFILE_BY_LOSS), "")
    ctx._v2prep = d
    return d


def kem_order(kems):
    return sorted(set(kems), key=lambda k: (PS.KEM_FAMILY_ORDER.index(kem_family_of(k)), k))


def kem_color(k):
    return PS.KEM_FAMILY_COLORS[kem_family_of(k)]


def log_ticks(ax, lo, hi, axis="y"):
    cand = np.array([1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000])
    t = cand[(cand >= lo / 1.01) & (cand <= hi * 1.01)]
    if axis == "y":
        ax.set_yticks(np.log10(t)); ax.set_yticklabels([str(x) for x in t])
    else:
        ax.set_xticks(np.log10(t)); ax.set_xticklabels([str(x) for x in t])


# ═════════════════════════════════════════════════════════════════════════════════════════════════════════
# V2-F01  Distributions de latence (violons + boxplot), par niveau x profil
# ═════════════════════════════════════════════════════════════════════════════════════════════════════════
@figure("v2", "F01", "violons_latence_profils", ["v2_conn"], "Handshake latency distributions by signature, KEM, protocol and network profile")
def f01(ctx):
    d = prep(ctx)
    m = d[(d.family == "main") & (d.auth == "single") & d.ok]
    out = []
    for level in LEVELS:
        for prof in ("ideal", "moderate", "degraded"):
            sub = m[(m.level == level) & (m.profile == prof)]
            if sub.empty:
                continue
            fig, axes = plt.subplots(2, 2, figsize=(7.16, 5.9), sharey=True)
            rows = []
            lo_all, hi_all = [], []
            for i, proto in enumerate(("tls", "quic")):
                for j, sc in enumerate(("classical", "pqc")):
                    ax = axes[i][j]
                    cell = sub[(sub.proto == proto) & (sub.sig_class == sc)]
                    kems = kem_order(cell.kem)
                    bm = cell.groupby(["kem", "block"]).hs_ms.median().unstack("block")
                    data, pos, cols = [], [], []
                    for p, k in enumerate(kems, start=1):
                        v = cell[cell.kem == k].hs_ms.to_numpy(float)
                        est, lo, hi = boot_blocks(bm.loc[k].to_numpy())
                        rows.append(dict(proto=proto, level=level, profile=prof, sig=cell.sig.iloc[0], sig_class=sc, kem=k, n=len(v),
                                         mean_ms=v.mean(), median_ms=np.median(v), cv_pct=100 * v.std(ddof=1) / v.mean(),
                                         p95_ms=np.percentile(v, 95), p99_ms=np.percentile(v, 99), max_ms=v.max(),
                                         block_median_est=est, block_median_ci_lo=lo, block_median_ci_hi=hi))
                        cap = np.percentile(v, 99)                       # densite estimee sur [min, p99] ; la queue extreme est l'objet de F08
                        data.append(np.log10(np.clip(v, None, cap))); pos.append(p); cols.append(kem_color(k))
                        lo_all.append(np.percentile(v, 0.5)); hi_all.append(np.percentile(v, 99))
                    parts = ax.violinplot(data, positions=pos, widths=0.8, showextrema=False)
                    for pc, c in zip(parts["bodies"], cols):
                        pc.set_facecolor(c); pc.set_edgecolor("none"); pc.set_alpha(0.75)
                    ax.boxplot([np.log10(cell[cell.kem == k].hs_ms.to_numpy(float)) for k in kems], positions=pos, widths=0.14, showfliers=False,
                               whis=(5, 95), boxprops=dict(color="black", linewidth=0.6), whiskerprops=dict(color="black", linewidth=0.6),
                               capprops=dict(color="black", linewidth=0.6), medianprops=dict(color="black", linewidth=1.2))
                    ax.set_xticks(pos)
                    ax.set_xticklabels([PS.format_kem_label_flat(k) for k in kems], rotation=40, ha="right", rotation_mode="anchor", fontsize=6.3)
                    ax.set_title(f"{PS.PROTOCOL_LABELS[proto]} – {cell.sig.iloc[0]} ({SIGCLASS_LABEL[sc]})", fontsize=8)
                    PS.style_axes(ax, "y")
                    panel_letter(ax, "abcd"[2 * i + j])
            lo, hi = min(lo_all) * 0.85, max(hi_all) * 1.2
            for ax in axes.ravel():
                ax.set_ylim(np.log10(lo), np.log10(hi)); log_ticks(ax, lo, hi)
            for i in range(2):
                axes[i][0].set_ylabel("Handshake duration (ms), log scale", fontsize=8)
            fam = {kem_family_of(k) for k in sub.kem}
            fig.legend(handles=PS.kem_family_legend_handles(fam), loc="lower center", ncol=5, frameon=False, fontsize=7, bbox_to_anchor=(0.5, -0.04))
            fig.tight_layout(rect=[0, 0.04, 1, 1])
            out.append(Variant(f"{level}_{prof}", fig, pd.DataFrame(rows),
                               f"{PROFILE_LABEL[prof]}; density and axis clipped at p99 (tails: see F08); box whiskers p5-p95; CI = block bootstrap of block medians"))
    return out


# ═════════════════════════════════════════════════════════════════════════════════════════════════════════
# V2-F02  Penalite ML-DSA en fonction du RTT (loi D = k * max(0, RTT - T))
# ═════════════════════════════════════════════════════════════════════════════════════════════════════════
@figure("v2", "F02", "penalite_mldsa_vs_rtt", ["v2_conn"], "ML-DSA minus ECDSA handshake time versus RTT")
def f02(ctx):
    d = prep(ctx)
    fx = d[(d.family == "fx") & (d.auth == "single") & (d.process == "none") & (d.loss_nom == 0) & d.ok]
    out = []
    for metric, mlabel in (("hs_ms", "handshake"), ("app_ms", "app-ready")):
        fxm = fx[fx[metric].notna()]
        res = paired_block_stat(fxm, "sig", "mldsa65", "secp384r1", ["proto", "kem", "rtt"], metric, "diff")
        for unit in ("ms", "rtt"):
            fig, axes = plt.subplots(1, 2, figsize=(7.16, 2.9), sharey=True)
            rows = []
            for ax, proto in zip(axes, ("tls", "quic")):
                r = res[res.proto == proto]
                for kem in kem_order(r.kem):
                    g = r[r.kem == kem].sort_values("rtt")
                    if unit == "rtt":
                        g = g[g.rtt > 0]
                        f = 1.0 / g.rtt.to_numpy()
                    else:
                        f = np.ones(len(g))
                    y, lo, hi = g.est.to_numpy() * f, g.lo.to_numpy() * f, g.hi.to_numpy() * f
                    c = kem_color(kem)
                    ax.fill_between(g.rtt, lo, hi, color=c, alpha=0.18, linewidth=0)
                    ax.plot(g.rtt, y, marker="o", color=c, label=PS.format_kem_label_flat(kem))
                    rows += [dict(metric=mlabel, unit=unit, proto=proto, kem=kem, rtt_ms=a, delta=b, ci_lo=c1, ci_hi=c2, n_blocks=n)
                             for a, b, c1, c2, n in zip(g.rtt, y, lo, hi, g.n_blocks)]
                if unit == "ms":
                    xs = np.array([0, 150.0])
                    for kx, ls in ((1, ":"), (2, "--")):
                        ax.plot(xs, kx * xs, color="#777777", linestyle=ls, linewidth=0.8, zorder=1)
                        ax.text(150, kx * 150, f" {kx} RTT", fontsize=6.5, va="center", color="#555555")
                else:
                    for kx in (1, 2):
                        ax.axhline(kx, color="#777777", linestyle=":" if kx == 1 else "--", linewidth=0.8, zorder=1)
                ax.set_title(PS.PROTOCOL_LABELS[proto], fontsize=8.5); ax.set_xlabel("RTT (ms)")
                ax.set_xticks([0, 50, 100, 150]); PS.style_axes(ax, "y")
                ax.axhline(0, color="black", linewidth=0.6)
                panel_letter(ax, "ab"[("tls", "quic").index(proto)])
            axes[0].set_ylabel(f"ML-DSA-65 − ECDSA P-384\n({mlabel}), " + ("ms" if unit == "ms" else "divided by RTT"), fontsize=8)
            axes[0].legend(frameon=False, fontsize=7, loc="upper left")
            fig.tight_layout()
            out.append(Variant(f"{mlabel.replace('-', '_')}_{unit}", fig, pd.DataFrame(rows),
                               "paired by block, 95% CI = block bootstrap; dotted/dashed = 1 and 2 RTT"))
    return out


# ═════════════════════════════════════════════════════════════════════════════════════════════════════════
# V2-F03  Taille des vols serveur (captures pcap) contre les seuils de fenetre initiale / anti-amplification
# ═════════════════════════════════════════════════════════════════════════════════════════════════════════
@figure("v2", "F03", "vols_serveur_seuils", ["v2_flight"], "Server flight size versus initial-window and anti-amplification thresholds")
def f03(ctx):
    f = ctx.df("v2_flight").copy()
    f["cfg"] = f["label"].str.replace("delayonly_delay25ms", "", regex=False).str.replace("__pcap__mb2", "", regex=False).str.replace("__qmtu", "", regex=False)
    f["cfg"] = f["cfg"].str.replace("_mtu1280", "MTU1280 ", regex=False).str.replace("__padto8700", " pad8700", regex=False).str.strip().replace("", "baseline")
    f["sig"] = f["pair"].str.split("_").str[0]
    f["rest_bytes"] = (f["server_bytes"] - f["b1_bytes"] - f["b2_bytes"]).clip(lower=0)
    fig, axes = plt.subplots(1, 2, figsize=(7.16, 3.3), sharey=True)
    for ax, proto in zip(axes, ("tls", "quic")):
        g = f[f.proto == proto].reset_index(drop=True)
        x = np.arange(len(g))
        b1, b2, rest = g.b1_bytes.to_numpy(), g.b2_bytes.to_numpy(), g.rest_bytes.to_numpy()
        ax.bar(x, b1, 0.62, color="#9e9ac8", edgecolor="#555555", linewidth=0.3, label="burst 1")
        ax.bar(x, b2, 0.62, bottom=b1, color="#6a51a3", edgecolor="#555555", linewidth=0.3, label="burst 2")
        ax.bar(x, rest, 0.62, bottom=b1 + b2, **PS.TRAFFIC_RESIDUAL_STYLE, label="later bursts")
        if proto == "tls":
            ax.axhline(14480, color="#D55E00", linewidth=1.0, linestyle="--"); ax.text(len(g) - 0.5, 14480, "TCP IW10 = 14 480 B", ha="right", va="bottom", fontsize=6.5, color="#D55E00")
        else:
            ax.axhline(12520, color="#D55E00", linewidth=1.0, linestyle="--"); ax.text(len(g) - 0.5, 12520, "12 520 B", ha="right", va="bottom", fontsize=6.5, color="#D55E00")
            ax.hlines(3 * g.client_bytes, x - 0.42, x + 0.42, color="#0072B2", linewidth=1.4, label="3 × client bytes")
        for xi, tot in zip(x, g.server_bytes):
            ax.text(xi, tot, f"{tot / 1024:.1f}", ha="center", va="bottom", fontsize=6, fontweight="bold")
        ax.set_xticks(x); ax.set_xticklabels([f"{s}\n{c}" for s, c in zip(g.sig, g.cfg)], rotation=90, fontsize=6)
        ax.set_title(PS.PROTOCOL_LABELS[proto], fontsize=8.5); PS.style_axes(ax, "y"); panel_letter(ax, "ab"[("tls", "quic").index(proto)])
    axes[0].set_ylabel("Server bytes (RTT 50 ms)"); axes[0].set_ylim(0, 16500)
    h, l = axes[1].get_legend_handles_labels()
    fig.legend(h, l, loc="lower center", ncol=4, frameon=False, fontsize=7, bbox_to_anchor=(0.5, -0.02))
    fig.tight_layout(rect=[0, 0.05, 1, 1])
    data = f[["proto", "cfg", "sig", "pair", "client_bytes", "b1_bytes", "b2_bytes", "rest_bytes", "server_bytes", "n_bursts", "b1_over_client"]]
    return [Variant("tous", fig, data, "single deterministic capture per configuration (no error bars); labels in KB above bars")]


# ═════════════════════════════════════════════════════════════════════════════════════════════════════════
# V2-F04  CPU et memoire par handshake, client / serveur, IC par bootstrap de blocs
# ═════════════════════════════════════════════════════════════════════════════════════════════════════════
@figure("v2", "F04", "cpu_memoire_roles", ["v2_conn"], "CPU time per handshake and peak memory, client and server")
def f04(ctx):
    d = prep(ctx)
    m = d[(d.family == "main") & (d.profile == "ideal") & d.ok]
    out = []
    metrics = (("cpu", "cli_cpu_us", "srv_cpu_us", 1e-3, "CPU time per connection (ms), log scale", True),
               ("mem", "cli_mem_b", "srv_mem_b", 1 / 2**20, "Peak memory (MB)", False))
    for proto, auth in PROTO_AUTH:
        for level in LEVELS:
            sub = m[(m.proto == proto) & (m.auth == auth) & (m.level == level)]
            if sub.empty:
                continue
            for key, ccol, scol, sc, ylabel, logy in metrics:
                sigs = SIGS_BY_LEVEL[level]
                fig, axes = plt.subplots(1, 2, figsize=(7.16, 3.1), sharey=True)
                rows, tops = [], []
                for ax, sig in zip(axes, sigs):
                    cell = sub[sub.sig == sig]
                    kems = kem_order(cell.kem)
                    x = np.arange(len(kems)); w = 0.4
                    for r, (role, col, hatch) in enumerate((("client", ccol, ""), ("server", scol, "///"))):
                        est = []
                        for k in kems:
                            bm = cell[cell.kem == k].groupby("block")[col].median().to_numpy() * sc
                            e, lo, hi = boot_blocks(bm)
                            est.append((e, lo, hi))
                            rows.append(dict(proto=proto, auth=auth, level=level, sig=sig, kem=k, role=role, metric=key, est=e, ci_lo=lo, ci_hi=hi))
                        e = np.array([t[0] for t in est]); lo = np.array([t[1] for t in est]); hi = np.array([t[2] for t in est])
                        ax.bar(x + (r - 0.5) * w, e, w, color=[kem_color(k) for k in kems], edgecolor="#444444", linewidth=0.4, hatch=hatch, zorder=3)
                        ax.errorbar(x + (r - 0.5) * w, e, yerr=[np.nan_to_num(e - lo), np.nan_to_num(hi - e)], fmt="none", ecolor="#222222", elinewidth=0.6, capsize=1.5, zorder=4)
                        tops.append(np.nanmax(hi))
                    ax.set_xticks(x); ax.set_xticklabels([PS.format_kem_label_flat(k) for k in kems], rotation=40, ha="right", rotation_mode="anchor", fontsize=6.3)
                    ax.set_title(f"{sig} ({SIGCLASS_LABEL['classical' if sig == sigs[0] else 'pqc']})", fontsize=8.5)
                    PS.style_axes(ax, "y"); panel_letter(ax, "ab"[sigs.index(sig)])
                    if logy:
                        ax.set_yscale("log")
                axes[0].set_ylabel(ylabel, fontsize=8)
                for ax in axes:
                    ax.set_ylim(5 if logy else 0, max(tops) * (1.3 if logy else 1.15))
                    if logy:
                        tk = [t for t in (5, 10, 20, 50, 100, 200) if t <= max(tops) * 1.3]
                        ax.set_yticks(tk); ax.set_yticklabels([str(t) for t in tk]); ax.yaxis.set_minor_formatter(matplotlib.ticker.NullFormatter())
                role_h = [plt.Rectangle((0, 0), 1, 1, facecolor="white", edgecolor="black", hatch=h, label=l) for l, h in (("Client", ""), ("Server", "///"))]
                fig.legend(handles=PS.kem_family_legend_handles({kem_family_of(k) for k in sub.kem}) + role_h, loc="lower center", ncol=4, frameon=False, fontsize=6.8, bbox_to_anchor=(0.5, -0.1))
                fig.tight_layout()
                out.append(Variant(f"{key}_{proto}_{auth}_{level}", fig, pd.DataFrame(rows), "ideal network; per-connection process CPU (includes process start); CI = block bootstrap"))
    return out


# ═════════════════════════════════════════════════════════════════════════════════════════════════════════
# V2-F05  Surcout relatif des KEM par rapport a la courbe NIST classique du meme niveau
# ═════════════════════════════════════════════════════════════════════════════════════════════════════════
@figure("v2", "F05", "ratio_kem_vs_classique", ["v2_conn"], "Latency ratio of each KEM versus the classical NIST-curve baseline")
def f05(ctx):
    d = prep(ctx)
    m = d[(d.family == "main") & d.ok]
    out = []
    for proto, auth in PROTO_AUTH:
        for prof in ("ideal", "moderate", "degraded"):
            fig, axes = plt.subplots(3, 2, figsize=(7.16, 7.2), sharey=True)
            rows = []
            for i, level in enumerate(LEVELS):
                for j, sig in enumerate(SIGS_BY_LEVEL[level]):
                    ax = axes[i][j]
                    cell = m[(m.proto == proto) & (m.auth == auth) & (m.profile == prof) & (m.sig == sig)]
                    kems = [k for k in kem_order(cell.kem) if k != BASE_KEM[level]]
                    est = []
                    for k in kems:
                        r = paired_block_stat(cell[cell.kem.isin([k, BASE_KEM[level]])], "kem", k, BASE_KEM[level], ["sig"], "hs_ms", "ratio")
                        e = r.iloc[0] if len(r) else None
                        est.append((np.nan if e is None else e.est, np.nan if e is None else e.lo, np.nan if e is None else e.hi))
                        rows.append(dict(proto=proto, auth=auth, profile=prof, level=level, sig=sig, kem=k, baseline=BASE_KEM[level],
                                         ratio=est[-1][0], ci_lo=est[-1][1], ci_hi=est[-1][2]))
                    x = np.arange(len(kems))
                    e = np.array([t[0] for t in est]); lo = np.array([t[1] for t in est]); hi = np.array([t[2] for t in est])
                    ax.bar(x, e, 0.7, color=[kem_color(k) for k in kems], edgecolor="#444444", linewidth=0.4, zorder=3)
                    ax.errorbar(x, e, yerr=[np.nan_to_num(e - lo), np.nan_to_num(hi - e)], fmt="none", ecolor="#222222", elinewidth=0.6, capsize=1.5, zorder=4)
                    ax.axhline(1.0, color="#555555", linewidth=0.9, linestyle="--"); ax.set_yscale("log")
                    ax.set_xticks(x); ax.set_xticklabels([PS.format_kem_label_flat(k) for k in kems], rotation=40, ha="right", rotation_mode="anchor", fontsize=6.3)
                    ax.set_title(f"{level} – {sig}", fontsize=8); PS.style_axes(ax, "y"); panel_letter(ax, "abcdef"[2 * i + j])
                axes[i][0].set_ylabel(f"ratio vs {BASE_KEM[level]}", fontsize=8)
            fig.legend(handles=PS.kem_family_legend_handles([f for f in PS.KEM_FAMILY_ORDER if f != "classical"] + ["classical"]), loc="lower center", ncol=5, frameon=False, fontsize=7, bbox_to_anchor=(0.5, -0.02))
            fig.tight_layout(rect=[0, 0.03, 1, 1])
            out.append(Variant(f"{proto}_{auth}_{prof}", fig, pd.DataFrame(rows), f"{PROFILE_LABEL[prof]}; ratio of paired block medians; CI = block bootstrap"))
    return out


# ═════════════════════════════════════════════════════════════════════════════════════════════════════════
# V2-F06  Sensibilite a la perte x RTT (plan factoriel)
# ═════════════════════════════════════════════════════════════════════════════════════════════════════════
@figure("v2", "F06", "sensibilite_perte_rtt", ["v2_conn"], "Handshake latency (median and p95) versus packet loss for each RTT (factorial design)")
def f06(ctx):
    d = prep(ctx)
    fx = d[(d.family == "fx") & (d.auth == "single") & d.ok]
    out = []
    rtts = (0.0, 50.0, 100.0, 150.0); losses = (0.0, 1.0, 2.0, 5.0)
    stats = {"median": (lambda g: g.median(), "median"), "p95": (lambda g: g.quantile(0.95), "95th percentile")}
    for stat, (fn, slabel) in stats.items():
        for proto in ("tls", "quic"):
            for process in ("iid", "ge-mild", "ge-severe"):
                fig, axes = plt.subplots(1, 4, figsize=(7.16, 2.7), sharey=True)
                rows = []
                for ax, rtt in zip(axes, rtts):
                    cell = fx[(fx.proto == proto) & (fx.rtt == rtt)]
                    for (kem, sc), _ in cell.groupby(["kem", "sig_class"]):
                        ys = []
                        for L in losses:
                            g = cell[(cell.kem == kem) & (cell.sig_class == sc) & (cell.loss_nom == L) & (cell.process == ("none" if L == 0 else process))]
                            e, lo, hi = boot_blocks(g.groupby("block").hs_ms.apply(fn).to_numpy())
                            ys.append((e, lo, hi))
                            rows.append(dict(proto=proto, process=process, statistic=stat, rtt_ms=rtt, kem=kem, sig_class=sc, loss_pct=L, value_ms=e, ci_lo=lo, ci_hi=hi))
                        e = np.array([t[0] for t in ys]); lo = np.array([t[1] for t in ys]); hi = np.array([t[2] for t in ys])
                        ax.errorbar(losses, e, yerr=[np.nan_to_num(e - lo), np.nan_to_num(hi - e)], color=kem_color(kem), linestyle="-" if sc == "classical" else "--",
                                    marker="o" if sc == "classical" else "s", markersize=3.2, linewidth=1.1, elinewidth=0.6, capsize=1.5)
                    ax.set_yscale("log"); ax.set_xticks(losses); ax.set_xlabel("loss (%)"); ax.set_title(f"RTT {int(rtt)} ms", fontsize=8); PS.style_axes(ax, "y")
                    panel_letter(ax, "abcd"[rtts.index(rtt)])
                axes[0].set_ylabel(f"Handshake duration, {slabel} (ms)", fontsize=8)
                h = [Line2D([], [], color=kem_color(k), label=PS.format_kem_label_flat(k)) for k in kem_order(fx.kem)] + \
                    [Line2D([], [], color="black", linestyle="-", marker="o", label="ECDSA P-384"), Line2D([], [], color="black", linestyle="--", marker="s", label="ML-DSA-65")]
                fig.legend(handles=h, loc="lower center", ncol=4, frameon=False, fontsize=7, bbox_to_anchor=(0.5, -0.1))
                fig.tight_layout()
                out.append(Variant(f"{stat}_{proto}_{process.replace('-', '_')}", fig, pd.DataFrame(rows),
                                   f"{PS.PROTOCOL_LABELS[proto]}; loss process {process}; {slabel} per block, then median over blocks, 95% CI block bootstrap"))
    return out


# ═════════════════════════════════════════════════════════════════════════════════════════════════════════
# V2-F07  Taux d'echec de handshake (Clopper-Pearson)
# ═════════════════════════════════════════════════════════════════════════════════════════════════════════
@figure("v2", "F07", "taux_echec_perte", ["v2_conn"], "Handshake failure rate versus packet loss (Clopper-Pearson 95% CI)")
def f07(ctx):
    d = prep(ctx)
    fx = d[(d.family == "fx") & (d.auth == "single")]
    fig, axes = plt.subplots(2, 3, figsize=(7.16, 4.4), sharey=True)
    rows = []
    for i, proto in enumerate(("tls", "quic")):
        for j, process in enumerate(("iid", "ge-mild", "ge-severe")):
            ax = axes[i][j]
            for sc, c, off in (("classical", "#7F7F7F", -0.07), ("pqc", "#D55E00", 0.07)):
                xs, ys, los, his = [], [], [], []
                for L in (0.0, 1.0, 2.0, 5.0):
                    g = fx[(fx.proto == proto) & (fx.sig_class == sc) & (fx.loss_nom == L) & (fx.process == ("none" if L == 0 else process))]
                    k, n = int((~g.ok).sum()), len(g)
                    lo, hi = clopper_pearson(k, n)
                    xs.append(L + off); ys.append(100 * k / n if n else np.nan); los.append(100 * lo); his.append(100 * hi)
                    rows.append(dict(proto=proto, process=process, sig_class=sc, loss_pct=L, failures=k, n=n, rate_pct=ys[-1], cp_lo_pct=100 * lo, cp_hi_pct=100 * hi))
                ys, los, his = map(np.array, (ys, los, his))
                ax.errorbar(xs, ys, yerr=[ys - los, his - ys], fmt="o", color=c, markersize=3.5, elinewidth=0.7, capsize=2, label=SIGCLASS_LABEL[sc])
            ax.set_xticks([0, 1, 2, 5]); PS.style_axes(ax, "y"); ax.set_title(f"{PS.PROTOCOL_LABELS[proto]} – {process}", fontsize=8)
            panel_letter(ax, "abcdef"[3 * i + j])
            if i == 1:
                ax.set_xlabel("loss (%)")
        axes[i][0].set_ylabel("failed handshakes (%)", fontsize=8)
    axes[0][0].legend(frameon=False, fontsize=6.5)
    for ax in axes.ravel():
        ax.set_ylim(bottom=-0.02)
    fig.tight_layout()
    return [Variant("fx", fig, pd.DataFrame(rows), "factorial cells pooled over RTT and KEM; a failure = client timeout or missing handshake; zero counts show the CP upper bound")]


# ═════════════════════════════════════════════════════════════════════════════════════════════════════════
# V2-F08  Queues de distribution (CCDF) a RTT 50 ms
# ═════════════════════════════════════════════════════════════════════════════════════════════════════════
@figure("v2", "F08", "ccdf_queues_rtt50", ["v2_conn"], "Complementary CDF of handshake duration at RTT 50 ms")
def f08(ctx):
    d = prep(ctx)
    fx = d[(d.family == "fx") & (d.auth == "single") & (d.rtt == 50.0) & d.ok]
    out = []
    for L in (0.0, 1.0, 2.0, 5.0):
        fig, axes = plt.subplots(1, 2, figsize=(7.16, 3.0), sharey=True)
        rows = []
        for ax, proto in zip(axes, ("tls", "quic")):
            for (kem, sc), g in fx[(fx.proto == proto) & (fx.loss_nom == L) & (fx.process == ("none" if L == 0 else "iid"))].groupby(["kem", "sig_class"]):
                v = np.sort(g.hs_ms.to_numpy(float)); n = len(v)
                p = 1.0 - (np.arange(1, n + 1) - 0.5) / n
                step = max(1, n // 800)
                ax.step(v[::step], p[::step], where="post", color=kem_color(kem), linestyle="-" if sc == "classical" else "--", linewidth=1.1)
                for q in (0.5, 0.9, 0.99, 0.999):
                    rows.append(dict(proto=proto, loss_pct=L, kem=kem, sig_class=sc, quantile=q, value_ms=float(np.quantile(v, q)), n=n))
            ax.set_xscale("log"); ax.set_yscale("log"); ax.set_ylim(5e-4, 1.05); ax.set_xlabel("handshake duration (ms)")
            ax.set_title(PS.PROTOCOL_LABELS[proto], fontsize=8.5); PS.style_axes(ax, "both"); panel_letter(ax, "ab"[("tls", "quic").index(proto)])
        axes[0].set_ylabel("P(duration > t)", fontsize=8)
        h = [Line2D([], [], color=kem_color(k), label=PS.format_kem_label_flat(k)) for k in kem_order(fx.kem)] + \
            [Line2D([], [], color="black", linestyle="-", label="ECDSA P-384"), Line2D([], [], color="black", linestyle="--", label="ML-DSA-65")]
        fig.legend(handles=h, loc="lower center", ncol=4, frameon=False, fontsize=7, bbox_to_anchor=(0.5, -0.08))
        fig.tight_layout()
        out.append(Variant(f"loss{str(L).replace('.', 'p')}", fig, pd.DataFrame(rows), f"loss {L}% iid; pooled over the 20 blocks (descriptive; inference uses block medians)"))
    return out


# ═════════════════════════════════════════════════════════════════════════════════════════════════════════
# V2-F09  Controle qualite : sentinelles par bloc, temperature et frequence
# ═════════════════════════════════════════════════════════════════════════════════════════════════════════
@figure("v2", "F09", "controle_qualite_blocs", ["v2_conn"], "Quality control: sentinel latency, CPU temperature and frequency per block")
def f09(ctx):
    d = prep(ctx)
    s = d[(d.family == "sentinel") & d.ok]
    fig, axes = plt.subplots(2, 2, figsize=(7.16, 4.6), sharex=True)
    rows = []
    mk = {"pre": "o", "mid": "s", "post": "^"}
    for j, proto in enumerate(("tls", "quic")):
        ax = axes[0][j]
        for sc, c in (("classical", "#0072B2"), ("pqc", "#D55E00")):
            for pos in ("pre", "mid", "post"):
                g = s[(s.proto == proto) & (s.sig_class == sc) & (s.sentinel == pos)].groupby("block").hs_ms.median()
                ax.plot(g.index, g.values, marker=mk[pos], markersize=3, linewidth=0.7, color=c, alpha=0.9)
                rows += [dict(kind="sentinel", proto=proto, sig_class=sc, position=pos, block=b, value=v) for b, v in g.items()]
        ax.set_title(f"{PS.PROTOCOL_LABELS[proto]} sentinels (ideal network)", fontsize=8); ax.set_ylabel("handshake median (ms)" if j == 0 else "", fontsize=8)
        PS.style_axes(ax, "y"); panel_letter(ax, "ab"[j])
        env = d[d.proto == proto].groupby("block").agg(temp=("temp_b", "mean"), mhz=("mhz_b", "mean"), load=("load_b", "mean"))
        ax = axes[1][j]; ax2 = ax.twinx()
        ax.plot(env.index, env.temp, color="#D55E00", marker="o", markersize=2.5, linewidth=0.9)
        ax2.plot(env.index, env.mhz, color="#0072B2", marker="s", markersize=2.5, linewidth=0.9)
        ax.set_ylabel("CPU temperature (°C)" if j == 0 else "", color="#D55E00", fontsize=8); ax2.set_ylabel("CPU MHz" if j == 1 else "", color="#0072B2", fontsize=8)
        ax.set_xlabel("block"); PS.style_axes(ax, "y"); ax2.spines["top"].set_visible(False); ax2.grid(False); panel_letter(ax, "cd"[j])
        rows += [dict(kind="env", proto=proto, sig_class="", position="", block=b, value=np.nan, temp_c=r.temp, mhz=r.mhz, load=r.load) for b, r in env.iterrows()]
    h = [Line2D([], [], color="#0072B2", label="ECDSA"), Line2D([], [], color="#D55E00", label="ML-DSA")] + [Line2D([], [], color="black", marker=m, linestyle="None", label=k) for k, m in mk.items()]
    fig.legend(handles=h, loc="lower center", ncol=5, frameon=False, fontsize=7, bbox_to_anchor=(0.5, -0.03))
    fig.tight_layout(rect=[0, 0.03, 1, 1])
    return [Variant("sentinelles_env", fig, pd.DataFrame(rows), "pre/mid/post sentinels measure drift inside a block; blocks are the inferential unit")]


# ═════════════════════════════════════════════════════════════════════════════════════════════════════════
# V2-F10  Surcout de l'authentification mutuelle (TLS)
# ═════════════════════════════════════════════════════════════════════════════════════════════════════════
@figure("v2", "F10", "cout_auth_mutuelle", ["v2_conn"], "Extra handshake time of mutual authentication (TLS)")
def f10(ctx):
    d = prep(ctx)
    m = d[(d.family == "main") & (d.proto == "tls") & d.ok]
    out = []
    for level in LEVELS:
        fig, axes = plt.subplots(1, 3, figsize=(7.16, 3.0), sharey=True)
        rows = []
        for ax, prof in zip(axes, ("ideal", "moderate", "degraded")):
            cell = m[(m.level == level) & (m.profile == prof)]
            r = paired_block_stat(cell, "auth", "mutual", "single", ["sig", "kem"], "hs_ms", "diff")
            kems = kem_order(r.kem); x = np.arange(len(kems)); sigs = SIGS_BY_LEVEL[level]
            for si, sig in enumerate(sigs):
                g = r[r.sig == sig].set_index("kem").reindex(kems)
                xo = x + (si - 0.5) * 0.4
                ax.bar(xo, g.est, 0.4, color=[kem_color(k) for k in kems], edgecolor="#444444", linewidth=0.4, hatch="" if si == 0 else "///", zorder=3)
                ax.errorbar(xo, g.est, yerr=[np.nan_to_num(g.est - g.lo), np.nan_to_num(g.hi - g.est)], fmt="none", ecolor="#222222", elinewidth=0.6, capsize=1.5, zorder=4)
                rows += [dict(level=level, profile=prof, sig=sig, kem=k, delta_ms=a, ci_lo=b, ci_hi=c) for k, a, b, c in zip(kems, g.est, g.lo, g.hi)]
            ax.set_xticks(x); ax.set_xticklabels([PS.format_kem_label_flat(k) for k in kems], rotation=40, ha="right", rotation_mode="anchor", fontsize=6.3)
            ax.set_title(prof.capitalize(), fontsize=8.5); PS.style_axes(ax, "y"); ax.axhline(0, color="black", linewidth=0.6); panel_letter(ax, "abc"[("ideal", "moderate", "degraded").index(prof)])
        axes[0].set_ylabel("mutual − server-auth (ms)", fontsize=8)
        h = [plt.Rectangle((0, 0), 1, 1, facecolor="white", edgecolor="black", hatch=hh, label=s) for s, hh in zip(SIGS_BY_LEVEL[level], ("", "///"))]
        fig.legend(handles=PS.kem_family_legend_handles({kem_family_of(k) for k in m.kem}) + h, loc="lower center", ncol=4, frameon=False, fontsize=6.8, bbox_to_anchor=(0.5, -0.1))
        fig.tight_layout()
        out.append(Variant(level, fig, pd.DataFrame(rows), "paired by block; hatched = ML-DSA; CI = block bootstrap"))
    return out


# ═════════════════════════════════════════════════════════════════════════════════════════════════════════
# V2-F11  k predit contre k observe (modele de seuil)
# ═════════════════════════════════════════════════════════════════════════════════════════════════════════
@figure("v2", "F11", "k_predit_vs_observe", ["v2_kpred"], "Predicted versus observed number of extra RTTs (k) caused by ML-DSA")
def f11(ctx):
    k = ctx.df("v2_kpred")
    need = {"proto", "level", "kem", "k_pool", "k_pool_lo", "k_pool_hi", "k_pred"}
    if not need <= set(k.columns):
        raise RuntimeError(f"colonnes manquantes dans p3_k_pred_vs_obs.csv : {need - set(k.columns)}")
    fig, axes = plt.subplots(1, 2, figsize=(7.16, 3.3), sharex=True, sharey=True)
    for ax, proto in zip(axes, ("tls", "quic")):
        g = k[k.proto == proto]
        for _, r in g.iterrows():
            ax.errorbar(r.k_pred, r.k_pool, yerr=[[r.k_pool - r.k_pool_lo], [r.k_pool_hi - r.k_pool]], fmt=PS.SECURITY_LEVEL_MARKERS[r.level],
                        color=kem_color(r.kem), markersize=4.5, elinewidth=0.6, capsize=1.5, alpha=0.9)
        lim = [min(0, np.nanmin(g.k_pool_lo) - 0.2), max(np.nanmax(g.k_pool_hi), np.nanmax(g.k_pred)) + 0.3]
        ax.plot(lim, lim, color="#555555", linestyle="--", linewidth=0.8); ax.set_xlim(lim); ax.set_ylim(lim)
        ax.set_xlabel("predicted k"); ax.set_title(PS.PROTOCOL_LABELS[proto], fontsize=8.5); PS.style_axes(ax, "both"); panel_letter(ax, "ab"[("tls", "quic").index(proto)])
    axes[0].set_ylabel("observed k (pooled RTT slope)", fontsize=8)
    fig.legend(handles=PS.kem_family_legend_handles({kem_family_of(x) for x in k.kem}) + PS.security_level_legend_handles(), loc="lower center", ncol=4, frameon=False, fontsize=6.8, bbox_to_anchor=(0.5, -0.1))
    fig.tight_layout()
    return [Variant("tous", fig, k[["proto", "auth", "level", "kem", "k_pred", "k_pool", "k_pool_lo", "k_pool_hi", "evidence"]].copy(), "dashed line = perfect prediction; marker = level, colour = KEM family")]
