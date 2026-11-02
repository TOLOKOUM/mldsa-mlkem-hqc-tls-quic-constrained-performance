#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fig_v3.py -- figures des extensions v3 (niveau de securite 3) : reprise de session, compression de certificat, charge
concurrente, pont v3->v2. Entrees : sorties de 13_analyse_extensions.py (p6_connexions.csv.gz, p6_load_niveaux.csv, p6_pont_v2.csv).
Chaque bras ecrit dans SA campagne (v3_resume / v3_comp / v3_load / pont) : aucune collision possible entre bras.
Convention de couleur : ici le KEM est fixe par variante (sa couleur = famille de KEM, comme en v2) ; les signatures et les modes
(complet/reprise, algorithmes de compression) se distinguent par style de trait, marqueur et hachure."""
from __future__ import annotations
import numpy as np
import pandas as pd
import matplotlib
import matplotlib.ticker
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D

from figkit import (figure, Variant, boot_blocks, paired_block_stat, clopper_pearson, panel_letter, kem_family_of, PS)

SIG_PAIR = ("secp384r1", "mldsa65")
SIG_LABEL = {"secp384r1": "ECDSA P-384", "mldsa65": "ML-DSA-65"}
SIG_MARK = {"secp384r1": "o", "mldsa65": "s"}
KEMS = ("x448_mlkem768", "hqc192")
COMP_COLORS = {"none": "#7F7F7F", "zlib": "#009E73", "brotli": "#CC79A7", "zstd": "#F0E442"}
COMP_ORDER = ["none", "zlib", "brotli", "zstd"]


def kcol(k):
    return PS.KEM_FAMILY_COLORS[kem_family_of(k)]


def prep_conn(ctx):
    if hasattr(ctx, "_v3prep"):
        return ctx._v3prep
    d = ctx.df("v3_conn").copy()
    d["comp"] = d["comp"].fillna("").astype(str)
    d["mode"] = np.where(d["resumed"] == 1, "resumed", "full")
    d["ok"] = d["app_ms"].notna()
    d["rtt"] = d["rtt"].astype(float); d["loss"] = d["loss"].astype(float)
    ctx._v3prep = d
    return d


def prep_load(ctx):
    l = ctx.df("v3_load").copy()
    l["cli_bound"] = l["cli_bound"].astype(str).str.lower().isin(("true", "1"))
    return l


# ═════════════════════════════════════════════════════════════════════════════════════════════════════════
# REPRISE DE SESSION
# ═════════════════════════════════════════════════════════════════════════════════════════════════════════
def resume_rows(ctx):
    d = prep_conn(ctx)
    return d[(d.res == 1) & (d.zrtt == 0) & (d.comp == "") & d.ok]


@figure("v3_resume", "R01", "reprise_latence_rtt", ["v3_conn"], "App-ready time, full handshake versus resumed, versus RTT")
def r01(ctx):
    d = resume_rows(ctx); d = d[d.loss == 0]
    out = []
    for kem in KEMS:
        sub = d[d.kem == kem]
        if sub.empty:
            continue
        fig, axes = plt.subplots(1, 2, figsize=(7.16, 2.9), sharey=True); rows = []
        for ax, proto in zip(axes, ("tls", "quic")):
            for sig in SIG_PAIR:
                for mode, ls in (("full", "-"), ("resumed", "--")):
                    g = sub[(sub.proto == proto) & (sub.sig == sig) & (sub["mode"] == mode)]
                    xs, ys, los, his = [], [], [], []
                    for rtt, gg in g.groupby("rtt"):
                        e, lo, hi = boot_blocks(gg.groupby("block").app_ms.median().to_numpy())
                        xs.append(rtt); ys.append(e); los.append(lo); his.append(hi)
                        rows.append(dict(proto=proto, kem=kem, sig=sig, mode=mode, rtt_ms=rtt, app_ms=e, ci_lo=lo, ci_hi=hi))
                    ys, los, his = map(np.array, (ys, los, his))
                    ax.errorbar(xs, ys, yerr=[np.nan_to_num(ys - los), np.nan_to_num(his - ys)], color=kcol(kem), linestyle=ls, marker=SIG_MARK[sig],
                                markersize=3.5, linewidth=1.1, elinewidth=0.6, capsize=1.5, markerfacecolor=kcol(kem) if sig == "mldsa65" else "white")
            ax.set_title(PS.PROTOCOL_LABELS[proto], fontsize=8.5); ax.set_xlabel("RTT (ms)"); PS.style_axes(ax, "y"); panel_letter(ax, "ab"[("tls", "quic").index(proto)])
        axes[0].set_ylabel("App-ready time (ms)", fontsize=8)
        h = [Line2D([], [], color="black", linestyle=ls, label=lb) for ls, lb in (("-", "full handshake"), ("--", "resumed"))] + \
            [Line2D([], [], color="black", marker=SIG_MARK[s], markerfacecolor="white" if s == SIG_PAIR[0] else "black", linestyle="None", label=SIG_LABEL[s]) for s in SIG_PAIR]
        fig.legend(handles=h, loc="lower center", ncol=4, frameon=False, fontsize=7, bbox_to_anchor=(0.5, -0.06)); fig.tight_layout()
        out.append(Variant(kem, fig, pd.DataFrame(rows), f"{PS.format_kem_label_flat(kem)}; no loss; actual mode reported by client; CI = block bootstrap"))
    return out


@figure("v3_resume", "R02", "reprise_penalite_mldsa", ["v3_conn"], "ML-DSA penalty with and without session resumption")
def r02(ctx):
    d = resume_rows(ctx); d = d[d.loss == 0]
    out = []
    for kem in KEMS:
        sub = d[d.kem == kem]
        if sub.empty:
            continue
        fig, axes = plt.subplots(1, 2, figsize=(7.16, 2.9), sharey=True); rows = []
        for ax, proto in zip(axes, ("tls", "quic")):
            for mode, ls, mk in (("full", "-", "o"), ("resumed", "--", "s")):
                r = paired_block_stat(sub[(sub.proto == proto) & (sub["mode"] == mode)], "sig", "mldsa65", "secp384r1", ["rtt"], "app_ms", "diff")
                if r.empty:
                    continue
                r = r.sort_values("rtt")
                ax.fill_between(r.rtt, r.lo, r.hi, color=kcol(kem), alpha=0.15, linewidth=0)
                ax.plot(r.rtt, r.est, color=kcol(kem), linestyle=ls, marker=mk, markersize=3.5, label=mode)
                rows += [dict(proto=proto, kem=kem, mode=mode, rtt_ms=a, delta_ms=b, ci_lo=c, ci_hi=e, n_blocks=n) for a, b, c, e, n in zip(r.rtt, r.est, r.lo, r.hi, r.n_blocks)]
            xs = np.array([0, 150.0])
            for kx, st in ((1, ":"), (2, "--")):
                ax.plot(xs, kx * xs, color="#777777", linestyle=st, linewidth=0.7, zorder=1); ax.text(150, kx * 150, f" {kx} RTT", fontsize=6.5, va="center", color="#555555")
            ax.axhline(0, color="black", linewidth=0.6); ax.set_title(PS.PROTOCOL_LABELS[proto], fontsize=8.5); ax.set_xlabel("RTT (ms)")
            PS.style_axes(ax, "y"); panel_letter(ax, "ab"[("tls", "quic").index(proto)])
        axes[0].set_ylabel("ML-DSA-65 − ECDSA P-384, app-ready (ms)", fontsize=8); axes[0].legend(frameon=False, fontsize=7, loc="upper left"); fig.tight_layout()
        out.append(Variant(kem, fig, pd.DataFrame(rows), "paired by block; solid = full handshake, dashed = resumed"))
    return out


@figure("v3_resume", "R03", "reprise_octets", ["v3_conn"], "Bytes received by the client, full versus resumed")
def r03(ctx):
    d = resume_rows(ctx); d = d[(d.loss == 0) & (d.rtt == 50.0) & d.rx.notna()]
    if d.empty:
        return []
    fig, axes = plt.subplots(1, 2, figsize=(7.16, 3.1), sharey=True); rows = []
    for ax, proto in zip(axes, ("tls", "quic")):
        g = d[d.proto == proto]
        cats = [(s, k) for s in SIG_PAIR for k in KEMS if len(g[(g.sig == s) & (g.kem == k)])]
        x = np.arange(len(cats)); w = 0.4
        for i, mode in enumerate(("full", "resumed")):
            v = [g[(g.sig == s) & (g.kem == k) & (g["mode"] == mode)].rx.median() for s, k in cats]
            ax.bar(x + (i - 0.5) * w, v, w, color=[kcol(k) for _, k in cats], edgecolor="#444444", linewidth=0.4, hatch="" if mode == "full" else "///", zorder=3)
            rows += [dict(proto=proto, sig=s, kem=k, mode=mode, rx_bytes_median=val) for (s, k), val in zip(cats, v)]
        ax.set_xticks(x); ax.set_xticklabels([f"{SIG_LABEL[s]}\n{PS.format_kem_label_flat(k)}" for s, k in cats], fontsize=6.3)
        ax.set_title(PS.PROTOCOL_LABELS[proto], fontsize=8.5); PS.style_axes(ax, "y"); panel_letter(ax, "ab"[("tls", "quic").index(proto)])
    axes[0].set_ylabel("Bytes received (RTT 50 ms)", fontsize=8)
    h = [plt.Rectangle((0, 0), 1, 1, facecolor="white", edgecolor="black", hatch=hh, label=lb) for hh, lb in (("", "full"), ("///", "resumed"))]
    fig.legend(handles=PS.kem_family_legend_handles({kem_family_of(k) for k in KEMS}) + h, loc="lower center", ncol=4, frameon=False, fontsize=7, bbox_to_anchor=(0.5, -0.06)); fig.tight_layout()
    return [Variant("rtt50", fig, pd.DataFrame(rows), "bytes are deterministic (median); no error bars")]


@figure("v3_resume", "R04", "reprise_taux_effectif", ["v3_conn"], "Share of planned resumptions that were actually resumed")
def r04(ctx):
    d = prep_conn(ctx)
    d = d[(d.res == 1) & (d.zrtt == 0) & (d.comp == "") & (d.mode_planned == "resumed")]
    if d.empty:
        return []
    fig, ax = plt.subplots(figsize=(7.16, 3.0)); rows = []
    cells = sorted(d.groupby(["proto", "sig", "kem", "rtt", "loss"]).groups.keys())
    for i, (proto, sig, kem, rtt, loss) in enumerate(cells):
        g = d[(d.proto == proto) & (d.sig == sig) & (d.kem == kem) & (d.rtt == rtt) & (d.loss == loss)]
        k, n = int((g.resumed == 1).sum()), len(g); lo, hi = clopper_pearson(k, n)
        ax.errorbar(i, k / n, yerr=[[k / n - lo], [hi - k / n]], fmt="o" if proto == "tls" else "s", color=kcol(kem), markersize=3.5, elinewidth=0.6, capsize=1.5)
        rows.append(dict(proto=proto, sig=sig, kem=kem, rtt_ms=rtt, loss_pct=loss, resumed=k, n=n, rate=k / n, cp_lo=lo, cp_hi=hi))
    ax.axhline(0.98, color="#D55E00", linestyle="--", linewidth=0.9); ax.text(len(cells) - 1, 0.98, "pre-registered threshold 98 %", ha="right", va="bottom", fontsize=6.5, color="#D55E00")
    ax.set_ylim(0.9, 1.005); ax.set_xlabel("cell (protocol, signature, KEM, RTT, loss)"); ax.set_xticks([]); ax.set_ylabel("resumed / planned", fontsize=8); PS.style_axes(ax, "y")
    h = [Line2D([], [], color="black", marker=m, linestyle="None", label=PS.PROTOCOL_LABELS[p]) for p, m in (("tls", "o"), ("quic", "s"))]
    ax.legend(handles=h, frameon=False, fontsize=7, loc="lower left"); fig.tight_layout()
    return [Variant("toutes_cellules", fig, pd.DataFrame(rows), "validity check R0: a resumption measurement only counts if the ticket was accepted")]


@figure("v3_resume", "R05", "reprise_gain_vs_perte", ["v3_conn"], "Time saved by resumption versus packet loss (RTT 50 ms)")
def r05(ctx):
    d = resume_rows(ctx); d = d[d.rtt == 50.0]
    if d.empty or d.loss.nunique() < 2:
        return []
    out = []
    for kem in KEMS:
        sub = d[d.kem == kem]
        if sub.empty:
            continue
        fig, axes = plt.subplots(1, 2, figsize=(7.16, 2.9), sharey=True); rows = []
        for ax, proto in zip(axes, ("tls", "quic")):
            for sig in SIG_PAIR:
                r = paired_block_stat(sub[(sub.proto == proto) & (sub.sig == sig)], "mode", "full", "resumed", ["loss"], "app_ms", "diff")
                if r.empty:
                    continue
                r = r.sort_values("loss")
                ax.errorbar(r.loss, r.est, yerr=[np.nan_to_num(r.est - r.lo), np.nan_to_num(r.hi - r.est)], color=kcol(kem), marker=SIG_MARK[sig], markersize=3.5, linewidth=1.1,
                            elinewidth=0.6, capsize=1.5, markerfacecolor="white" if sig == SIG_PAIR[0] else kcol(kem), label=SIG_LABEL[sig])
                rows += [dict(proto=proto, kem=kem, sig=sig, loss_pct=a, saved_ms=b, ci_lo=c, ci_hi=e) for a, b, c, e in zip(r.loss, r.est, r.lo, r.hi)]
            ax.axhline(0, color="black", linewidth=0.6); ax.set_title(PS.PROTOCOL_LABELS[proto], fontsize=8.5); ax.set_xlabel("loss (%)"); PS.style_axes(ax, "y"); panel_letter(ax, "ab"[("tls", "quic").index(proto)])
        axes[0].set_ylabel("full − resumed, app-ready (ms)", fontsize=8); axes[0].legend(frameon=False, fontsize=7); fig.tight_layout()
        out.append(Variant(kem, fig, pd.DataFrame(rows), "paired by block; positive = resumption saves time"))
    return out


# ═════════════════════════════════════════════════════════════════════════════════════════════════════════
# COMPRESSION DE CERTIFICAT (TLS uniquement : limite declaree pour QUIC)
# ═════════════════════════════════════════════════════════════════════════════════════════════════════════
def comp_rows(ctx):
    d = prep_conn(ctx)
    d = d[(d.comp != "") & (d.proto == "tls") & d.ok].copy()
    d["groupe"] = np.where(d["pad"] > 0, "ctl" + d["pad"].astype(int).astype(str), "chain" + d["chain"].astype(int).astype(str))
    return d


@figure("v3_comp", "C01", "compression_octets", ["v3_conn"], "Bytes received with and without certificate compression (TLS)")
def c01(ctx):
    d = comp_rows(ctx); d = d[(d.loss == 0) & d.rx.notna()]
    if d.empty:
        return []
    out = []
    for kem in KEMS:
        sub = d[(d.kem == kem) & (d.rtt == d.rtt.min())]
        if sub.empty:
            continue
        groups = [g for g in ("chain1", "chain2", "ctl8700", "ctl16000") if g in set(sub.groupe)]
        cats = [(g, s) for g in groups for s in SIG_PAIR if len(sub[(sub.groupe == g) & (sub.sig == s)])]
        comps = [c for c in COMP_ORDER if c in set(sub.comp)]
        fig, ax = plt.subplots(figsize=(7.16, 3.1)); rows = []; x = np.arange(len(cats)); w = 0.8 / len(comps)
        for i, c in enumerate(comps):
            v = [sub[(sub.groupe == g) & (sub.sig == s) & (sub.comp == c)].rx.median() for g, s in cats]
            ax.bar(x + (i - (len(comps) - 1) / 2) * w, v, w * 0.92, color=COMP_COLORS[c], edgecolor="#444444", linewidth=0.4, zorder=3, label=c)
            rows += [dict(kem=kem, group=g, sig=s, comp=c, rx_bytes_median=val) for (g, s), val in zip(cats, v)]
        ax.set_xticks(x); ax.set_xticklabels([f"{g}\n{SIG_LABEL[s]}" for g, s in cats], fontsize=6.5)
        ax.set_ylabel("Bytes received (median)", fontsize=8); PS.style_axes(ax, "y"); ax.legend(title="compression", frameon=False, fontsize=7, ncol=4); fig.tight_layout()
        out.append(Variant(kem, fig, pd.DataFrame(rows), "TLS only; QUIC compression unavailable in the MsQuic build (declared limitation); ctl* = padded controls"))
    return out


@figure("v3_comp", "C02", "compression_latence", ["v3_conn"], "Time change due to certificate compression versus RTT (TLS)")
def c02(ctx):
    d = comp_rows(ctx); d = d[d.loss == 0]
    if d.empty:
        return []
    out = []
    for kem in KEMS:
        sub = d[d.kem == kem]
        groups = [g for g in ("chain1", "chain2", "ctl8700", "ctl16000") if g in set(sub.groupe)]
        if not groups:
            continue
        fig, axes = plt.subplots(1, len(groups), figsize=(7.16, 2.8), sharey=True, squeeze=False); axes = axes[0]; rows = []
        for ax, g in zip(axes, groups):
            for sig in SIG_PAIR:
                for c in [c for c in COMP_ORDER if c != "none" and c in set(sub.comp)]:
                    sg = sub[(sub.groupe == g) & (sub.sig == sig) & (sub.comp.isin([c, "none"]))]
                    if sg.empty:
                        continue
                    r = paired_block_stat(sg, "comp", c, "none", ["rtt"], "app_ms", "diff")
                    if r.empty:
                        continue
                    r = r.sort_values("rtt")
                    ax.errorbar(r.rtt, r.est, yerr=[np.nan_to_num(r.est - r.lo), np.nan_to_num(r.hi - r.est)], color=COMP_COLORS[c], marker=SIG_MARK[sig], markersize=3, linewidth=0.9,
                                elinewidth=0.5, capsize=1.2, markerfacecolor="white" if sig == SIG_PAIR[0] else COMP_COLORS[c])
                    rows += [dict(kem=kem, group=g, sig=sig, comp=c, rtt_ms=a, delta_ms=b, ci_lo=lo, ci_hi=hi) for a, b, lo, hi in zip(r.rtt, r.est, r.lo, r.hi)]
            ax.axhline(0, color="black", linewidth=0.6); ax.set_title(g, fontsize=8); ax.set_xlabel("RTT (ms)"); PS.style_axes(ax, "y"); panel_letter(ax, "abcd"[groups.index(g)])
        axes[0].set_ylabel("compressed − none, app-ready (ms)", fontsize=8)
        h = [Line2D([], [], color=COMP_COLORS[c], label=c) for c in COMP_ORDER if c != "none"] + [Line2D([], [], color="black", marker=SIG_MARK[s], markerfacecolor="white" if s == SIG_PAIR[0] else "black", linestyle="None", label=SIG_LABEL[s]) for s in SIG_PAIR]
        fig.legend(handles=h, loc="lower center", ncol=5, frameon=False, fontsize=7, bbox_to_anchor=(0.5, -0.06)); fig.tight_layout()
        out.append(Variant(kem, fig, pd.DataFrame(rows), "paired by block versus compression 'none'; ML-DSA chains are incompressible (expect ~0)"))
    return out


@figure("v3_comp", "C03", "compression_effective", ["v3_conn"], "Check: share of connections that actually used a compressed certificate (TLS)")
def c03(ctx):
    d = comp_rows(ctx)
    d = d[d.cert_type.notna()]
    if d.empty:
        return []
    d = d.assign(compressed=(d.cert_type == 25).astype(float))
    g = d.groupby(["comp", "groupe", "sig"]).compressed.mean().reset_index()
    fig, ax = plt.subplots(figsize=(7.16, 2.9)); cats = [(a, b) for a in ("chain1", "chain2", "ctl8700", "ctl16000") for b in SIG_PAIR if len(g[(g.groupe == a) & (g.sig == b)])]
    comps = [c for c in COMP_ORDER if c in set(g.comp)]; x = np.arange(len(cats)); w = 0.8 / len(comps)
    for i, c in enumerate(comps):
        v = [float(g[(g.comp == c) & (g.groupe == a) & (g.sig == b)].compressed.mean()) if len(g[(g.comp == c) & (g.groupe == a) & (g.sig == b)]) else np.nan for a, b in cats]
        ax.bar(x + (i - (len(comps) - 1) / 2) * w, v, w * 0.92, color=COMP_COLORS[c], edgecolor="#444444", linewidth=0.4, label=c, zorder=3)
    ax.set_xticks(x); ax.set_xticklabels([f"{a}\n{SIG_LABEL[b]}" for a, b in cats], fontsize=6.5); ax.set_ylabel("Certificate message type 25 (share)", fontsize=8); PS.style_axes(ax, "y")
    ax.legend(title="compression", frameon=False, fontsize=7, ncol=4); fig.tight_layout()
    return [Variant("tous", fig, g, "verification of effectiveness: type 25 = CompressedCertificate seen on the wire; 'none' must be 0")]


# ═════════════════════════════════════════════════════════════════════════════════════════════════════════
# CHARGE CONCURRENTE
# ═════════════════════════════════════════════════════════════════════════════════════════════════════════
def level_stat(g, col, fn=np.nanmedian):
    return boot_blocks(g.groupby("block")[col].apply(lambda s: fn(s.to_numpy())).to_numpy())


@figure("v3_load", "L01", "charge_debit_latence_cpu", ["v3_load"], "Throughput, latency, CPU utilisation and failures versus concurrency")
def l01(ctx):
    l = prep_load(ctx); l = l[l.tls_server != "stock"]
    out = []
    for kem in KEMS:
        for rtt in sorted(l.rtt.unique()):
            sub = l[(l.kem == kem) & (l.rtt == rtt)]
            if sub.empty:
                continue
            fig, axes = plt.subplots(2, 2, figsize=(7.16, 5.2)); rows = []
            panels = (("X", "Throughput (handshakes/s)", axes[0][0]), ("app_med", "App-ready median (ms)", axes[0][1]),
                      ("util_srv", "CPU utilisation (solid server, dashed client)", axes[1][0]), ("fail", "Failed connections (share)", axes[1][1]))
            for col, ylab, ax in panels:
                for proto in ("tls", "quic"):
                    for sig in SIG_PAIR:
                        g = sub[(sub.proto == proto) & (sub.sig == sig)]
                        if g.empty:
                            continue
                        xs, ys, los, his, bound = [], [], [], [], []
                        for c, gc in sorted(g.groupby("conc")):
                            e, lo, hi = level_stat(gc, col); xs.append(c); ys.append(e); los.append(lo); his.append(hi); bound.append(gc.cli_bound.mean() > 0.5)
                            rows.append(dict(proto=proto, sig=sig, kem=kem, rtt_ms=rtt, metric=col, conc=c, value=e, ci_lo=lo, ci_hi=hi, client_bound=bool(bound[-1])))
                        ys, los, his = map(np.array, (ys, los, his)); ls = "-" if proto == "tls" else "--"
                        ax.plot(xs, ys, color=kcol(kem), linestyle=ls, marker=SIG_MARK[sig], markersize=3.5, linewidth=1.0, markerfacecolor="white" if sig == SIG_PAIR[0] else kcol(kem))
                        ax.fill_between(xs, los, his, color=kcol(kem), alpha=0.12, linewidth=0)
                        if col == "util_srv":
                            yc = [level_stat(gc, "util_cli")[0] for _, gc in sorted(g.groupby("conc"))]
                            ax.plot(xs, yc, color="#555555", linestyle=ls, marker=SIG_MARK[sig], markersize=2.5, linewidth=0.7, alpha=0.8, markerfacecolor="white" if sig == SIG_PAIR[0] else "#555555")
                        bx = [x for x, b in zip(xs, bound) if b]
                        if bx:
                            ax.plot(bx, [y for y, b in zip(ys, bound) if b], "x", color="#D55E00", markersize=6, zorder=5)
                ax.set_xscale("log", base=2); ax.set_xticks([1, 2, 4, 8, 16, 32]); ax.set_xticklabels(["1", "2", "4", "8", "16", "32"]); ax.set_xlabel("concurrent connections"); ax.set_ylabel(ylab, fontsize=7.5); PS.style_axes(ax, "y")
                if col == "util_srv":
                    ax.axhline(0.85, color="#D55E00", linewidth=0.7, linestyle=":"); ax.set_ylim(0, 1.1)
                if col == "app_med":
                    ax.set_yscale("log")
                    ax.yaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda v, _: f"{v:g}")); ax.yaxis.set_minor_formatter(matplotlib.ticker.FuncFormatter(lambda v, _: f"{v:g}" if v in (2, 5, 20, 50, 200, 500, 2000) else ""))
            for ax, lt in zip(axes.ravel(), "abcd"):
                panel_letter(ax, lt)
            h = [Line2D([], [], color="black", linestyle=ls, label=PS.PROTOCOL_LABELS[p]) for p, ls in (("tls", "-"), ("quic", "--"))] + \
                [Line2D([], [], color="black", marker=SIG_MARK[s], markerfacecolor="white" if s == SIG_PAIR[0] else "black", linestyle="None", label=SIG_LABEL[s]) for s in SIG_PAIR] + \
                [Line2D([], [], color="#D55E00", marker="x", linestyle="None", label="client > 85 % CPU (unusable)")]
            fig.legend(handles=h, loc="lower center", ncol=3, frameon=False, fontsize=7, bbox_to_anchor=(0.5, -0.04)); fig.tight_layout(rect=[0, 0.05, 1, 1])
            out.append(Variant(f"{kem}_rtt{int(rtt)}", fig, pd.DataFrame(rows), "median over blocks of per-block level statistics; band = 95% block bootstrap; red x = client-bound levels (generator saturated, not a server result)"))
    return out


@figure("v3_load", "L02", "charge_calibration_serveur_mt", ["v3_load"], "Calibration: multi-connection TLS server versus stock server at concurrency 1")
def l02(ctx):
    l = prep_load(ctx); l = l[(l.proto == "tls") & (l.conc == 1)]
    if not {"mt", "stock"} <= set(l.tls_server):
        return []
    fig, axes = plt.subplots(1, 2, figsize=(7.16, 2.9)); rows = []
    for ax, (metric, lab) in zip(axes, (("app_med", "MT − stock, app-ready median (ms)"), ("S_ms", "MT / stock, server CPU per connection"))):
        i = 0; xt = []
        for rtt in sorted(l.rtt.unique()):
            for sig in SIG_PAIR:
                for kem in KEMS:
                    sub = l[(l.rtt == rtt) & (l.sig == sig) & (l.kem == kem)]
                    r = paired_block_stat(sub, "tls_server", "mt", "stock", ["rtt"], metric, "diff" if metric == "app_med" else "ratio")
                    if r.empty:
                        continue
                    e = r.iloc[0]
                    ax.errorbar(i, e.est, yerr=[[max(0, e.est - e.lo)], [max(0, e.hi - e.est)]], fmt=SIG_MARK[sig], color=kcol(kem), markersize=4, elinewidth=0.7, capsize=2,
                                markerfacecolor="white" if sig == SIG_PAIR[0] else kcol(kem))
                    rows.append(dict(metric=metric, rtt_ms=rtt, sig=sig, kem=kem, est=e.est, ci_lo=e.lo, ci_hi=e.hi)); xt.append(f"{int(rtt)}\n{SIG_LABEL[sig][:5]}"); i += 1
        ax.axhline(0 if metric == "app_med" else 1, color="#555555", linestyle="--", linewidth=0.8)
        if metric == "app_med":
            ax.axhspan(-0.5, 0.5, color="#999999", alpha=0.15);
        else:
            ax.axhspan(0.85, 1.15, color="#999999", alpha=0.15)
        ax.set_xticks(range(len(xt))); ax.set_xticklabels(xt, fontsize=5.5); ax.set_ylabel(lab, fontsize=7.5); ax.set_xlabel("RTT (ms) / signature"); PS.style_axes(ax, "y")
    for ax, lt in zip(axes, "ab"):
        panel_letter(ax, lt)
    fig.legend(handles=PS.kem_family_legend_handles({kem_family_of(k) for k in KEMS}), loc="lower center", ncol=3, frameon=False, fontsize=7, bbox_to_anchor=(0.5, -0.06)); fig.tight_layout()
    return [Variant("c1", fig, pd.DataFrame(rows), "gray band = pre-registered equivalence band; the MT server may only be used for the load arm if it lies inside")]


@figure("v3_load", "L03", "charge_cpu_par_connexion", ["v3_load"], "CPU per connection: server versus client (load generator)")
def l03(ctx):
    l = prep_load(ctx); l = l[(~l.cli_bound) & (l.conc >= 4) & (l.tls_server != "stock")]
    if l.empty:
        return []
    out = []
    for rtt in sorted(l.rtt.unique()):
        sub = l[l.rtt == rtt]
        fig, ax = plt.subplots(figsize=(7.16, 3.0)); rows = []
        cats = [(p, s, k) for p in ("tls", "quic") for k in KEMS for s in SIG_PAIR if len(sub[(sub.proto == p) & (sub.sig == s) & (sub.kem == k)])]
        x = np.arange(len(cats)); w = 0.4
        for j, (col, hatch, lab) in enumerate((("S_ms", "", "server"), ("Scli_ms", "///", "client"))):
            est = [level_stat(sub[(sub.proto == p) & (sub.sig == s) & (sub.kem == k)], col) for p, s, k in cats]
            e = np.array([t[0] for t in est]); lo = np.array([t[1] for t in est]); hi = np.array([t[2] for t in est])
            ax.bar(x + (j - 0.5) * w, e, w, color=[kcol(k) for _, _, k in cats], edgecolor="#444444", linewidth=0.4, hatch=hatch, zorder=3)
            ax.errorbar(x + (j - 0.5) * w, e, yerr=[np.nan_to_num(e - lo), np.nan_to_num(hi - e)], fmt="none", ecolor="#222222", elinewidth=0.6, capsize=1.5, zorder=4)
            rows += [dict(role=lab, proto=p, sig=s, kem=k, rtt_ms=rtt, cpu_ms_per_conn=a, ci_lo=b, ci_hi=c) for (p, s, k), a, b, c in zip(cats, e, lo, hi)]
        ax.set_xticks(x); ax.set_xticklabels([f"{PS.PROTOCOL_LABELS[p]}\n{SIG_LABEL[s][:5]}\n{PS.format_kem_label_flat(k)}" for p, s, k in cats], fontsize=5.8)
        ax.set_ylabel("CPU per connection (ms), c ≥ 4", fontsize=8); ax.set_yscale("log"); PS.style_axes(ax, "y")
        hh = [plt.Rectangle((0, 0), 1, 1, facecolor="white", edgecolor="black", hatch=h, label=lb) for h, lb in (("", "server"), ("///", "client"))]
        fig.legend(handles=PS.kem_family_legend_handles({kem_family_of(k) for k in KEMS}) + hh, loc="lower center", ncol=4, frameon=False, fontsize=7, bbox_to_anchor=(0.5, -0.06)); fig.tight_layout()
        out.append(Variant(f"rtt{int(rtt)}", fig, pd.DataFrame(rows), "only non client-bound levels; CPU integrated over the steady-state window"))
    return out


# ═════════════════════════════════════════════════════════════════════════════════════════════════════════
# PONT v3 -> v2 (l'image v3 n'a pas deplace la mesure)
# ═════════════════════════════════════════════════════════════════════════════════════════════════════════
@figure("pont", "X01", "pont_sentinelles_v3_v2", ["v3_bridge"], "Bridge: sentinel median v3 minus v2")
def x01(ctx):
    b = ctx.df("v3_bridge")
    need = {"proto", "sig", "kem", "delta_med_ms", "lo", "hi"}
    if not need <= set(b.columns) or b.empty:
        return []
    fig, ax = plt.subplots(figsize=(7.16, 2.8)); x = np.arange(len(b))
    ax.axhspan(-0.5, 0.5, color="#999999", alpha=0.2)
    for i, r in b.reset_index(drop=True).iterrows():
        ax.errorbar(i, r.delta_med_ms, yerr=[[r.delta_med_ms - r.lo], [r.hi - r.delta_med_ms]], fmt="o" if r.proto == "tls" else "s", color=kcol(r.kem), markersize=4, elinewidth=0.7, capsize=2,
                    markerfacecolor="white" if r.sig == SIG_PAIR[0] else kcol(r.kem))
    ax.axhline(0, color="black", linewidth=0.6); ax.set_xticks(x); ax.set_xticklabels([f"{PS.PROTOCOL_LABELS[p]}\n{SIG_LABEL.get(s, s)[:5]}" for p, s in zip(b.proto, b.sig)], fontsize=6.5)
    ax.set_ylabel("v3 − v2, sentinel median (ms)", fontsize=8); PS.style_axes(ax, "y"); fig.tight_layout()
    return [Variant("tous", fig, b.copy(), "grey band = pre-registered +-0.5 ms: the v3 image did not shift the measurement")]
