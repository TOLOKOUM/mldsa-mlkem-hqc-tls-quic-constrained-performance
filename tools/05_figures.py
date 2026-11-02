#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
05_figures.py — Figures et tableaux de l'article (phase 3), à partir des CSV de la phase 2.

Entrées (dans --in, par défaut analysis_v2/phase2) :
  p2_c1_main_contrasts.csv, p2_c5_factorial_cells.csv, p2_c7_size_decomposition.csv,
  p2_q_tails.csv, flight_timeline_summary.csv   (chacun est optionnel : la figure est sautée si absent)

Sorties (dans --out, par défaut analysis_v2/figures) : PNG (300 dpi) + PDF vectoriel + tableaux .tex/.csv.
Compatible matplotlib >= 3.5 (testé 3.6). Aucune donnée brute n'est relue : tout vient des CSV de la phase 2,
donc les chiffres des figures sont exactement ceux du rapport.

Usage :
  python3 tools/05_figures.py --in analysis_v2/phase2 --out analysis_v2/figures [--lang fr|en]
"""
import argparse
import os
import sys

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D

# Palette Okabe-Ito (lisible en daltonisme et en niveaux de gris)
C_QUIC = "#0072B2"
C_TLS = "#D55E00"
C_GREY = "#666666"
C_CLASS = "#009E73"
C_ML = "#CC79A7"
C_PAD = "#E69F00"
PROFILE_COL = {"ideal": "#009E73", "moderate": "#E69F00", "degraded": "#CC79A7"}

TXT = {
    "fr": {
        "rtt": "RTT (ms)", "eff": "Effet ML-DSA − classique (ms)",
        "model": "modèle de seuil : RTT − 2,4 ms",
        "f1_title": "Effet de ML-DSA-65 selon le RTT, sans perte",
        "bytes": "Octets du vol serveur", "limit_q": "limite d'anti-amplification (3 × Initial client)",
        "limit_t": "fenêtre initiale TCP (10 MSS)",
        "burst": "rafale", "cls": "classique (secp384r1)", "mld": "ML-DSA-65", "pad": "ECDSA rempli à 8 700 o",
        "rel": "Surcoût relatif de ML-DSA (%)", "robust": "preuve robuste", "second": "preuve secondaire (TLS, perte groupée)",
        "total": "total", "size": "taille", "resid": "résidu (calcul)", "q": "quantile", "dq": "Écart ML-DSA − classique (ms)",
        "loss": "perte nominale (%)", "diff": "Écart (ms)",
    },
    "en": {
        "rtt": "RTT (ms)", "eff": "ML-DSA − classical effect (ms)",
        "model": "threshold model: RTT − 2.4 ms",
        "f1_title": "ML-DSA-65 effect versus RTT, loss-free",
        "bytes": "Server flight bytes", "limit_q": "anti-amplification limit (3 × client Initial)",
        "limit_t": "TCP initial window (10 MSS)",
        "burst": "burst", "cls": "classical (secp384r1)", "mld": "ML-DSA-65", "pad": "ECDSA padded to 8,700 B",
        "rel": "ML-DSA relative overhead (%)", "robust": "robust evidence", "second": "secondary evidence (TLS, clustered loss)",
        "total": "total", "size": "size", "resid": "residual (compute)", "q": "quantile", "dq": "ML-DSA − classical gap (ms)",
        "loss": "nominal loss (%)", "diff": "Gap (ms)",
    },
}


def setup_style():
    plt.rcParams.update({
        "font.size": 9, "axes.titlesize": 9.5, "axes.labelsize": 9, "legend.fontsize": 8,
        "xtick.labelsize": 8, "ytick.labelsize": 8, "axes.spines.top": False, "axes.spines.right": False,
        "axes.grid": True, "grid.alpha": 0.25, "grid.linewidth": 0.5, "figure.dpi": 100,
        "savefig.bbox": "tight", "pdf.fonttype": 42, "ps.fonttype": 42,
    })


def save(fig, out, name):
    for ext in ("png", "pdf"):
        p = os.path.join(out, "%s.%s" % (name, ext))
        fig.savefig(p, dpi=300 if ext == "png" else None)
    plt.close(fig)
    print("  figure:", name)


def read(indir, name):
    p = os.path.join(indir, name)
    if not os.path.exists(p):
        print("  (absent, figure sautée) :", name)
        return None
    return pd.read_csv(p)


# ----------------------------------------------------------------------------- F1
def fig_threshold(df, out, T):
    """Effet ML-DSA vs RTT, sans perte, QUIC vs TLS, par KEM."""
    d = df[(df.proc == "none") & (df.loss == 0)].copy()
    if d.empty:
        return
    kems = [k for k in ("x448_mlkem768", "hqc192") if k in set(d.kem)]
    fig, axes = plt.subplots(1, len(kems), figsize=(3.4 * len(kems) + 0.4, 3.0), sharey=True, squeeze=False)
    names = {"x448_mlkem768": "X448+ML-KEM-768", "hqc192": "HQC-192"}
    xs = np.linspace(0, 160, 50)
    for ax, kem in zip(axes[0], kems):
        for proto, col, mk in (("quic", C_QUIC, "o"), ("tls", C_TLS, "s")):
            s = d[(d.proto == proto) & (d.kem == kem)].sort_values("rtt")
            if s.empty:
                continue
            off = -1.5 if proto == "quic" else 1.5
            ax.errorbar(s.rtt + off, s["mean"], yerr=[s["mean"] - s.lo, s.hi - s["mean"]],
                        color=col, marker=mk, ms=4, lw=1.2, capsize=2, label=proto.upper())
        if kem == "x448_mlkem768":
            ax.plot(xs, np.maximum(xs - 2.4, -2.4), ls="--", color=C_GREY, lw=0.9, label=T["model"])
        ax.axhline(0, color="k", lw=0.6)
        ax.set_title(names.get(kem, kem))
        ax.set_xlabel(T["rtt"])
        ax.set_xticks([0, 50, 100, 150])
    axes[0][0].set_ylabel(T["eff"])
    axes[0][0].legend(frameon=False, loc="upper left")
    fig.suptitle(T["f1_title"], y=1.02, fontsize=10)
    fig.tight_layout()
    save(fig, out, "fig1_effet_mldsa_vs_rtt")


# ----------------------------------------------------------------------------- F2
def fig_flights(fl, out, T):
    """Vols serveur reconstitués des pcap : octets par rafale, avec le seuil de la couche transport."""
    f = fl[~fl.label.str.contains("mtu1280")].copy()
    if f.empty:
        return

    def kind(r):
        if "padto8700" in r.label:
            return "pad"
        return "mld" if r.pair.startswith("mldsa") else "cls"

    f["kind"] = f.apply(kind, axis=1)
    order = {"cls": 0, "mld": 1, "pad": 2}
    fig, axes = plt.subplots(1, 2, figsize=(9.0, 2.9), sharex=False)
    for ax, proto in zip(axes, ("quic", "tls")):
        s = f[f.proto == proto].sort_values("kind", key=lambda c: c.map(order))
        if s.empty:
            continue
        ylab = []
        bar_col = C_QUIC if proto == "quic" else C_TLS
        for i, (_, r) in enumerate(s.iterrows()):
            y = len(s) - 1 - i
            b1, b2 = r.b1_bytes, r.b2_bytes
            ax.barh(y, b1, color=bar_col, height=0.5)
            ax.barh(y, b2, left=b1, color="#BBBBBB", height=0.5)
            tot = b1 + b2
            txt = "1re rafale t=%.0f ms" % r.b1_t_ms if T is TXT["fr"] else "1st burst t=%.0f ms" % r.b1_t_ms
            ax.text(tot + 250, y + 0.12, txt + " (%d B)" % b1, ha="left", va="center", fontsize=7, color=bar_col, zorder=5,
                    bbox=dict(facecolor="white", edgecolor="none", pad=0.8))
            if b2 > 600:
                t2 = "2e rafale t=%.0f ms" % r.b2_t_ms if T is TXT["fr"] else "2nd burst t=%.0f ms" % r.b2_t_ms
                ax.text(tot + 250, y - 0.17, t2 + " (%d B)" % b2, ha="left", va="center", fontsize=7, color=C_GREY, zorder=5,
                        bbox=dict(facecolor="white", edgecolor="none", pad=0.8))
            ylab.append((y, T[r.kind]))
        ax.set_yticks([a for a, _ in ylab])
        ax.set_yticklabels([b for _, b in ylab])
        if proto == "quic":
            lim = 3 * float(s.client_bytes.iloc[0])
            lab = T["limit_q"]
        else:
            lim = 10 * 1448
            lab = T["limit_t"]
        ax.axvline(lim, color="k", ls="--", lw=1.0)
        ax.text(lim, len(s) - 0.45, lab, ha="center", va="bottom", fontsize=7,
                bbox=dict(facecolor="white", edgecolor="none", pad=1.5))
        ax.set_xlabel(T["bytes"] + " (B)")
        ax.set_title(proto.upper() + " — RTT 50 ms, X448+ML-KEM-768")
        ax.set_xlim(0, max(lim, (s.b1_bytes + s.b2_bytes).max()) * 1.75)
        ax.set_ylim(-0.6, len(s) + 0.35)
    fig.tight_layout()
    save(fig, out, "fig2_vols_serveur")


# ----------------------------------------------------------------------------- F3
def fig_forest(c1, out, T):
    for (proto, auth), g in c1.groupby(["proto", "auth"]):
        profs = [p for p in ("ideal", "moderate", "degraded") if p in set(g.profile)]
        if not profs:
            continue
        g = g.copy()
        g["row"] = g.level.astype(str) + " " + g.kem.astype(str)
        rows = list(dict.fromkeys(g.sort_values(["level", "kem"]).row))
        pos = {r: len(rows) - 1 - i for i, r in enumerate(rows)}
        fig, axes = plt.subplots(1, len(profs), figsize=(2.7 * len(profs) + 1.2, 0.2 * len(rows) + 1.3),
                                 sharey=True, squeeze=False)
        for ax, prof in zip(axes[0], profs):
            s = g[g.profile == prof]
            for _, r in s.iterrows():
                y = pos[r.row]
                rob = str(r.evidence) == "ROBUSTE"
                col = PROFILE_COL.get(prof, C_GREY)
                ax.plot([r.rel_lo, r.rel_hi], [y, y], color=col, lw=1.1, alpha=1 if rob else 0.55)
                ax.plot(r.rel_pct, y, "o", ms=4, color=col, mfc=col if rob else "white", mew=1.0)
            ax.axvline(0, color="k", lw=0.6)
            ax.set_title(prof)
            ax.set_xlabel(T["rel"])
        axes[0][0].set_yticks(list(pos.values()))
        axes[0][0].set_yticklabels(list(pos.keys()))
        h = [Line2D([], [], marker="o", color=C_GREY, ls="", mfc=C_GREY, label=T["robust"]),
             Line2D([], [], marker="o", color=C_GREY, ls="", mfc="white", label=T["second"])]
        fig.suptitle("%s — auth %s" % (proto.upper(), auth), y=1.0, fontsize=10)
        fig.tight_layout()
        fig.legend(handles=h, frameon=False, loc="upper center", bbox_to_anchor=(0.5, 0.0), ncol=2, fontsize=8)
        save(fig, out, "fig3_forest_%s_%s" % (proto, auth))


# ----------------------------------------------------------------------------- F4
def fig_size(c7, out, T):
    d = c7[c7.composante.isin(["total", "taille", "residu"])].copy()
    if d.empty:
        return
    protos = [p for p in ("quic", "tls") if p in set(d.proto)]
    fig, axes = plt.subplots(1, len(protos), figsize=(3.6 * len(protos) + 0.4, 3.0), sharey=True, squeeze=False)
    cols = {"total": "#333333", "taille": C_PAD, "residu": C_ML}
    lab = {"total": T["total"], "taille": T["size"], "residu": T["resid"]}
    for ax, proto in zip(axes[0], protos):
        s = d[d.proto == proto]
        for ci, comp in enumerate(("total", "taille", "residu")):
            for mtu, mk in ((1280, "s"), (1500, "o")):
                t = s[(s.composante == comp) & (s.mtu == mtu)].sort_values("loss_nom")
                if t.empty:
                    continue
                x = np.arange(len(t)) + (ci - 1) * 0.22 + (0.05 if mtu == 1500 else -0.05)
                ax.errorbar(x, t["mean"], yerr=[t["mean"] - t.lo, t.hi - t["mean"]], fmt=mk, ms=4,
                            color=cols[comp], capsize=2, lw=1.0, mfc=cols[comp] if mtu == 1500 else "white")
                ax.set_xticks(np.arange(len(t)))
                ax.set_xticklabels(["%g" % v for v in t.loss_nom])
        ax.axhline(0, color="k", lw=0.6)
        ax.set_title(proto.upper())
        ax.set_xlabel(T["loss"])
    axes[0][0].set_ylabel(T["diff"])
    h = [Line2D([], [], marker="o", color=cols[k], ls="", label=lab[k]) for k in cols]
    h += [Line2D([], [], marker="o", color="k", ls="", label="MTU 1500"),
          Line2D([], [], marker="s", color="k", ls="", mfc="white", label="MTU 1280")]
    axes[0][-1].legend(handles=h, frameon=False, fontsize=7, loc="upper left")
    fig.tight_layout()
    save(fig, out, "fig4_decomposition_taille_calcul")


# ----------------------------------------------------------------------------- F5
def fig_tails(tl, out, T):
    d = tl[(tl.auth == "single") & (tl.level == "L3") & (tl.kem == "x448_mlkem768")]
    if d.empty:
        return
    protos = [p for p in ("quic", "tls") if p in set(d.proto)]
    qs = sorted(d.q.unique())
    fig, axes = plt.subplots(1, len(protos), figsize=(3.5 * len(protos) + 0.4, 3.0), squeeze=False)
    for ax, proto in zip(axes[0], protos):
        for k, prof in enumerate(("ideal", "moderate", "degraded")):
            s = d[(d.proto == proto) & (d.profile == prof)].set_index("q").reindex(qs)
            x = np.arange(len(qs)) + (k - 1) * 0.18
            ax.errorbar(x, s["diff"], yerr=[s["diff"] - s.lo, s.hi - s["diff"]], fmt="o", ms=3.5,
                        color=PROFILE_COL[prof], capsize=2, lw=1.0, label=prof)
        ax.set_xticks(np.arange(len(qs)))
        ax.set_xticklabels(["%g" % q for q in qs])
        ax.axhline(0, color="k", lw=0.6)
        ax.set_xlabel(T["q"])
        ax.set_title(proto.upper())
    axes[0][0].set_ylabel(T["dq"])
    axes[0][0].legend(frameon=False, loc="upper left")
    fig.tight_layout()
    save(fig, out, "fig5_queues_quantiles")


# ----------------------------------------------------------------------------- tableaux
def fmt_ci(m, lo, hi, nd=1):
    return "%.*f [%.*f ; %.*f]" % (nd, m, nd, lo, nd, hi)


def tables(c1, c5, out):
    if c5 is not None:
        d = c5[(c5.proc == "none") & (c5.loss == 0)].copy()
        if not d.empty:
            d["effet_ms"] = [fmt_ci(a, b, c) for a, b, c in zip(d["mean"], d.lo, d.hi)]
            t = d.pivot_table(index=["kem", "rtt"], columns="proto", values="effet_ms", aggfunc="first")
            t.to_csv(os.path.join(out, "tab_effet_vs_rtt.csv"))
            with open(os.path.join(out, "tab_effet_vs_rtt.tex"), "w", encoding="utf-8") as fh:
                tt = t.reset_index()
                tt["rtt"] = tt["rtt"].astype(int)
                fh.write(tt.to_latex(index=False, escape=True,
                         caption="Effet de ML-DSA-65 (ms, IC 95\\,\\% bootstrap par blocs), sans perte.",
                         label="tab:effet-rtt"))
            print("  table: tab_effet_vs_rtt")
    if c1 is not None:
        d = c1[(c1.level == "L3") & (c1.kem == "x448_mlkem768")].copy()
        if not d.empty:
            d["rel"] = [fmt_ci(a, b, c) for a, b, c in zip(d.rel_pct, d.rel_lo, d.rel_hi)]
            d["abs"] = [fmt_ci(a, b, c) for a, b, c in zip(d["mean"], d.lo, d.hi)]
            d["p_holm"] = d.p_holm.map(lambda v: ("%.2f" % v) if v >= 0.01 else ("%.1e" % v))
            d["evidence"] = d.evidence.map(lambda v: "robuste" if str(v) == "ROBUSTE" else "secondaire")
            cols = ["proto", "auth", "profile", "evidence", "abs", "rel", "p_holm"]
            t = d[cols].sort_values(["proto", "auth", "profile"])
            t.to_csv(os.path.join(out, "tab_principal_L3.csv"), index=False)
            with open(os.path.join(out, "tab_principal_L3.tex"), "w", encoding="utf-8") as fh:
                fh.write(t.to_latex(index=False, escape=True,
                         caption="Contraste ML-DSA-65 vs classique, niveau L3, X448+ML-KEM-768 (ms et \\%).",
                         label="tab:principal"))
            print("  table: tab_principal_L3")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="indir", default="analysis_v2/phase2")
    ap.add_argument("--out", default="analysis_v2/figures")
    ap.add_argument("--lang", choices=["fr", "en"], default="fr")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    T = TXT[a.lang]
    setup_style()
    c1 = read(a.indir, "p2_c1_main_contrasts.csv")
    c5 = read(a.indir, "p2_c5_factorial_cells.csv")
    c7 = read(a.indir, "p2_c7_size_decomposition.csv")
    tl = read(a.indir, "p2_q_tails.csv")
    fl = read(a.indir, "flight_timeline_summary.csv")
    if c5 is not None:
        fig_threshold(c5, a.out, T)
    if fl is not None:
        fig_flights(fl, a.out, T)
    if c1 is not None:
        fig_forest(c1, a.out, T)
    if c7 is not None:
        fig_size(c7, a.out, T)
    if tl is not None:
        fig_tails(tl, a.out, T)
    tables(c1, c5, a.out)
    print("Terminé ->", a.out)


if __name__ == "__main__":
    main()
