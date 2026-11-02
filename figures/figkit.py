#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""figkit.py -- infrastructure commune des figures : registre, sorties SANS COLLISION, empreintes, statistiques de blocs.

PRINCIPES
  * Une figure = un identifiant unique (campagne, FID). Deux figures ne peuvent pas partager le meme identifiant (erreur a l'import).
  * Arborescence de sortie (OUT = figures_out par defaut) :
        OUT/<campagne>/<FID>_<slug>/<variante>/{figure.pdf, figure.png, data.csv, meta.json}
        OUT/<campagne>/<FID>_<slug>/_FIGURE.json          (empreinte, liste des variantes, statut)
        OUT/_archive/<campagne>/<FID>_<slug>__<UTC>/      (anciennes versions : jamais supprimees)
        OUT/INDEX.csv                                    (reconstruit a chaque execution)
    Campagnes : v2, v3_resume, v3_comp, v3_load, pont. Un bras ne peut jamais ecrire chez un autre.
  * Ecriture ATOMIQUE : tout est construit dans OUT/.tmp/..., puis l'ancien dossier (s'il existe et que les entrees ont change)
    est ARCHIVE, puis le nouveau est renomme en place. Une erreur en cours de route laisse l'ancien resultat intact.
  * Empreinte = sha256(contenu des fichiers d'entree + code de la figure + parametres). Entrees identiques -> la figure est
    declaree "a jour" et n'est pas regeneree (sauf --force, qui archive quand meme l'ancienne version).
  * Un verrou (OUT/.lock) interdit deux executions simultanees sur le meme dossier de sortie.
  * data.csv contient EXACTEMENT les valeurs tracees (ce que l'article cite doit pouvoir etre relu dans ce fichier).
"""
from __future__ import annotations
import datetime as dt
import fcntl
import hashlib
import json
import os
import platform
import re
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt          # noqa: E402
import plot_style as PS                  # noqa: E402,F401  (applique les rcParams)

CAMPAIGNS = ("v2", "v3_resume", "v3_comp", "v3_load", "pont")
BOOT_B = 2000
BOOT_SEED = 12345
FIGKIT_VERSION = "1.0"

# ═════════════════════════════════════════════════════════════════════════════════════════════════════════
# Registre
# ═════════════════════════════════════════════════════════════════════════════════════════════════════════
@dataclass
class Spec:
    campaign: str
    fid: str
    slug: str
    inputs: list
    fn: object
    module_file: str
    title: str = ""

    @property
    def dirname(self):
        return f"{self.fid}_{self.slug}"


REGISTRY: dict = {}


def figure(campaign, fid, slug, inputs, title=""):
    if campaign not in CAMPAIGNS:
        raise ValueError(f"campagne inconnue {campaign!r} (attendu : {CAMPAIGNS})")
    if not re.fullmatch(r"[A-Za-z0-9]+", fid) or not re.fullmatch(r"[a-z0-9_]+", slug):
        raise ValueError(f"identifiant/slug invalide : {fid!r} {slug!r}")

    def deco(fn):
        key = (campaign, fid)
        if key in REGISTRY:
            raise RuntimeError(f"COLLISION d'identifiant de figure : {key} deja declare par {REGISTRY[key].fn.__name__}")
        for (c, f), s in REGISTRY.items():
            if c == campaign and s.slug == slug:
                raise RuntimeError(f"COLLISION de dossier : {campaign}/{slug} deja utilise par {f}")
        REGISTRY[key] = Spec(campaign, fid, slug, list(inputs), fn, sys.modules[fn.__module__].__file__, title)
        return fn
    return deco


@dataclass
class Variant:
    key: str
    fig: object
    data: pd.DataFrame
    note: str = ""


# ═════════════════════════════════════════════════════════════════════════════════════════════════════════
# Entrees (chargement paresseux + empreintes)
# ═════════════════════════════════════════════════════════════════════════════════════════════════════════
def sha256_file(path, chunk=1 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def find_one(root, name):
    """Cherche `name` (nom de fichier exact) sous root ; refuse l'ambiguite plutot que de choisir au hasard."""
    root = Path(root)
    hits = sorted(p for p in root.rglob(name) if "_archive" not in p.parts)
    if not hits:
        return None
    if len(hits) > 1:
        raise RuntimeError(f"{name} trouve {len(hits)} fois sous {root} : {[str(h) for h in hits]} -- precisez --v2-dir/--v3-dir")
    return hits[0]


# cle d'entree -> (option de repertoire, nom de fichier)
INPUT_FILES = {
    "v2_conn": ("v2_dir", "conn.csv.gz"),
    "v2_flight": ("v2_dir", "flight_timeline_summary.csv"),
    "v2_kpred": ("v2_dir", "p3_k_pred_vs_obs.csv"),
    "v3_conn": ("v3_dir", "p6_connexions.csv.gz"),
    "v3_load": ("v3_dir", "p6_load_niveaux.csv"),
    "v3_bridge": ("v3_dir", "p6_pont_v2.csv"),
}


class Ctx:
    def __init__(self, dirs: dict):
        self.dirs = dirs
        self._paths, self._hash, self._df = {}, {}, {}

    def path(self, key):
        if key not in self._paths:
            opt, name = INPUT_FILES[key]
            d = self.dirs.get(opt)
            self._paths[key] = find_one(d, name) if d else None
        return self._paths[key]

    def available(self, key):
        return self.path(key) is not None

    def sha(self, key):
        if key not in self._hash:
            self._hash[key] = sha256_file(self.path(key))
        return self._hash[key]

    def df(self, key, **kw):
        if key not in self._df:
            p = self.path(key)
            if p is None:
                raise FileNotFoundError(f"entree {key!r} ({INPUT_FILES[key][1]}) introuvable")
            self._df[key] = pd.read_csv(p, low_memory=False, **kw)
        return self._df[key]

    def fingerprint(self, spec: Spec):
        h = hashlib.sha256()
        for k in sorted(spec.inputs):
            h.update(k.encode()); h.update(self.sha(k).encode())
        for f in (HERE / "figkit.py", Path(spec.module_file), HERE / "plot_style.py"):
            h.update(sha256_file(f).encode())
        h.update(f"B={BOOT_B};seed={BOOT_SEED};v={FIGKIT_VERSION}".encode())
        return h.hexdigest()

    def inputs_meta(self, spec: Spec):
        return {k: dict(path=str(self.path(k)), sha256=self.sha(k), bytes=os.path.getsize(self.path(k))) for k in sorted(spec.inputs)}


# ═════════════════════════════════════════════════════════════════════════════════════════════════════════
# Ecriture sans collision
# ═════════════════════════════════════════════════════════════════════════════════════════════════════════
def utc_stamp():
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


class OutDir:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock = open(self.root / ".lock", "w")
        try:
            fcntl.flock(self._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise SystemExit(f"❌ {self.root} est deja utilise par une autre execution (verrou .lock).")
        self._lock.write(f"pid={os.getpid()} {utc_stamp()}\n"); self._lock.flush()

    def target(self, spec):
        return self.root / spec.campaign / spec.dirname

    def status(self, spec, fingerprint):
        meta = self.target(spec) / "_FIGURE.json"
        if not meta.exists():
            return "nouvelle"
        try:
            m = json.loads(meta.read_text())
        except Exception:
            return "modifiee"
        if m.get("status") == "complete" and m.get("fingerprint") == fingerprint:
            return "a_jour"
        return "modifiee"

    def write_figure(self, spec, variants, fingerprint, inputs_meta, force=False):
        """Construit dans .tmp, archive l'ancienne version si elle existe, puis renomme. Retourne (statut, dossier)."""
        st = self.status(spec, fingerprint)
        if st == "a_jour" and not force:
            return "a_jour", self.target(spec)
        keys = [v.key for v in variants]
        if len(set(keys)) != len(keys):
            raise RuntimeError(f"{spec.campaign}/{spec.fid} : cles de variantes dupliquees {sorted(k for k in keys if keys.count(k) > 1)}")
        tmp = self.root / ".tmp" / f"{spec.campaign}_{spec.dirname}_{os.getpid()}"
        if tmp.exists():
            shutil.rmtree(tmp)
        tmp.mkdir(parents=True)
        try:
            for v in variants:
                if not re.fullmatch(r"[A-Za-z0-9_.\-]+", v.key):
                    raise ValueError(f"cle de variante invalide {v.key!r}")
                vd = tmp / v.key
                vd.mkdir()
                v.fig.savefig(vd / "figure.pdf", bbox_inches="tight")
                v.fig.savefig(vd / "figure.png", bbox_inches="tight", dpi=300)
                plt.close(v.fig)
                v.data.to_csv(vd / "data.csv", index=False)
                (vd / "meta.json").write_text(json.dumps(dict(
                    campaign=spec.campaign, fid=spec.fid, slug=spec.slug, variant=v.key, note=v.note,
                    n_data_rows=int(len(v.data)), data_columns=list(v.data.columns),
                    inputs=inputs_meta, fingerprint=fingerprint, created_utc=utc_stamp(),
                    versions=dict(python=platform.python_version(), numpy=np.__version__, pandas=pd.__version__,
                                  matplotlib=matplotlib.__version__),
                    bootstrap=dict(B=BOOT_B, seed=BOOT_SEED, unit="blocs entiers, percentile 2.5/97.5"),
                ), indent=2, ensure_ascii=False))
            (tmp / "_FIGURE.json").write_text(json.dumps(dict(
                status="complete", campaign=spec.campaign, fid=spec.fid, slug=spec.slug, title=spec.title,
                fingerprint=fingerprint, variants=keys, created_utc=utc_stamp(), inputs=inputs_meta), indent=2, ensure_ascii=False))
        except BaseException:
            shutil.rmtree(tmp, ignore_errors=True)
            raise
        tgt = self.target(spec)
        tgt.parent.mkdir(parents=True, exist_ok=True)
        archived = None
        if tgt.exists():
            archived = self.root / "_archive" / spec.campaign / f"{spec.dirname}__{utc_stamp()}"
            archived.parent.mkdir(parents=True, exist_ok=True)
            os.replace(tgt, archived)                 # l'ancienne version est CONSERVEE
        os.replace(tmp, tgt)
        return ("regeneree" if archived else "nouvelle"), tgt

    def write_index(self):
        rows = []
        for fj in sorted(self.root.glob("*/*/_FIGURE.json")):
            if fj.parts[-3] in ("_archive", ".tmp"):
                continue
            m = json.loads(fj.read_text())
            for v in m.get("variants", []):
                d = fj.parent / v
                rows.append(dict(campaign=m["campaign"], fid=m["fid"], slug=m["slug"], variant=v,
                                 pdf=str((d / "figure.pdf").relative_to(self.root)), png=str((d / "figure.png").relative_to(self.root)),
                                 data=str((d / "data.csv").relative_to(self.root)), created_utc=m["created_utc"],
                                 fingerprint=m["fingerprint"][:12]))
        idx = pd.DataFrame(rows)
        idx.to_csv(self.root / "INDEX.csv", index=False)
        return idx


# ═════════════════════════════════════════════════════════════════════════════════════════════════════════
# Statistiques : l'UNITE d'inference est le BLOC (comme scripts 01-13)
# ═════════════════════════════════════════════════════════════════════════════════════════════════════════
def rng_fixed():
    return np.random.default_rng(BOOT_SEED)


def boot_blocks(x, B=None, rng=None, stat=np.nanmedian):
    """x : valeurs PAR BLOC (une par bloc). Retourne (estimation, lo, hi) : mediane des medianes de bloc, IC95 % percentile."""
    x = np.asarray(x, float)
    x = x[np.isfinite(x)]
    if len(x) == 0:
        return np.nan, np.nan, np.nan
    est = float(stat(x))
    if len(x) < 3:
        return est, np.nan, np.nan
    B = B or BOOT_B
    rng = rng or rng_fixed()
    idx = rng.integers(0, len(x), size=(B, len(x)))
    s = stat(x[idx], axis=1)
    return est, float(np.percentile(s, 2.5)), float(np.percentile(s, 97.5))


def block_medians(df, keys, val):
    """Mediane par (keys, bloc) -> DataFrame large : index=bloc, colonnes=keys."""
    g = df.groupby(list(keys) + ["block"])[val].median().unstack(list(keys))
    return g


def paired_block_stat(df, split, a, b, keys, val, how="diff", rng=None):
    """Pour chaque combinaison de `keys` : statistique appariee PAR BLOC entre df[split]==a et df[split]==b
       (how='diff' -> med(a)-med(b) ; 'ratio' -> med(a)/med(b)), puis bootstrap des blocs.
       Retourne un DataFrame (keys..., est, lo, hi, n_blocks)."""
    rng = rng or rng_fixed()
    keys = list(keys)
    m = df.groupby(keys + [split, "block"])[val].median().reset_index()
    rows = []
    for k, g in m.groupby(keys):
        k = k if isinstance(k, tuple) else (k,)
        pa = g[g[split] == a].set_index("block")[val]
        pb = g[g[split] == b].set_index("block")[val]
        common = pa.index.intersection(pb.index)
        if len(common) == 0:
            continue
        x = (pa[common] - pb[common]) if how == "diff" else (pa[common] / pb[common])
        est, lo, hi = boot_blocks(x.to_numpy(), rng=rng)
        rows.append(dict(zip(keys, k), est=est, lo=lo, hi=hi, n_blocks=len(common)))
    return pd.DataFrame(rows)


def clopper_pearson(k, n, alpha=0.05):
    from scipy.stats import beta
    if n == 0:
        return np.nan, np.nan
    lo = 0.0 if k == 0 else beta.ppf(alpha / 2, k, n - k + 1)
    hi = 1.0 if k == n else beta.ppf(1 - alpha / 2, k + 1, n - k)
    return float(lo), float(hi)


def panel_letter(ax, letter, x=-0.02, y=1.06):
    ax.text(x, y, f"({letter})", transform=ax.transAxes, fontsize=8.5, fontweight="bold", va="bottom")


def kem_family_of(kem):
    kc = PS.derive_kem_class(kem)
    return PS.classify_kem_family(kc, kem)
