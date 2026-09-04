# position_sensitivity.py
import os, re, glob
import numpy as np
import pandas as pd

BASE = "captures"
KNOWN_SIG_ALGS = ["ed25519", "mldsa44", "secp384r1", "mldsa65",
                   "secp521r1", "mldsa87"]


def parse_manifest(path):
    order = {}
    in_order = False
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line == "execution_order:":
                in_order = True
                continue
            if in_order:
                m = re.match(r"(\d+)\)\s+(\S+)\|(\S+)", line)
                if m:
                    pos, sig, kem = m.groups()
                    order[f"{sig}|{kem}"] = int(pos)
                elif line.startswith("timestamp_end"):
                    break
    return order


rows = []
warnings = []

for csv_path in glob.glob(os.path.join(BASE, "*", "*", "*", "csv", "handshake_*.csv")):
    parts = csv_path.split(os.sep)
    _, protocol, auth_mode, network, _, filename = parts[-6:]

    base = filename[len("handshake_"):-len(".csv")]
    prefix = f"{protocol}_{auth_mode}_"
    if not base.startswith(prefix):
        warnings.append(f"prefix mismatch: {filename}")
        continue
    rest = base[len(prefix):]

    m = re.search(r"_block(\d+)of(\d+)$", rest)
    if not m:
        warnings.append(f"no block suffix: {filename}")
        continue
    block_index, n_blocks = int(m.group(1)), int(m.group(2))
    rest = rest[:m.start()]

    if not rest.endswith(network):
        warnings.append(f"network suffix mismatch: {filename}")
        continue
    rest = rest[:-len(network)].rstrip("_")

    sig_alg = None
    for cand in KNOWN_SIG_ALGS:
        if rest == cand or rest.startswith(cand + "_"):
            sig_alg = cand
            break
    if sig_alg is None:
        warnings.append(f"unrecognized sig_alg: {filename}")
        continue
    kem = rest[len(sig_alg):].lstrip("_")

    config_id = f"{sig_alg}|{kem}"
    cell_id = f"{protocol}|{auth_mode}|{network}"

    manifest_glob = os.path.join(
        BASE, protocol, auth_mode, network,
        f"block_manifest_block{block_index}of{n_blocks}_seed*.log"
    )
    manifests = glob.glob(manifest_glob)
    if not manifests:
        warnings.append(f"no manifest for {csv_path}")
        continue
    order = parse_manifest(manifests[0])
    sweep_position = order.get(config_id)
    if sweep_position is None:
        warnings.append(f"{config_id} not in manifest {manifests[0]}")
        continue

    df = pd.read_csv(csv_path)
    df = df[df["success"] == 1].copy()
    df["config_id"] = config_id
    df["cell_id"] = cell_id
    df["sweep_position"] = sweep_position
    rows.append(df[["handshake_duration_ms", "config_id", "cell_id",
                     "sweep_position"]])

if warnings:
    print(f"{len(warnings)} warnings (showing first 10):")
    for w in warnings[:10]:
        print("  ", w)

full = pd.concat(rows, ignore_index=True)

# ---- Step 1: collapse to the 630 configuration-cell MEANS -----------------
# Corrected unit of analysis: one row per (config_id, cell_id), not one row
# per individual handshake. sweep_position is constant within a
# (config_id, cell_id) group by construction (fixed sweep order per cell).
cell_means = (
    full.groupby(["config_id", "cell_id", "sweep_position"], as_index=False)
        ["handshake_duration_ms"].mean()
)
cell_means.to_csv("configuration_cell_means.csv", index=False)
print(f"\nCollapsed to {len(cell_means)} configuration-cell means "
      f"({cell_means.config_id.nunique()} configs x "
      f"{cell_means.cell_id.nunique()} cells)")

# ---- Step 2: regression on the 630 means, config + cell fixed effects,
#              cluster-robust SEs clustered by cell_id (15 clusters) -------
y = cell_means["handshake_duration_ms"].astype(float).values
X = pd.get_dummies(cell_means[["config_id", "cell_id"]].astype(str),
                    drop_first=True)
X.insert(0, "intercept", 1.0)
X["sweep_position"] = cell_means["sweep_position"].astype(float).values
X = X.astype(float)
cluster_ids = cell_means["cell_id"].values

n, k = X.shape
G = len(np.unique(cluster_ids))
Xm = X.values

XtX_inv = np.linalg.pinv(Xm.T @ Xm)
beta = XtX_inv @ Xm.T @ y
resid = y - Xm @ beta

# Cluster-robust (CR1) sandwich estimator, clustered by sweep cell
meat = np.zeros((k, k))
for cid in np.unique(cluster_ids):
    idx = cluster_ids == cid
    Xg = Xm[idx]
    ug = resid[idx]
    score_g = Xg.T @ ug
    meat += np.outer(score_g, score_g)

# Standard small-cluster correction (Stata/Cameron-Miller default)
correction = (G / (G - 1)) * ((n - 1) / (n - k))
V_cluster = correction * XtX_inv @ meat @ XtX_inv
se_cluster = np.sqrt(np.clip(np.diag(V_cluster), 0, None))

pos_idx = list(X.columns).index("sweep_position")
coef = beta[pos_idx]
se = se_cluster[pos_idx]

# t-distribution with G-1 dof, standard for cluster-robust inference
# with few clusters (Cameron & Miller, 2015)
try:
    from scipy import stats as _stats
    dof = G - 1
    t_stat = coef / se
    p_val = 2 * (1 - _stats.t.cdf(abs(t_stat), dof))
    crit = _stats.t.ppf(0.975, dof)
except ImportError:
    from math import erf, sqrt
    t_stat = coef / se
    p_val = 2 * (1 - 0.5 * (1 + erf(abs(t_stat) / sqrt(2))))
    crit = 1.96
    print("NOTE: scipy unavailable, using normal approximation "
          "instead of t(G-1) — install scipy for the exact reported CI.")

ci_low, ci_high = coef - crit * se, coef + crit * se

print(f"\nSweep-position effect (630 configuration-cell means, "
      f"cluster-robust by {G} sweep cells):")
print(f"  coef = {coef:.4f} ms/rank")
print(f"  cluster-robust SE = {se:.4f}")
print(f"  95% CI = [{ci_low:.2f}, {ci_high:.2f}]")
print(f"  p-value = {p_val:.4f}")

pd.DataFrame([{
    "coef_ms_per_rank": coef, "cluster_robust_se": se,
    "ci_low": ci_low, "ci_high": ci_high, "p_value": p_val,
    "n_obs": n, "n_clusters": G, "n_configs": cell_means.config_id.nunique()
}]).to_csv("position_sensitivity_results.csv", index=False)
print("\nSaved position_sensitivity_results.csv "
      "and configuration_cell_means.csv")
