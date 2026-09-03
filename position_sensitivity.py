# position_sensitivity.py
import os
import re
import glob
from math import erf, sqrt

import numpy as np
import pandas as pd

BASE = "captures"
KNOWN_SIG_ALGS = ["ed25519", "mldsa44", "secp384r1", "mldsa65",
                   "secp521r1", "mldsa87"]


def parse_manifest(path):
    """Return dict: 'sig|kem' -> sweep_position (1-indexed int)."""
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
                     "sweep_position", "block_index", "n_blocks"]])

if warnings:
    print(f"{len(warnings)} warnings (showing first 10):")
    for w in warnings[:10]:
        print("  ", w)

full = pd.concat(rows, ignore_index=True)
full.to_csv("all_runs_with_position.csv", index=False)
print(f"\nBuilt all_runs_with_position.csv: {len(full)} rows, "
      f"{full.cell_id.nunique()} cells, {full.config_id.nunique()} configs")

# ---- Pooled regression across ALL cells (fixes the collinearity issue) ----
# handshake_duration_ms ~ config_id (fixed effect) + cell_id (fixed effect)
#                        + sweep_position (continuous, the effect of interest)
# This works because a given config_id occupies DIFFERENT sweep_position
# values across the ~630 independently-seeded cells, breaking the
# within-cell collinearity between config_id and sweep_position.

sub = full.copy()

# To keep the design matrix tractable, drop the rarest configs/cells if needed
# (not expected to be necessary here: 42 configs x ~630 cells is standard).
X = pd.get_dummies(sub[["config_id", "cell_id"]].astype(str), drop_first=True)
X.insert(0, "intercept", 1.0)
X["sweep_position"] = sub["sweep_position"].astype(float).values
X = X.astype(float)
y = sub["handshake_duration_ms"].astype(float).values

print(f"\nDesign matrix: {X.shape[0]} rows x {X.shape[1]} columns")

XtX_inv = np.linalg.pinv(X.values.T @ X.values)
beta = XtX_inv @ X.values.T @ y
resid = y - X.values @ beta
n, k = X.shape
dof = max(n - k, 1)
sigma2 = (resid @ resid) / dof
se = np.sqrt(np.clip(np.diag(XtX_inv) * sigma2, 0, None))

pos_idx = list(X.columns).index("sweep_position")
coef = beta[pos_idx]
coef_se = se[pos_idx]
t_stat = coef / coef_se if coef_se > 0 else np.nan
p_approx = (2 * (1 - 0.5 * (1 + erf(abs(t_stat) / sqrt(2))))
            if not np.isnan(t_stat) else np.nan)

print(f"\nPooled sweep_position effect: {coef:.4f} ms per rank "
      f"(SE={coef_se:.4f}), t={t_stat:.2f}, p≈{p_approx:.4g}")
print(f"Interpretation: over the full 1-42 rank range, this implies an "
      f"average drift of {coef*41:.2f} ms between the first and last "
      f"executed configuration, after controlling for configuration "
      f"identity and cell (protocol/auth/network) identity.")

pd.DataFrame([{
    "coef_ms_per_rank": coef, "se": coef_se, "t_stat": t_stat,
    "p_approx": p_approx, "n_obs": n, "n_configs": sub.config_id.nunique(),
    "n_cells": sub.cell_id.nunique(),
    "implied_range_effect_ms": coef * 41
}]).to_csv("position_sensitivity_results.csv", index=False)
print("\nSaved position_sensitivity_results.csv")
