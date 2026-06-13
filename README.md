# Post-Quantum TLS 1.3 and QUIC Handshakes under Constrained Networks: Combining ML-DSA with ML-KEM and HQC


>
> David Rive Tolokoum, Yve Bruno Mbezoa, Hervé Talé Kalachi.
> *"Post-Quantum TLS 1.3 and QUIC Handshakes under Constrained Networks: Combining ML-DSA with ML-KEM and HQC"*
> Submitted to *Computer Networks*, 2026.

## 1. Overview

This repository contains the **complete artifact** for a large-scale experimental study evaluating the combined impact of **ML-DSA** signatures with **ML-KEM** and **HQC** key encapsulation mechanisms in **TLS 1.3** and **QUIC** under network conditions calibrated from real measurements at ENSP Yaoundé (Orange Cameroon, April 2026).

### Measurement Scale

| Experiment Type | Measurements | Details |
|-----------------|-------------|---------|
| Full handshakes (Study 1 + 2) | **312,000** | N = 500 per configuration |
| Session resumption | Reported separately | N = 500 per scenario |
| Concurrent load | Reported separately | 10 / 50 / 100 clients |
| KEM families | 2 | ML-KEM (lattice) + HQC (code-based) |
| Security tiers | 3 | NIST Level I, III, V |
| Protocols | 2 | TLS 1.3 + QUIC |
| Network scenarios | 6 | Ideal, Local YDE, Backbone, Degraded, GE-stable, GE-unstable |

### Central Thesis

Post-quantum protocol performance **cannot be predicted from primitive micro-benchmarks alone**. Once post-quantum signatures are introduced, certificate size, packetization, retransmission behavior, and transport architecture can change the relative ranking of TLS and QUIC.

---

## 2. Key Findings

| Finding | Description |
|---------|-------------|
| **AVX2 Performance Paradox** | ML-DSA reduces TLS median by up to 75.7% vs. ECDSA under ideal conditions on x86-64/AVX2 |
| **Protocol Reversal** | TLS becomes faster than QUIC for all Tier 3 KEMs with ML-DSA65 at Local YDE (35 ms / 2% loss) |
| **Super-additivity in TLS** | 7/10 migration paths are super-additive in TLS; QUIC shows sub-additive behavior (6/10) |
| **HQC Bottleneck Inversion** | HQC dominates handshake cost in QUIC, making the signature choice nearly neutral under ideal conditions |
| **Gilbert-Elliott Catastrophe** | ML-DSA87 + P-521 + HQC-256 reaches 18,595 ms mean (p99 > 25 s) under GE unstable burst loss |

---

## 3. Repository Structure

```
.mldsa-mlkem-hqc-tls-quic-constrained-performance/
│
├── 0-docker/                                      # Docker environment
│   ├── Dockerfile                                 # OpenSSL 3.4.2-dev + liboqs + oqsprovider
│   └── scripts/
│       ├── doCert.sh                              # X.509 certificate generation
│       ├── perftestServerTlsQuic.sh               # TLS/QUIC server-side test runner
│       ├── perftestClientTlsQuic.sh               # TLS/QUIC client-side test runner
│       ├── perftestServerClientTlsQuic.sh         # Combined server + client launcher
│       ├── perftestClientConcurrent.sh            # Concurrent-load client
│       ├── perftestClientResumptionBatch.sh       # Session resumption client
│       ├── perftestServerCompress.sh              # RFC 8879 compression server
│       └── perftestClientCompress.sh              # RFC 8879 compression client
│
├── mldsa-mlkem-study1/                            # Study 1 — ML-DSA × ML-KEM
│   ├── TLS/
│   │   ├── csv/
│   │   │   ├── ed25519_tls_ideal.csv
│   │   │   ├── ed25519_tls_africa_local.csv
│   │   │   ├── ed25519_tls_africa_backbone.csv
│   │   │   └── ge/                              # Gilbert-Elliott CSVs
│   │   ├── log/
│   │   │   ├── TLS_pq_ideal.log
│   │   │   ├── TLS_pq_africa_local.log
│   │   │   ├── TLS_pq_africa_backbone.log
│   │   │   ├── TLS_pq_africa_degraded.log
│   │   │   └── ge/
│   │   │       ├── TLS_mlkem_ge_stable.log
│   │   │       └── TLS_mlkem_ge_unstable.log
│   │   └── plots/                               # Per-signature raw violin plots
│   │       ├── ed25519_tls_ideal.pdf
│   │       ├── ed25519_tls_ideal.svg
│   │       ├── ed25519_tls_africa_local.pdf
│   │       ├── ed25519_tls_africa_local.svg
│   ├── QUIC/
│   │   ├── csv/
│   │   │   ├── ed25519_quic_ideal.csv
│   │   │   ├── ed25519_quic_africa_local.csv
│   │   │   ├── ed25519_quic_africa_backbone.csv
│   │   │   └── ge/
│   │   ├── log/
│   │   │   ├── QUIC_pq_ideal.log
│   │   │   ├── QUIC_pq_africa_local.log
│   │   │   ├── QUIC_pq_africa_backbone.log
│   │   │   ├── QUIC_pq_africa_degraded.log
│   │   │   └── ge/
│   │   └── plots/
│   │       ├── ed25519_quic_ideal.pdf
│   │       ├── ed25519_quic_ideal.svg
│   │       ├── ed25519_quic_africa_local.pdf
│   ├── Analysis/
│   │   ├── analysis_output.txt                  # Ideal-condition statistics
│   │   ├── analysis_africa_output.txt           # Constrained-network statistics
│   │   └── analysis_ge_output.txt               # Gilbert-Elliott statistics
│   ├── result_concurrent/
│   │   ├── tls_c10_none_l0_d0_20260603_090144/
│   │   ├── tls_c10_simple_l2_d35_20260603_090300/
│   │   ├── tls_c10_simple_l10_d200_20260603_090746/
│   ├── scripts/
│   │   ├── analysis_pq_signatures.py            # Ideal-condition analysis
│   │   ├── analysis_africa_scenarios.py         # Constrained-network analysis
│   │   ├── analysis_ge.py                       # Gilbert-Elliott analysis
│   │   ├── analyse_concurrent.py                # Concurrent-load analysis
│   │   ├── compare_concurrent.py                # TLS vs. QUIC concurrent comparison
│   │   ├── plot_pq_signatures.py                # Ideal violin / heatmap / super-add figures
│   │   ├── plot_africa_scenarios.py             # Delta-evolution and protocol-reversal figures
│   │   ├── plot_ge_violin.py                    # GE burst-loss violin plots
│   │   └── plot_violins_phase5.py               # Per-signature raw violin plots
│   │   └── handshakeProcess.py               
│   └── plots/                                   # Publication figures — Study 1
│       ├── fig1a_level1_violin.pdf
│       ├── fig1a_level1_violin.png
│       ├── fig1b_level3_violin.pdf
│       └── ge_violin/
│           ├── fig_GE_stable_L1.pdf
│           ├── fig_GE_stable_L1.png
│
├── mldsa-hqc-study2/                            # Study 2 — ML-DSA × HQC
│   ├── TLS/
│   │   ├── csv/
│   │   │   ├── ed25519_tls_ideal.csv
│   │   │   ├── ed25519_tls_africa_local.csv
│   │   │   ├── ed25519_tls_africa_backbone.csv
│   │   │   └── ge/
│   │   ├── log/
│   │   │   ├── TLS_hqc_ideal.log
│   │   │   ├── TLS_hqc_africa_local.log
│   │   │   ├── TLS_hqc_africa_backbone.log
│   │   │   ├── TLS_hqc_africa_degraded.log
│   │   │   └── ge/
│   │   └── plots/
│   │       ├── ed25519_tls_ideal.pdf
│   │       ├── ed25519_tls_ideal.svg
│   │       ├── ed25519_tls_africa_local.pdf
│   ├── QUIC/
│   │   ├── csv/
│   │   │   ├── ed25519_quic_ideal.csv
│   │   │   ├── ed25519_quic_africa_local.csv
│   │   │   ├── ed25519_quic_africa_backbone.csv
│   │   │   ├── ed25519_quic_africa_degraded.csv
│   │   │   └── ge/
│   │   ├── log/
│   │   │   ├── QUIC_hqc_ideal.log
│   │   │   ├── QUIC_hqc_africa_local.log
│   │   │   ├── QUIC_hqc_africa_backbone.log
│   │   │   ├── QUIC_hqc_africa_degraded.log
│   │   │   └── ge/
│   │   │       ├── QUIC_hqc_ge_stable.log
│   │   │       └── QUIC_hqc_ge_unstable.log
│   │   └── plots/
│   │       ├── ed25519_quic_ideal.pdf
│   │       ├── ed25519_quic_ideal.svg
│   │       ├── ed25519_quic_africa_local.pdf
│   ├── Analysis/
│   │   ├── analysis_hqc_output.txt
│   │   ├── analysis_hqc_africa_output.txt
│   │   └── analysis_ge_output.txt
│   ├── result_concurrent/
│   │   ├── tls_c10_none_l0_d0_20260603_215822/
│   │   ├── tls_c10_none_l2_d35_20260603_220259/
│   │   ├── tls_c10_none_l10_d200_20260603_220705/
│   ├── scripts/
│   │   ├── analysis_hqc.py                      # Ideal-condition analysis
│   │   ├── analysis_hqc_africa.py               # Constrained-network analysis
│   │   ├── analysis_ge.py                       # Gilbert-Elliott analysis
│   │   ├── analyse_concurrent.py                # Concurrent-load analysis
│   │   ├── compare_concurrent.py                # TLS vs. QUIC concurrent comparison
│   │   ├── handshakeProcess.py                  # Raw log parsing utilities
│   │   ├── plot_hqc_ideal.py                    # HQC ideal-condition figures
│   │   ├── plot_hqc_africa.py                   # HQC constrained-network figures
│   │   └── plot_violins_phase6.py               # Per-signature HQC violin plots
│   └── plots/                                   # Publication figures — Study 2
│       ├── fig1a_level1_hqc_violin.pdf
│       ├── fig1a_level1_hqc_violin.png
│       ├── fig1b_level3_hqc_violin.pdf
│
├── resumption_study/
│   ├── scripts/
│   │   ├── Launcherv3_resumption_batch.sh
│   │   ├── run_resumption_batch_matrix.sh
│   │   └── analyse_resumption_batch.py
│   ├── results/
│   │   ├── tls_none_l0_d0_20260604_211209/
│   │   ├── tls_none_l0_d0_20260604_212203/
│   └── analysis/
│       ├── comparison_resumption_batch.csv
│       ├── comparison_resumption_batch_mldsa65_mlkem768.pdf
│       ├── comparison_resumption_batch_mldsa65_mlkem768.png
│       ├── comparison_resumption_batch_mldsa65_mlkem768.svg
│
├── compression_study/
│   ├── scripts/
│   │   ├── Launcherv3_compress.sh
│   │   ├── run_compress_matrix.sh
│   │   └── analyse_compress.py
│   ├── results/
│   │   └── tls_none_l0_d0_20260608_153650/
│   └── analysis/
├── microbench/
│   ├── microbench_results.txt                           
│
├── Launcherv3_pq_mlkem.sh                     # Study 1 full matrix orchestrator
├── Launcherv3_pq_hqc.sh                       # Study 2 full matrix orchestrator
├── Launcherv3_mlkem_concurrent.sh             # ML-KEM concurrent-load orchestrator
├── Launcherv3_hqc_concurrent.sh               # HQC concurrent-load orchestrator
└── run_concurrent_matrix.sh                   # Run all concurrent experiments
```

---

## 4. Hardware and Software Requirements

### Hardware (as used in the paper)

| Component | Specification |
|-----------|---------------|
| Machine | HP ProBook 640 G4 |
| CPU | Intel Core i5-8250U @ 1.60–3.40 GHz |
| ISA extensions | **AVX2** (required for ML-DSA native performance) |
| Cores | 4 physical / 8 logical threads |
| RAM | 24 GB DDR4 |
| OS | Ubuntu 24.04 LTS |
| Docker | 26.1+ |
| Disk | ≥ 20 GB free (for Docker image + raw data) |

> **Note on AVX2:** The AVX2 performance paradox observed in this study is **architecture-specific**. Results on ARM, embedded, or mobile platforms will differ. Cross-architecture validation is identified as future work.

### Software Stack

| Component | Version | Role |
|-----------|---------|------|
| OpenSSL | 3.4.2-dev | TLS 1.3 stack |
| liboqs | 0.12.0 | Post-quantum primitives |
| oqsprovider | 0.8.0 | OpenSSL provider for PQ algorithms |
| MsQuic | — | QUIC protocol stack |
| tc / netem | Linux kernel | Network impairment injection |
| Python | ≥ 3.10 | Analysis and figure generation |
| Docker | ≥ 26.1 | Reproducible container environment |

---

## 5. Installation and Environment Setup

### Step 1: Clone the repository

```bash
git clone https://github.com/TOLOKOUM/mldsa-mlkem-hqc-tls-quic-constrained-performance.git
cd mldsa-mlkem-hqc-tls-quic-constrained-performance
```

### Step 2: Install system dependencies

```bash
sudo apt update
sudo apt install -y \
    docker.io \
    git \
    iproute2 \          # provides tc/netem
    python3 \
    python3-pip \
    python3-venv

# Add current user to docker group (log out/in to take effect)
sudo usermod -aG docker $USER
```

### Step 3: Install Python dependencies

```bash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install \
    numpy \
    scipy \
    pandas \
    matplotlib \
    seaborn
```

### Step 4: Build the Docker image

```bash
cd docker
docker build -t uma-tls-quic-pq-34 .
cd ..
```

> **Build time:** approximately 15–25 minutes depending on network speed. The image compiles OpenSSL 3.4.2-dev, liboqs 0.12.0, oqsprovider 0.8.0, and MsQuic from source.

### Step 5: Verify the installation

```bash
# Check OpenSSL version inside the container
docker run --rm uma-tls-quic-pq-34 openssl version
# Expected: OpenSSL 3.4.2-dev ...

# List available post-quantum algorithms
docker run --rm uma-tls-quic-pq-34 \
    openssl list -signature-algorithms -provider oqsprovider \
    | grep -i "mldsa\|hqc"
```

---

## 6. Network Scenarios

All scenarios are calibrated from field measurements conducted at **ENSP Yaoundé** using **Orange Cameroon** infrastructure in **April 2026**.

### 6.1 Uniform-Loss Scenarios (tc/netem)

| Scenario ID | Label | RTT | Loss | Calibration |
|-------------|-------|-----|------|-------------|
| `ideal` | Ideal | 0 ms | 0% | Docker localhost, no impairment |
| `local_yde` | Local YDE | 35 ms | 2% | Orange regional path, P25 = 34 ms |
| `backbone` | Backbone | 200 ms | 4% | International path, P50 = 207 ms |
| `degraded` | Degraded | 200 ms | 10% | Peak-hour congestion estimate |

**Launcher arguments:**

| Scenario | `mode` | `loss` | `delay` |
|----------|--------|--------|---------|
| Ideal | `none` | `0` | `0` |
| Local YDE | `simple` | `2` | `35` |
| Backbone | `simple` | `4` | `200` |
| Degraded | `simple` | `10` | `200` |

### 6.2 Gilbert–Elliott Burst-Loss Models

The GE models use the same parameter sets as Montenegro et al. [1]:

| Model | p_g | p_b | ε_h | ε_k | Avg. loss |
|-------|-----|-----|-----|-----|-----------|
| GE-Stable | 0.10 | 0.50 | 0.70 | 0.10 | ≈ 22.5% |
| GE-Unstable | 0.20 | 0.40 | 0.90 | 0.20 | ≈ 52% |

Where: `p_g` = P(Good→Bad), `p_b` = P(Bad→Good), `ε_h` = P(loss | Good), `ε_k` = P(loss | Bad).

**Launcher arguments:**

| Scenario | `mode` | `loss` | `delay` |
|----------|--------|--------|---------|
| GE-Stable | `stable` | `0` | `0` |
| GE-Unstable | `unstable` | `0` | `0` |

### 6.3 tc/netem Configuration Details

See [`network/netem_config.sh`](network/netem_config.sh) for the exact `tc` commands applied inside the Docker network namespace for each scenario.

Example for Local YDE:
```bash
tc qdisc add dev eth0 root netem delay 35ms loss 2%
```

Example for GE-Stable:
```bash
tc qdisc add dev eth0 root netem \
    loss gemodel 10% 50% 70% 10%
```

---

## 7. Evaluated Configurations

### Study 1 — ML-DSA × ML-KEM (26 Signature × KEM pairs)

| Tier | Signature (Classical → PQ) | KEMs evaluated |
|------|---------------------------|----------------|
| L1 | Ed25519 → ML-DSA44 | P-256, X25519, P-256+ML-KEM512, X25519+ML-KEM512, ML-KEM512 |
| L3 | secp384r1 → ML-DSA65 | P-384, X448, P-384+ML-KEM768, X448+ML-KEM768, ML-KEM768 |
| L5 | secp521r1 → ML-DSA87 | P-521, P-521+ML-KEM1024, ML-KEM1024 |

### Study 2 — ML-DSA × HQC (26 Signature × KEM pairs)

| Tier | Signature (Classical → PQ) | KEMs evaluated |
|------|---------------------------|----------------|
| L1 | Ed25519 → ML-DSA44 | P-256, X25519, HQC-128, P-256+HQC-128, X25519+HQC-128 |
| L3 | secp384r1 → ML-DSA65 | P-384, X448, HQC-192, P-384+HQC-192, X448+HQC-192 |
| L5 | secp521r1 → ML-DSA87 | P-521, HQC-256, P-521+HQC-256 |


## 8. Reproducing the Experiments

### 8.1 Study 1 — ML-DSA × ML-KEM

#### Uniform-loss scenarios (TLS + QUIC)

```bash
cd mldsa-mlkem-study1/

# TLS — all 4 uniform-loss scenarios
../../Launcherv3_pq_mlkem.sh tls single nocapture none   0  0
../../Launcherv3_pq_mlkem.sh tls single nocapture simple 2  35
../../Launcherv3_pq_mlkem.sh tls single nocapture simple 4  200
../../Launcherv3_pq_mlkem.sh tls single nocapture simple 10 200

# QUIC — all 4 uniform-loss scenarios
../../Launcherv3_pq_mlkem.sh quic single nocapture none   0  0
../../Launcherv3_pq_mlkem.sh quic single nocapture simple 2  35
../../Launcherv3_pq_mlkem.sh quic single nocapture simple 4  200
../../Launcherv3_pq_mlkem.sh quic single nocapture simple 10 200
```

#### Gilbert–Elliott burst-loss models

```bash
# TLS — GE models
../../Launcherv3_pq_mlkem.sh tls single nocapture stable   0 0
../../Launcherv3_pq_mlkem.sh tls single nocapture unstable 0 0

# QUIC — GE models
../../Launcherv3_pq_mlkem.sh quic single nocapture stable   0 0
../../Launcherv3_pq_mlkem.sh quic single nocapture unstable 0 0
```

> **Estimated runtime:** 6–8 hours on equivalent hardware (Intel Core i5-8250U).

### 8.3 Study 2 — ML-DSA × HQC

```bash
cd mldsa-hqc-study2/

# TLS — all scenarios including GE
for scenario in "none 0 0" "simple 2 35" "simple 4 200" "simple 10 200" \
                "stable 0 0" "unstable 0 0"; do
    read -r mode loss delay <<< "$scenario"
    bash ../../Launcherv3_pq_hqc.sh tls single nocapture $mode $loss $delay
done

# QUIC — all scenarios including GE
for scenario in "none 0 0" "simple 2 35" "simple 4 200" "simple 10 200" \
                "stable 0 0" "unstable 0 0"; do
    read -r mode loss delay <<< "$scenario"
    bash ../../Launcherv3_pq_hqc.sh quic single nocapture $mode $loss $delay
done
```

> **Estimated runtime:** 8–12 hours on equivalent hardware.  
> **Note:** HQC-256 under GE-unstable can produce individual handshakes exceeding 25 seconds. This is an expected result, not a hang — see Section 2 (Gilbert-Elliott Catastrophe finding).

### 8.4 Expected Output

Each launcher produces one log file per Signature × Protocol × Scenario combination, stored in either `TLS/log/` or `QUIC/log/`. CSV files are then generated from these logs by the Python analysis scripts handshakeProcess.py  and placed in `TLS/csv/` and `QUIC/csv/`, respectively.

CSV format:
```
run_id,sig,kem,protocol,scenario,rtt_ms,loss_pct,handshake_time_ms,status
1,mldsa65,mlkem768,tls,local_yde,35,2,186.92,success
2,mldsa65,mlkem768,tls,local_yde,35,2,188.14,success
...
500,mldsa65,mlkem768,tls,local_yde,35,2,191.07,success
```

---

## 9. Data Description

### 9.1 Raw Data Location

| Study | Protocol | Path |
|-------|----------|------|
| Study 1 — ML-KEM (uniform loss) | TLS | `mldsa-mlkem-study1/TLS/csv/` |
| Study 1 — ML-KEM (uniform loss) | QUIC | `mldsa-mlkem-study1/QUIC/csv/` |
| Study 1 — GE models | TLS + QUIC | `mldsa-mlkem-study1/{TLS,QUIC}/log/ge/` |
| Study 2 — HQC (uniform loss) | TLS | `mldsa-hqc-study2/TLS/csv/` |
| Study 2 — HQC (uniform loss) | QUIC | `mldsa-hqc-study2/QUIC/csv/` |
| Study 2 — GE models | TLS + QUIC | `mldsa-hqc-study2/{TLS,QUIC}/log/ge/` |

### 9.2 CSV Naming Convention

Uniform-loss scenarios:
```
{sig}_{protocol}_{scenario}.csv

Examples:
  mldsa65_tls_ideal.csv
  mldsa65_tls_africa_local.csv
  mldsa65_tls_africa_backbone.csv
  mldsa65_tls_africa_degraded.csv
  ed25519_quic_ideal.csv
  secp384r1_quic_africa_backbone.csv
```

Gilbert–Elliott scenarios:
```
{sig}_{protocol}_ge_stable.csv
{sig}_{protocol}_ge_unstable.csv

Examples:
  mldsa65_tls_ge_stable.csv
  mldsa87_quic_ge_unstable.csv
```

---

## 10. Statistical Analysis

### 10.1 Methodology

All statistical tests are implemented in the `scripts/` directory of each study.

| Test | Tool | Purpose |
|------|------|---------|
| Shapiro–Wilk | `scipy.stats.shapiro` | Confirm non-normality (all distributions, p < 0.001) |
| Mann–Whitney U | `scipy.stats.mannwhitneyu` | Non-parametric pairwise comparison |
| Bonferroni correction | Manual | Control family-wise error rate (α = 0.001) |
| Cliff's delta | Custom | Effect size for each pairwise comparison |

Primary location metric is the **median**. Mean, p95, and p99 are reported as secondary tail metrics.

### 10.2 Run Statistical Analysis — Study 1

```bash
cd mldsa-mlkem-study1/scripts/

# Ideal conditions
python3 analysis_pq_signatures.py

# Constrained-network scenarios
python3 analysis_africa_scenarios.py

# Gilbert-Elliott scenarios
python3 analysis_ge.py
```

Output is written to `mldsa-mlkem-study1/Analysis/`:
- `analysis_output.txt` — ideal-condition statistics
- `analysis_africa_output.txt` — constrained-network statistics
- `analysis_ge_output.txt` — Gilbert–Elliott statistics

### 10.3 Run Statistical Analysis — Study 2

```bash
cd mldsa-hqc-study2/scripts/

python3 analysis_hqc.py
python3 analysis_hqc_africa.py
python3 analysis_ge.py
```

Output is written to `mldsa-hqc-study2/Analysis/`:
- `analysis_hqc_output.txt`
- `analysis_hqc_africa_output.txt`
- `analysis_ge_output.txt`

---

## 11. Generating Figures

### 11.1 Study 1 — ML-DSA × ML-KEM

```bash
cd mldsa-mlkem-study1/scripts/

# Ideal-condition violin plots
python3 plot_pq_signatures.py

# Delta-evolution and protocol-reversal figures
python3 plot_africa_scenarios.py

# GE burst-loss violin plots
python3 plot_ge_violin.py

# Per-signature raw violin plots
python3 plot_violins_phase5.py
```

Figures are written to `mldsa-mlkem-study1/plots/` in both `.pdf` and `.png` formats.

### 11.2 Study 2 — ML-DSA × HQC

```bash
cd mldsa-hqc-study2/scripts/

# HQC ideal-condition figures
python3 plot_hqc_ideal.py

# HQC constrained-network figures
python3 plot_hqc_africa.py

# Per-signature HQC violin plots
python3 plot_violins_phase6.py
```

Figures are written to `mldsa-hqc-study2/plots/` in both `.pdf` and `.png` formats.

### 11.3 Figure Index

| Figure | Script | Output file |
|--------|--------|-------------|
| Fig. 1 — Ideal violin plots L1/L3 (Study 1) | `plot_pq_signatures.py` | `plots/fig1a_level1_violin.*` |
| Fig. 2 — Heatmap Δ% ML-DSA vs classical | `plot_pq_signatures.py` | `plots/fig2_heatmap_delta.*` |
| Fig. 3 — Super-additivity ratios | `plot_pq_signatures.py` | `plots/fig3_superadditivity.*` |
| Fig. 4 — Delta evolution across scenarios | `plot_africa_scenarios.py` | `plots/fig4_delta_evolution.*` |
| Fig. 5 — Protocol reversal TLS vs QUIC | `plot_africa_scenarios.py` | `plots/fig5_protocol_reversal.*` |
| Fig. 6 — Deployment heatmap Study 1 | `plot_africa_scenarios.py` | `plots/fig6_deployment_heatmap.*` |
| Fig. 7 — Ideal vs degraded scatter Study 1 | `plot_africa_scenarios.py` | `plots/fig7_ideal_vs_degraded.*` |
| Fig. 8 — HQC ideal violin plots (Study 2) | `plot_hqc_ideal.py` | `plots/fig8_hqc_violin.*` |
| Fig. 9 — HQC delta evolution | `plot_hqc_africa.py` | `plots/fig9_hqc_delta.*` |
| Fig. 10 — HQC deployment heatmap | `plot_hqc_africa.py` | `plots/fig10_hqc_heatmap.*` |
| GE violin Study 1 (supplementary) | `plot_ge_violin.py` | `plots/ge_violin/fig_GE_*.*` |

---

## 12. Micro-benchmarks

Micro-benchmarks measure isolated cryptographic operation latency to provide causal justification for the AVX2 performance paradox documented in the paper.

### 12.1 Run Inside the Docker Container

```bashdocker run --rm uma-tls-quic-pq-34 bash -c "
    echo '=== Classical Signatures ==='
    openssl speed ed25519 ecdsap384 ecdsap521 2>&1
    echo ''
    echo '=== ML-DSA (OQS provider) ==='
    openssl speed -provider oqsprovider mldsa44 mldsa65 mldsa87 2>&1
" > microbench/microbench_results.txt
```

### 12.2 Reference Results (Table 2 in paper)

Measured on HP ProBook 640 G4, Intel Core i5-8250U, AVX2, Ubuntu 24.04 LTS,
OpenSSL 3.4.2-dev + liboqs 0.12.0 + oqsprovider 0.8.0, N ≈ 10,000 iterations.

| Algorithm | Sign (µs) | Verify (µs) | NIST Level |
|-----------|-----------|-------------|------------|
| Ed25519 | 42.6 | 135.8 | I |
| secp384r1 | 249.7 | 657.6 | III |
| secp521r1 | 381.0 | 764.1 | V |
| ML-DSA-44 | 89.5 | 34.6 | II |
| ML-DSA-65 | 142.9 | 51.7 | III |
| ML-DSA-87 | 153.9 | 73.9 | V |

> **Interpretation:** secp384r1 Sign (249.7 µs) is 1.75× slower than ML-DSA-65 Sign (142.9 µs) despite ML-DSA-65 producing certificates 32× larger. This asymmetry — driven by AVX2 NTT acceleration in ML-DSA — is the mechanism underlying the AVX2 performance paradox reported in Key Finding 1. secp521r1 has no dedicated Intel hardware acceleration path; P-521 scalar multiplication is executed entirely in software.

---

## 13. Validation Against Montenegro et al. [1]

To confirm that our framework correctly reproduces the baseline from Montenegro et al. before introducing ML-DSA, run the original launcher:

```bash
# Reproduce Montenegro et al. — ideal conditions
Launcherv3.sh tls single nocapture none 0 0
Launcherv3.sh quic single nocapture none 0 0
```
<table>
  <caption>Expected agreement (mean handshake times, ms)</caption>
  <thead>
    <tr><th>Configuration</th><th>Our result</th><th>Montenegro et al. [1]</th><th>|Δ|%</th></tr>
  </thead>
  <tbody>
    <tr><td>TLS — Ed25519 + ML-KEM512</td><td>4.87 ms</td><td>≈ 4.9 ms</td><td>0.6%</td></tr>
    <tr><td>TLS — Ed25519 + p256_ML-KEM512</td><td>9.24 ms</td><td>≈ 9.1 ms</td><td>1.5%</td></tr>
    <tr><td>TLS — secp384r1 + ML-KEM768</td><td>5.11 ms</td><td>≈ 5.2 ms</td><td>1.7%</td></tr>
    <tr><td>TLS — secp521r1 + ML-KEM1024</td><td>11.02 ms</td><td>≈ 11.1 ms</td><td>0.7%</td></tr>
    <tr><td>QUIC — Ed25519 + ML-KEM512</td><td>2.95 ms</td><td>≈ 2.9 ms</td><td>1.7%</td></tr>
    <tr><td>QUIC — Ed25519 + p256_ML-KEM512</td><td>12.14 ms</td><td>≈ 12.0 ms</td><td>1.2%</td></tr>
    <tr><td>QUIC — secp384r1 + ML-KEM768</td><td>3.98 ms</td><td>≈ 3.9 ms</td><td>2.1%</td></tr>
  </tbody>
</table>

All reproduced values agree with Montenegro et al values within **±3%**. KEM performance rankings match 100%.

> **Note on divergence:** Our machine (Intel Core i5-8250U, 1.6–3.4 GHz, laptop) differs from the Montenegro et al. hardware (Intel Xeon Silver 4214, 2.2 GHz, server). Both support AVX2. Absolute values differ by up to 2× for some configurations due to clock speed and cache hierarchy differences; relative rankings and Δ% comparisons are unaffected.

---

## 14. Supplementary Materials

The following materials are available in `mldsa-mlkem-study1/plots/` and `mldsa-hqc-study2/plots/` and are not included in the main paper due to space constraints.

### Supplementary Figures

| File | Description |
|------|-------------|
| `mldsa-mlkem-study1/plots/ge_violin/fig_GE_stable_L*.{pdf,png}` | GE-stable violin plots, Levels I/III/V, Study 1 |
| `mldsa-mlkem-study1/plots/ge_violin/fig_GE_unstable_L*.{pdf,png}` | GE-unstable violin plots, Levels I/III/V, Study 1 |
| `mldsa-hqc-study2/plots/fig1*_hqc_violin.*` | Ideal-condition HQC violin plots, Levels I/III/V |
| `mldsa-hqc-study2/plots/ge_violin/fig_GE_*_hqc.*` | GE violin plots, Study 2 |

### Supplementary Data Files

| File | Description |
|------|-------------|
| `mldsa-mlkem-study1/Analysis/analysis_output.txt` | Full statistics — Study 1 ideal conditions |
| `mldsa-mlkem-study1/Analysis/analysis_africa_output.txt` | Full statistics — Study 1 constrained networks |
| `mldsa-mlkem-study1/Analysis/analysis_ge_output.txt` | Full statistics — Study 1 GE models |
| `mldsa-hqc-study2/Analysis/analysis_hqc_output.txt` | Full statistics — Study 2 ideal conditions |
| `mldsa-hqc-study2/Analysis/analysis_hqc_africa_output.txt` | Full statistics — Study 2 constrained networks |
| `mldsa-hqc-study2/Analysis/analysis_ge_output.txt` | Full statistics — Study 2 GE models |

---

## 15. Citation

If you use this repository, the data, or the code it contains, please cite:

```bibtex
@article{tolokoum2026pq,
  author    = {Tolokoum, David Rive and Mbezoa, Yve Bruno and {Talé Kalachi}, Hervé},
  title     = {Post-Quantum {TLS} 1.3 and {QUIC} Handshakes under Constrained Networks:
               Combining {ML-DSA} with {ML-KEM} and {HQC}},
  journal   = {Computer Networks},
  year      = {2026},
  note      = {Submitted},
  url       = {https://github.com/TOLOKOUM/mldsa-mlkem-hqc-tls-quic-constrained-performance}
}
```

---

## 16. License

This repository is released under the **MIT License** — see [`LICENSE`](LICENSE) for full terms.

The Docker image integrates the following open-source components:

| Component | License |
|-----------|---------|
| [OpenSSL](https://openssl.org/) | Apache 2.0 / OpenSSL License |
| [liboqs](https://github.com/open-quantum-safe/liboqs) | MIT License |
| [oqsprovider](https://github.com/open-quantum-safe/oqs-provider) | MIT License |
| [MsQuic](https://github.com/microsoft/msquic) | MIT License |

---

## 17. Contact

| Role | Name | Email |
|------|------|-------|
| Lead author — experiments, code, analysis, writing | David Rive Tolokoum | davidtolokoum8@gmail.com |
| Co-author — validation, analysis | Yve Bruno Mbezoa | mbezoayvebruno@gmail.com |
| Supervisor / corresponding author | Hervé Talé Kalachi | herve.tale@univ-yaounde1.cm |

**Affiliation:**
Department of Computer Engineering,
National Advanced School of Engineering (ENSPY),
University of Yaoundé I, Yaoundé, Cameroon.

