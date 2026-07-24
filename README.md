# Post-Quantum TLS 1.3 and QUIC Handshakes under Constrained Networks: Combining ML-DSA with ML-KEM and HQC

> David Rive Tolokoum, Yve Bruno MBEZOA, Hervé Talé Kalachi.  
> *Post-Quantum TLS 1.3 and QUIC Handshakes under Constrained Networks: Combining ML-DSA with ML-KEM and HQC*  
> Submitted to *Computer Networks*, 2026.

## 1. Overview

This repository contains the artifact package for a large-scale experimental study evaluating the combined impact of **ML-DSA** signatures with **ML-KEM** and **HQC** key encapsulation mechanisms in **TLS 1.3** and **QUIC** under constrained network conditions calibrated from field measurements at ENSP Yaoundé using Orange Cameroon infrastructure.

The repository provides scripts, data, logs, analysis code, and additional figures/tables supporting the results reported in the paper.

### Measurement Scale

| Experiment Type | Measurements | Details |
|-----------------|--------------|---------|
| Full handshakes | **312,000** | Study 1 + Study 2, N = 500 per configuration |
| Session resumption | Reported separately | N = 500 per scenario |
| Concurrent load | Reported separately | 10 / 50 / 100 simultaneous clients |
| KEM families | 2 | ML-KEM and HQC |
| Security tiers | 3 | NIST categories I, III, V |
| Protocols | 2 | TLS 1.3 and QUIC |
| Network scenarios | 6 | Ideal, Local YDE, Backbone, Degraded, GE-stable, GE-unstable |

### Central Thesis

Post-quantum protocol performance **cannot be predicted from primitive micro-benchmarks alone**. Once post-quantum signatures are introduced, certificate size, packetization, retransmission behavior, and transport architecture can change the relative ranking of TLS and QUIC.


## 2. Key Findings

| Finding | Description |
|---------|-------------|
| **AVX2 Performance Paradox** | ML-DSA reduces TLS median latency by up to 75.7% versus ECDSA under ideal conditions on x86-64/AVX2; the effect is directionally consistent with isolated sign/verify micro-benchmarks, but the primitive-level gap (hundreds of µs) is far smaller than the handshake-level gap (ms to tens of ms), so a full phase-level attribution remains open |
| **TLS/QUIC Protocol Reversal** | TLS becomes faster than QUIC for all Tier 3 KEMs with ML-DSA65 in the Local YDE scenario, at an *effective* RTT of ≈70 ms (35 ms configured per side — see Section 6.1) |
| **KEM/Signature Interaction** | Using a bootstrap-validated factorial interaction index (rather than a fixed-ratio threshold), TLS migration paths are predominantly **sub-additive** (8/10), while QUIC shows a mixed pattern (3/10 super-additive, 6/10 sub-additive); most significant effects remain below 2 ms in absolute magnitude |
| **HQC Bottleneck Inversion** | HQC dominates handshake cost in QUIC, making the signature choice nearly neutral under ideal conditions |
| **Gilbert–Elliott Tail-Latency Regime** | ML-DSA87 + P-521 + HQC-256 reaches 18,595 ms mean latency and p99 above 25 s under GE-unstable burst loss (TLS); the QUIC counterpart of this configuration is currently excluded from the paper pending re-validation (see Section 12.3) |

## 3. Repository Structure
```
mldsa-mlkem-hqc-tls-quic-constrained-performance/
│
├── README.md
├── LICENSE
├── CITATION.cff
│
├── 0-docker/                                      # Docker environment
│   ├── Dockerfile                                 # OpenSSL 3.4.2-dev + liboqs + oqsprovider + MsQuic
│   └── scripts/
│       ├── doCert.sh                              # X.509 certificate generation
│       ├── perftestServerTlsQuic.sh               # TLS/QUIC server-side test runner
│       ├── perftestClientTlsQuic.sh               # TLS/QUIC client-side test runner
│       ├── perftestServerClientTlsQuic.sh         # Combined server + client launcher
│       ├── perftestClientConcurrent.sh            # Concurrent-load client
│       ├── perftestClientResumptionBatch.sh       # Session-resumption client
│       ├── perftestServerCompress.sh              # RFC 8879 compression server
│       └── perftestClientCompress.sh              # RFC 8879 compression client
│
├── network/
│   └── netem_config.sh                            # tc/netem scenario definitions
│
├── mldsa-mlkem-study1/                            # Study 1 — ML-DSA × ML-KEM
│   ├── TLS/
│   │   ├── csv/
│   │   ├── log/
│   │   └── plots/
│   ├── QUIC/
│   │   ├── csv/
│   │   ├── log/
│   │   └── plots/
│   ├── Analysis/
│   │   ├── analysis_output.txt                    # Ideal-condition statistics
│   │   ├── analysis_africa_output.txt             # Constrained-network statistics
│   │   └── analysis_ge_output.txt                 # Gilbert--Elliott statistics
│   ├── result_concurrent/
│   ├── scripts/
│   │   ├── analysis_pq_signatures.py
│   │   ├── analysis_africa_scenarios.py
│   │   ├── analysis_ge.py
│   │   ├── analyse_concurrent.py
│   │   ├── compare_concurrent.py
│   │   ├── handshakeProcess.py
│   │   ├── plot_pq_signatures.py
│   │   ├── plot_africa_scenarios.py
│   │   ├── plot_ge_violin.py
│   │   └── plot_violins_phase5.py
│   └── plots/
│       ├── fig1a_level1_violin.pdf
│       ├── fig1b_level3_violin.pdf
│       ├── fig3_superadditivity.pdf
│       └── ge_violin/
│
├── mldsa-hqc-study2/                              # Study 2 — ML-DSA × HQC
│   ├── TLS/
│   │   ├── csv/
│   │   ├── log/
│   │   └── plots/
│   ├── QUIC/
│   │   ├── csv/
│   │   ├── log/
│   │   └── plots/
│   ├── Analysis/
│   │   ├── analysis_hqc_output.txt
│   │   ├── analysis_hqc_africa_output.txt
│   │   └── analysis_ge_output.txt
│   ├── result_concurrent/
│   ├── scripts/
│   │   ├── analysis_hqc.py
│   │   ├── analysis_hqc_africa.py
│   │   ├── analysis_ge.py
│   │   ├── analyse_concurrent.py
│   │   ├── compare_concurrent.py
│   │   ├── handshakeProcess.py
│   │   ├── plot_hqc_ideal.py
│   │   ├── plot_hqc_africa.py
│   │   └── plot_violins_phase6.py
│   └── plots/
│       ├── fig1a_level1_hqc_violin.pdf
│       ├── fig1b_level3_hqc_violin.pdf
│       └── ge_violin/
│
├── resumption_study/
│   ├── scripts/
│   ├── results/
│   └── analysis/
│
├── compression_study/
│   ├── scripts/
│   ├── results/
│   └── analysis/
│
├── microbench/
│   └── microbench_results.txt
│
├── Launcherv3_pq_mlkem.sh                         # Study 1 full-matrix orchestrator
├── Launcherv3_pq_hqc.sh                           # Study 2 full-matrix orchestrator
├── Launcherv3_mlkem_concurrent.sh                 # ML-KEM concurrent-load orchestrator
├── Launcherv3_hqc_concurrent.sh                   # HQC concurrent-load orchestrator
└── run_concurrent_matrix.sh                       # Run all concurrent experiments
```

## 4. Hardware and Software Requirements

### Hardware Used in the Paper

| Component      | Specification                        |
| -------------- | ------------------------------------ |
| Machine        | HP ProBook 640 G4                    |
| CPU            | Intel Core i5-8250U @ 1.60–3.40 GHz |
| ISA extensions | AVX2                                 |
| Cores          | 4 physical / 8 logical threads       |
| RAM            | 24 GB DDR4                           |
| OS             | Ubuntu 24.04 LTS                     |
| Docker         | 26.1+                                |
| Disk           | At least 20 GB free                  |

> **Note on AVX2.** The AVX2 performance advantage reported in the paper is architecture-specific and directional (Section 2, above): the isolated sign/verify micro-benchmarks (Section 14) confirm the *direction* of the effect but are an order of magnitude smaller than the observed handshake-level gains, so a complete quantitative attribution requires further phase-level instrumentation. Results on ARM, embedded, or mobile platforms may differ; cross-architecture validation is future work.

### Software Stack

| Component   | Version                                        | Role                               |
| ----------- | ---------------------------------------------- | ---------------------------------- |
| OpenSSL     | 3.4.2-dev                                      | TLS 1.3 stack                      |
| liboqs      | 0.12.0                                         | Post-quantum primitives            |
| oqsprovider | 0.8.0                                          | OpenSSL provider for PQ algorithms |
| MsQuic      | Repository version bundled in the Docker image | QUIC stack                         |
| tc/netem    | Linux kernel                                   | Network impairment injection (uniform-loss scenarios) |
| Pumba       | Bundled in the Docker image                    | Gilbert–Elliott burst-loss injection |
| Python      | >= 3.10                                        | Analysis and figure generation     |
| Docker      | >= 26.1                                        | Reproducible container environment |

> **Note on OpenSSL/MsQuic provenance.** `liboqs` and `oqs-provider` are pinned to fixed release tags in the Dockerfile. OpenSSL and MsQuic are currently built from forked repositories referenced by branch name rather than a pinned commit SHA, so two independent image builds are not guaranteed to be bit-identical (see Section 15 and the paper's Limitations section). A future release of this repository will pin exact commit SHAs and publish the resulting image digest.

---

## 5. Installation and Environment Setup

### Step 1 — Clone the repository

```bash
git clone https://github.com/TOLOKOUM/mldsa-mlkem-hqc-tls-quic-constrained-performance.git
cd mldsa-mlkem-hqc-tls-quic-constrained-performance
```

### Step 2 — Install system dependencies

```bash
sudo apt update
sudo apt install -y \
    docker.io \
    git \
    iproute2 \
    python3 \
    python3-pip \
    python3-venv

sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"
```

After adding the user to the `docker` group, log out and log back in.

### Step 3 — Install Python dependencies

```bash
python3 -m venv venv
source venv/bin/activate

pip install --upgrade pip
pip install numpy scipy pandas matplotlib seaborn
```

### Step 4 — Build the Docker image

```bash
cd 0-docker
docker build -t uma-tls-quic-pq-34 .
cd ..
```

Build time is approximately 15–25 minutes depending on network speed and CPU performance.

### Step 5 — Verify the installation

```bash
docker run --rm uma-tls-quic-pq-34 openssl version
```

Expected output begins with:

```text
OpenSSL 3.4.2-dev
```

List available post-quantum algorithms:

```bash
docker run --rm uma-tls-quic-pq-34 \
    openssl list -signature-algorithms -provider oqsprovider \
    | grep -i "mldsa\|hqc"
```

---

## 6. Network Scenarios

All network scenarios are based on field measurements conducted at **ENSP Yaoundé** using **Orange Cameroon** infrastructure in **April 2026**.

### 6.1 Uniform-Loss Scenarios

Delay is injected independently with `tc/netem` on the `eth0` interface of **both** the client and server containers. Because a full round trip traverses both egress points once, the **effective RTT delivered to the connection is approximately twice the per-side configured value** below. Packet loss is configured on the **server's egress only**, so it characterizes the server-to-client direction rather than a symmetric end-to-end rate. This asymmetry is a property of the current injection method, not of the target network path, and is documented in full in the paper (Section 4.3, Table 5).

| Scenario ID | Label     | Per-side delay | Effective RTT | Loss (srv→clt) | Calibration                       |
| ----------- | --------- | -------------- | -------------- | --------------- | ---------------------------------- |
| `ideal`     | Ideal     | 0 ms   | 0 ms   | 0%   | Docker localhost, no impairment   |
| `local_yde` | Local YDE | 35 ms  | ≈70 ms  | 2%   | Orange regional path, P25 = 34 ms |
| `backbone`  | Backbone  | 200 ms | ≈400 ms | 4%   | International path, P50 = 207 ms  |
| `degraded`  | Degraded  | 200 ms | ≈400 ms | 10%  | Peak-hour congestion estimate     |

Launcher arguments (the `loss`/`delay` values below are the **per-side** parameters passed to `tc`):

| Scenario  | `mode`   | `loss` | `delay` |
| --------- | -------- | ------ | ------- |
| Ideal     | `none`   | `0`    | `0`     |
| Local YDE | `simple` | `2`    | `35`    |
| Backbone  | `simple` | `4`    | `200`   |
| Degraded  | `simple` | `10`   | `200`   |

Equivalent low-level commands (applied separately on the client and server containers; delay on both, loss on the server only):

```bash
# Server container
tc qdisc add dev eth0 root netem delay 35ms loss 2%
# Client container
tc qdisc add dev eth0 root netem delay 35ms
```

### 6.2 Gilbert–Elliott Burst-Loss Models

Unlike the four uniform-loss scenarios above, the Gilbert–Elliott models are **not** injected with `tc/netem`. They are injected via **Pumba's `loss-gemodel`**, applied to the **server container only**, with **no additional propagation delay**. GE results should therefore be read as isolating the effect of burst loss alone, at near-zero RTT, rather than as burst loss superimposed on a field-calibrated RTT.

The Gilbert–Elliott models use the same parameter sets as Montenegro et al.:

| Model       | `p_g` | `p_b` | `epsilon_h` | `epsilon_k` |
| ----------- | ----- | ----- | ----------- | ----------- |
| GE-stable   | 0.10  | 0.50  | 0.70        | 0.10        |
| GE-unstable | 0.20  | 0.40  | 0.90        | 0.20        |

Launcher arguments:

| Scenario    | `mode`     | `loss` | `delay` |
| ----------- | ---------- | ------ | ------- |
| GE-stable   | `stable`   | `0`    | `0`     |
| GE-unstable | `unstable` | `0`    | `0`     |

Equivalent low-level command (server container only):

```bash
pumba netem --duration 1h --interface eth0 \
    loss-gemodel --pg 0.10 --pb 0.50 --one-h 0.70 --one-k 0.10 <server_container>
```

> **Note on GE re-validation.** One QUIC configuration (ML-DSA87 + P-521+HQC-256, GE-unstable) showed an internal inconsistency during this revision (lower degradation under GE-unstable than under GE-stable, contrary to the model's higher nominal stationary loss rate). This value has been excluded from the paper pending a full re-run of the GE-unstable sweep for Study 2; see `mldsa-hqc-study2/Analysis/` for the current state of this investigation.

---

## 7. Evaluated Configurations

### Study 1 — ML-DSA × ML-KEM

Each security tier is evaluated with a classical signature and the corresponding ML-DSA parameter set.

| Tier | Signature pair       | KEMs evaluated                                              |
| ---- | -------------------- | ------------------------------------------------------------ |
| L1   | Ed25519 / ML-DSA44   | P-256, X25519, P-256+ML-KEM512, X25519+ML-KEM512, ML-KEM512 |
| L3   | secp384r1 / ML-DSA65 | P-384, X448, P-384+ML-KEM768, X448+ML-KEM768, ML-KEM768     |
| L5   | secp521r1 / ML-DSA87 | P-521, P-521+ML-KEM1024, ML-KEM1024                         |

### Study 2 — ML-DSA × HQC

| Tier | Signature pair       | KEMs evaluated                                        |
| ---- | -------------------- | ------------------------------------------------------ |
| L1   | Ed25519 / ML-DSA44   | P-256, X25519, HQC-128, P-256+HQC-128, X25519+HQC-128 |
| L3   | secp384r1 / ML-DSA65 | P-384, X448, HQC-192, P-384+HQC-192, X448+HQC-192     |
| L5   | secp521r1 / ML-DSA87 | P-521, HQC-256, P-521+HQC-256                         |

> **Note on primitive naming.** P-256, X25519, P-384, X448, and P-521 are classical ECDHE key-establishment groups, not KEMs in the strict NIST sense; they are grouped here with ML-KEM/HQC only for evaluation-matrix convenience. See the paper (Section 4.4) for the precise NIST-standardized vs. oqsprovider-experimental vs. hybrid-construction distinctions.

---

## 8. Reproducibility Modes

This repository supports two reproducibility modes.

### Mode A — Reproduce the analysis from provided data

Use this mode to regenerate statistics, tables, and figures from the CSV/log files included in the repository. This is the recommended mode for reviewers who want to verify the numerical results without rerunning the full network experiments.

```bash
cd mldsa-mlkem-study1/scripts/
python3 analysis_pq_signatures.py
python3 analysis_africa_scenarios.py
python3 analysis_ge.py
python3 plot_pq_signatures.py
python3 plot_africa_scenarios.py

cd ../../mldsa-hqc-study2/scripts/
python3 analysis_hqc.py
python3 analysis_hqc_africa.py
python3 analysis_ge.py
python3 plot_hqc_ideal.py
python3 plot_hqc_africa.py
```

### Mode B — Reproduce the experiments from scratch

Use this mode to rebuild the Docker image and rerun the TLS/QUIC handshake campaigns. This mode requires privileges for `tc/netem` and Pumba, and takes substantially longer. Because OpenSSL and MsQuic are not currently pinned to exact commits (Section 4), absolute latencies from a fresh build may differ from those reported in the paper even though the qualitative KEM ranking and relative ML-DSA effect should be preserved (Section 15).

```bash
cd 0-docker
docker build -t uma-tls-quic-pq-34 .
cd ..
```

Then run the desired experiment matrix as described below.

---

## 9. Reproducing the Full-Handshake Campaigns

### 9.1 Study 1 — ML-DSA × ML-KEM

```bash
cd mldsa-mlkem-study1/
```

Uniform-loss scenarios:

```bash
# TLS
../Launcherv3_pq_mlkem.sh tls single nocapture none   0  0
../Launcherv3_pq_mlkem.sh tls single nocapture simple 2  35
../Launcherv3_pq_mlkem.sh tls single nocapture simple 4  200
../Launcherv3_pq_mlkem.sh tls single nocapture simple 10 200

# QUIC
../Launcherv3_pq_mlkem.sh quic single nocapture none   0  0
../Launcherv3_pq_mlkem.sh quic single nocapture simple 2  35
../Launcherv3_pq_mlkem.sh quic single nocapture simple 4  200
../Launcherv3_pq_mlkem.sh quic single nocapture simple 10 200
```

Gilbert–Elliott models:

```bash
# TLS
../Launcherv3_pq_mlkem.sh tls single nocapture stable   0 0
../Launcherv3_pq_mlkem.sh tls single nocapture unstable 0 0

# QUIC
../Launcherv3_pq_mlkem.sh quic single nocapture stable   0 0
../Launcherv3_pq_mlkem.sh quic single nocapture unstable 0 0
```

Estimated runtime on the reference machine: 6–8 hours.

### 9.2 Study 2 — ML-DSA × HQC

```bash
cd ../mldsa-hqc-study2/
```

TLS:

```bash
for scenario in "none 0 0" "simple 2 35" "simple 4 200" "simple 10 200" \
                "stable 0 0" "unstable 0 0"; do
    read -r mode loss delay <<< "$scenario"
    ../Launcherv3_pq_hqc.sh tls single nocapture "$mode" "$loss" "$delay"
done
```

QUIC:

```bash
for scenario in "none 0 0" "simple 2 35" "simple 4 200" "simple 10 200" \
                "stable 0 0" "unstable 0 0"; do
    read -r mode loss delay <<< "$scenario"
    ../Launcherv3_pq_hqc.sh quic single nocapture "$mode" "$loss" "$delay"
done
```

Estimated runtime on the reference machine: 8–12 hours.

> **Note.** HQC-256 under GE-unstable can produce individual handshakes exceeding 25 seconds. This is an expected result, not a hang.

---

## 10. Expected Output

Each launcher produces log files under either `TLS/log/` or `QUIC/log/`. CSV files are generated from the logs by the parsing utilities and stored in `TLS/csv/` or `QUIC/csv/`.

Representative CSV format:

```text
run_id,sig,kem,protocol,scenario,rtt_ms,loss_pct,handshake_time_ms,status
1,mldsa65,mlkem768,tls,local_yde,35,2,186.92,success
2,mldsa65,mlkem768,tls,local_yde,35,2,188.14,success
...
500,mldsa65,mlkem768,tls,local_yde,35,2,191.07,success
```

> The `rtt_ms` field in these logs records the **per-side** configured delay (matching the Launcher argument), not the effective end-to-end RTT — see Section 6.1.

---

## 11. Data Description

### 11.1 Raw and Processed Data

| Study                         | Protocol    | Path                                                                           |
| ----------------------------- | ----------- | ------------------------------------------------------------------------------ |
| Study 1 — ML-KEM uniform loss | TLS         | `mldsa-mlkem-study1/TLS/csv/`                                                  |
| Study 1 — ML-KEM uniform loss | QUIC        | `mldsa-mlkem-study1/QUIC/csv/`                                                 |
| Study 1 — GE models           | TLS/QUIC    | `mldsa-mlkem-study1/{TLS,QUIC}/log/ge/`                                        |
| Study 2 — HQC uniform loss    | TLS         | `mldsa-hqc-study2/TLS/csv/`                                                    |
| Study 2 — HQC uniform loss    | QUIC        | `mldsa-hqc-study2/QUIC/csv/`                                                   |
| Study 2 — GE models           | TLS/QUIC    | `mldsa-hqc-study2/{TLS,QUIC}/log/ge/`                                          |
| Session resumption            | TLS/QUIC    | `resumption_study/results/`                                                    |
| Concurrent load               | TLS/QUIC    | `mldsa-mlkem-study1/result_concurrent/`, `mldsa-hqc-study2/result_concurrent/` |
| Micro-benchmarks              | Sign/verify | `microbench/microbench_results.txt`                                            |

### 11.2 CSV Naming Convention

Uniform-loss scenarios:

```text
{sig}_{protocol}_{scenario}.csv
```

Examples:

```text
mldsa65_tls_ideal.csv
mldsa65_tls_africa_local.csv
mldsa65_tls_africa_backbone.csv
mldsa65_tls_africa_degraded.csv
ed25519_quic_ideal.csv
secp384r1_quic_africa_backbone.csv
```

Gilbert–Elliott scenarios:

```text
{sig}_{protocol}_ge_stable.csv
{sig}_{protocol}_ge_unstable.csv
```

Examples:

```text
mldsa65_tls_ge_stable.csv
mldsa87_quic_ge_unstable.csv
```

---

## 12. Statistical Analysis

All statistical tests are implemented in the `scripts/` directory of each study.

| Test or Metric                   | Tool                       | Purpose                            |
| --------------------------------- | -------------------------- | ----------------------------------- |
| Shapiro–Wilk                      | `scipy.stats.shapiro`      | Check normality                    |
| Mann–Whitney U                    | `scipy.stats.mannwhitneyu` | Pairwise non-parametric comparison (stochastic ordering, not equality of medians) |
| Bonferroni correction              | Manual                     | Family-wise error control, $m{=}26$ classical-vs-ML-DSA comparisons per network condition; conservative fixed threshold $\alpha=0.001$ used throughout |
| Cliff's delta                     | Custom                     | Non-parametric effect size, reported where raw per-run data allow |
| Factorial interaction index ($I$) | Custom, with bootstrap CI  | KEM×signature migration interaction; replaces an earlier fixed-ratio test that was unstable when the classical-signature baseline was close to or worse than ML-DSA (see Section 12.1 below) |
| Median                            | `numpy` / `pandas`         | Primary location metric            |
| Mean, p95, p99                    | `numpy` / `pandas`         | Tail and service-level metrics      |

The primary location metric is the **median**. Mean, p95, and p99 are reported as secondary tail metrics.

### 12.1 Study 1

```bash
cd mldsa-mlkem-study1/scripts/

python3 analysis_pq_signatures.py
python3 analysis_africa_scenarios.py
python3 analysis_ge.py
```

Outputs:

```text
mldsa-mlkem-study1/Analysis/analysis_output.txt
mldsa-mlkem-study1/Analysis/analysis_africa_output.txt
mldsa-mlkem-study1/Analysis/analysis_ge_output.txt
```

### 12.2 Study 2

```bash
cd mldsa-hqc-study2/scripts/

python3 analysis_hqc.py
python3 analysis_hqc_africa.py
python3 analysis_ge.py
```

Outputs:

```text
mldsa-hqc-study2/Analysis/analysis_hqc_output.txt
mldsa-hqc-study2/Analysis/analysis_hqc_africa_output.txt
mldsa-hqc-study2/Analysis/analysis_ge_output.txt
```

### 12.3 Known Open Items

The following items are under active investigation and are documented transparently rather than silently corrected:

- **QUIC GE-unstable, ML-DSA87+P-521+HQC-256** (Study 2): excluded from the paper pending a full re-run of the GE-unstable sweep (Section 6.2).
- **Cross-study absolute-latency comparability** (Study 1 vs. Study 2): the two studies were built and run as separate Docker campaigns; OpenSSL/MsQuic are not yet pinned to exact commit SHAs (Section 4), so purely classical baselines shared between studies (e.g., secp521r1+P-521) differ by up to ~3× in absolute latency between campaigns. The *relative* ML-DSA-vs-classical effect size is stable across campaigns. See the paper's Limitations section for full discussion.

---

## 13. Generating Figures

### 13.1 Study 1 — ML-DSA × ML-KEM

```bash
cd mldsa-mlkem-study1/scripts/

python3 plot_pq_signatures.py
python3 plot_africa_scenarios.py
python3 plot_ge_violin.py
python3 plot_violins_phase5.py
```

### 13.2 Study 2 — ML-DSA × HQC

```bash
cd mldsa-hqc-study2/scripts/

python3 plot_hqc_ideal.py
python3 plot_hqc_africa.py
python3 plot_violins_phase6.py
```

### 13.3 Figure Index

| Figure                            | Script                     | Output file                                          |
| ---------------------------------- | -------------------------- | ------------------------------------------------------ |
| Study 1 ideal violin plots         | `plot_pq_signatures.py`    | `mldsa-mlkem-study1/plots/fig1*_violin.*`            |
| Study 1 KEM×signature interaction index | `plot_pq_signatures.py`    | `mldsa-mlkem-study1/plots/fig3_superadditivity.*`    |
| Study 1 protocol reversal          | `plot_africa_scenarios.py` | `mldsa-mlkem-study1/plots/fig*_protocol_reversal.*`  |
| Study 1 deployment heatmap         | `plot_africa_scenarios.py` | `mldsa-mlkem-study1/plots/fig*_deployment_heatmap.*` |
| Study 1 GE violin plots            | `plot_ge_violin.py`        | `mldsa-mlkem-study1/plots/ge_violin/fig_GE_*.*`      |
| Study 2 HQC ideal violin plots     | `plot_hqc_ideal.py`        | `mldsa-hqc-study2/plots/fig*_hqc_violin.*`           |
| Study 2 HQC delta evolution        | `plot_hqc_africa.py`       | `mldsa-hqc-study2/plots/fig*_hqc_delta.*`            |
| Study 2 HQC deployment heatmap     | `plot_hqc_africa.py`       | `mldsa-hqc-study2/plots/fig*_hqc_heatmap.*`          |


## 14. Micro-benchmarks

Micro-benchmarks measure isolated cryptographic operation latency to help interpret the AVX2 performance behavior observed in the protocol-level results. These are used only as a directional interpretive aid; they are **not** used as protocol results, and are known to be an order of magnitude smaller than the handshake-level effects they help explain (Section 2).

### 14.1 Run Micro-benchmarks

```bash
docker run --rm --cpuset-cpus="0" uma-tls-quic-pq-34 bash -c "
    openssl speed ed25519 ecdsap384 ecdsap521 2>&1
    openssl speed -provider oqsprovider mldsa44 mldsa65 mldsa87 2>&1
" | tee microbench/microbench_results.txt
```

### 14.2 Reference Results

Measured on HP ProBook 640 G4, Intel Core i5-8250U, AVX2, Ubuntu 24.04 LTS, OpenSSL 3.4.2-dev, liboqs 0.12.0, oqsprovider 0.8.0, $T=10\,\text{s}$ per algorithm. These are the exact values reported in Table 4 of the paper; `microbench_results.txt` in this repository is the single source of truth for this table.

| Algorithm | Sign (µs) | Verify (µs) | NIST Category |
| --------- | --------- | ----------- | -------------- |
| Ed25519   | 38.0      | 123.3       | I             |
| secp384r1 | 225.8     | 503.3       | III           |
| secp521r1 | 299.9     | 577.6       | V             |
| ML-DSA44  | 76.9      | 27.3        | II            |
| ML-DSA65  | 124.0     | 46.8        | III           |
| ML-DSA87  | 153.0     | 73.9        | V             |

These values are used only to interpret protocol-level results; they are not used as handshake measurements.


## 15. Validation Against Prior TLS/QUIC Measurements

To validate the framework, we reproduced a subset of the ideal-condition configurations from Montenegro et al. (*Computer Networks*, vol. 275, article 111957) using the original launcher and configuration style. Montenegro et al. ran on a server-grade Intel Xeon Silver 4214 (2.20 GHz), whereas our platform is a mobile-grade Intel Core i5-8250U (1.60–3.40 GHz); **absolute handshake latencies therefore differ substantially between the two testbeds and are not expected to match**. Reproducibility is instead assessed through the **relative KEM ranking**: the pure post-quantum KEM remains the fastest configuration and the hybrid KEM remains the slowest at every security tier, in both TLS and QUIC, matching the ranking reported by Montenegro et al. in every evaluated case (Table 3 of the paper).

| Protocol | Configuration          | Montenegro et al. (ms) | Ours (ms) | KEM ranking matches |
| -------- | ---------------------- | ----------------------- | --------- | -------------------- |
| TLS      | Ed25519 + ML-KEM512       | 2.49                     | 5.10      | ✓                     |
| TLS      | Ed25519 + p256_ML-KEM512  | 9.36                     | 21.83     | ✓                     |
| TLS      | secp384r1 + ML-KEM768     | 5.71                     | 13.94     | ✓                     |
| TLS      | secp521r1 + ML-KEM1024    | 11.09                    | 25.57     | ✓                     |
| QUIC     | Ed25519 + ML-KEM512       | 2.65                     | 2.52      | ✓                     |
| QUIC     | Ed25519 + p256_ML-KEM512  | 11.91                    | 16.22     | ✓                     |
| QUIC     | secp384r1 + ML-KEM768     | 3.96                     | 5.00      | ✓                     |

> **Note.** Earlier drafts of this README reported a ±3% absolute agreement with Montenegro et al.'s values; this was inconsistent with Table 3 above (absolute differences of up to ~2×, expected given the different CPU platforms) and has been corrected. The correct and only claim supported by our data is **preservation of the relative KEM ranking**, not absolute-value reproduction.


## 16. Supplementary Materials

The following materials are available in the repository and are not included in the main paper due to space constraints.

### 16.1 Supplementary Figures

| File or directory                     | Description                                                   |
| --------------------------------------- | --------------------------------------------------------------- |
| `mldsa-mlkem-study1/plots/ge_violin/` | GE-stable and GE-unstable violin plots for Study 1            |
| `mldsa-mlkem-study1/plots/`           | Additional ideal-condition and deployment figures for Study 1 |
| `mldsa-hqc-study2/plots/`             | HQC ideal-condition, constrained-network, and heatmap figures |
| `mldsa-hqc-study2/plots/ge_violin/`   | GE violin plots for Study 2, when generated                   |

### 16.2 Supplementary Data Files

| File                                                       | Description                                              |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `mldsa-mlkem-study1/Analysis/analysis_output.txt`          | Full statistics — Study 1 ideal conditions               |
| `mldsa-mlkem-study1/Analysis/analysis_africa_output.txt`   | Full statistics — Study 1 constrained networks           |
| `mldsa-mlkem-study1/Analysis/analysis_ge_output.txt`       | Full statistics — Study 1 GE models                      |
| `mldsa-hqc-study2/Analysis/analysis_hqc_output.txt`        | Full statistics — Study 2 ideal conditions               |
| `mldsa-hqc-study2/Analysis/analysis_hqc_africa_output.txt` | Full statistics — Study 2 constrained networks           |
| `mldsa-hqc-study2/Analysis/analysis_ge_output.txt`         | Full statistics — Study 2 GE models (see Section 12.3 for the known QUIC GE-unstable exclusion) |
| `resumption_study/analysis/`                               | Session-resumption analysis outputs                      |
| `compression_study/analysis/`                              | Certificate-compression analysis outputs, when available |
| `microbench/microbench_results.txt`                        | Isolated sign/verify micro-benchmark results — single source of truth for Table 4 of the paper |


## 17. Contact

| Role                                               | Name                | Email                                                             |
| ----------------------------------------------------- | ---------------------- | -------------------------------------------------------------------- |
| Lead author — experiments, code, analysis, writing | David Rive Tolokoum | [davidtolokoum8@gmail.com](mailto:davidtolokoum8@gmail.com)       |
| Co-author — validation, analysis                   | Yve Bruno MBEZOA    | [mbezoayvebruno@gmail.com](mailto:mbezoayvebruno@gmail.com)       |
| Supervisor / corresponding author                  | Hervé Talé Kalachi  | [herve.tale@univ-yaounde1.cm](mailto:herve.tale@univ-yaounde1.cm) |

Affiliations:

* Department of Computer Engineering, National Advanced School of Engineering (ENSPY/NASEY), University of Yaoundé I, Yaoundé, Cameroon.
* Department of Computer Science, Faculty of Sciences, University of Yaoundé I, Yaoundé, Cameroon.
