
# Post-Quantum TLS 1.3 and QUIC Handshakes under Constrained Networks: Combining ML-DSA with ML-KEM and HQC

> **David Rive Tolokoum**, **Yves Bruno MBEZOA**, **Hervé Talé Kalachi**  
> *Post-Quantum TLS 1.3 and QUIC Handshakes under Constrained Networks: Combining ML-DSA with ML-KEM and HQC*  

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Containers-blue.svg)](0-docker/)
[![OpenSSL / OQS](https://img.shields.io/badge/Cryptography-liboqs%20%2F%20oqsprovider-green.svg)](https://github.com/open-quantum-safe/)

---

## 1. Overview

This repository contains the official artifact package for a large-scale experimental study evaluating the combined impact of **ML-DSA** signatures (FIPS 204) with **ML-KEM** (FIPS 203) and **HQC** key encapsulation mechanisms in **TLS 1.3** and **QUIC** under constrained network conditions calibrated from field measurements conducted at ENSP Yaoundé using Orange and MTN Cameroon infrastructure.

The repository provides automated execution harnesses, Docker environments, raw captures, statistical analysis pipelines, and publication-ready plotting scripts supporting the results reported in the paper.

### Measurement Scale

| Experiment Type | Measurements | Details |
| :--- | :--- | :--- |
| **Full Handshakes** | **312,000+** | Sweep matrix ($N = 500$ per configuration) |
| **Session Resumption** | Measured separately | $N = 500$ per scenario ($0$-RTT / Ticket Resumption) |
| **Concurrent Load** | Measured separately | Multi-client concurrency stress ($1, 5, 10, 20, 50$ clients) |
| **KEM Families** | 2 | Lattice-based (**ML-KEM**) and Code-based (**HQC**) |
| **Security Tiers** | 3 | NIST Categories I, III, V (L1, L3, L5) |
| **Protocols** | 2 | TLS 1.3 (over TCP) and QUIC (over UDP) |
| **Network Scenarios** | 5 | Ideal, Moderate 4G, Degraded 4G, GE-stable, GE-unstable |

### Central Thesis

Post-quantum protocol performance **cannot be predicted from primitive micro-benchmarks alone**. Once post-quantum signatures are introduced, certificate size, packetization, retransmission behavior, and transport architecture fundamentally alter the relative ranking and latency profiles of TLS 1.3 and QUIC.

---

## 3. Repository Structure

```text
.
├── 0-docker/                     # Docker environment setup
│   ├── Dockerfile                # OpenSSL 3.4.2-dev + liboqs + oqsprovider + MsQuic
│   └── scripts/                  # Container test harnesses
│       ├── doCert.sh             # X.509 PQC certificate generator
│       ├── perftestServerTlsQuic.sh    # Server-side test runner
│       ├── perftestClientTlsQuic.sh    # Client-side test runner
│       ├── perftestClientConcurrent.sh # Concurrency client harness
│       └── perftestClientResumption.sh # Session resumption runner
├── captures/                     # Raw experimental data (logs, cgroup metrics, pcap)
│   ├── tls/                      # TLS 1.3 captures (single & mutual auth)
│   ├── quic/                     # QUIC captures (single auth)
│   ├── advanced_tests/           # Concurrency and resumption CSV outputs
│   ├── traffic_size/             # Single-connection pcap & sslkeys for frame analysis
│   └── orchestration_logs/       # Full campaign orchestration logs
├── launchers/                    # Executable shell harnesses
│   ├── run_all_scenario_tests.sh # Master automation runner (sweep + advanced + validation)
│   ├── run_microbenchmarks.sh    # Primitive speed microbenchmarks
│   ├── capture_traffic_matrix.sh # Traffic capture harness across SIG x KEM matrix
│   ├── capture_pcap_demo.sh      # Single-handshake Wireshark capture script
│   └── Collect_Session.sh        # Real-world 4G network session collection tool
├── scripts_analysis/             # Data processing and statistics scripts
│   ├── analyze_handshake_performance.py # Latency statistics, IC95, and overhead vs baseline
│   ├── analyze_resource_usage.py       # Container CPU/RAM cgroup metric aggregation
│   ├── analyze_concurrent_load.py       # Multi-client throughput and latency parser
│   ├── analyze_resumption.py            # Session resumption vs full handshake gains
│   ├── analyze_sessions.py             # Field session calibration and netem derivation
│   ├── parse_traffic_size.py            # tshark packet/frame size breakdown
│   └── parse_microbench.py              # OpenSSL speed parser
├── scripts_plotting/            # Publication-ready figure generation
│   ├── plot_global_kem_comparison.py    # Global overhead ratio (ML-KEM vs HQC)
│   ├── plot_global_network_sensitivity.py# Latency degradation under network impairment
│   ├── plot_global_sig_comparison.py    # ML-DSA vs Classical signature delta
│   ├── plot_handshake_latency.py        # CDF and boxplots for handshake duration
│   └── plot_resource_usage.py           # CPU/RAM usage bar charts
├── microbench_results/           # Raw and parsed openssl speed microbenchmarks
├── plots_global/                 # Exported vector figures (.pdf / .png)
├── results_traffic_size/         # Parsed network traffic matrices and reports
├── sessions/                     # Real-world 4G network calibration session captures
├── CITATION.cff                  # Citation metadata
├── docker-compose-localhost.yaml # Local docker compose configuration
├── Launcher_pq_mldsa_mlkem_hqc.sh# Main test execution harness (Sweep)
├── Launcher_advanced_tests.sh    # Advanced test orchestrator (Concurrency & Resumption)
└── Launcher_preflight_check.sh   # Diagnostic and sanity check script

```

---

## 4. Hardware and Software Stack

### Reference Testbed Machine

| Component | Specification |
| --- | --- |
| **Model** | HP ProBook 640 G4 |
| **CPU** | Intel Core i5-8250U @ 1.60 GHz (Turbo up to 3.40 GHz) |
| **ISA Extensions** | AVX2, AES-NI |
| **Cores** | 4 Physical / 8 Logical Threads |
| **RAM** | 24 GB DDR4 |
| **OS** | Ubuntu 24.04 LTS (Kernel 6.8) |
| **Container Engine** | Docker 26.1+ |

### Software Stack

| Component | Version / Source | Role |
| --- | --- | --- |
| **OpenSSL** | `3.4.2-dev` | TLS 1.3 protocol stack |
| **liboqs** | `0.12.0` | Post-quantum cryptographic primitives |
| **oqsprovider** | `0.8.0` | OpenSSL 3.x provider for PQC |
| **MsQuic** | Bundled in Docker | QUIC transport protocol stack |
| **tc/netem** | Linux Kernel | Network impairment injection (latency/loss) |
| **Pumba** | Bundled in Docker | Gilbert–Elliott burst-loss emulation |
| **Python** | `>= 3.10` | Statistical analysis & visualization (`pandas`, `matplotlib`, `numpy`) |

---

## 5. Installation and Setup

### Step 1 — Clone the Repository

```bash
git clone [https://github.com/TOLOKOUM/mldsa-mlkem-hqc-tls-quic-constrained-performance.git](https://github.com/TOLOKOUM/mldsa-mlkem-hqc-tls-quic-constrained-performance.git)
cd mldsa-mlkem-hqc-tls-quic-constrained-performance

```

### Step 2 — System Dependencies & Docker

```bash
sudo apt update
sudo apt install -y docker.io docker-compose tshark git python3 python3-pip python3-venv

sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"
# Note: Log out and log back in to apply docker group membership.

```

### Step 3 — Python Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install numpy pandas matplotlib seaborn

```

---

## 6. Execution & Reproducibility

### 1. Preflight Diagnostic Check

Before running large benchmarks, run the preflight script to verify Docker container networking, binary exit codes, and mutual authentication support:

```bash
./Launcher_preflight_check.sh both

```

### 2. Main Handshake Sweep (`Launcher_pq_mldsa_mlkem_hqc.sh`)

Executes automated handshake sweeps across cryptographic combinations ($N = 500$ runs per cell):

```bash
./Launcher_pq_mldsa_mlkem_hqc.sh <kem-family> <protocol> <auth-mode> <capture-mode> <network-profile> [loss-percent] [delay-ms]

```

* **Example 1 — Ideal Network (TLS 1.3, Server-Only Auth, ML-KEM & HQC):**
```bash
./Launcher_pq_mldsa_mlkem_hqc.sh both tls single nocapture none 0 0

```


* **Example 2 — Moderate 4G Scenario ($30.02\text{ ms}$ delay, $0.3\%$ loss):**
```bash
./Launcher_pq_mldsa_mlkem_hqc.sh both quic single nocapture simple 0.3 30.02

```


* **Example 3 — Burst-Loss Scenario (Gilbert-Elliott Unstable):**
```bash
./Launcher_pq_mldsa_mlkem_hqc.sh both tls single nocapture unstable 0 0

```



### 3. Advanced Tests & Full Automation

* **Run Concurrency and Session Resumption:**
```bash
./Launcher_advanced_tests.sh ideal

```


* **Run Master Campaign (Sweep + Concurrency + Resumption + Validation):**
```bash
./launchers/run_all_scenario_tests.sh ideal

```



---

## 7. Data Analysis & Figure Generation

Once benchmarks complete, process the raw logs and generate the figures presented in the paper using the analysis pipeline:

### 1. Statistical Processing

```bash
# Parse raw handshake logs to CSV
python3 scripts_analysis/logs_to_csv.py captures/tls/single/none/handshake_logs

# Calculate latencies, IC95, and overhead ratios
python3 scripts_analysis/analyze_handshake_performance.py captures/tls/single/none

# Extract CPU/RAM cgroup resource metrics
python3 scripts_analysis/analyze_resource_usage.py --input-dir captures/

# Parse frame sizes from captured pcaps
python3 scripts_analysis/parse_traffic_size.py --input-dir captures/traffic_size/

```

### 2. Plotting Paper Figures

```bash
# Generate Global KEM Overhead Comparison (Ratio vs Baseline)
python3 scripts_plotting/plot_global_kem_comparison.py

# Generate Network Sensitivity Curves (Ideal to GE-Unstable)
python3 scripts_plotting/plot_global_network_sensitivity.py

# Generate Signature Delta Comparison (ML-DSA vs Classical)
python3 scripts_plotting/plot_global_sig_comparison.py

# Generate CPU / RAM Usage Bar Charts
python3 scripts_plotting/plot_resource_usage.py

```

Outputs are written in vector PDF and high-resolution PNG formats to `plots_global/`.

---

## 8. Cryptographic Micro-benchmarks

To evaluate isolated primitive speed (keygen, sign, verify, encaps, decaps) independent of transport overheads:

```bash
# Execute OpenSSL speed benchmarks
./launchers/run_microbenchmarks.sh microbench_results 10

# Parse output into CSV/Markdown
python3 scripts_analysis/parse_microbench.py --input microbench_results/microbench_raw_*.txt

```

---

## Citation

If you use this artifact package, testbed scripts, or dataset in your research, please cite our paper as follows:

```bibtex
@article{tolokoum2026pqc_tls_quic,
  author    = {Tolokoum, David Rive and Mbezoa, Yves Bruno and Kalachi, Herv\'e Tal\'e},
  title     = {Post-Quantum TLS 1.3 and QUIC Handshakes under Constrained Networks: Combining ML-DSA with ML-KEM and HQC},
  journal   = {Submitted to Computer Networks},
  year      = {2026},
  note      = {Artifact package available at \url{[https://github.com/TOLOKOUM/mldsa-mlkem-hqc-tls-quic-constrained-performance](https://github.com/TOLOKOUM/mldsa-mlkem-hqc-tls-quic-constrained-performance)}}
}

```

---

## License

This project is open-source software licensed under the [MIT License](https://www.google.com/search?q=LICENSE).

```

```
