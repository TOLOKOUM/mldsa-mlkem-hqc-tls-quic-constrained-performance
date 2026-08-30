# Post-Quantum TLS 1.3 and QUIC Handshakes under Emulated Delay and Loss: Combining ML-DSA with ML-KEM and HQC

> **David Rive Tolokoum**, **Yve Bruno MBEZOA**, **Hervé Talé Kalachi**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Containers-blue.svg)](0-docker/)
[![OpenSSL / OQS](https://img.shields.io/badge/Cryptography-liboqs%20%2F%20oqsprovider-green.svg)](https://github.com/open-quantum-safe/)

---

This repository is the full artifact for the paper evaluating **ML-DSA**
signatures combined with **ML-KEM** and **HQC** in **TLS 1.3** and **QUIC**,
under an ideal baseline, two field-calibrated constrained-network scenarios,
and two Gilbert–Elliott burst-loss regimes. It contains the Docker-based
testbed, the full execution harness, every analysis and figure-generation
script, and the raw/processed results underlying every table and figure in
the paper — including the statistical audit and reanalysis scripts written
in response to peer review (measurement-completeness audit, paired-block
statistical tests, TLS/QUIC timer-gap quantification, and censoring
reanalysis).

The campaign covers 42 signature×KEM configurations across 3 NIST security
levels (L1/L3/L5), 5 network scenarios, and 2 authentication modes (TLS
single/mutual, QUIC single only — see [Known limitations](#known-limitations)),
collected as 4 randomized blocks of 125 runs each.

---

## Repository structure

```text
.
├── 0-docker/                        # Docker image definition + in-container test scripts
│   ├── Dockerfile
│   └── scripts/                     # doCert.sh, perftestServerTlsQuic.sh, perftestClientTlsQuic.sh, ...
├── captures/                        # Experimental output (tracked in git; see note below)
│   ├── tls/{single,mutual}/<scenario>/
│   │   ├── handshake_logs/          # Raw per-execution handshake logs (.log)
│   │   ├── csv/                     # Per-block handshake CSVs (execution, duration, success, block_index, n_blocks)
│   │   └── analyse/                 # handshake_stats.csv, handshake_overhead.csv, significance_tests_auto.csv,
│   │                                 #   signature_paired_comparisons.csv, handshake_report.md
│   ├── quic/single/<scenario>/      # Same layout as tls/ (no quic/mutual/ — see Known limitations)
│   ├── pcap_demo/<scenario>/{tls,quic}/single/
│   │                                 # One decrypted .pcap + NSS keylog (*_sslkeys.log) per configuration,
│   │                                 #   for Ideal/Moderate/Degraded — underlies the exact message-size
│   │                                 #   table and the TLS/QUIC timer-gap measurement (see Statistical
│   │                                 #   audit trail below)
│   └── tls/auth_cost_none.csv       # Single-vs-mutual paired comparison output (see analyze_auth_cost.py)
├── launchers/                       # Secondary/utility shell scripts
│   ├── run_microbenchmarks.sh       # Raw OpenSSL-speed primitive benchmarking
│   ├── capture_pcap_campaign.sh     # Produces the full captures/pcap_demo/ matrix (42 configs × 3 scenarios × 2 protocols)
│   ├── capture_pcap_demo.sh         # Single-handshake capture for manual inspection
│   ├── capture_traffic_matrix.sh    # Traffic-size capture matrix (single connection per config)
│   ├── analyze_traffic_size.sh      # Manual tshark breakdown of a single pcap (diagnostic use)
│   └── Collect_Session.sh           # Field 4G session capture (ping/iperf), see sessions/
├── scripts_analysis/                # Log parsing, statistics, and CSV aggregation
│   ├── logs_to_csv.py                    # handshake_logs/*.log -> csv/*.csv (one row per execution)
│   ├── analyze_handshake_performance.py  # handshake_stats.csv / handshake_overhead.csv /
│   │                                      #   significance_tests_auto.csv / signature_paired_comparisons.csv
│   ├── compare_distributions.py          # Formal hypothesis tests: Mann-Whitney/Cliff's delta (inter-scenario),
│   │                                      #   paired block bootstrap + exact permutation test on Δ (same KEM,
│   │                                      #   sig varies), independent-sample block bootstrap (auth-mode compare)
│   ├── analyze_auth_cost.py              # Single-vs-mutual TLS cost, two-independent-sample block bootstrap
│   ├── audit_measurement_totals.py       # Closes the full-campaign measurement count against raw per-block CSVs
│   ├── block_variance_report.py          # Inter-/intra-block variance ratio + lag-1 autocorrelation audit
│   ├── measure_timer_asymmetry.py        # TLS/QUIC HandshakeFlightEnd-vs-HANDSHAKE_DONE gap from pcap_demo/
│   ├── analyze_censoring.py              # RMST reanalysis: cost of excluding failed handshakes, at a common deadline
│   ├── Analyze_resource_usage.py         # Aggregates cgroup CPU/mem into resource_usage_*.csv
│   ├── parse_traffic_size.py             # tshark-based handshake byte-size breakdown (pcap -> csv)
│   ├── parse_handshake_logs.py
│   ├── parse_microbench.py
│   └── analyze_sessions.py               # Pools/filters raw 4G field sessions (sessions/) into scenario calibration
├── scripts_plotting/                # Publication-ready figure generation
│   ├── plot_style.py                # Shared palette/typography/layout/KEM-classification module — imported by all others
│   ├── plot_handshake_latency.py
│   ├── plot_traffic_size.py
│   ├── plot_resource_usage.py
│   ├── plot_global_kem_comparison.py
│   ├── plot_global_sig_comparison.py
│   └── plot_global_network_sensitivity.py
├── results/                         # Field-calibration pipeline output (scenarios_reels.csv, sessions_summary.csv,
│                                     #   rapport_methodologique.md)
├── results_resources/               # Aggregated CPU/RAM (resource_by_combo.csv, resource_summary.csv)
├── results_traffic/                 # Aggregated message-size breakdown + figures
├── plots_global/                    # Cross-scenario / cross-level synthesis figures
├── microbench_results/              # Raw and parsed openssl-speed microbenchmarks
├── sessions/                        # Raw field 4G calibration captures (MTN/Orange, ping+iperf logs)
├── docker-compose-localhost.yaml
├── Launcher_pq_mldsa_mlkem_hqc.sh   # Main sweep harness
├── CITATION.cff
└── LICENSE
```

> **Note on `captures/`:** unlike some earlier internal notes on this
> project, `captures/` is tracked in git (raw `.pcap`/`.pcapng` files are
> excluded via `.gitignore`; everything else — CSVs, keylogs, and generated
> reports — is kept, since several statistical-audit scripts and the
> paper's Data Availability statement reference specific files under it).

---

## Prerequisites

- **Docker** (with cgroup CPU/memory accounting enabled)
- **[Pumba](https://github.com/alexei-led/pumba)**, for `netem`/Gilbert-Elliott network impairment
- **tshark** — `sudo apt-get install -y tshark` (used by `parse_traffic_size.py`, `measure_timer_asymmetry.py`, and `analyze_traffic_size.sh`)
- **Python 3.9+** with `pandas`, `numpy`, `matplotlib`
- A pre-built OQS-enabled test image (`uma-tls-quic-pq-34`, or your own tag) — built from `0-docker/Dockerfile`

```bash
pip install pandas numpy matplotlib
docker build -t uma-tls-quic-pq-34 -f 0-docker/Dockerfile 0-docker/
```

> **Run everything from the repository root.** Every analysis/plotting
> script resolves `captures/`, `results*/`, and `plots_global/` relative to
> the current working directory. Always invoke as
> `python3 scripts_analysis/<script>.py` (or `scripts_plotting/...`) from
> the repo root.

---

## Quick start

### 1. Preflight check and main harness

```bash
./Launcher_pq_mldsa_mlkem_hqc.sh <kem_family> <protocol> <auth_mode> <capture_mode> <network_profile> [loss_pct] [delay_ms]
```

| Parameter | Values | Notes |
|---|---|---|
| `<kem_family>` | `mlkem`, `hqc`, `both` | `both` runs classical + hybrid + pure-PQC for every KEM family |
| `<protocol>` | `tls`, `quic` | |
| `<auth_mode>` | `single`, `mutual` | QUIC currently only has `single`-auth captures |
| `<capture_mode>` | `nocapture`, `captureKey`, `capture` | `nocapture` is required for the full 500-execution statistical sweep |
| `<network_profile>` | `none`, `simple`, `stable`, `unstable` | `none` = Ideal; `simple` = static loss/delay (needs the two optional args); `stable`/`unstable` = Gilbert-Elliott |
| `[loss_pct]`, `[delay_ms]` | e.g. `1.3`, `62.51` | Only used when `<network_profile>` is `simple` |

```bash
# Ideal network, TLS 1.3, single-auth, full statistical sweep (ML-KEM + HQC)
./Launcher_pq_mldsa_mlkem_hqc.sh both tls single nocapture none

# Moderate 4G profile (MTN, field-calibrated: 1.3% loss, 62.51ms one-way delay), QUIC
./Launcher_pq_mldsa_mlkem_hqc.sh both quic single nocapture simple 1.3 62.51

# Degraded 4G profile (Orange, field-calibrated: 1.5833% loss, 83.52ms one-way delay), TLS mutual
./Launcher_pq_mldsa_mlkem_hqc.sh both tls mutual nocapture simple 1.5833 83.52

# Gilbert-Elliott unstable profile, TLS mutual auth
./Launcher_pq_mldsa_mlkem_hqc.sh both tls mutual nocapture unstable
```

**Resuming an interrupted run.** The launcher is idempotent: it skips any
`(sig_alg, kem)` combination already present in the target scenario's
`resource_usage_*.csv`. Re-issue the exact same command to resume.

### 2. Representative packet captures (message size + timer-gap analysis)

```bash
./launchers/capture_pcap_campaign.sh   # produces captures/pcap_demo/{none,simple_*}/{tls,quic}/single/
```

One decrypted `.pcap` + NSS keylog per configuration, for Ideal/Moderate/
Degraded, both protocols. This is the input to `measure_timer_asymmetry.py`
and to the exact message-size table.

---

## Data pipeline: capture → analysis → figures

### Stage 1 — Raw logs to CSV

```bash
python3 scripts_analysis/logs_to_csv.py captures/tls/single/none/handshake_logs
python3 scripts_analysis/logs_to_csv.py captures --all   # recursively, every scenario
```

### Stage 2 — Statistics and aggregation

```bash
python3 scripts_analysis/analyze_handshake_performance.py captures/tls/single/none
python3 scripts_analysis/Analyze_resource_usage.py --input-dir captures/
python3 scripts_analysis/parse_traffic_size.py --input-dir captures/pcap_demo --out-dir results_traffic/
```

Per scenario, `analyze_handshake_performance.py` writes, under
`captures/<protocol>/<auth_mode>/<scenario>/analyse/`:

| File | Content |
|---|---|
| `handshake_stats.csv` | Mean/median/p95/p99 + block-bootstrap 95% CI per configuration |
| `handshake_overhead.csv` | Overhead vs. pooled classical baseline, same level |
| `significance_tests_auto.csv` | PQ-vs-classical-baseline Cliff's delta, block-bootstrap CI (systematic sweep, BH-corrected) |
| `signature_paired_comparisons.csv` | Classical-vs-ML-DSA, same KEM/level, Δ by paired block bootstrap + exact permutation test |
| `handshake_report.md` | Human-readable summary of all of the above |

### Stage 3 — Statistical audit trail

These scripts answer specific methodological points raised in peer review;
each is a pure reanalysis of already-collected data (no new measurements):

```bash
# Closes the total-measurement count against the raw per-block CSVs
python3 scripts_analysis/audit_measurement_totals.py --root captures/ --out audit_report.csv

# Inter-/intra-block variance ratio and lag-1 autocorrelation (justifies the 4-block design)
python3 scripts_analysis/block_variance_report.py --root captures/ --out block_variance.csv

# TLS/QUIC HandshakeFlightEnd vs. HANDSHAKE_DONE gap, from captures/pcap_demo/
python3 scripts_analysis/measure_timer_asymmetry.py --root captures/pcap_demo --out timer_asymmetry.csv

# Single-vs-mutual TLS cost, two-independent-sample block bootstrap
python3 scripts_analysis/analyze_auth_cost.py --single-dir captures/tls/single/none --mutual-dir captures/tls/mutual/none --out captures/tls/auth_cost_none.csv

# Cost of excluding failed handshakes (RMST at a common deadline)
python3 scripts_analysis/analyze_censoring.py --root captures/ --deadline-ms 5000 --out censoring_report.csv
```

### Stage 4 — Figures

All figure scripts import `scripts_plotting/plot_style.py` (colorblind-safe
palette, typography, KEM-family classification/sorting shared everywhere).

| Script | Scope | Output |
|---|---|---|
| `plot_handshake_latency.py` | Per protocol × auth mode × scenario × level | `captures/<protocol>/<auth_mode>/<scenario>/plots/handshake_*.pdf` |
| `plot_traffic_size.py` | Global, single auth only | `results_traffic/plots/traffic_size_{classical,pq}_sig.pdf` |
| `plot_resource_usage.py` | Per protocol × auth mode × scenario × level | `captures/<protocol>/<auth_mode>/<scenario>/plots/resource_{cpu,mem}_*.pdf` |
| `plot_global_kem_comparison.py` | Cross-level, ideal network only | `plots_global/kem_family_overhead_by_level.pdf` |
| `plot_global_sig_comparison.py` | Cross-level, ideal network only, paired by KEM | `plots_global/sig_family_latency_delta_by_level.pdf` |
| `plot_global_network_sensitivity.py` | Cross-scenario, cross-level | `plots_global/network_sensitivity_by_level.pdf` |

Every figure is written as a vectorial PDF (`pdf.fonttype: 42`) and a
300 dpi PNG.

---

## Network profile reference

| Directory name | Label used in the paper | Description |
|---|---|---|
| `none` | Ideal | No delay, no loss |
| `simple_loss1.3_delay62.51ms` | Moderate | MTN 4G, Yaoundé — pooled, IQR-filtered field calibration (5/6 sessions) |
| `simple_loss1.5833_delay83.52ms` | Degraded | Orange 4G, Yaoundé — pooled, IQR-filtered field calibration (6/6 sessions) |
| `stable` | GE-Stable | Gilbert–Elliott burst-loss, mild parameters (20.0% marginal loss) |
| `unstable` | GE-Unstable | Gilbert–Elliott burst-loss, severe parameters (43.3% marginal loss) |

One-way delay is applied symmetrically on both container interfaces (so
round-trip delay matches the field-measured RTT); loss is injected
asymmetrically, server-to-client only. Raw field-calibration sessions
(ping/iperf logs, 12 sessions across 2 operators) are under `sessions/`;
`analyze_sessions.py` reproduces the pooled/IQR-filtered values above.

---

## Known limitations

These are documented in detail in the paper (Threats to Validity); briefly:

- **QUIC mutual authentication is not available.** `quics_connection`
  accepts the relevant client-cert flags without erroring, but never
  actually presents the client certificate — confirmed by cross-checking
  wire-level logs, not by trusting the exit code. All QUIC results in the
  paper are single-authentication.
- **The GE-Stable/GE-Unstable qdisc-verification safeguard** (poll-and-abort
  on injection failure) is not applied to the stationary-loss path
  (Moderate/Degraded); see the paper's Threats to Validity for the exact
  scope of this asymmetry.
- **TLS and QUIC handshake timers measure different RFC 9001 events**
  (`handshake complete` vs. `handshake confirmed`); `measure_timer_asymmetry.py`
  and `captures/pcap_demo/` provide a direct, quantified bound on this gap
  rather than leaving it unquantified.
- One randomized block out of 2,520 (`secp521r1`/`p521_hqc256`, Moderate,
  TLS mutual, block 4/4) is missing from the capture directory and is
  excluded from every statistic, per `audit_measurement_totals.py`.

---

## Data integrity notes

- **`Launcher_pq_mldsa_mlkem_hqc.sh` appends to `resource_usage_*.csv`, it never overwrites it.** Re-running on an already-complete scenario adds duplicate rows for re-executed combinations; the idempotent skip check prevents this for interrupted-run resumes, but a fully intentional re-run should start from a clean file.
- **Decimal-comma corruption**: under a French/EU locale, the shell-side `awk printf "%.3f"` formatting in resource-usage collection can emit a comma instead of a dot in `cpu_usec_per_handshake`, splitting that field into two CSV columns. Mechanical and reversible; repair before analysis on an affected file.
- Every plotting/analysis script validates its input structure and prints an explicit `[ATTENTION]`/`[!]` rather than silently producing a biased or incomplete result. Treat any such message as blocking.
- All CSV schemas referenced by the statistical-audit scripts assume the per-block columns `execution, mode, handshake_duration_ms, success, block_index, n_blocks`, produced by `logs_to_csv.py`.

---

## Citation

See [`CITATION.cff`](./CITATION.cff) for citation metadata.

## License

See [`LICENSE`](./LICENSE) for licensing terms.
