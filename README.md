# Where Post-Quantum Authentication Costs Time: A Testbed Study of ML-DSA, ML-KEM, and HQC in TLS 1.3 and QUIC Handshakes

> **David Rive Tolokoum**, **Yve Bruno Mbezoa**, **Hervé Talé Kalachi**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23977851.svg)](https://doi.org/10.5281/zenodo.23977851)

Replication package for the article above. It contains the Docker-based testbed, the campaign launchers and plans, the
pre-registration of the extension campaigns, every analysis and figure script, and the processed data behind the reported
numbers. The raw per-connection records and packet captures are too large for this repository and are deposited on
Zenodo (see [Data availability](#data-availability)).

## What was measured

| Campaign | Design | Size |
|---|---|---|
| **A** (main) | Randomized blocked design: 20 blocks, 137 cells; cell order and pair order are re-drawn in every block; sentinel visits measure drift | 24,440 visits, 343,800 connections |
| **B1** session resumption | 20 blocks, pre-registered | 28,400 records |
| **B2** certificate compression (RFC 8879) | 20 blocks, pre-registered | 44,400 records |
| **B3** concurrent load | Closed loop, one server core, persistent load generators | 1,280 load levels |

B1–B3 were pre-registered before the data were collected: [`PREREGISTRATION_v3.md`](PREREGISTRATION_v3.md), with the
hashes of the pre-registered files in [`PREREG_HASHES.txt`](PREREG_HASHES.txt). The inference unit is the block; intervals
are block bootstraps. The article lists the revised bands and the one vacuous bound.

## Data availability

| Where | What |
|---|---|
| **This repository** | Scripts, plans (`plans/`, `plans_v3/`), campaign state (`campaign_state*/`), processed data (`analysis_v2/`, `analysis_v3/`), pilot data, HQC-192 packet captures (`launchers/captures/`) |
| **Zenodo, [doi:10.5281/zenodo.23977851](https://doi.org/10.5281/zenodo.23977851)** (CC BY 4.0) | Raw data, listed below, with SHA-256 checksums in `CHECKSUMS_zenodo.sha256` |
| **Git tag `legacy-first-version`** | Data of the first version of the study (`captures/`, `results_*`), no longer in the working tree |

| Zenodo archive | Extracts to (repository root) |
|---|---|
| `raw_captures_v2_campaignA.tar.gz` | `captures_v2/` (campaign A) |
| `raw_captures_v3_resume_comp_B1_B2.tar.gz` | `captures_v3_resume/`, `captures_v3_comp/` |
| `raw_captures_v3_load_B3.tar.gz` | `captures_v3_load/` |
| `packet_captures_hqc192.tar.gz` | `launchers/captures/` (also committed here) |
| `campaign_logs.tar.gz` | `campagne_*.log`, `governor_watch.log` |

```bash
sha256sum -c CHECKSUMS_zenodo.sha256
for f in raw_captures_*.tar.gz campaign_logs.tar.gz; do tar -xzf "$f" -C /path/to/repository; done
```

## 1. Check the reported numbers (no raw data needed)

`port/` reproduces the sensitivity analyses and Figures 2, 3, 4 and 13 from the processed data in `analysis_v2/` and
`analysis_v3/`. Requirements: Python 3 with `pandas`, `numpy`, `matplotlib`.

```bash
pip install pandas numpy matplotlib
export DATA_DIR=$PWD            # repository root; files are found at any depth
export OUT_DIR=$PWD/port_out; mkdir -p "$OUT_DIR"
python3 port/sens2.py     # slopes: block means vs medians, with and without block 20
python3 port/acc.py       # visit / connection / failure accounting by family
python3 port/b1.py        # B1 slopes, RTT 50-150 (intention-to-treat and per-protocol)
python3 port/b1b.py       # B1 slopes, RTT 0-150
python3 port/b2.py        # B2 compression deltas, with and without block 5
python3 port/fig02.py     # Figure 2
python3 port/mkfigs.py    # Figures 3, 4 and 13
```

Point estimates are deterministic. Bootstrap interval bounds can differ by about 0.001 between numpy versions.

## 2. Repository map

```text
.
├── 0-docker/                    # image definition and in-container scripts (image uma-tls-quic-pq-34, campaign A)
├── Dockerfile.v3, Dockerfile.v3b, docker_ctx_overlay/, ctx_v3/   # images for B1-B2 (v3) and B3 (v3b); see README_v3.md
├── Launcher_pq_mldsa_mlkem_hqc.sh, Launcher_ext.sh               # handshake launchers (campaign A / extensions)
├── launchers/                   # run_campaign.sh, make_plans.sh, capture_pcap_demo.sh, capture_pcap_campaign.sh, ...
│   └── captures/                # HQC-192 packet captures with TLS key logs (RTT 50 ms, no loss)
├── run_campaign_ext.sh, make_plans_ext.sh, probe_features.sh     # extension campaigns B1-B3
├── plans/, plans_v3/            # campaign plans (A; B1-B3 and pilots)
├── campaign_state*/             # campaign execution state, one folder per campaign
├── pq_common.py                 # shared constants and statistics helpers
├── tools/                       # analysis pipeline for campaign A (01-09), see section 3
├── analysis/                    # analysis of B1-B3 (13_analyse_extensions.py, rapport_extensions.py)
├── analysis_v2/                 # processed outputs of campaign A (conn.csv.gz, visits.csv, QC, phase2-phase5)
├── analysis_v3/                 # processed outputs of B1-B3 (p6_*.csv, p6_connexions.csv.gz)
├── figures/                     # make_figures.py: all figures, see figures/README_figures.md
├── port/                        # portable scripts of section 1
├── PREREGISTRATION_v3.md, PREREG_HASHES.txt, ANALYSIS_PLAN.md
├── microbench_results/          # OpenSSL speed microbenchmarks
├── sessions/                    # field 4G calibration sessions (ping/iperf), first version
└── scripts_analysis/, scripts_plotting/   # scripts of the first version of the study (inputs at tag legacy-first-version)
```

`analysis/synth_ext.py` generates **synthetic** data to test the analysis pipeline. They are not measurements.

## 3. Re-run the analysis from the raw data

Extract `captures_v2/` from Zenodo first. Run from the repository root; `PYTHONPATH=.` lets `tools/` import `pq_common.py`.
Every script documents its options with `--help`.

```bash
pip install pandas numpy matplotlib scipy
PYTHONPATH=. python3 tools/01_ingest.py --root captures_v2 --state campaign_state/state.csv --plan plans/plan_all.csv --out analysis_v2
PYTHONPATH=. python3 tools/02_qc.py --ana analysis_v2 --root captures_v2 --state campaign_state/state.csv
PYTHONPATH=. python3 tools/04_confirmatory.py --in analysis_v2
python3 tools/05_figures.py --in analysis_v2/phase2 --out analysis_v2/figures --lang en
python3 tools/07_threshold_model.py --in analysis_v2 --out analysis_v2/phase3
python3 tools/08_robustesse_modele.py --phase3 analysis_v2/phase3
python3 tools/09_ressources.py --in analysis_v2 --out analysis_v2/phase4
```

| Script | Role |
|---|---|
| `01_ingest.py` | Raw captures to clean tables (`conn.csv.gz`, `visits.csv`, `manifests.csv`) and a completeness audit; estimates no effect |
| `02_qc.py` | Quality controls and pre-specified exclusion rules, applied before any contrast |
| `03_tls_loss_process.py` | Loss process actually experienced by TLS flows, from per-connection pcaps |
| `04_confirmatory.py` | Confirmatory contrasts per block, block bootstrap, Holm correction within families |
| `05_figures.py` | Figures and tables from the phase 2 CSVs |
| `06_flight_timeline.py` | Server flight (burst) timeline of TLS and QUIC from per-connection pcaps |
| `07_threshold_model.py` | Threshold model of the first server flight, tested on the held-out pairs |
| `08_robustesse_modele.py` | Robustness of the threshold model: trivial models, distance to the threshold, constant sweep |
| `09_ressources.py` | CPU, memory and packet cost; one value per visit, inference across blocks |
| `analysis/13_analyse_extensions.py` | B1-B3 analysis (`--root` takes one capture folder per arm) |

All figures can also be generated by `python3 figures/make_figures.py --list` and the commands in
[`figures/README_figures.md`](figures/README_figures.md).

## 4. Re-run the measurements

Requirements: Docker, Python 3.9+, `tshark` for packet captures. Campaign A used the image `uma-tls-quic-pq-34`
(`docker build -t uma-tls-quic-pq-34 -f 0-docker/Dockerfile 0-docker/`). The extension campaigns must follow the order in
[`README_v3.md`](README_v3.md): build the v3 image, probe the features, generate the plans with `make_plans_ext.sh`,
run a one-block pilot, freeze the pre-registration, then run 20 blocks per arm. The B3 generators need the `v3b` image,
built only when no measurement block is running (compilation distorts CPU measurements).

HQC-192 packet captures (RTT 50 ms is 25 ms per interface; no loss; MTU 1500) were produced with:

```bash
./launchers/capture_pcap_demo.sh quic mldsa65   hqc192 single delay-only 0 25
./launchers/capture_pcap_demo.sh quic secp384r1 hqc192 single delay-only 0 25
./launchers/capture_pcap_demo.sh tls  mldsa65   hqc192 single delay-only 0 25
./launchers/capture_pcap_demo.sh tls  secp384r1 hqc192 single delay-only 0 25
```

Each run writes a `.pcap`, an `_sslkeys.log` and a `.meta.txt` under `launchers/captures/pcap_demo/`. Open them in
Wireshark with the key log set in the TLS preferences.

## Known limitations

See the article's *Threats to Validity*. In brief: one implementation per protocol, one host and an emulated network; TLS
segmentation offload made realized loss lower than nominal in campaign A, so TLS loss results are secondary; the causes of
QUIC failures under overload and of the QUIC throughput dip at 8 concurrent connections are not established; the
HQC-192 packet captures were made after the campaigns, at one RTT, and do not read the sender's internal window.

## Citation and licenses

Cite via [`CITATION.cff`](CITATION.cff). Code: MIT ([`LICENSE`](LICENSE)). Raw data on Zenodo: CC BY 4.0.
