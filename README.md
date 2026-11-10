# Where Post-Quantum Authentication Costs Time: replication artifact

Artifact of: D. R. Tolokoum, Y. B. Mbezoa, H. Talé Kalachi, "Where Post-Quantum Authentication Costs Time: A Testbed Study of ML-DSA, ML-KEM, and HQC in TLS 1.3 and QUIC Handshakes".

- Raw data (large, not in git): Zenodo, doi:10.5281/zenodo.24109129 (version 2; all versions: doi:10.5281/zenodo.23977850).
- Pre-registration of campaign S: tag `prereg-S`.
- The design of the first version of this study (42 configurations, five network conditions) is kept under the tag `legacy-first-version`; this README describes the current study.

## Campaigns

| Campaign | Content | Raw data | Analysis outputs |
|---|---|---|---|
| A | Randomized campaign, 20 blocks, 24,440 visits, 343,800 connections | Zenodo (`captures_v2/`, not in git) | `analysis_v2/`, `scripts_analysis/`, `01_ingest.py`, `02_qc.py`, `04_confirmatory.py`, `ANALYSIS_PLAN.md` |
| B1 | Session resumption, level 3 | Zenodo (`captures_v3_resume/`) | `analysis_v3/p6_resume_*.csv` |
| B2 | Certificate compression, level 3 | Zenodo (`captures_v3_comp/`) | `analysis_v3/p6_comp_*.csv` |
| B3 | Concurrent load, 1-64 clients, level 3 | Zenodo (`captures_v3_load/`) | `analysis_v3/p6_load_*.csv` |
| S | Pre-registered threshold-crossing test (padded certificate chains), 24,000 connections | Zenodo version 2 (`campagne_S_donnees_brutes.tar.gz`) | `analysis_S/`, `analysis_S_hs/` |

Pilot runs of B1-B3 (`captures_v3_pilot/`, `captures_v3_load_pilot/`, `captures_v3_load_pilot3/`) are kept for transparency.

## Layout

- `0-docker/`, `Dockerfile.v3`, `Dockerfile.v3b`, `ctx_v3/`, `docker_ctx_overlay/`: testbed images.
- `Launcher_pq_mldsa_mlkem_hqc.sh`, `Launcher_ext.sh`, `run_campaign_ext.sh`, `make_plans_ext.sh`, `probe_features.sh`, `launchers/`, `plans/`, `plans_v3/`: launchers and randomized plans.
- `campaign_state*/`: per-campaign execution state (block, cell, visit, exit code, seed).
- `PREREGISTRATION_v3.md`, `PREREG_HASHES.txt`: pre-registration of B1-B3 and hashes of the registered files.
- `analysis/13_analyse_extensions.py`: analysis of B1-B3 (its SHA-256 prefix is quoted in the article).
- `seuil_S/`: campaign S. `PREREGISTRATION_S.md`, `freeze_S/` (frozen predictions), `DEVIATIONS_S.md` (post-freeze deviations), `analyse_seuil.py` (frozen analysis), `fw_segments.py`, `make_plan_S.py`, `phase0_check.py`, `predict_freeze.py`, `SHA256_GEL.txt`, `SHA256_DONNEES_BRUTES.txt`, `LISEZMOI_S.md`.
- `analysis_S/`: results of campaign S (`S_cells.csv`, `S_brackets.csv`, `S_controls.csv`, `S_endpoints.csv`, `S_monotonicity.csv`, `S_report.txt`, `S_staircase.pdf`, `mech/`, `mech_v3/`). `analysis_S_hs/`: the same analysis with the alternative handshake-time measure (`hs_ms`).
- `paper_figs/`: `make_fig14.py` regenerates the staircase figure of the article from `analysis_S/S_cells.csv` and `S_brackets.csv`.

## Post hoc analyses (not pre-registered)

`analysis/little_B3.py` (time per attempt in the closed-loop load test, using all attempts, from `analysis_v3/p6_load_niveaux.csv`) and `analysis/duree_echecs_B3.py` (duration of each load attempt from the client logs, QUIC) were written after the analyses were frozen.

## Integrity

Campaign S raw archive `campagne_S_donnees_brutes.tar.gz`: SHA-256 `a3bb2df9d952a89490842b84b3c0765737008512981b9b6e0b82101dd004b5f4`. Hashes of the frozen files: `seuil_S/SHA256_GEL.txt`; of the raw data: `seuil_S/SHA256_DONNEES_BRUTES.txt`.

## Scope and limits

One host, one software stack per protocol (OpenSSL for TLS, MsQuic for QUIC), emulated network. QUIC mutual authentication was not evaluated. The results describe this testbed; see the article for the deviations from the pre-registrations.

## Licence

MIT (see `LICENSE`).
