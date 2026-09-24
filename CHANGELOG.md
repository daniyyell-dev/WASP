# Changelog

## 0.2.1 — 2026-09-14

- Added C2-gated Cobalt Strike evaluation cells on all three hosts (27 experiments; nine techniques including core and expansion inject paths).
- Organised the release into a 70,598-row longitudinal benign dataset and a controlled paired dataset split into **1,874 controlled-clean** and **1,896 injection-labelled** snapshots from 63 matched experiments.
- The complete dataset now contains **74,368** snapshot rows (70,598 longitudinal benign + 3,770 controlled evaluation).
- Finalised citation metadata, the CC BY 4.0 licence declaration, data-only validation and Mendeley Data packaging.
- Restricted the Mendeley Data deposit to the `data/` CSV partitions. Docs, metadata and citation files remain in the GitHub reproducibility repository.
- Archived `WASP-v0.2.0-rc1` outside the public repository to avoid mixing release candidates.
- Updated README, data card and dataset summary for four payload families (NimPlant, Cobalt Strike, AsyncRAT, Quasar RAT).

## 0.2.0-rc1 — 2026-08-28

- Rebuilt the release from all 36 accepted matched pairs (1,809 rows: 890 benign and 919 injection-labelled).
- Added the nine accepted Server 2016 pairs omitted from the previous candidate.
- Removed the cross-architecture Character Map fallback: three unenrolled Windows 10 pairs remain public with blank AE fields and explicit structural-only status.
- Aligned frozen scores and seven-method baselines to the same 33 matching-host enrolled pairs (752 benign and 781 injection-labelled snapshots).
- Distinguished the public v1.7 schema (70 core fields, 70 masks and 18 derived fields) from the frozen model's 63 inputs (45 v1.4-era core fields plus 18 derived ratios or capability flags).
- Qualified ground truth: 35 pairs show structural displacement consistent with takeover; the sole unverified pair is retained.
- Prepared self-contained validation, metric-reproduction, figure-rendering and benign-only autoencoder-training tools for the separate GitHub repository.

## 0.1.0-rc2 — 2026-08-28

- Rebuilt the evaluation matrix from the completed 27-cell accepted injection dataset across Windows 10, Windows Server 2016 and Windows 11 x64.
- Expanded public evaluation from 13 to 27 matched benign/injected experiments (1,604 snapshot rows).
- Regenerated snapshot scores, thresholds, coverage metadata, checksums and archive.
- Replaced the stale four-pair baseline export with seven methods evaluated on the exact 27 released pairs.
- Added explicit `model_binary_id` disclosure for the three Windows 10 x86-to-x64 conditioning fallbacks.
- Corrected release documentation to reflect unequal retained condition lengths, 786 benign rows, 818 injected rows and four matched benign alerts.
- Corrected prose documentation to match the version 1.4.0 schema: 70 core features, 70 missingness indicators and 18 derived features.

## 0.1.0-rc1 — 2026-08-26

- Prepared the first sanitised data-release candidate.
- Included 70,598 benign numeric runtime snapshots from 2,102 launches.
- Included 1,196 rows from thirteen matched benign/injected evaluation experiments.
- Added explicit AsyncRAT, Quasar RAT and NimPlant quantitative coverage metadata.
- Retained complete, partial and missed frozen-model outcomes.
- Removed direct host/run identifiers, process IDs, timestamps and source paths.
- Excluded executable binaries, raw JSONL, C2 material, credentials and model files.
- Added sanitised model receipts supporting leakage-safe training and baseline analysis.
- Added per-snapshot v2 reconstruction scores, thresholds and decisions.
- Added machine-readable schema, feature dictionary, metrics and checksums.
