# Collection and processing methods

## Benign collection

The study enumerated eligible trusted executables from Windows system directories, applied safety exclusions, and attempted independent launches. Accepted benign launches were sampled approximately every 250 ms through the first 5 seconds and approximately every 1 second thereafter through a 20-second observation window. The matched evaluation runs used a 30-second window under the same initial burst cadence.

The three released benign matrices contain:

| Host profile | Binary–host profiles | Accepted launches | Snapshots |
|---|---:|---:|---:|
| `windows10` | 225 | 669 | 22,750 |
| `win11_x64` | 238 | 694 | 22,347 |
| `win2016_dc` | 249 | 739 | 25,501 |

Only accepted numeric feature rows are released. Failed launch artifacts and Windows executable copies are outside the package.

## Runtime feature construction

One output row represents one process snapshot. The 70 core features cover elapsed time, memory footprint, process resources, adjacent CPU/I/O deltas, memory-region aggregates, executable/private memory, loaded modules, network endpoints, PEB image-base properties and available thread-locality indicators. The release adds one explicit binary `<feature>__missing` mask per core feature and 18 deterministic derived values.

For a core feature `x`, a blank field is always paired with `x__missing = 1`; a present measurement normally has `x__missing = 0`. Missing does not mean zero. The longitudinal benign collection predates 22 schema-evolution fields introduced or retained in the wider v1.7 export. Those 22 feature values are blank for every benign row and their masks are explicitly set to one. They remain populated where available in the matched evaluation partition. Delta fields are absent in the first valid snapshot and are derived only from the preceding valid snapshot in the same run. The feature contract and preprocessing transform are specified in `metadata/feature_schema.json`; compact definitions are in `metadata/feature_dictionary.csv`.

## Pseudonymisation

Original host identifiers, filesystem paths, process IDs, timestamps and run names were removed. Each benign source run was mapped deterministically to a host-scoped sequential key such as `windows10-run-0001`. The mapping to original identifiers is not released. Binary IDs are retained because they are required categorical conditioning variables and identify common trusted Windows targets, not bundled executable files.

## Controlled side-by-side evaluation

The evaluation partition contains 63 accepted matched pairs and 3,770 snapshots: 1,874 benign and 1,896 injection-labelled. It covers 37 host–target profiles representing 24 distinct binary IDs across Windows 10, Windows Server 2016 and Windows 11 x64. The four payload families are NimPlant, Cobalt Strike, AsyncRAT and Quasar RAT. Nine declared techniques are represented. Cobalt Strike contributes 27 C2-gated experiments: the same nine-technique matrix on each of the three hosts. Exact factors and per-condition row counts are listed in `metadata/experiment_coverage.csv`.

Each pair contains a benign condition and an injection-labelled condition. Every process launch has a distinct `run_group_id`, while both conditions share an experiment-level `pair_group_id`. `model_binary_id` records the exact categorical profile used by the frozen model. Three Windows 10 `charmap_x86` pairs were not enrolled in that host model and therefore retain blank AE fields with `score_status=binary_not_enrolled`; no cross-architecture fallback is used. The package identifies the payload family and declared technique but contains no payload binary, network destination, C2 configuration or injection implementation.

## Interpretation of supplied metrics

The controlled paired dataset is stored as two condition-specific files: `data/controlled_paired_dataset/controlled_clean_snapshots.csv` contains 1,874 controlled-clean snapshots and `data/controlled_paired_dataset/injection_labelled_snapshots.csv` contains 1,896 injection-labelled snapshots. The same 63 `pair_group_id` values link the independently launched conditions across both files. `metadata/evaluation_metrics.json` is a sanitised descriptive export of the frozen v2 model-scoring report. It records score status for all 63 pairs and thresholds/confusion counts for the 60 pairs enrolled in their matching host model. The scoreable subset contains 1,736 controlled-clean and 1,758 injection-labelled snapshots. Using the implementation's inclusive threshold rule, the model flags 1,712 injection-labelled snapshots and seven controlled-clean snapshots; all injected snapshots meet or exceed threshold in 59 pairs. The remaining scoreable pair contributes all 46 injected false negatives. Three Windows 10 `charmap_x86` pairs are retained as structural-only data because the binary was not enrolled in the matching host model. The publication release requires `metadata/baseline_comparison.json` to cover the same 60 scoreable pairs for every declared comparison method. These outcomes are descriptive repeated-snapshot results, not population estimates, because the design contains one matched experiment per released cell and uneven row counts.

## Leakage controls for downstream analysis

1. Split by `run_group_id`, never by individual row.
2. Fit imputation, scaling, feature selection and thresholds on benign training groups only.
3. Keep all snapshots from one run in one partition.
4. Treat payload, technique, class and experiment fields as reporting metadata, not model inputs.
5. Report both snapshot counts and independent run or experiment counts.
6. Use run-level aggregation and run-level resampling for confirmatory inference.

## Reported model preparation

The code supplied separately through the WASP GitHub repository reproduces the corrected preparation contract. Complete launches are allocated to an approximately 70:30 temporal split within each binary identity. Schema transformations, missing-value medians, robust centres and interquartile scales are fitted only from the training runs. Scaled inputs are clipped to `[-20, 20]`, and injected observations never enter fitting or threshold calibration. `metadata/model_bundle_receipts.json` records the sanitised host-level parameters and source hashes without distributing model checkpoints.
