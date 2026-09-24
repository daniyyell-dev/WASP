# WASP data card

## Dataset summary

WASP contains longitudinal process snapshots from benign launches of trusted Windows binaries and a controlled evaluation set in which the same trusted image paths were observed under benign and injected conditions. The release is designed for research on runtime anomaly detection, binary-conditioned autoencoders, process-injection telemetry and leakage-aware evaluation.

## Composition

The benign partition contains 70,598 snapshots from 2,102 accepted launches across three Windows host profiles. There are 712 binary–host profile combinations: 225 on Windows 10, 238 on Windows 11 x64 and 249 on Windows Server 2016. This number is not a claim of 712 globally unique executable basenames because a trusted binary may occur on multiple hosts.

The controlled partition contains **63** matched experiments and **3,770** snapshots: **1,874** clean-condition and **1,896** injection-labelled. It spans three host profiles and four payload families (NimPlant, Cobalt Strike, AsyncRAT, Quasar RAT). Cobalt Strike contributes 27 C2-gated cells across nine declared injection techniques. Together with the longitudinal benign dataset, the release contains **74,368** snapshot rows.

## Unit of observation and independence

One row is one snapshot of one running process. Rows from the same launch share a pseudonymous `run_group_id` and are temporally correlated. Launches, not snapshots, are the defensible unit for splitting and uncertainty estimation. Each released host–payload–technique–binary cell is represented by one matched experiment in this matrix.

## Features and labels

The public feature schema is version 1.7.0. The release provides 70 core runtime features, an explicit binary missingness indicator for every core field, and 18 derived ratios or capability flags. Feature families include timing, working-set and commitment measurements, CPU and I/O deltas, memory-region classifications, private/writable executable memory, module counts, network endpoint counts, PEB image-base state and thread-context or thread-start locality. The longitudinal benign collection predates 22 schema-evolution fields; those feature values are blank throughout the benign partitions and their masks are one. The supplied frozen autoencoder has 63 inputs: 45 v1.4-era core fields plus the 18 derived fields. The other 25 public core fields comprise three deliberately excluded drift- or age-sensitive fields, one optional unsigned-image field and 21 fields introduced in v1.5--v1.7 after model training. Missingness indicators are availability metadata, not reconstruction targets.

The benign files are all-benign and therefore do not repeat a constant class label. The evaluation matrix uses `class_label` (`benign` or `injected`) and `label_injected` (0 or 1), plus payload family and technique metadata. Labels and experiment factors are excluded from model inputs.

## Collection and processing

Approved trusted binaries were independently launched in an authorised Windows laboratory. The collector sampled rapidly during process start and then at a slower steady cadence. Cumulative CPU and I/O counters were converted into adjacent-snapshot deltas within a run. Numeric features were exported with missing values left blank and accompanied by explicit masks. Direct host identifiers, original run timestamps, process IDs and artifact paths were replaced or removed for this public release. Cobalt Strike evaluation cells are retained only when malware snapshots show outbound lab C2 endpoints.

## Intended uses

- Study benign-only anomaly detection for trusted Windows processes.
- Evaluate grouping, preprocessing and thresholding strategies without row-level leakage.
- Analyse runtime memory indicators associated with controlled injection conditions.
- Reproduce descriptive figures and critically audit the manuscript's dataset counts.

## Uses outside scope

- Operational exploitation, payload deployment or instruction on performing process injection.
- Malware attribution or family classification from 63 experimental pairs.
- Claims of universal malware detection, production readiness or population-level error rates.
- Random snapshot-level train/test splitting.
- Automated blocking decisions without independent operational validation.

## Biases and limitations

The longitudinal benign dataset covers three laboratory OS profiles and trusted system binaries, not ordinary enterprise workloads. Host configuration, patch level, security products and idle-launch behaviour can shift the feature distribution. Many binaries have only a few launches. The controlled partition is uneven across families and hosts; some Cobalt Strike cells record a remote-thread compatibility fallback in private manifests while retaining the declared technique label. The capture cadence may miss short-lived transitions. Sixty pairs are scoreable by their matching enrolled host model; three Windows 10 `charmap_x86` pairs remain structural-only. This design does not establish universal separation or production performance.

## Privacy, safety and access

The release contains aggregate numeric telemetry only. Executables, payloads, credentials, network destinations, command lines, raw memory and offensive scripts are excluded. Raw JSONL remains gated outside this public dataset pending a separate minimisation, governance and licensing review.

## Distribution

Mendeley Data hosts the five numeric CSV partitions under `data/` at <https://doi.org/10.17632/gj8vp49xm5.1>. This GitHub repository hosts the data card, methods, ethics statement, feature schema, coverage tables, frozen metrics, baseline comparison and model receipts. Checksums in `SHA256SUMS` cover the repository metadata and the separately downloaded CSV files.

## Maintenance

Use immutable Mendeley Data versions for the CSV deposit. Any added host, run, payload family, technique, corrected row, altered field meaning or changed missingness convention requires a new dataset version and regenerated checksums. Never silently replace a published file.
