# WASP - Windows Adversarial Simulation of Process Injection

![WASP — Adversarial Process-Injection Snapshots](assets/images/wasp-c2-connections-thumbnail.png)

Defensive analysis code, documentation and machine-readable metadata for the
WASP dataset: repeated runtime snapshots of trusted Windows binaries under
normal execution and controlled, authorised process-injection conditions.
**WASP** stands for **Windows Adversarial Simulation of Process Injection**.

## Dataset

The five CSV files are published separately on Mendeley Data:

> Jeremiah, Daniel; Rafiq, Husnain; Ta, Vinh Thong; Okoyeigbo, Obinna;
> Akande, Jamiu (2026),
> “WASP: Adversarial Process-Injection Snapshots from Trusted Windows Binaries”,
> Mendeley Data, V1. https://doi.org/10.17632/gj8vp49xm5.1

The repository does not distribute Windows executables, payloads, injectors,
raw memory, operational C2 configuration, credentials, network destinations or
instructions for reproducing the adversarial activity.

## Dataset structure

Download and extract the Mendeley Data deposit. Its structure is:

```text
data/
├── longitudinal_benign_dataset/
│   ├── windows10.csv
│   ├── win2016_dc.csv
│   └── win11_x64.csv
└── controlled_paired_dataset/
    ├── controlled_clean_snapshots.csv
    └── injection_labelled_snapshots.csv
```

The longitudinal partition contains 70,598 benign snapshots from 2,102 process
launches. It supports analysis of how trusted Windows binaries behave under
normal conditions across Windows 10, Windows Server 2016 and Windows 11.

The controlled partition contains 1,874 clean-condition and 1,896
injection-labelled snapshots from 63 matched experiments. The two conditions
were independently launched; `pair_group_id` associates conditions from the
same experiment, while `run_group_id` identifies snapshots from one launch.

## Quick start

Python 3.11 is recommended.

```bash
git clone https://github.com/daniyyell-dev/WASP.git
cd WASP
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Place the extracted deposit at `data/wasp/data/`, or provide its parent
directory explicitly with `--release-root`:

```bash
python scripts/validate_release.py --release-root data/wasp
python scripts/reproduce_metrics.py --release-root data/wasp --output-dir outputs
python scripts/render_figures.py --release-root data/wasp --output-dir outputs/figures
```

The validation command checks the five files, schema, row counts, grouping,
missingness masks, disclosure boundaries and hashes. The reproduction command
creates `summary.json`, `pair_results.csv` and `REPORT.md`. The figure command
creates three publication-result figures.

## Correct use of the data

1. Keep every `run_group_id` in one data split; snapshots from the same launch
   are repeated measurements, not independent samples.
2. Keep both conditions of each controlled experiment together using
   `pair_group_id` when splitting or resampling.
3. Fit imputation, scaling, feature selection and thresholds on training data
   only. Do not use labels, payload names, techniques, host identifiers,
   timestamps or grouping keys as predictors.
4. Use the longitudinal files for benign-only learning and the controlled files
   for defensive comparison. Report both snapshot-level results and counts of
   independent launches or experiments.

See [`docs/DATA_CARD.md`](docs/DATA_CARD.md) and
[`docs/METHODS.md`](docs/METHODS.md) for the complete feature and evaluation
contract.

## Autoencoder notebook and training

For the interactive workflow, install the notebook dependencies and set the
dataset location if it differs from `data/wasp/data`:

```bash
python -m pip install -r requirements-notebook.txt
export WASP_DATA_ROOT=/path/to/extracted/data
jupyter notebook notebooks/autoencoder_benign_injection.ipynb
```

For command-line training:

```bash
python scripts/train_autoencoder.py \
  --release-root data/wasp \
  --output-root models \
  --device cpu
```

Training uses complete run groups, training-only preprocessing, a 63-input
binary-conditioned autoencoder and benign-only threshold calibration. Exact
weights may vary across software and hardware. The frozen `ae_score`,
`ae_threshold` and `ae_flag` fields reproduce the published decisions without
requiring the withheld model checkpoints.

Expected frozen-score results are 59/60 completely detected scoreable pairs,
1,712/1,758 flagged injection-labelled snapshots and 7/1,736 flagged matched
clean snapshots. These are descriptive laboratory results, not production
false-positive estimates.

## Repository contents

| Path | Purpose |
|---|---|
| `scripts/validate_release.py` | Validate structure, counts, hashes and disclosure boundaries |
| `scripts/reproduce_metrics.py` | Reproduce frozen-score and structural-indicator results |
| `scripts/render_figures.py` | Generate three result figures |
| `scripts/train_autoencoder.py` | Train host-specific autoencoders |
| `scripts/model.py` | Define the binary-conditioned autoencoder |
| `notebooks/autoencoder_benign_injection.ipynb` | Interactive training and evaluation workflow |
| `config/model.json` | Public training configuration |
| `metadata/` | Schema, coverage, metrics, comparisons and model receipts |
| `docs/` | Data card, methods, ethics and dataset licence |
| `SHA256SUMS` | Checksums for repository metadata and Mendeley CSV files |

## Safety and licences

This release is for defensive research. Its labels describe authorised
laboratory conditions and do not support malware attribution, universal
detection claims or automated blocking without independent validation.

Code is licensed under the MIT License. The Mendeley Data dataset is licensed
under CC BY 4.0. See [`docs/ETHICS_AND_ACCESS.md`](docs/ETHICS_AND_ACCESS.md)
and [`docs/LICENSE_DATASET.md`](docs/LICENSE_DATASET.md).
