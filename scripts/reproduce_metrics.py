#!/usr/bin/env python3
"""Reproduce the paper's released-data detector and rule comparisons."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import beta, binomtest


PAIR_BOOTSTRAP_SEED = 20260828
PAIR_BOOTSTRAP_REPLICATES = 20000
CONTROLLED_DATA_FILES = (
    "data/controlled_paired_dataset/controlled_clean_snapshots.csv",
    "data/controlled_paired_dataset/injection_labelled_snapshots.csv",
)


def _rate(num: int, den: int) -> float:
    return float(num / den) if den else float("nan")


def _clopper_pearson(successes: int, trials: int, alpha: float = 0.05) -> list[float]:
    lower = 0.0 if successes == 0 else float(beta.ppf(alpha / 2, successes, trials - successes + 1))
    upper = 1.0 if successes == trials else float(beta.ppf(1 - alpha / 2, successes + 1, trials - successes))
    return [lower, upper]


def _confusion(frame: pd.DataFrame, decision: pd.Series) -> dict[str, float | int]:
    truth = frame["label_injected"].astype(int).to_numpy()
    pred = decision.astype(bool).to_numpy()
    tp = int(np.sum(pred & (truth == 1)))
    fp = int(np.sum(pred & (truth == 0)))
    tn = int(np.sum(~pred & (truth == 0)))
    fn = int(np.sum(~pred & (truth == 1)))
    precision = _rate(tp, tp + fp)
    recall = _rate(tp, tp + fn)
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "sensitivity": recall,
        "false_positive_rate": _rate(fp, fp + tn),
        "precision": precision,
        "f1": _rate(2 * precision * recall, precision + recall),
    }


def _pair_bootstrap(pair_counts: pd.DataFrame) -> dict[str, list[float]]:
    rng = np.random.default_rng(PAIR_BOOTSTRAP_SEED)
    values = pair_counts[["tp", "fn", "fp", "tn"]].to_numpy(dtype=np.int64)
    sensitivity = np.empty(PAIR_BOOTSTRAP_REPLICATES, dtype=float)
    fpr = np.empty(PAIR_BOOTSTRAP_REPLICATES, dtype=float)
    for index in range(PAIR_BOOTSTRAP_REPLICATES):
        sampled = values[rng.integers(0, len(values), size=len(values))].sum(axis=0)
        tp, fn, fp, tn = sampled
        sensitivity[index] = tp / (tp + fn)
        fpr[index] = fp / (fp + tn)
    return {
        "sensitivity_95_ci": np.quantile(sensitivity, [0.025, 0.975]).tolist(),
        "false_positive_rate_95_ci": np.quantile(fpr, [0.025, 0.975]).tolist(),
        "replicates": PAIR_BOOTSTRAP_REPLICATES,
        "seed": PAIR_BOOTSTRAP_SEED,
    }


def _median_log_ratio_bootstrap(log_ratios: pd.Series) -> dict[str, float | list[float] | int]:
    """Estimate a pair-level interval for the median injected/benign score ratio."""
    values = log_ratios.to_numpy(dtype=float)
    if not np.isfinite(values).all():
        raise RuntimeError("pair mean-score ratios must be finite and strictly positive")
    rng = np.random.default_rng(PAIR_BOOTSTRAP_SEED)
    draws = np.empty(PAIR_BOOTSTRAP_REPLICATES, dtype=float)
    for index in range(PAIR_BOOTSTRAP_REPLICATES):
        sampled = values[rng.integers(0, len(values), size=len(values))]
        draws[index] = np.median(sampled)
    log_interval = np.quantile(draws, [0.025, 0.975])
    return {
        "median_log10_ratio": float(np.median(values)),
        "median_injected_to_benign_mean_ratio": float(10 ** np.median(values)),
        "median_injected_to_benign_mean_ratio_95_ci": (10 ** log_interval).tolist(),
        "replicates": PAIR_BOOTSTRAP_REPLICATES,
        "seed": PAIR_BOOTSTRAP_SEED,
    }


def _subgroups(frame: pd.DataFrame, decision: pd.Series) -> dict[str, dict[str, dict[str, float | int]]]:
    dimensions = ("host_model", "payload_family", "technique_label")
    output: dict[str, dict[str, dict[str, float | int]]] = {}
    for dimension in dimensions:
        output[dimension] = {}
        for value, indices in frame.groupby(dimension).groups.items():
            selected = frame.loc[indices]
            output[dimension][str(value)] = _confusion(selected, decision.loc[indices])
    return output


def load_controlled_pairs(release_root: Path) -> pd.DataFrame:
    frames = [pd.read_csv(release_root / relative, low_memory=False) for relative in CONTROLLED_DATA_FILES]
    return pd.concat(frames, ignore_index=True)


def analyse(release_root: Path) -> tuple[dict, pd.DataFrame]:
    frame = load_controlled_pairs(release_root)
    scoreable = frame.loc[frame["score_status"].eq("scoreable")].copy()
    scoreable["ae_score"] = pd.to_numeric(scoreable["ae_score"], errors="raise")
    scoreable["ae_threshold"] = pd.to_numeric(scoreable["ae_threshold"], errors="raise")
    ae_decision = scoreable["ae_score"].ge(scoreable["ae_threshold"])
    if not np.array_equal(ae_decision.astype(int), scoreable["ae_flag"].astype(int)):
        raise RuntimeError("stored ae_flag values disagree with the inclusive score threshold")

    pair_rows: list[dict] = []
    count_rows: list[dict] = []
    for pair_id, pair in scoreable.groupby("pair_group_id", sort=True):
        benign = pair.loc[pair["label_injected"].eq(0)]
        injected = pair.loc[pair["label_injected"].eq(1)]
        benign_flag = benign["ae_score"].ge(benign["ae_threshold"])
        injected_flag = injected["ae_score"].ge(injected["ae_threshold"])
        threshold = float(pair["ae_threshold"].iloc[0])
        pair_rows.append(
            {
                "pair_group_id": pair_id,
                "host_model": pair["host_model"].iloc[0],
                "payload_family": pair["payload_family"].iloc[0],
                "technique_label": pair["technique_label"].iloc[0],
                "binary_id": pair["binary_id"].iloc[0],
                "threshold": threshold,
                "benign_rows": len(benign),
                "injected_rows": len(injected),
                "benign_mean_ratio": float(benign["ae_score"].mean() / threshold),
                "injected_mean_ratio": float(injected["ae_score"].mean() / threshold),
                "benign_max_ratio": float(benign["ae_score"].max() / threshold),
                "injected_min_ratio": float(injected["ae_score"].min() / threshold),
                "complete_injected_exceedance": bool(injected_flag.all()),
                "any_benign_alert": bool(benign_flag.any()),
                "injected_flagged": int(injected_flag.sum()),
                "benign_flagged": int(benign_flag.sum()),
            }
        )
        count_rows.append(
            {
                "pair_group_id": pair_id,
                "tp": int(injected_flag.sum()),
                "fn": int((~injected_flag).sum()),
                "fp": int(benign_flag.sum()),
                "tn": int((~benign_flag).sum()),
            }
        )
    pairs = pd.DataFrame(pair_rows)
    pair_counts = pd.DataFrame(count_rows)

    pair_successes = int(pairs["complete_injected_exceedance"].sum())
    pair_benign_alerts = int(pairs["any_benign_alert"].sum())
    mean_direction = pairs["injected_mean_ratio"].gt(pairs["benign_mean_ratio"])
    log_ratios = np.log10(pairs["injected_mean_ratio"] / pairs["benign_mean_ratio"])

    private_rule = pd.to_numeric(scoreable["executable_private_bytes"], errors="coerce").fillna(0).gt(0)
    writable_rule = pd.to_numeric(scoreable["writable_executable_bytes"], errors="coerce").fillna(0).gt(0)
    path_rule = pd.to_numeric(scoreable["image_path_backed_exec_ratio"], errors="coerce").lt(1)

    summary = {
        "analytical_unit_warning": "Snapshots are repeated measurements; matched pairs are the independent evaluation units.",
        "released_evaluation": {
            "rows": int(len(frame)),
            "pairs": int(frame["pair_group_id"].nunique()),
            "scoreable_rows": int(len(scoreable)),
            "scoreable_pairs": int(scoreable["pair_group_id"].nunique()),
        },
        "autoencoder_snapshot": _confusion(scoreable, ae_decision),
        "autoencoder_pair": {
            "complete_exceedance_pairs": pair_successes,
            "scoreable_pairs": int(len(pairs)),
            "complete_exceedance_rate": _rate(pair_successes, len(pairs)),
            "complete_exceedance_95_ci": _clopper_pearson(pair_successes, len(pairs)),
            "matched_benign_alert_pairs": pair_benign_alerts,
            "matched_benign_alert_rate": _rate(pair_benign_alerts, len(pairs)),
            "matched_benign_alert_95_ci": _clopper_pearson(pair_benign_alerts, len(pairs)),
        },
        "pair_cluster_bootstrap": _pair_bootstrap(pair_counts),
        "pair_score_separation": {
            "pairs_with_higher_injected_mean": int(mean_direction.sum()),
            "one_sided_exact_sign_p": float(binomtest(int(mean_direction.sum()), len(pairs), 0.5, alternative="greater").pvalue),
            **_median_log_ratio_bootstrap(log_ratios),
        },
        "fixed_rules": {
            "private_executable_bytes_gt_0": _confusion(scoreable, private_rule),
            "writable_executable_bytes_gt_0": _confusion(scoreable, writable_rule),
            "path_backed_execution_ratio_lt_1": _confusion(scoreable, path_rule),
        },
        "subgroups": _subgroups(scoreable, ae_decision),
    }
    return summary, pairs


def _report(summary: dict) -> str:
    snapshot = summary["autoencoder_snapshot"]
    pair = summary["autoencoder_pair"]
    bootstrap = summary["pair_cluster_bootstrap"]
    separation = summary["pair_score_separation"]
    rules = summary["fixed_rules"]
    return "\n".join(
        [
            "# WASP released-data reproduction",
            "",
            "> Snapshot rows are repeated measurements. The matched pair is the primary independent evaluation unit.",
            "",
            "## Frozen autoencoder",
            "",
            f"- Complete injected threshold exceedance: {pair['complete_exceedance_pairs']}/{pair['scoreable_pairs']} pairs ({100*pair['complete_exceedance_rate']:.1f}%).",
            f"- Snapshot sensitivity: {snapshot['tp']}/{snapshot['tp'] + snapshot['fn']} ({100*snapshot['sensitivity']:.1f}%).",
            f"- Matched-benign false-positive rate: {snapshot['fp']}/{snapshot['fp'] + snapshot['tn']} ({100*snapshot['false_positive_rate']:.2f}%).",
            f"- Pair-cluster sensitivity interval: {100*bootstrap['sensitivity_95_ci'][0]:.2f}--{100*bootstrap['sensitivity_95_ci'][1]:.2f}%.",
            f"- Pair-cluster false-positive interval: {100*bootstrap['false_positive_rate_95_ci'][0]:.3f}--{100*bootstrap['false_positive_rate_95_ci'][1]:.3f}%.",
            f"- Back-transformed median log-ratio: {separation['median_injected_to_benign_mean_ratio']:.0f} (95% pair-bootstrap CI {separation['median_injected_to_benign_mean_ratio_95_ci'][0]:.0f}--{separation['median_injected_to_benign_mean_ratio_95_ci'][1]:.0f}).",
            "",
            "## Fixed structural indicators",
            "",
            f"- Private executable bytes > 0: {rules['private_executable_bytes_gt_0']['tp']} injected and {rules['private_executable_bytes_gt_0']['fp']} benign alerts.",
            f"- Writable executable bytes > 0: {rules['writable_executable_bytes_gt_0']['tp']} injected and {rules['writable_executable_bytes_gt_0']['fp']} benign alerts.",
            f"- Path-backed execution ratio < 1: {rules['path_backed_execution_ratio_lt_1']['tp']} injected and {rules['path_backed_execution_ratio_lt_1']['fp']} benign alerts.",
            "",
            "These released-data checks reproduce detector decisions; they do not reconstruct withheld payloads, raw memory or private laboratory artefacts.",
            "",
        ]
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-root", type=Path, default=Path("data/wasp"))
    parser.add_argument("--output-dir", type=Path, default=Path("outputs"))
    args = parser.parse_args()
    summary, pairs = analyse(args.release_root.resolve())
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    pairs.to_csv(args.output_dir / "pair_results.csv", index=False)
    (args.output_dir / "REPORT.md").write_text(_report(summary), encoding="utf-8")
    print(_report(summary), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
