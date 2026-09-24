#!/usr/bin/env python3
"""Render public-data figures without private snapshots or model checkpoints."""

from __future__ import annotations

import argparse
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.lines import Line2D

from reproduce_metrics import analyse, load_controlled_pairs


BLUE = "#2F6B8A"
ORANGE = "#D97706"
RED = "#9F2D20"
INK = "#263238"
GRID = "#D9E1E5"


def _style() -> None:
    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 9,
            "axes.titlesize": 10,
            "axes.labelsize": 9,
            "axes.edgecolor": INK,
            "axes.linewidth": 0.7,
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
        }
    )


def _save(fig: plt.Figure, output_dir: Path, stem: str) -> None:
    fig.savefig(output_dir / f"{stem}.pdf", bbox_inches="tight")
    fig.savefig(output_dir / f"{stem}.png", dpi=350, bbox_inches="tight")
    plt.close(fig)


def render_pair_intervals(frame: pd.DataFrame, output_dir: Path) -> None:
    scoreable = frame.loc[frame["score_status"].eq("scoreable")].copy()
    scoreable["ratio"] = pd.to_numeric(scoreable["ae_score"]) / pd.to_numeric(scoreable["ae_threshold"])
    rows = []
    for pair_id, pair in scoreable.groupby("pair_group_id", sort=True):
        benign = np.log10(np.maximum(pair.loc[pair["label_injected"].eq(0), "ratio"], 1e-12))
        injected = np.log10(np.maximum(pair.loc[pair["label_injected"].eq(1), "ratio"], 1e-12))
        rows.append(
            {
                "label": f"{pair['host_model'].iloc[0]} / {pair['payload_family'].iloc[0]} / {pair['technique_label'].iloc[0]} / {pair['binary_id'].iloc[0]}",
                "b05": np.quantile(benign, 0.05),
                "b50": np.median(benign),
                "b95": np.quantile(benign, 0.95),
                "bmax": np.max(benign),
                "i05": np.quantile(injected, 0.05),
                "i50": np.median(injected),
                "i95": np.quantile(injected, 0.95),
                "imin": np.min(injected),
            }
        )
    rows.sort(key=lambda row: (row["imin"], row["label"]))
    y = np.arange(len(rows))
    fig, ax = plt.subplots(figsize=(9.2, 8.0))
    for index, row in enumerate(rows):
        ax.plot([row["b05"], row["b95"]], [index, index], color=BLUE, lw=1.2)
        ax.scatter(row["b50"], index, color=BLUE, s=12)
        ax.scatter(row["bmax"], index, color=BLUE, marker="x", s=18)
        ax.plot([row["i05"], row["i95"]], [index, index], color=RED, lw=1.2)
        ax.scatter(row["i50"], index, color=RED, s=12)
        ax.scatter(row["imin"], index, facecolor="white", edgecolor=RED, marker="D", s=20)
    ax.axvline(0, color=INK, ls="--", lw=1.0, label="Frozen threshold")
    ax.set_yticks(y, [row["label"] for row in rows], fontsize=6.3)
    ax.set_xlabel(r"log$_{10}$(AE score / frozen threshold)")
    ax.set_title(f"Released score intervals for all {len(rows)} scoreable matched pairs", loc="left")
    ax.legend(
        handles=[
            Line2D([], [], color=BLUE, marker="o", lw=1.2, label="Benign 5th-95th; median"),
            Line2D([], [], color=BLUE, marker="x", lw=0, label="Benign maximum"),
            Line2D([], [], color=RED, marker="o", lw=1.2, label="Injected 5th-95th; median"),
            Line2D([], [], color=RED, marker="D", markerfacecolor="white", lw=0, label="Injected minimum"),
        ],
        frameon=False,
        ncol=2,
        fontsize=7,
        loc="lower right",
    )
    ax.grid(True, axis="x", color=GRID, lw=0.55)
    ax.set_axisbelow(True)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    _save(fig, output_dir, "pair_score_intervals")


def render_detector_comparison(summary: dict, output_dir: Path) -> None:
    series = [
        ("Binary-conditioned AE", summary["autoencoder_snapshot"]),
        ("Private executable bytes > 0", summary["fixed_rules"]["private_executable_bytes_gt_0"]),
        ("Writable executable bytes > 0", summary["fixed_rules"]["writable_executable_bytes_gt_0"]),
        ("Path-backed ratio < 1", summary["fixed_rules"]["path_backed_execution_ratio_lt_1"]),
    ]
    y = np.arange(len(series))
    sensitivity = np.asarray([100 * row[1]["sensitivity"] for row in series])
    fpr = np.asarray([100 * row[1]["false_positive_rate"] for row in series])
    fig, ax = plt.subplots(figsize=(7.4, 3.0))
    height = 0.34
    ax.barh(y - height / 2, sensitivity, height, color=ORANGE, label="Sensitivity")
    ax.barh(y + height / 2, fpr, height, color=BLUE, label="Matched-benign FPR")
    for index, value in enumerate(sensitivity):
        ax.text(value + 0.7, index - height / 2, f"{value:.1f}", va="center", fontsize=8)
    for index, value in enumerate(fpr):
        ax.text(max(value + 0.7, 0.7), index + height / 2, f"{value:.2f}", va="center", fontsize=8)
    ax.set_yticks(y, [name for name, _ in series])
    ax.invert_yaxis()
    ax.set_xlim(0, 106)
    ax.set_xlabel("Matched-evaluation snapshot rate (%)")
    ax.set_title("Frozen autoencoder and direct structural indicators", loc="left")
    ax.legend(frameon=False, loc="upper center", bbox_to_anchor=(0.5, -0.23), ncol=2)
    ax.grid(True, axis="x", color=GRID, lw=0.55)
    ax.set_axisbelow(True)
    ax.spines[["top", "right"]].set_visible(False)
    fig.subplots_adjust(left=0.34, right=0.98, top=0.86, bottom=0.29)
    _save(fig, output_dir, "detector_comparison")


def render_sole_below_threshold(frame: pd.DataFrame, output_dir: Path) -> None:
    scoreable = frame.loc[frame["score_status"].eq("scoreable")].copy()
    scoreable["ratio"] = pd.to_numeric(scoreable["ae_score"]) / pd.to_numeric(scoreable["ae_threshold"])
    missed = None
    for _, pair in scoreable.groupby("pair_group_id", sort=True):
        injected = pair.loc[pair["label_injected"].eq(1)]
        if injected["ratio"].lt(1).all():
            missed = pair
            break
    if missed is None:
        raise RuntimeError("no entirely below-threshold scoreable pair found")
    benign = missed.loc[missed["label_injected"].eq(0)].sort_values("snapshot_sequence")
    injected = missed.loc[missed["label_injected"].eq(1)].sort_values("snapshot_sequence")
    fig, axes = plt.subplots(
        1,
        2,
        figsize=(7.2, 2.75),
        gridspec_kw={"wspace": 0.34},
        constrained_layout=True,
    )
    axes[0].plot(injected["snapshot_sequence"], injected["ratio"], color=RED, lw=1.8)
    axes[0].axhline(1, color=INK, ls="--", lw=1.0)
    axes[0].set_yscale("log")
    axes[0].set_xlabel("Released snapshot sequence")
    axes[0].set_ylabel("AE score / frozen threshold")
    axes[0].set_title("A  Subthreshold trajectory", loc="left")
    for values, colour, label in (
        (benign["ratio"], BLUE, "Matched benign"),
        (injected["ratio"], RED, "Injection-labelled"),
    ):
        x = np.sort(np.log10(np.maximum(values.to_numpy(dtype=float), 1e-12)))
        y = np.arange(1, len(x) + 1) / len(x)
        axes[1].step(x, y, where="post", color=colour, lw=1.8, label=label)
    axes[1].axvline(0, color=INK, ls="--", lw=1.0)
    axes[1].set_xlabel(r"log$_{10}$(AE score / frozen threshold)")
    axes[1].set_ylabel("Cumulative fraction")
    axes[1].set_title("B  Matched score distributions", loc="left")
    axes[1].legend(frameon=False, fontsize=7, loc="lower right")
    for ax in axes:
        ax.grid(True, color=GRID, lw=0.5)
        ax.set_axisbelow(True)
        ax.spines[["top", "right"]].set_visible(False)
    _save(fig, output_dir, "sole_below_threshold_pair")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-root", type=Path, default=Path("data/wasp"))
    parser.add_argument("--output-dir", type=Path, default=Path("outputs/figures"))
    args = parser.parse_args()
    _style()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    frame = load_controlled_pairs(args.release_root)
    summary, _ = analyse(args.release_root.resolve())
    render_pair_intervals(frame, args.output_dir)
    render_detector_comparison(summary, args.output_dir)
    render_sole_below_threshold(frame, args.output_dir)
    print(f"Wrote public figures to {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
