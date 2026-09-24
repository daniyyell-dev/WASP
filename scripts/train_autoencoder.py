#!/usr/bin/env python3
"""Train the published 63-input binary-conditioned AE from benign release CSVs."""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from torch.utils.data import DataLoader, TensorDataset

from model import (
    AutoencoderArchitecture,
    BinaryConditionedAutoencoder,
    seed_everything,
    select_device,
)


DEFAULT_HOSTS = ("windows10", "win11_x64", "win2016_dc")


def _transform(values: np.ndarray, name: str, epsilon: float) -> np.ndarray:
    output = values.astype(np.float64, copy=True)
    present = np.isfinite(output)
    selected = output[present]
    if name in {"log1p_then_robust_scale", "adjacent_delta_then_log1p_then_robust_scale"}:
        if np.any(selected < 0):
            raise ValueError(f"{name} received a negative value")
        output[present] = np.log1p(selected)
    elif name == "signed_log1p_absolute_then_robust_scale":
        output[present] = np.sign(selected) * np.log1p(np.abs(selected))
    elif name == "fixed_epsilon_logit_then_robust_scale":
        if np.any((selected < 0) | (selected > 1)):
            raise ValueError(f"{name} received a value outside [0, 1]")
        clipped = np.clip(selected, epsilon, 1 - epsilon)
        output[present] = np.log(clipped / (1 - clipped))
    elif name != "identity_then_robust_scale":
        raise ValueError(f"unsupported transform: {name}")
    return output


def _grouped_split(frame: pd.DataFrame) -> tuple[np.ndarray, np.ndarray, list[str], list[str]]:
    train = np.zeros(len(frame), dtype=bool)
    validation = np.zeros(len(frame), dtype=bool)
    vocabulary: list[str] = []
    skipped: list[str] = []
    for binary_id, indices in frame.groupby("binary_id", sort=True).groups.items():
        index = np.asarray(list(indices), dtype=int)
        runs = sorted(set(frame.loc[index, "run_group_id"].astype(str).tolist()))
        if len(index) < 8 or len(runs) < 2:
            skipped.append(str(binary_id))
            continue
        train_count = max(1, min(len(runs) - 1, int(0.7 * len(runs))))
        train_runs = set(runs[:train_count])
        validation_runs = set(runs[train_count:])
        binary_train = index[frame.loc[index, "run_group_id"].astype(str).isin(train_runs)]
        binary_validation = index[frame.loc[index, "run_group_id"].astype(str).isin(validation_runs)]
        if len(binary_train) < 5 or len(binary_validation) < 3:
            skipped.append(str(binary_id))
            continue
        train[binary_train] = True
        validation[binary_validation] = True
        vocabulary.append(str(binary_id))
    train_runs = set(frame.loc[train, "run_group_id"].astype(str))
    validation_runs = set(frame.loc[validation, "run_group_id"].astype(str))
    if train_runs.intersection(validation_runs):
        raise RuntimeError("run-group leakage detected")
    return train, validation, vocabulary, skipped


def _snapshot_mse(
    model: BinaryConditionedAutoencoder,
    features: np.ndarray,
    binary_indices: np.ndarray,
    device: torch.device,
    batch_size: int = 1024,
) -> np.ndarray:
    model.eval()
    output: list[np.ndarray] = []
    with torch.no_grad():
        for start in range(0, len(features), batch_size):
            x = torch.from_numpy(features[start : start + batch_size]).to(device)
            b = torch.from_numpy(binary_indices[start : start + batch_size]).to(device)
            error = torch.mean((model(x, b) - x) ** 2, dim=1)
            output.append(error.cpu().numpy())
    return np.concatenate(output).astype(np.float64)


def _thresholds(
    scores: np.ndarray,
    binary_indices: np.ndarray,
    run_ids: np.ndarray,
    validation: np.ndarray,
    vocabulary: list[str],
) -> tuple[dict[str, float], float]:
    run_scores = []
    for run_id in dict.fromkeys(run_ids[validation].tolist()):
        selected = scores[validation & (run_ids == run_id)]
        if len(selected) >= 10:
            run_scores.append(float(np.quantile(selected, 0.95)))
    global_reference = float(
        np.quantile(run_scores, 0.99)
        if len(run_scores) >= 2
        else np.quantile(scores[validation], 0.99)
    )
    thresholds = {}
    for index, binary_id in enumerate(vocabulary):
        selected = scores[validation & (binary_indices == index)]
        binary_tail = float(np.quantile(selected, 0.99)) if len(selected) else global_reference
        thresholds[binary_id] = max(binary_tail, 0.5 * global_reference)
    return thresholds, global_reference


def train_host(
    release_root: Path,
    output_root: Path,
    host: str,
    config: dict,
    receipt: dict,
    device: torch.device,
    max_binaries: int | None,
) -> dict:
    frame = pd.read_csv(
        release_root / "data/longitudinal_benign_dataset" / f"{host}.csv",
        low_memory=False,
    )
    feature_names = list(receipt["feature_names"])
    transforms = dict(receipt["feature_transforms"])
    if len(feature_names) != 63:
        raise RuntimeError(f"{host}: expected 63 historical model inputs; found {len(feature_names)}")
    if max_binaries is not None:
        selected = sorted(frame["binary_id"].unique())[:max_binaries]
        frame = frame.loc[frame["binary_id"].isin(selected)].reset_index(drop=True)
    else:
        frame = frame.reset_index(drop=True)
    train_mask, validation_mask, vocabulary, skipped = _grouped_split(frame)
    usable = frame["binary_id"].astype(str).isin(vocabulary).to_numpy()
    frame = frame.loc[usable].reset_index(drop=True)
    train_mask = train_mask[usable]
    validation_mask = validation_mask[usable]
    vocab_index = {binary_id: index for index, binary_id in enumerate(vocabulary)}
    binary_indices = frame["binary_id"].map(vocab_index).to_numpy(dtype=np.int64)
    run_ids = frame["run_group_id"].astype(str).to_numpy(dtype=object)

    epsilon = float(config["logit_epsilon"])
    raw = frame[feature_names].apply(pd.to_numeric, errors="coerce").to_numpy(dtype=np.float64)
    transformed = np.column_stack(
        [_transform(raw[:, index], transforms[name], epsilon) for index, name in enumerate(feature_names)]
    )
    medians = np.nanmedian(transformed[train_mask], axis=0)
    if not np.isfinite(medians).all():
        missing = [name for name, value in zip(feature_names, medians) if not np.isfinite(value)]
        raise RuntimeError(f"{host}: features entirely missing in training: {missing}")
    missing_rows, missing_columns = np.where(~np.isfinite(transformed))
    transformed[missing_rows, missing_columns] = medians[missing_columns]
    centre = np.median(transformed[train_mask], axis=0)
    q25, q75 = np.quantile(transformed[train_mask], [0.25, 0.75], axis=0)
    scale = np.where((q75 - q25) <= 1e-12, 1.0, q75 - q25)
    clip = float(config["scaled_clip"])
    features = np.clip((transformed - centre) / scale, -clip, clip).astype(np.float32)

    seed = int(config["seed"])
    seed_everything(seed)
    architecture_config = config["architecture"]
    architecture = AutoencoderArchitecture(
        feature_dim=len(feature_names),
        binary_count=len(vocabulary),
        embedding_dim=int(architecture_config["embedding_dim"]),
        encoder_hidden_sizes=tuple(architecture_config["encoder_hidden_sizes"]),
        latent_dim=int(architecture_config["latent_dim"]),
        decoder_hidden_sizes=tuple(architecture_config["decoder_hidden_sizes"]),
    )
    model = BinaryConditionedAutoencoder(architecture).to(device)
    training = config["training"]
    loader = DataLoader(
        TensorDataset(
            torch.from_numpy(features[train_mask]),
            torch.from_numpy(binary_indices[train_mask]),
        ),
        batch_size=min(int(training["batch_size"]), int(train_mask.sum())),
        shuffle=True,
        generator=torch.Generator().manual_seed(seed),
    )
    optimiser = torch.optim.AdamW(
        model.parameters(),
        lr=float(training["learning_rate"]),
        weight_decay=float(training["weight_decay"]),
    )
    best_loss = float("inf")
    best_state = None
    stale = 0
    history = []
    for epoch in range(1, int(training["epochs"]) + 1):
        model.train()
        batch_losses = []
        for batch_features, batch_binary in loader:
            batch_features = batch_features.to(device)
            batch_binary = batch_binary.to(device)
            optimiser.zero_grad(set_to_none=True)
            loss = torch.mean((model(batch_features, batch_binary) - batch_features) ** 2)
            loss.backward()
            optimiser.step()
            batch_losses.append(float(loss.detach().cpu()))
        validation_errors = _snapshot_mse(
            model, features[validation_mask], binary_indices[validation_mask], device
        )
        validation_loss = float(validation_errors.mean())
        history.append(
            {"epoch": epoch, "training_mse": float(np.mean(batch_losses)), "validation_mse": validation_loss}
        )
        if validation_loss + float(training["early_stopping_min_delta"]) < best_loss:
            best_loss = validation_loss
            best_state = copy.deepcopy(model.state_dict())
            stale = 0
        else:
            stale += 1
            if stale >= int(training["early_stopping_patience"]):
                break
    if best_state is None:
        raise RuntimeError(f"{host}: training produced no checkpoint")
    model.load_state_dict(best_state)
    all_scores = _snapshot_mse(model, features, binary_indices, device)
    thresholds, global_reference = _thresholds(
        all_scores, binary_indices, run_ids, validation_mask, vocabulary
    )

    host_output = output_root / host
    host_output.mkdir(parents=True, exist_ok=True)
    torch.save(
        {
            "state_dict": best_state,
            "architecture": {
                "feature_dim": architecture.feature_dim,
                "binary_count": architecture.binary_count,
                "embedding_dim": architecture.embedding_dim,
                "encoder_hidden_sizes": list(architecture.encoder_hidden_sizes),
                "latent_dim": architecture.latent_dim,
                "decoder_hidden_sizes": list(architecture.decoder_hidden_sizes),
            },
        },
        host_output / "model.pt",
    )
    np.savez(
        host_output / "preprocessor.npz",
        medians=medians,
        centre=centre,
        scale=scale,
        feature_names=np.asarray(feature_names),
    )
    metadata = {
        "host": host,
        "feature_names": feature_names,
        "feature_transforms": transforms,
        "binary_vocabulary": vocabulary,
        "skipped_binaries": skipped,
        "train_rows": int(train_mask.sum()),
        "validation_rows": int(validation_mask.sum()),
        "train_runs": int(frame.loc[train_mask, "run_group_id"].nunique()),
        "validation_runs": int(frame.loc[validation_mask, "run_group_id"].nunique()),
        "best_validation_mse": best_loss,
        "epochs_ran": len(history),
        "global_threshold_reference": global_reference,
        "thresholds": thresholds,
        "threshold_rule": "max(binary_validation_q99, 0.5 * host_validation_run_p95_q99)",
        "seed": seed,
        "new_training_warning": "This recreates the published protocol. Exact weights can differ across software and hardware versions; released frozen scores reproduce the reported decisions.",
    }
    (host_output / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    (host_output / "history.json").write_text(json.dumps(history, indent=2) + "\n", encoding="utf-8")
    return metadata


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-root", type=Path, default=Path("data/wasp"))
    parser.add_argument("--output-root", type=Path, default=Path("models"))
    parser.add_argument("--hosts", default=",".join(DEFAULT_HOSTS))
    parser.add_argument("--device", choices=("auto", "cpu", "cuda", "mps"), default="auto")
    parser.add_argument("--epochs", type=int, help="Optional testing override for the configured epoch limit.")
    parser.add_argument("--max-binaries", type=int, help="Optional smoke-test limit; do not use for reported models.")
    args = parser.parse_args()
    repository_root = Path(__file__).resolve().parents[1]
    config = json.loads((repository_root / "config/model.json").read_text(encoding="utf-8"))
    if args.epochs is not None:
        config["training"]["epochs"] = args.epochs
    receipts = json.loads(
        (repository_root / "metadata/model_bundle_receipts.json").read_text(encoding="utf-8")
    )["bundles"]
    receipt_map = {receipt["host_key"]: receipt for receipt in receipts}
    device = select_device(args.device)
    summaries = []
    for host in [value.strip() for value in args.hosts.split(",") if value.strip()]:
        print(f"Training {host} on {device} ...")
        summaries.append(
            train_host(
                args.release_root.resolve(),
                args.output_root.resolve(),
                host,
                config,
                receipt_map[host],
                device,
                args.max_binaries,
            )
        )
    (args.output_root / "INDEX.json").write_text(json.dumps(summaries, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(summaries)} model bundle(s) to {args.output_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
