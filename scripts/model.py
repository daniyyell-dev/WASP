"""Binary-conditioned tabular autoencoder used by the public trainer."""

from __future__ import annotations

import os
import random
from dataclasses import dataclass
from typing import Sequence

import numpy as np
import torch
from torch import Tensor, nn


@dataclass(frozen=True)
class AutoencoderArchitecture:
    feature_dim: int
    binary_count: int
    embedding_dim: int
    encoder_hidden_sizes: tuple[int, ...]
    latent_dim: int
    decoder_hidden_sizes: tuple[int, ...]


def _mlp(input_size: int, hidden_sizes: Sequence[int], output_size: int) -> nn.Sequential:
    layers: list[nn.Module] = []
    current = input_size
    for size in hidden_sizes:
        layers.extend((nn.Linear(current, size), nn.ReLU()))
        current = size
    layers.append(nn.Linear(current, output_size))
    return nn.Sequential(*layers)


class BinaryConditionedAutoencoder(nn.Module):
    def __init__(self, architecture: AutoencoderArchitecture) -> None:
        super().__init__()
        self.architecture = architecture
        self.binary_embedding = nn.Embedding(
            architecture.binary_count, architecture.embedding_dim
        )
        self.encoder = _mlp(
            architecture.feature_dim + architecture.embedding_dim,
            architecture.encoder_hidden_sizes,
            architecture.latent_dim,
        )
        self.decoder = _mlp(
            architecture.latent_dim + architecture.embedding_dim,
            architecture.decoder_hidden_sizes,
            architecture.feature_dim,
        )

    def forward(self, features: Tensor, binary_ids: Tensor) -> Tensor:
        condition = self.binary_embedding(binary_ids)
        latent = self.encoder(torch.cat((features, condition), dim=1))
        return self.decoder(torch.cat((latent, condition), dim=1))


def seed_everything(seed: int) -> None:
    os.environ["PYTHONHASHSEED"] = str(seed)
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)
    torch.use_deterministic_algorithms(True, warn_only=True)
    if hasattr(torch.backends, "cudnn"):
        torch.backends.cudnn.benchmark = False
        torch.backends.cudnn.deterministic = True


def _backend_ready(name: str) -> bool:
    if name == "cpu":
        return True
    if name == "cuda":
        return bool(torch.cuda.is_available())
    if name == "mps":
        return bool(hasattr(torch.backends, "mps") and torch.backends.mps.is_available())
    return False


def _device_works(device: torch.device) -> bool:
    try:
        value = torch.zeros(2, 2, device=device)
        value = value + 1
        if device.type == "cuda":
            torch.cuda.synchronize()
        elif device.type == "mps" and hasattr(torch, "mps"):
            torch.mps.synchronize()
        float(value.sum().cpu())
        return True
    except Exception:
        return False


def select_device(requested: str = "auto") -> torch.device:
    requested = (os.environ.get("WASP_DEVICE") or requested or "auto").strip().lower()
    if requested not in {"auto", "cpu", "cuda", "mps"}:
        raise ValueError(f"unknown device {requested!r}")
    order = ["cuda", "mps", "cpu"] if requested == "auto" else [requested, "cpu"]
    seen: list[str] = []
    for name in order:
        if name in seen or not _backend_ready(name):
            continue
        seen.append(name)
        device = torch.device(name)
        if _device_works(device):
            if requested not in {"auto", "cpu"} and name != requested:
                print(f"{requested} unavailable; using {name}")
            return device
    return torch.device("cpu")
