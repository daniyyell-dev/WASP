#!/usr/bin/env python3
"""Validate the public WASP archive without accessing private lab data."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from collections import Counter
from pathlib import Path


EXPECTED_BENIGN = {
    "windows10.csv": (22750, 669),
    "win11_x64.csv": (22347, 694),
    "win2016_dc.csv": (25501, 739),
}
EXPECTED_FAMILY_EXPERIMENTS = {
    "NimPlant": 14,
    "Cobalt Strike": 27,
    "AsyncRAT": 10,
    "Quasar RAT": 12,
}
EXPECTED_HOST_EXPERIMENTS = {
    "windows10": 18,
    "win2016_dc": 27,
    "win11_x64": 18,
}
EXPECTED_TECHNIQUES = {
    "early_bird_apc",
    "process_hollowing",
    "remote_thread",
    "queue_apc",
    "thread_hijack",
    "rtl_create_user_thread",
    "module_stomp",
    "reflective_dll",
    "nt_create_thread_ex",
}
EXPECTED_BASELINES = {
    "binary_conditioned_autoencoder",
    "constant_embedding_autoencoder",
    "robust_feature_distance",
    "isolation_forest",
    "writable_executable_bytes_gt_0",
    "private_executable_bytes_gt_0",
    "path_backed_exec_ratio_lt_1",
}
PUBLICATION_TEXT_FILES = (
    "README.md",
    "docs/METHODS.md",
    "docs/DATA_CARD.md",
    "docs/ETHICS_AND_ACCESS.md",
    "docs/LICENSE_DATASET.md",
    "CITATION.cff",
)
REQUIRED_DATA_FILES = (
    "data/controlled_paired_dataset/controlled_clean_snapshots.csv",
    "data/controlled_paired_dataset/injection_labelled_snapshots.csv",
    "data/longitudinal_benign_dataset/windows10.csv",
    "data/longitudinal_benign_dataset/win11_x64.csv",
    "data/longitudinal_benign_dataset/win2016_dc.csv",
)
REQUIRED_REPO_FILES = (
    "README.md",
    "LICENSE.md",
    "CITATION.cff",
    "SHA256SUMS",
    "docs/METHODS.md",
    "docs/DATA_CARD.md",
    "docs/ETHICS_AND_ACCESS.md",
    "docs/LICENSE_DATASET.md",
    "metadata/dataset_summary.json",
    "metadata/feature_schema.json",
    "metadata/evaluation_metrics.json",
    "metadata/baseline_comparison.json",
    "metadata/experiment_coverage.csv",
    "metadata/feature_dictionary.csv",
    "metadata/model_bundle_receipts.json",
)
DATA_DEPOSIT_FORBIDDEN = (
    "README.md",
    "LICENSE.md",
    "CITATION.cff",
    "CHANGELOG.md",
    "UPLOAD_CHECKLIST.md",
    "docs",
    "metadata",
    "scripts",
    "code",
    "config",
)
STALE_SEMANTIC_PATTERNS = (
    re.compile(r"\b36 (?:(?:accepted|matched) )*pairs\b", re.I),
    re.compile(r"\b33 (?:scoreable|matching-host|host-enrolled)\b", re.I),
    re.compile(r"\b32\s*(?:/|of)\s*33\b", re.I),
    re.compile(r"\b735\s*(?:/|of)\s*781\b", re.I),
    re.compile(r"\b4\s*(?:/|of)\s*752\b", re.I),
    re.compile(r"\bflags 735 injection", re.I),
    re.compile(r"\b1,809\b"),
    re.compile(r"\b890 benign\b", re.I),
    re.compile(r"\b919 injection", re.I),
    re.compile(r"\bthree payload families\b", re.I),
    re.compile(r"\bfour controlled experiments\b", re.I),
    re.compile(r"WASP-v0\.2\.0"),
    re.compile(r"\bcorpus\b|\bcorpora\b", re.I),
)
FORBIDDEN_SUFFIXES = {
    ".exe", ".dll", ".sys", ".bin", ".jsonl", ".pt", ".npz", ".pkl",
    ".dmp", ".ps1", ".bat", ".cmd", ".py",
}
DIRECT_IDENTIFIER_PATTERNS = (
    re.compile(r"/Users/", re.I),
    re.compile(r"C:\\Users\\", re.I),
    re.compile(r"file:///", re.I),
    re.compile(r"ATTACKER-WIN", re.I),
    re.compile(r"BEGIN [A-Z ]*PRIVATE KEY"),
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


def _payload_key(value: str) -> str:
    key = re.sub(r"[^a-z0-9]", "", value.lower())
    return {"quasarrat": "quasar", "quasar": "quasar"}.get(key, key)


def _validate_masks(
    rows: list[dict[str, str]],
    core_features: list[str],
    partition: str,
    errors: list[str],
) -> None:
    non_binary: Counter[str] = Counter()
    blank_without_mask: Counter[str] = Counter()
    for row in rows:
        for feature in core_features:
            mask_field = f"{feature}__missing"
            mask = row.get(mask_field, "")
            if mask not in {"0", "1"}:
                non_binary[mask_field] += 1
            value = row.get(feature, "")
            if not value.strip() and mask != "1":
                blank_without_mask[feature] += 1
    if non_binary:
        examples = ", ".join(sorted(non_binary)[:5])
        errors.append(
            f"{partition}: {sum(non_binary.values())} missingness masks are blank or non-binary "
            f"(examples: {examples})"
        )
    if blank_without_mask:
        examples = ", ".join(sorted(blank_without_mask)[:5])
        errors.append(
            f"{partition}: {sum(blank_without_mask.values())} blank feature values do not have mask 1 "
            f"(examples: {examples})"
        )


def _resolve_checksum_target(relative: str, data_root: Path, repo_root: Path) -> Path:
    if relative.startswith("data/"):
        return data_root / relative
    return repo_root / relative


def validate(data_root: Path, repo_root: Path) -> list[str]:
    errors: list[str] = []
    for relative in REQUIRED_DATA_FILES:
        if not (data_root / relative).is_file():
            errors.append(f"missing required data file: {relative}")
    for relative in REQUIRED_REPO_FILES:
        if not (repo_root / relative).is_file():
            errors.append(f"missing required GitHub file: {relative}")

    for relative in DATA_DEPOSIT_FORBIDDEN:
        path = data_root / relative
        if path.exists():
            errors.append(f"Mendeley Data deposit must be data-only; found {relative}")

    for path in data_root.rglob("*"):
        if path.is_file() and path.suffix.lower() in FORBIDDEN_SUFFIXES:
            errors.append(f"forbidden public artefact: {path.relative_to(data_root)}")

    feature_schema_path = repo_root / "metadata/feature_schema.json"
    core_features: list[str] = []
    if feature_schema_path.is_file():
        try:
            feature_schema = json.loads(feature_schema_path.read_text(encoding="utf-8"))
            core_features = [str(item["name"]) for item in feature_schema["core_features"]]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            errors.append(f"invalid feature schema: {exc}")
        if len(core_features) != 70:
            errors.append(f"feature schema contains {len(core_features)} core fields, expected 70")
    benign_total = 0
    run_total = 0
    for filename, (expected_rows, expected_runs) in EXPECTED_BENIGN.items():
        path = data_root / "data/longitudinal_benign_dataset" / filename
        if not path.is_file():
            errors.append(f"missing benign partition: {filename}")
            continue
        rows = _rows(path)
        if core_features:
            _validate_masks(rows, core_features, filename, errors)
        runs = {row.get("run_group_id", "") for row in rows}
        if len(rows) != expected_rows:
            errors.append(f"{filename}: expected {expected_rows} rows; found {len(rows)}")
        if len(runs) != expected_runs:
            errors.append(f"{filename}: expected {expected_runs} runs; found {len(runs)}")
        benign_total += len(rows)
        run_total += len(runs)
    if (benign_total, run_total) != (70598, 2102):
        errors.append(f"benign totals are {(benign_total, run_total)}, expected (70598, 2102)")

    clean_path = data_root / "data/controlled_paired_dataset/controlled_clean_snapshots.csv"
    injected_path = data_root / "data/controlled_paired_dataset/injection_labelled_snapshots.csv"
    scoreable_cells: set[tuple[str, str, str, str]] = set()
    if clean_path.is_file() and injected_path.is_file():
        clean_rows = _rows(clean_path)
        injected_rows = _rows(injected_path)
        if len(clean_rows) != 1874 or any(row.get("label_injected") != "0" for row in clean_rows):
            errors.append("controlled-clean partition must contain exactly 1,874 label_injected=0 rows")
        if len(injected_rows) != 1896 or any(row.get("label_injected") != "1" for row in injected_rows):
            errors.append("injection-labelled partition must contain exactly 1,896 label_injected=1 rows")
        evaluation = clean_rows + injected_rows
        if core_features:
            _validate_masks(evaluation, core_features, "evaluation", errors)
        labels = Counter(row.get("class_label") for row in evaluation)
        pairs = {row.get("pair_group_id") for row in evaluation}
        runs = {row.get("run_group_id") for row in evaluation}
        scoreable = [row for row in evaluation if row.get("score_status") == "scoreable"]
        if (len(evaluation), labels["benign"], labels["injected"]) != (3770, 1874, 1896):
            errors.append("evaluation rows do not match 3,770 = 1,874 benign + 1,896 injected")
        if (len(pairs), len(runs)) != (63, 126):
            errors.append(f"evaluation grouping is {(len(pairs), len(runs))}, expected (63, 126)")
        if len({row["pair_group_id"] for row in scoreable}) != 60:
            errors.append("scoreable evaluation does not contain 60 matched pairs")
        scoreable_labels = Counter(row.get("class_label") for row in scoreable)
        if (len(scoreable), scoreable_labels["benign"], scoreable_labels["injected"]) != (
            3494,
            1736,
            1758,
        ):
            errors.append("scoreable evaluation does not match 3,494 = 1,736 benign + 1,758 injected")
        flags = Counter((row["class_label"], row.get("ae_flag")) for row in scoreable)
        if flags[("injected", "1")] != 1712 or flags[("benign", "1")] != 7:
            errors.append("frozen AE decisions do not reproduce 1,712 injected and 7 benign alerts")
        experiments: dict[str, dict[str, str]] = {}
        for row in evaluation:
            experiment_id = row.get("experiment_id", "")
            factors = {
                name: row.get(name, "")
                for name in ("host_model", "payload_family", "technique_label", "binary_id")
            }
            if experiment_id in experiments and experiments[experiment_id] != factors:
                errors.append(f"evaluation factors vary within {experiment_id}")
            experiments[experiment_id] = factors
        family_experiments = Counter(row["payload_family"] for row in experiments.values())
        host_experiments = Counter(row["host_model"] for row in experiments.values())
        techniques = {row["technique_label"] for row in experiments.values()}
        if dict(family_experiments) != EXPECTED_FAMILY_EXPERIMENTS:
            errors.append(f"experiment family coverage is {dict(family_experiments)}, expected {EXPECTED_FAMILY_EXPERIMENTS}")
        if dict(host_experiments) != EXPECTED_HOST_EXPERIMENTS:
            errors.append(f"experiment host coverage is {dict(host_experiments)}, expected {EXPECTED_HOST_EXPERIMENTS}")
        if techniques != EXPECTED_TECHNIQUES:
            errors.append(f"declared techniques are {sorted(techniques)}, expected {sorted(EXPECTED_TECHNIQUES)}")
        if sum(1 for row in evaluation if row.get("payload_family") == "Cobalt Strike") != 1961:
            errors.append("Cobalt Strike evaluation row count is not 1,961")
        cobalt_by_host = Counter(
            row["host_model"]
            for row in experiments.values()
            if row["payload_family"] == "Cobalt Strike"
        )
        if dict(cobalt_by_host) != {"windows10": 9, "win2016_dc": 9, "win11_x64": 9}:
            errors.append(f"Cobalt Strike experiment coverage by host is {dict(cobalt_by_host)}")
        for host in EXPECTED_HOST_EXPERIMENTS:
            cobalt_techniques = {
                row["technique_label"]
                for row in experiments.values()
                if row["payload_family"] == "Cobalt Strike" and row["host_model"] == host
            }
            if cobalt_techniques != EXPECTED_TECHNIQUES:
                errors.append(f"{host}: Cobalt Strike does not cover all nine declared techniques")
        scoreable_cells = {
            (
                row.get("host_model", ""),
                _payload_key(row.get("payload_family", "")),
                row.get("technique_label", ""),
                row.get("binary_id", ""),
            )
            for row in scoreable
        }

    metrics_path = repo_root / "metadata/evaluation_metrics.json"
    if metrics_path.is_file():
        try:
            metric_results = json.loads(metrics_path.read_text(encoding="utf-8"))["results"]
            statuses = Counter(row.get("status") for row in metric_results)
            if len(metric_results) != 63 or statuses != Counter(
                {"scoreable": 60, "unscored_binary_not_enrolled_in_matching_host_model": 3}
            ):
                errors.append(f"evaluation_metrics coverage is {len(metric_results)} rows with statuses {dict(statuses)}")
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            errors.append(f"invalid evaluation_metrics.json: {exc}")

    baseline_path = repo_root / "metadata/baseline_comparison.json"
    if baseline_path.is_file() and scoreable_cells:
        try:
            baseline_results = json.loads(baseline_path.read_text(encoding="utf-8"))["results"]
            baseline_methods = {str(row.get("baseline", "")) for row in baseline_results}
            baseline_cells = {
                (
                    str(row.get("host_model", "")),
                    _payload_key(str(row.get("payload", ""))),
                    str(row.get("technique", "")),
                    str(row.get("binary_id", "")),
                )
                for row in baseline_results
            }
            cell_method_counts = Counter(
                (
                    (
                        str(row.get("host_model", "")),
                        _payload_key(str(row.get("payload", ""))),
                        str(row.get("technique", "")),
                        str(row.get("binary_id", "")),
                    ),
                    str(row.get("baseline", "")),
                )
                for row in baseline_results
            )
            if baseline_methods != EXPECTED_BASELINES:
                errors.append(f"baseline methods are {sorted(baseline_methods)}, expected {sorted(EXPECTED_BASELINES)}")
            if baseline_cells != scoreable_cells:
                errors.append(
                    f"baseline comparison covers {len(baseline_cells)} cells, expected the exact 60 scoreable cells"
                )
            if len(baseline_results) != 420 or any(count != 1 for count in cell_method_counts.values()):
                errors.append("baseline comparison must contain exactly one result for each of 60 cells x 7 methods")
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            errors.append(f"invalid baseline_comparison.json: {exc}")

    methods_path = repo_root / "docs/METHODS.md"
    if methods_path.is_file():
        methods_text = methods_path.read_text(encoding="utf-8")
        if "22 schema-evolution fields" not in methods_text or "masks are explicitly set to one" not in methods_text:
            errors.append("METHODS.md does not document the 22-field benign schema-evolution exception")

    for relative in PUBLICATION_TEXT_FILES:
        path = repo_root / relative
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        for pattern in STALE_SEMANTIC_PATTERNS:
            if pattern.search(text):
                errors.append(f"stale pre-v0.2.1 semantics in {relative}: {pattern.pattern}")

    citation_path = repo_root / "CITATION.cff"
    if citation_path.is_file() and not re.search(
        r"(?m)^version:\s*[\"']?0\.2\.1[\"']?\s*$",
        citation_path.read_text(encoding="utf-8"),
    ):
        errors.append("CITATION.cff version is not 0.2.1")
    if citation_path.is_file():
        citation_text = citation_path.read_text(encoding="utf-8")
        for family_name in ("Jeremiah", "Rafiq", "Ta", "Okoyeigbo", "Akande"):
            if not re.search(rf'family-names:\s*[\"\']{family_name}[\"\']', citation_text):
                errors.append(f"CITATION.cff is missing author {family_name}")
        if "husnain2.rafiq@northumbria.ac.uk" not in citation_text:
            errors.append("CITATION.cff does not contain Husnain Rafiq's approved email")
        if "akandejamiu5044@nsuk.edu.ng" not in citation_text:
            errors.append("CITATION.cff does not contain Jamiu Akande's approved email")

    checksum_path = repo_root / "SHA256SUMS"
    if checksum_path.is_file():
        for line in checksum_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            expected, relative = line.split(maxsplit=1)
            relative = relative.strip().lstrip("*")
            target = _resolve_checksum_target(relative, data_root, repo_root)
            if not target.is_file():
                errors.append(f"checksum references absent file: {relative}")
            elif _sha256(target) != expected:
                errors.append(f"checksum mismatch: {relative}")

    text_suffixes = {".md", ".json", ".csv", ".py", ".yml", ".yaml", ".txt"}
    for root, label in ((data_root, "data"), (repo_root, "github")):
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in text_suffixes:
                continue
            if path.name == "validate_release.py":
                # This file necessarily contains the disclosure patterns it searches for.
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            for pattern in DIRECT_IDENTIFIER_PATTERNS:
                if pattern.search(text):
                    errors.append(
                        f"possible direct identifier in {label}/{path.relative_to(root)}: {pattern.pattern}"
                    )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--release-root",
        type=Path,
        default=Path("data/wasp"),
        help="Extracted Mendeley Data deposit root that contains the data/ CSV partitions.",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=None,
        help="GitHub reproducibility repository root that contains docs/ and metadata/.",
    )
    args = parser.parse_args()
    repo_root = (args.repo_root or Path(__file__).resolve().parents[1]).resolve()
    errors = validate(args.release_root.resolve(), repo_root)
    if errors:
        print("RELEASE VALIDATION FAILED")
        for error in errors:
            print(f"- {error}")
        return 1
    print("RELEASE VALIDATION PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
