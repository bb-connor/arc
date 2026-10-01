#!/usr/bin/env python3
"""Validate public chio-kernel-core Kani proof enrollment."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = REPO_ROOT / "crates/kernel/chio-kernel-core/src/kani_public_harnesses.rs"
DEFAULT_MULTI_MANIFEST = REPO_ROOT / ".kani/harnesses.toml"
DEFAULT_PUBLIC_MANIFEST = (
    REPO_ROOT / "formal/rust-verification/kani-public-harnesses.toml"
)
PROTOCOL_HARNESSES = (
    "verify_composite_quota_all_or_nothing",
    "verify_quota_maximum_immutable",
    "verify_captured_invocation_count_monotonic",
    "verify_replay_fingerprint_uniqueness",
    "verify_family_binding_preservation",
    "verify_threshold_distinct_signers",
)
FUNCTION_DECLARATION = re.compile(
    r"^(?:pub(?:\([^)]*\))?\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\b"
)


class ContractError(RuntimeError):
    """A public Kani enrollment contract is invalid."""


def load_toml(path: Path) -> dict[str, Any]:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ContractError(f"unable to load {path}: {error}") from error


def unique_names(names: list[str], label: str) -> list[str]:
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        raise ContractError(f"{label} contains duplicate harnesses: {duplicates!r}")
    return names


def source_proofs(path: Path) -> list[str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise ContractError(f"unable to load {path}: {error}") from error

    proofs = []
    for index, line in enumerate(lines):
        if line.strip() != "#[kani::proof]":
            continue
        cursor = index + 1
        while cursor < len(lines):
            candidate = lines[cursor].strip()
            if not candidate or candidate.startswith("//") or candidate.startswith("#["):
                cursor += 1
                continue
            declaration = FUNCTION_DECLARATION.match(candidate)
            if declaration is None:
                raise ContractError(
                    f"{path}:{index + 1}: #[kani::proof] is not followed by a function"
                )
            proofs.append(declaration.group(1))
            break
        else:
            raise ContractError(
                f"{path}:{index + 1}: #[kani::proof] has no following function"
            )

    if not proofs:
        raise ContractError(f"{path} contains no #[kani::proof] functions")
    return unique_names(proofs, str(path))


def multi_manifest_core_pr(path: Path) -> list[str]:
    data = load_toml(path)
    if data.get("schema") != "chio.kani.multi-crate.v1":
        raise ContractError(f"{path} has an unexpected schema")
    entries = data.get("harness")
    if not isinstance(entries, list):
        raise ContractError(f"{path} harness must be an array of tables")

    names = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ContractError(f"{path} harness[{index}] must be a table")
        if entry.get("crate") == "chio-kernel-core" and entry.get("lane") == "pr":
            name = entry.get("harness")
            if not isinstance(name, str) or not name:
                raise ContractError(
                    f"{path} harness[{index}] has an invalid harness name"
                )
            names.append(name)
    if not names:
        raise ContractError(f"{path} has no chio-kernel-core lane=pr harnesses")
    return unique_names(names, f"{path} chio-kernel-core lane=pr")


def public_manifest_pr(path: Path) -> list[str]:
    data = load_toml(path)
    if data.get("schema") != "chio.kani-public-harnesses.v1":
        raise ContractError(f"{path} has an unexpected schema")
    if data.get("crate") != "chio-kernel-core":
        raise ContractError(f"{path} must describe chio-kernel-core")
    lanes = data.get("lanes")
    if not isinstance(lanes, dict):
        raise ContractError(f"{path} lanes must be a table")
    pr_lane = lanes.get("pr")
    if not isinstance(pr_lane, dict):
        raise ContractError(f"{path} lanes.pr must be a table")
    names = pr_lane.get("harnesses")
    if not isinstance(names, list) or not names:
        raise ContractError(f"{path} lanes.pr.harnesses must be a non-empty array")
    if any(not isinstance(name, str) or not name for name in names):
        raise ContractError(f"{path} lanes.pr.harnesses contains an invalid name")
    return unique_names(names, f"{path} lanes.pr")


def parity_error(reference: set[str], observed: set[str], label: str) -> str:
    missing = sorted(reference - observed)
    unexpected = sorted(observed - reference)
    return f"{label}: missing={missing!r} unexpected={unexpected!r}"


def check(source: Path, multi_manifest: Path, public_manifest: Path) -> int:
    proof_names = source_proofs(source)
    multi_names = multi_manifest_core_pr(multi_manifest)
    public_names = public_manifest_pr(public_manifest)

    proof_set = set(proof_names)
    surfaces = {
        "source #[kani::proof] set": proof_set,
        ".kani chio-kernel-core lane=pr set": set(multi_names),
        "formal lanes.pr set": set(public_names),
    }
    required = set(PROTOCOL_HARNESSES)
    errors = []
    for label, names in surfaces.items():
        missing_protocol = sorted(required - names)
        if missing_protocol:
            errors.append(
                f"{label} is missing required protocol harnesses: {missing_protocol!r}"
            )

    for label, names in list(surfaces.items())[1:]:
        if names != proof_set:
            errors.append(parity_error(proof_set, names, label))

    if errors:
        raise ContractError("Kani public harness parity mismatch:\n  " + "\n  ".join(errors))

    print(
        "Kani public harness contract passed "
        f"({len(proof_set)} proofs, {len(PROTOCOL_HARNESSES)} exact protocol harnesses)"
    )
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check public Kani source and manifest parity"
    )
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument(
        "--multi-manifest", type=Path, default=DEFAULT_MULTI_MANIFEST
    )
    parser.add_argument(
        "--public-manifest", type=Path, default=DEFAULT_PUBLIC_MANIFEST
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        return check(args.source, args.multi_manifest, args.public_manifest)
    except ContractError as error:
        print(f"check-kani-public-harnesses.py: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
