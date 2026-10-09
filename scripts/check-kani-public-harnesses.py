#!/usr/bin/env python3
"""Validate public chio-kernel-core Kani proof enrollment."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any

from kani_open_residual import validate_open_residuals

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = (
    REPO_ROOT / "crates/kernel/chio-kernel-core/src/kani_public_harnesses.rs"
)
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
REACHABLE_HARNESSES = (
    "verify_family_binding_preservation",
    "public_sign_receipt_rejects_kernel_key_mismatch_before_signing",
    "public_sign_receipt_accepts_matching_kernel_key",
    "public_sign_receipt_refuses_content_hash_mismatch",
    "public_sign_receipt_accepts_matching_content_hash",
)
KEY_COMPARISON_HARNESSES = (
    "public_sign_receipt_rejects_kernel_key_mismatch_before_signing",
    "public_sign_receipt_accepts_matching_kernel_key",
)
TRUST_REACHABLE_HARNESSES = {
    "chio-weights": (
        "public_weights_hash_of_determinism_and_shape",
        "public_model_card_require_live_fail_closed",
        "public_weights_error_urn_is_stable",
        "public_model_card_new_pins_schema_version",
    ),
    "chio-attest-verify": ("public_expect_report_data_determinism_and_binding",),
}
DEFAULT_TRUST_SOURCES = {
    crate: REPO_ROOT / f"crates/trust/{crate}/src/kani_public_harnesses.rs"
    for crate in TRUST_REACHABLE_HARNESSES
}

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


def source_proof_declarations(path: Path) -> dict[str, int | None]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise ContractError(f"unable to load {path}: {error}") from error

    proofs = {}
    for index, line in enumerate(lines):
        if line.strip() != "#[kani::proof]":
            continue
        cursor = index + 1
        unwind = None
        while cursor < len(lines):
            candidate = lines[cursor].strip()
            if re.match(r"#\[\s*kani::unwind\b", candidate):
                attribute = re.fullmatch(
                    r"#\[\s*kani::unwind\s*\(\s*([1-9][0-9]{0,9})\s*\)\s*\]", candidate
                )
                if (
                    attribute is None
                    or unwind is not None
                    or int(attribute.group(1)) > 2**32 - 1
                ):
                    raise ContractError(
                        f"{path}:{cursor + 1}: invalid or duplicate kani::unwind attribute"
                    )
                unwind = int(attribute.group(1))
            if not candidate or candidate.startswith(("//", "#[")):
                cursor += 1
                continue
            declaration = FUNCTION_DECLARATION.match(candidate)
            if declaration is None:
                raise ContractError(
                    f"{path}:{index + 1}: #[kani::proof] is not followed by a function"
                )
            name = declaration.group(1)
            if name in proofs:
                raise ContractError(f"{path} contains duplicate harnesses: {name}")
            proofs[name] = unwind
            break
        else:
            raise ContractError(
                f"{path}:{index + 1}: #[kani::proof] has no following function"
            )

    if not proofs:
        raise ContractError(f"{path} contains no #[kani::proof] functions")
    return proofs


def source_proofs(path: Path) -> list[str]:
    return list(source_proof_declarations(path))


def trust_source_paths(source: Path, overrides: list[str]) -> dict[str, Path]:
    paths = {}
    for override in overrides:
        crate, separator, path = override.partition("=")
        if (
            not separator
            or crate not in DEFAULT_TRUST_SOURCES
            or not path
            or crate in paths
        ):
            raise ContractError(
                f"invalid or duplicate trust source mapping: {override!r}"
            )
        paths[crate] = Path(path)
    if (source.resolve() != DEFAULT_SOURCE.resolve() or paths) and set(paths) != set(
        DEFAULT_TRUST_SOURCES
    ):
        raise ContractError(
            "source overrides require explicit trust source mappings for every trust crate"
        )
    return paths or dict(DEFAULT_TRUST_SOURCES)


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


def reachability_errors(
    source_path: Path,
    multi_path: Path,
    public_path: Path,
    trust_sources: dict[str, Path],
) -> list[str]:
    multi = load_toml(multi_path)
    public = load_toml(public_path)
    entries = {
        row["harness"]: row
        for row in multi["harness"]
        if row.get("crate") == "chio-kernel-core" and row.get("lane") == "pr"
    }
    errors = []
    try:
        validate_open_residuals(multi["harness"], require_expected=True)
    except ValueError as error:
        errors.append(str(error))
    allowed_harness_keys = {
        "crate",
        "harness",
        "default_unwind",
        "timeout_secs",
        "lane",
        "features",
        "unwinding_checks",
        "require_cover",
        "open_residual",
        "memcmp_unwind",
        "public_key_eq_unwind",
        "public_key_hex_unwind",
        "p256_encoder_bounds",
        "primary_rust_symbol",
        "notes",
    }
    allowed_public_keys = {
        "schema",
        "crate",
        "script",
        "unwinding_checks",
        "cover_required",
        "memcmp_unwind",
        "public_key_eq_unwind",
        "harness_groups",
        "covered_symbols",
        "lanes",
    }
    if set(public) - allowed_public_keys:
        errors.append("public-core manifest has unknown keys")
    for row in multi["harness"]:
        if set(row) - allowed_harness_keys:
            errors.append(f"multi-crate harness has unknown keys: {row.get('harness')}")
    for crate, names in TRUST_REACHABLE_HARNESSES.items():
        declarations = source_proof_declarations(trust_sources[crate])
        for name in names:
            matching = [
                row
                for row in multi["harness"]
                if row.get("crate") == crate and row.get("harness") == name
            ]
            if len(matching) != 1:
                errors.append(
                    f"required reachable proof missing or duplicated: {crate}::{name}"
                )
                continue
            row = matching[0]
            if (
                row.get("lane") != "pr"
                or row.get("unwinding_checks") is not True
                or row.get("require_cover") is not True
                or not isinstance(row.get("features"), list)
                or "kani" not in row["features"]
            ):
                errors.append(
                    f"trust proof must retain checked reachable PR enrollment: {crate}::{name}"
                )
            if crate == "chio-attest-verify" and (
                row.get("public_key_hex_unwind") is not None
                or row.get("public_key_eq_unwind") is not None
                or row.get("memcmp_unwind") is not None
                or row.get("p256_encoder_bounds") is not True
            ):
                errors.append(
                    "attest proof must retain standalone P256 encoding bounds"
                )
            bound = row.get("default_unwind")
            if (
                type(bound) is not int
                or not 1 <= bound <= 2**32 - 1
                or bound != declarations.get(name)
            ):
                errors.append(
                    f"trust harness must match its source unwind declaration: {crate}::{name}"
                )
    for name in REACHABLE_HARNESSES:
        entry = entries.get(name, {})
        if entry.get("unwinding_checks") is not True:
            errors.append(f"proof must enable unwinding checks: {name}")
        if entry.get("require_cover") is not True:
            errors.append(f"proof must require a reachable witness: {name}")
        if (
            not isinstance(entry.get("features"), list)
            or "kani" not in entry["features"]
        ):
            errors.append(
                f"reachable proof must select the portable hash backend: {name}"
            )
    mirrored = public.get("cover_required")
    expected = {
        name for name, row in entries.items() if row.get("require_cover") is True
    }
    if (
        not isinstance(mirrored, list)
        or any(not isinstance(name, str) for name in mirrored)
        or len(set(mirrored)) != len(mirrored)
        or set(mirrored) != expected
    ):
        errors.append(
            "public-core required cover posture differs from multi-crate manifest"
        )
    checks = public.get("unwinding_checks")
    if (
        not isinstance(checks, list)
        or any(not isinstance(name, str) for name in checks)
        or not set(REACHABLE_HARNESSES) <= set(checks)
    ):
        errors.append("public-core reachable proofs must enable unwinding checks")
    expected_memcmp = {name: 66 for name in KEY_COMPARISON_HARNESSES}
    observed_memcmp = {
        name: row["memcmp_unwind"]
        for name, row in entries.items()
        if "memcmp_unwind" in row
    }
    if (
        observed_memcmp != expected_memcmp
        or public.get("memcmp_unwind") != expected_memcmp
    ):
        errors.append(
            "key comparison loop bounds differ from the complete 65-byte contract"
        )
    hash_harnesses = (
        "public_sign_receipt_refuses_content_hash_mismatch",
        "public_sign_receipt_accepts_matching_content_hash",
    )
    expected_recursion = {name: 8 for name in hash_harnesses}
    observed_recursion = {
        name: row["public_key_eq_unwind"]
        for name, row in entries.items()
        if "public_key_eq_unwind" in row
    }
    if (
        observed_recursion != expected_recursion
        or public.get("public_key_eq_unwind") != expected_recursion
    ):
        errors.append(
            "receipt hash proofs must retain the checked key recursion bound 8"
        )
    source = source_path.read_text(encoding="utf-8")
    for name in hash_harnesses:
        if entries.get(name, {}).get("default_unwind") != 66 or not re.search(
            rf"(?m)^#\[kani::unwind\(66\)\]\s+pub fn {re.escape(name)}\(", source
        ):
            errors.append(
                f"receipt hash harness must declare its loop bound 66: {name}"
            )
    for name in KEY_COMPARISON_HARNESSES:
        if entries.get(name, {}).get("default_unwind") != 8 or not re.search(
            rf"(?m)^#\[kani::unwind\(8\)\]\s+pub fn {re.escape(name)}\(", source
        ):
            errors.append(
                f"key comparison harness must declare its ordinary bound 8: {name}"
            )
    return errors


def parity_error(reference: set[str], observed: set[str], label: str) -> str:
    missing = sorted(reference - observed)
    unexpected = sorted(observed - reference)
    return f"{label}: missing={missing!r} unexpected={unexpected!r}"


def check(
    source: Path,
    multi_manifest: Path,
    public_manifest: Path,
    trust_sources: dict[str, Path],
) -> int:
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
    errors = reachability_errors(source, multi_manifest, public_manifest, trust_sources)
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
        raise ContractError(
            "Kani public harness parity mismatch:\n  " + "\n  ".join(errors)
        )

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
        "--trust-source",
        action="append",
        default=[],
        metavar="CRATE=PATH",
        help="Explicit source path for each trust crate when overriding sources",
    )
    parser.add_argument("--multi-manifest", type=Path, default=DEFAULT_MULTI_MANIFEST)
    parser.add_argument("--public-manifest", type=Path, default=DEFAULT_PUBLIC_MANIFEST)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        sources = trust_source_paths(args.source, args.trust_source)
        return check(args.source, args.multi_manifest, args.public_manifest, sources)
    except ContractError as error:
        print(f"check-kani-public-harnesses.py: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
