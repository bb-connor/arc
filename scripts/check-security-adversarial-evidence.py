#!/usr/bin/env python3
"""Validate and execute security adversarial mutation evidence."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import platform
import re
import stat
import subprocess
import sys
import tempfile
import tomllib
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterator

SCHEMA = "chio.adversarial-mutation-evidence.v1"
SECURITY_CASES: dict[str, tuple[str, ...]] = {
    "label_downgrade": (
        "reader_subset_direction",
        "missing_clearance_allow",
        "ignored_store_error",
        "grant_replay",
    ),
    "canary_evasion": ("tripwire_after_dispatch",),
    "temporal_evasion": ("ingest_time_substitution",),
    "containment_rollback": (
        "truncation_ignored",
        "approval_plan_field_omission",
        "root_only_lift",
        "false_lifted_status",
    ),
    "key_log_omission": ("key_log_omission",),
    "key_log_noncontiguous_sync": ("key_log_noncontiguous_sync",),
    "key_log_inconsistent_growth": ("key_log_inconsistent_growth",),
    "key_log_split_view": ("key_log_split_view",),
    "rotation_partial_commit": ("rotation_partial_commit",),
    "rotation_unwitnessed_signing": ("rotation_unwitnessed_signing",),
    "old_key_backdating": ("old_key_backdating",),
    "broker_secret_boundary_crossing": ("broker_secret_boundary_crossing",),
    "broker_execution_overspend": ("broker_execution_overspend",),
    "broker_parent_double_charge": ("broker_parent_double_charge",),
    "broker_orphan_hold": ("broker_orphan_hold",),
    "broker_proof_replay": ("broker_proof_replay",),
    "broker_unbound_headers": ("broker_unbound_headers",),
    "broker_destination_rebinding": ("broker_destination_rebinding",),
    "broker_revocation_race": ("broker_revocation_race",),
    "broker_plaintext_custody": ("broker_plaintext_custody",),
    "sandbox_unsigned_manifest": ("sandbox_unsigned_manifest",),
    "sandbox_partial_enforcement": ("sandbox_partial_enforcement",),
    "sandbox_symlink_escape": ("sandbox_symlink_escape",),
    "sandbox_path_swap": ("sandbox_path_swap",),
    "sandbox_helper_substitution": ("sandbox_helper_substitution",),
    "sandbox_false_exec_success": ("sandbox_false_exec_success",),
    "sandbox_syscall_escape": ("sandbox_syscall_escape",),
    "sandbox_fd_or_env_leak": ("sandbox_fd_leak", "sandbox_env_leak"),
}
SAFE_ID = re.compile(r"^[a-z][a-z0-9_]*$")
PACKAGE = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")
TARGET = re.compile(r"^[a-z0-9][a-z0-9_]*$")
TEST_NAME = re.compile(r"^[A-Za-z0-9_]+(?:::[A-Za-z0-9_]+)*$")
FUNCTION = re.compile(r"^[A-Za-z0-9_:<>, ]{4,192}$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
CASE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
MUTANT_TEXT = re.compile(r"^[ -~]{0,192}$")
MUTANT_GENRES = frozenset(("FnValue", "BinaryOperator", "UnaryOperator"))
BINARY_REPLACEMENTS: dict[str, frozenset[str]] = {
    "==": frozenset(("!=",)),
    "!=": frozenset(("==",)),
    "&&": frozenset(("||",)),
    "||": frozenset(("&&",)),
    ">": frozenset(("<",)),
    ">=": frozenset(("<",)),
    "<": frozenset((">",)),
    "<=": frozenset((">",)),
}
MANIFEST_SCHEMA_VERSION = 1
MANIFEST_PRODUCER = "chio-adversarial-suite"
INPUT_BINDING_SCHEMA = "chio.adversarial-mutation-inputs.v3"


class EvidenceError(RuntimeError):
    """Evidence is absent, ambiguous, or invalid."""


@dataclass(frozen=True)
class LoadedCase:
    path: Path
    body: dict[str, Any]
    controls: dict[str, dict[str, Any]]
    campaigns: dict[str, dict[str, Any]]


@dataclass(frozen=True)
class SelectedMutant:
    """One native cargo-mutants record selected by stable semantic identity."""

    native: dict[str, Any]
    original: str | None


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle, object_pairs_hook=reject_duplicate_keys)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"{path}: invalid JSON: {error}") from error


def canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def sha256_file(path: Path, label: str) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        raise EvidenceError(
            f"{label}: unable to read input binding file: {error}"
        ) from error


def cargo_dependency_tables(
    manifest: dict[str, Any], *, include_dev_dependencies: bool
) -> Iterator[dict[str, Any]]:
    dependency_kinds = ["dependencies", "build-dependencies"]
    if include_dev_dependencies:
        dependency_kinds.append("dev-dependencies")
    for name in dependency_kinds:
        table = manifest.get(name)
        if isinstance(table, dict):
            yield table
    targets = manifest.get("target")
    if isinstance(targets, dict):
        for target in targets.values():
            if not isinstance(target, dict):
                continue
            for name in dependency_kinds:
                table = target.get(name)
                if isinstance(table, dict):
                    yield table


def load_cargo_manifest(path: Path) -> dict[str, Any]:
    try:
        body = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise EvidenceError(f"{path}: invalid Cargo manifest: {error}") from error
    if not isinstance(body, dict):
        raise EvidenceError(f"{path}: Cargo manifest is not a table")
    return body


def local_dependency_manifests(
    root: Path,
    manifest_path: Path,
    manifest: dict[str, Any],
    workspace_dependencies: dict[str, Any],
    *,
    include_dev_dependencies: bool,
) -> Iterator[Path]:
    for table in cargo_dependency_tables(
        manifest, include_dev_dependencies=include_dev_dependencies
    ):
        for dependency_name, raw_specification in table.items():
            specification = raw_specification
            base = manifest_path.parent
            if (
                isinstance(specification, dict)
                and specification.get("workspace") is True
            ):
                specification = workspace_dependencies.get(dependency_name)
                base = root
            if not isinstance(specification, dict):
                continue
            raw_path = specification.get("path")
            if not isinstance(raw_path, str):
                continue
            dependency_manifest = (base / raw_path / "Cargo.toml").resolve()
            try:
                dependency_manifest.relative_to(root)
            except ValueError as error:
                raise EvidenceError(
                    f"{dependency_manifest}: local Cargo dependency escaped the repository"
                ) from error
            if dependency_manifest.is_symlink() or not dependency_manifest.is_file():
                raise EvidenceError(
                    f"{dependency_manifest}: local Cargo dependency manifest is absent"
                )
            yield dependency_manifest


def package_input_closure(
    root: Path,
    package_dirs: dict[str, Path],
    package_names: set[str],
) -> set[Path]:
    """Return the conservative Cargo input closure for selected test roots.

    Root-package dev-dependencies are test inputs. A dependency's own
    dev-dependencies are not: Cargo does not propagate them transitively. Every
    regular file under a participating package remains bound because build
    scripts and include macros may consume files outside conventional Rust
    target directories.
    """

    root_manifest_path = root / "Cargo.toml"
    root_manifest = load_cargo_manifest(root_manifest_path)
    workspace = root_manifest.get("workspace")
    workspace_dependencies = (
        workspace.get("dependencies", {}) if isinstance(workspace, dict) else {}
    )
    if not isinstance(workspace_dependencies, dict):
        raise EvidenceError("workspace dependency table is invalid")

    pending: list[tuple[Path, bool]] = []
    for package_name in sorted(package_names):
        package_dir = package_dirs.get(package_name)
        if package_dir is None:
            raise EvidenceError(f"unknown Cargo package: {package_name}")
        pending.append((package_dir / "Cargo.toml", True))

    patches = root_manifest.get("patch")
    if isinstance(patches, dict):
        for patch_table in patches.values():
            if not isinstance(patch_table, dict):
                continue
            for specification in patch_table.values():
                if not isinstance(specification, dict) or not isinstance(
                    specification.get("path"), str
                ):
                    continue
                pending.append(
                    (
                        (root / specification["path"] / "Cargo.toml").resolve(),
                        False,
                    )
                )

    manifests: dict[Path, bool] = {}
    while pending:
        raw_manifest_path, include_dev_dependencies = pending.pop()
        manifest_path = raw_manifest_path.resolve()
        prior_included_dev = manifests.get(manifest_path)
        if prior_included_dev is not None and (
            prior_included_dev or not include_dev_dependencies
        ):
            continue
        try:
            manifest_path.relative_to(root)
        except ValueError as error:
            raise EvidenceError(
                f"{manifest_path}: Cargo input closure escaped the repository"
            ) from error
        if manifest_path.is_symlink() or not manifest_path.is_file():
            raise EvidenceError(f"{manifest_path}: Cargo input manifest is absent")
        manifest = load_cargo_manifest(manifest_path)
        manifests[manifest_path] = bool(
            prior_included_dev or include_dev_dependencies
        )
        pending.extend(
            (dependency_manifest, False)
            for dependency_manifest in local_dependency_manifests(
                root,
                manifest_path,
                manifest,
                workspace_dependencies,
                include_dev_dependencies=include_dev_dependencies,
            )
        )

    inputs = {
        root_manifest_path.resolve(),
        (root / "Cargo.lock").resolve(),
    }
    for optional in [
        root / "rust-toolchain",
        root / "rust-toolchain.toml",
        root / ".cargo/config",
        root / ".cargo/config.toml",
        root / ".cargo/mutants.toml",
    ]:
        if optional.exists():
            inputs.add(optional.resolve())
    for manifest_path in manifests:
        package_dir = manifest_path.parent
        for path in package_dir.rglob("*"):
            if any(part in {".git", "target"} for part in path.parts):
                continue
            if path.is_symlink():
                raise EvidenceError(
                    f"{path}: Cargo input closure cannot contain a symbolic link"
                )
            if path.is_file():
                inputs.add(path.resolve())
    return inputs


def campaign_input_digest(
    root: Path,
    package_dirs: dict[str, Path],
    campaign: dict[str, Any],
    control: dict[str, Any],
    case_path: Path,
) -> str:
    """Bind caught evidence to the exact mutation and behavioral-control inputs."""

    input_paths = package_input_closure(
        root,
        package_dirs,
        {campaign["package"], control["package"]},
    )
    input_paths.update(
        {
            (root / campaign["source"]).resolve(),
            (root / control["test_source"]).resolve(),
        }
    )
    evidence_outputs = {
        case_path.resolve(): "adversarial case",
        (root / "crates/core/chio-adversarial-suite/manifest.json").resolve(): (
            "adversarial manifest"
        ),
        (root / campaign["outcomes"]["path"]).resolve(): "mutation outcome",
    }
    overlapping_outputs = [
        label for path, label in evidence_outputs.items() if path in input_paths
    ]
    if overlapping_outputs:
        rendered = ", ".join(sorted(overlapping_outputs))
        raise EvidenceError(
            f"{campaign['id']}: mutation evidence output entered its Cargo input "
            f"closure: {rendered}"
        )
    files: list[dict[str, str]] = []
    for path in sorted(input_paths, key=lambda item: item.as_posix()):
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError as error:
            raise EvidenceError(
                f"{path}: input binding file escaped the repository"
            ) from error
        if path.is_symlink() or not path.is_file():
            raise EvidenceError(f"{relative}: input binding requires a regular file")
        files.append(
            {
                "path": relative,
                "sha256": sha256_file(path, relative),
            }
        )

    campaign_contract = {
        "id": campaign["id"],
        "control_id": campaign["control_id"],
        "package": campaign["package"],
        "source": campaign["source"],
        "function": campaign["function"],
        "minimum_caught": campaign["minimum_caught"],
        "outcomes_path": campaign["outcomes"]["path"],
    }
    if campaign.get("mutant") is not None:
        campaign_contract["mutant"] = campaign["mutant"]
    control_contract = {
        "id": control["id"],
        "package": control["package"],
        "test_source": control["test_source"],
        "target_kind": control["target_kind"],
        "target": control.get("target"),
        "features": control["features"],
        "required_target_os": control["required_target_os"],
        "test_name": control["test_name"],
    }
    binding = {
        "schema": INPUT_BINDING_SCHEMA,
        "campaign": campaign_contract,
        "control": control_contract,
        "files": files,
    }
    return hashlib.sha256(canonical_json_bytes(binding)).hexdigest()


def atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else 0o644
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            os.fchmod(handle.fileno(), mode)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def read_regular_file(path: Path, label: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise EvidenceError(f"{label}: expected a regular file")
    try:
        return path.read_bytes()
    except OSError as error:
        raise EvidenceError(f"{label}: unable to read file: {error}") from error


def atomic_replace_many(
    replacements: list[tuple[Path, bytes]], originals: dict[Path, bytes]
) -> None:
    """Stage a fail-closed multi-file replacement with rollback on write failure."""

    replacement_paths = [path for path, _payload in replacements]
    if len(replacement_paths) != len(set(replacement_paths)):
        raise EvidenceError("transaction contains a duplicate destination")
    if set(replacement_paths) != set(originals):
        raise EvidenceError("transaction originals do not match its destinations")

    staged: list[tuple[Path, Path]] = []
    try:
        for path, payload in replacements:
            current = read_regular_file(path, str(path))
            if current != originals[path]:
                raise EvidenceError(f"{path}: changed while refresh was running")
            mode = stat.S_IMODE(path.stat().st_mode)
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{path.name}.refresh.", dir=path.parent
            )
            temporary = Path(temporary_name)
            try:
                with os.fdopen(descriptor, "wb") as handle:
                    os.fchmod(handle.fileno(), mode)
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
            except BaseException:
                temporary.unlink(missing_ok=True)
                raise
            staged.append((path, temporary))

        for path in replacement_paths:
            if read_regular_file(path, str(path)) != originals[path]:
                raise EvidenceError(f"{path}: changed while refresh was being staged")

        replaced: list[Path] = []
        try:
            for path, temporary in staged:
                os.replace(temporary, path)
                replaced.append(path)
        except BaseException as error:
            rollback_errors: list[str] = []
            for path in reversed(replaced):
                try:
                    atomic_write(path, originals[path])
                except BaseException as rollback_error:
                    rollback_errors.append(f"{path}: {rollback_error}")
            if rollback_errors:
                raise EvidenceError(
                    "refresh commit failed and rollback was incomplete: "
                    + "; ".join(rollback_errors)
                ) from error
            if isinstance(error, OSError):
                raise EvidenceError(f"refresh commit failed: {error}") from error
            raise
    finally:
        for _path, temporary in staged:
            temporary.unlink(missing_ok=True)


@contextmanager
def refresh_lock(root: Path) -> Iterator[None]:
    lock_path = root / ".chio-security-adversarial-evidence.refresh.lock"
    try:
        lock_path.mkdir(mode=0o700)
    except FileExistsError as error:
        raise EvidenceError(
            f"{lock_path}: another refresh is active or a stale lock requires inspection"
        ) from error
    except OSError as error:
        raise EvidenceError(
            f"{lock_path}: unable to acquire refresh lock: {error}"
        ) from error
    try:
        yield
    finally:
        try:
            lock_path.rmdir()
        except OSError as error:
            raise EvidenceError(
                f"{lock_path}: unable to release refresh lock: {error}"
            ) from error


def exact_keys(
    value: dict[str, Any], required: set[str], optional: set[str], label: str
) -> None:
    keys = set(value)
    missing = required - keys
    unknown = keys - required - optional
    if missing or unknown:
        raise EvidenceError(
            f"{label}: field mismatch, missing={sorted(missing)}, unknown={sorted(unknown)}"
        )


def require_string(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise EvidenceError(f"{label}: invalid string")
    return value


def require_u32(value: Any, minimum: int, maximum: int, label: str) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise EvidenceError(f"{label}: expected integer in [{minimum}, {maximum}]")
    return value


def require_mutant_text(value: Any, label: str, *, empty: bool = True) -> str:
    if (
        not isinstance(value, str)
        or MUTANT_TEXT.fullmatch(value) is None
        or len(value) > 192
        or (not empty and not value)
    ):
        raise EvidenceError(f"{label}: invalid cargo-mutants source text")
    return value


def validate_mutant_selector(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvidenceError(f"{label}: semantic mutant selector is not an object")
    exact_keys(
        value, {"genre", "replacement"}, {"original", "occurrence", "error"}, label
    )
    genre = value["genre"]
    if genre not in MUTANT_GENRES:
        raise EvidenceError(f"{label}: unsupported native mutation genre")
    replacement = require_mutant_text(value["replacement"], f"{label}: replacement")
    original = value.get("original")
    occurrence = value.get("occurrence")
    error_expression = value.get("error")
    if occurrence is not None:
        occurrence = require_u32(occurrence, 1, 64, f"{label}: occurrence")

    if genre == "FnValue":
        if original is not None:
            raise EvidenceError(
                f"{label}: FnValue selector cannot name original source text"
            )
        if error_expression is not None:
            error_expression = require_mutant_text(
                error_expression, f"{label}: error expression", empty=False
            )
            if replacement != f"Err({error_expression})":
                raise EvidenceError(
                    f"{label}: custom error replacement must exactly wrap its expression"
                )
    else:
        if error_expression is not None:
            raise EvidenceError(
                f"{label}: only FnValue selectors can configure --error"
            )
        original = require_mutant_text(original, f"{label}: original", empty=False)
        if genre == "UnaryOperator":
            if replacement:
                raise EvidenceError(
                    f"{label}: unary deletion replacement must be empty"
                )
        elif replacement not in BINARY_REPLACEMENTS.get(original, frozenset()):
            raise EvidenceError(f"{label}: unsupported binary operator replacement")

    normalized = {
        "genre": genre,
        "replacement": replacement,
    }
    if original is not None:
        normalized["original"] = original
    if occurrence is not None:
        normalized["occurrence"] = occurrence
    if error_expression is not None:
        normalized["error"] = error_expression
    return normalized


def safe_rust_path(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise EvidenceError(f"{label}: expected path string")
    pure = PurePosixPath(value)
    if (
        pure.is_absolute()
        or not value.startswith("crates/")
        or pure.suffix != ".rs"
        or ".." in pure.parts
        or "." in pure.parts
    ):
        raise EvidenceError(f"{label}: unsafe Rust path")
    return value


def package_roots(root: Path) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for manifest in root.glob("crates/**/Cargo.toml"):
        try:
            body = tomllib.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
            raise EvidenceError(
                f"{manifest}: invalid Cargo manifest: {error}"
            ) from error
        package = body.get("package")
        if not isinstance(package, dict) or not isinstance(package.get("name"), str):
            continue
        name = package["name"]
        if name in result:
            raise EvidenceError(f"duplicate Cargo package name: {name}")
        result[name] = manifest.parent.resolve()
    return result


def require_under_package(
    root: Path, package_dirs: dict[str, Path], package: str, source: str
) -> Path:
    package_dir = package_dirs.get(package)
    if package_dir is None:
        raise EvidenceError(f"unknown Cargo package: {package}")
    resolved = (root / source).resolve()
    try:
        resolved.relative_to(package_dir)
    except ValueError as error:
        raise EvidenceError(
            f"{source}: does not belong to Cargo package {package}"
        ) from error
    if not resolved.is_file():
        raise EvidenceError(f"{source}: source file is absent")
    return resolved


def rust_function_exists(path: Path, selector: str, label: str) -> None:
    leaf = selector.rsplit("::", 1)[-1]
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", leaf):
        raise EvidenceError(f"{label}: selector does not end in a Rust function name")
    source = path.read_text(encoding="utf-8")
    if re.search(rf"\bfn\s+{re.escape(leaf)}\s*(?:<[^{{;()]*>)?\s*\(", source) is None:
        raise EvidenceError(f"{label}: function {leaf} is absent from {path}")


def validate_control(
    root: Path,
    package_dirs: dict[str, Path],
    value: Any,
    case_id: str,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvidenceError(f"{case_id}: control is not an object")
    exact_keys(
        value,
        {"id", "package", "test_source", "target_kind", "test_name"},
        {"target", "features", "required_target_os"},
        f"{case_id}: control",
    )
    control_id = require_string(value["id"], SAFE_ID, f"{case_id}: control id")
    package = require_string(value["package"], PACKAGE, f"{case_id}: control package")
    source = safe_rust_path(value["test_source"], f"{case_id}: control source")
    kind = value["target_kind"]
    if kind not in ("lib", "test"):
        raise EvidenceError(f"{case_id}: unsupported control target kind")
    target = value.get("target")
    if kind == "lib" and target is not None:
        raise EvidenceError(
            f"{case_id}: library control cannot name an integration target"
        )
    if kind == "test":
        target = require_string(target, TARGET, f"{case_id}: integration target")
        if Path(source).name != f"{target}.rs":
            raise EvidenceError(
                f"{case_id}: integration target does not match its source filename"
            )
    features = value.get("features", [])
    if (
        not isinstance(features, list)
        or len(features) > 8
        or len(set(features)) != len(features)
        or any(
            not isinstance(item, str) or PACKAGE.fullmatch(item) is None
            for item in features
        )
    ):
        raise EvidenceError(f"{case_id}: invalid Cargo feature list")
    required_os = value.get("required_target_os")
    if required_os not in (None, "linux"):
        raise EvidenceError(f"{case_id}: unsupported target operating system")
    test_name = require_string(
        value["test_name"], TEST_NAME, f"{case_id}: exact test name"
    )
    test_path = require_under_package(root, package_dirs, package, source)
    rust_function_exists(test_path, test_name, f"{case_id}: behavioral control")
    normalized = dict(value)
    normalized["features"] = list(features)
    normalized["required_target_os"] = required_os
    normalized["id"] = control_id
    normalized["package"] = package
    normalized["test_source"] = source
    normalized["test_name"] = test_name
    return normalized


def validate_campaign(
    root: Path,
    package_dirs: dict[str, Path],
    value: Any,
    controls: dict[str, dict[str, Any]],
    case_id: str,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvidenceError(f"{case_id}: mutation campaign is not an object")
    exact_keys(
        value,
        {
            "id",
            "control_id",
            "package",
            "source",
            "function",
            "minimum_caught",
            "outcomes",
        },
        {"mutant"},
        f"{case_id}: mutation campaign",
    )
    campaign_id = require_string(value["id"], SAFE_ID, f"{case_id}: mutation id")
    control_id = require_string(
        value["control_id"], SAFE_ID, f"{case_id}: control reference"
    )
    if control_id not in controls:
        raise EvidenceError(
            f"{case_id}: mutation {campaign_id} references an absent control"
        )
    package = require_string(value["package"], PACKAGE, f"{case_id}: mutation package")
    source = safe_rust_path(value["source"], f"{case_id}: mutation source")
    selector = require_string(
        value["function"], FUNCTION, f"{case_id}: function selector"
    )
    minimum = require_u32(value["minimum_caught"], 1, 64, f"{case_id}: minimum caught")
    outcomes = value["outcomes"]
    if not isinstance(outcomes, dict):
        raise EvidenceError(f"{case_id}: mutation outcomes is not an object")
    exact_keys(
        outcomes,
        {"path"},
        {"sha256", "inputs_sha256"},
        f"{case_id}: mutation outcomes",
    )
    expected_path = (
        f"audits/evidence/mutants/security/{campaign_id}/mutants.out/outcomes.json"
    )
    if outcomes["path"] != expected_path:
        raise EvidenceError(f"{case_id}: mutation outcome path is not canonical")
    digest = outcomes.get("sha256")
    if digest is not None:
        require_string(digest, SHA256, f"{case_id}: mutation outcomes digest")
    inputs_digest = outcomes.get("inputs_sha256")
    if inputs_digest is not None:
        require_string(inputs_digest, SHA256, f"{case_id}: mutation input digest")
    if (digest is None) != (inputs_digest is None):
        raise EvidenceError(
            f"{case_id}: outcome and input digests must be bound together"
        )
    mutant = value.get("mutant")
    if mutant is None:
        if digest is None:
            raise EvidenceError(
                f"{case_id}: pending mutation {campaign_id} lacks a semantic selector"
            )
    else:
        mutant = validate_mutant_selector(mutant, f"{case_id}: mutation selector")
        if minimum != 1:
            raise EvidenceError(
                f"{case_id}: a semantic selector must bind exactly one caught mutant"
            )
    production_path = require_under_package(root, package_dirs, package, source)
    rust_function_exists(production_path, selector, f"{case_id}: mutation target")
    normalized = dict(value)
    normalized["id"] = campaign_id
    normalized["control_id"] = control_id
    normalized["package"] = package
    normalized["source"] = source
    normalized["function"] = selector
    normalized["minimum_caught"] = minimum
    if mutant is not None:
        normalized["mutant"] = mutant
    return normalized


def span_start(span: Any, label: str) -> tuple[int, int]:
    if not isinstance(span, dict) or not isinstance(span.get("start"), dict):
        raise EvidenceError(f"{label}: malformed native source span")
    line = span["start"].get("line")
    column = span["start"].get("column")
    if type(line) is not int or line < 1 or type(column) is not int or column < 1:
        raise EvidenceError(f"{label}: malformed native source position")
    return line, column


def source_fragment(source_path: Path, span: Any, label: str) -> str:
    if not isinstance(span, dict) or not isinstance(span.get("end"), dict):
        raise EvidenceError(f"{label}: malformed native source span")
    start_line, start_column = span_start(span, label)
    end_line = span["end"].get("line")
    end_column = span["end"].get("column")
    if (
        type(end_line) is not int
        or type(end_column) is not int
        or end_line != start_line
        or end_column <= start_column
    ):
        raise EvidenceError(
            f"{label}: semantic operator span must occupy one source line"
        )
    try:
        lines = source_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise EvidenceError(
            f"{source_path}: unable to read mutation source: {error}"
        ) from error
    if start_line > len(lines):
        raise EvidenceError(f"{label}: native source span escaped the source file")
    line = lines[start_line - 1]
    if end_column - 1 > len(line):
        raise EvidenceError(f"{label}: native source span escaped its source line")
    return line[start_column - 1 : end_column - 1]


def native_mutant_semantics(
    native: Any, source_path: Path, label: str
) -> tuple[str, str, str | None, str]:
    if not isinstance(native, dict):
        raise EvidenceError(f"{label}: native mutant is not an object")
    function = native.get("function")
    function_name = (
        function.get("function_name") if isinstance(function, dict) else None
    )
    genre = native.get("genre")
    replacement = native.get("replacement")
    if (
        not isinstance(function_name, str)
        or genre not in MUTANT_GENRES
        or not isinstance(replacement, str)
    ):
        raise EvidenceError(f"{label}: malformed native mutant identity")
    original = (
        None
        if genre == "FnValue"
        else source_fragment(source_path, native.get("span"), label)
    )
    return function_name, genre, original, replacement


def semantic_match(
    native: Any,
    campaign: dict[str, Any],
    source_path: Path,
    label: str,
) -> tuple[bool, str | None]:
    if not isinstance(native, dict):
        raise EvidenceError(f"{label}: native mutant is not an object")
    function = native.get("function")
    function_name = (
        function.get("function_name") if isinstance(function, dict) else None
    )
    if not isinstance(function_name, str):
        return False, None
    selector = campaign["mutant"]
    if (
        native.get("package") != campaign["package"]
        or native.get("file") != campaign["source"]
        or function_name != campaign["function"]
        or native.get("genre") != selector["genre"]
    ):
        return False, None
    function_name, genre, original, replacement = native_mutant_semantics(
        native, source_path, label
    )
    matches = (
        genre == selector["genre"]
        and replacement == selector["replacement"]
        and original == selector.get("original")
    )
    return matches, original


def select_native_mutant(
    body: Any, campaign: dict[str, Any], source_path: Path
) -> SelectedMutant:
    if not isinstance(body, list) or not body:
        raise EvidenceError(
            f"{campaign['id']}: cargo-mutants preflight returned no native list"
        )
    candidates: list[SelectedMutant] = []
    for index, native in enumerate(body):
        matches, original = semantic_match(
            native, campaign, source_path, f"{campaign['id']}: preflight mutant {index}"
        )
        if matches:
            candidates.append(SelectedMutant(native=native, original=original))
    candidates.sort(
        key=lambda item: span_start(item.native.get("span"), campaign["id"])
    )
    occurrence = campaign["mutant"].get("occurrence")
    if occurrence is None:
        if len(candidates) != 1:
            raise EvidenceError(
                f"{campaign['id']}: semantic selector resolved to {len(candidates)} native mutants"
            )
        return candidates[0]
    if occurrence > len(candidates):
        raise EvidenceError(
            f"{campaign['id']}: semantic occurrence {occurrence} exceeds {len(candidates)} matches"
        )
    return candidates[occurrence - 1]


def require_statically_viable_mutant(
    selected: SelectedMutant, campaign: dict[str, Any]
) -> None:
    """Reject generator fallbacks whose emitted Rust is not type-grounded."""

    native = selected.native
    if native["genre"] != "FnValue":
        return
    function = native.get("function")
    return_type = function.get("return_type") if isinstance(function, dict) else None
    if not isinstance(return_type, str) or not return_type.startswith("-> "):
        raise EvidenceError(
            f"{campaign['id']}: FnValue mutant lacks a native return type"
        )
    replacement = native["replacement"]
    result_inner = None
    result_marker = return_type.find("Result<")
    if result_marker >= 0:
        result_inner = return_type[result_marker + len("Result<") :]
    error_expression = campaign["mutant"].get("error")
    viable = (
        replacement in ("true", "false")
        and return_type == "-> bool"
        or replacement in ("0", "1")
        and return_type
        in (
            "-> i8",
            "-> i16",
            "-> i32",
            "-> i64",
            "-> i128",
            "-> isize",
            "-> u8",
            "-> u16",
            "-> u32",
            "-> u64",
            "-> u128",
            "-> usize",
        )
        or replacement == "Ok(())"
        and result_inner is not None
        and result_inner.startswith("()")
        or replacement == "Ok(None)"
        and result_inner is not None
        and result_inner.startswith("Option<")
        or replacement == "Ok(vec![])"
        and result_inner is not None
        and result_inner.startswith("Vec<")
        or replacement == "Ok(BTreeMap::new())"
        and result_inner is not None
        and result_inner.startswith("BTreeMap<")
        or replacement == "Ok([0; 32])"
        and result_inner is not None
        and result_inner.startswith("[u8; 32]")
        or error_expression is not None
        and result_inner is not None
        and replacement == f"Err({error_expression})"
    )
    if not viable:
        raise EvidenceError(
            f"{campaign['id']}: FnValue replacement is not statically viable for {return_type}"
        )


def native_mutant_list_name(selected: SelectedMutant, campaign: dict[str, Any]) -> str:
    native = selected.native
    line, column = span_start(native.get("span"), campaign["id"])
    function = native["function"]
    genre = native["genre"]
    replacement = native["replacement"]
    if genre == "FnValue":
        return_type = function.get("return_type")
        if not isinstance(return_type, str) or not return_type.startswith("-> "):
            raise EvidenceError(
                f"{campaign['id']}: FnValue mutant lacks its native return type"
            )
        mutation = f"replace {campaign['function']} {return_type} with {replacement}"
    elif genre == "UnaryOperator":
        mutation = f"delete {selected.original} in {campaign['function']}"
    else:
        mutation = (
            f"replace {selected.original} with {replacement} in {campaign['function']}"
        )
    return f"{campaign['source']}:{line}:{column}: {mutation}"


def validate_outcomes(
    path: Path,
    campaign: dict[str, Any],
    expected_digest: str | None,
    source_path: Path,
    selected: SelectedMutant | None = None,
    *,
    bind_identity: bool = True,
) -> None:
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise EvidenceError(
            f"{path}: unable to read cargo-mutants outcomes: {error}"
        ) from error
    actual_digest = hashlib.sha256(payload).hexdigest()
    if expected_digest is not None and actual_digest != expected_digest:
        raise EvidenceError(
            f"{path}: digest mismatch, expected {expected_digest}, observed {actual_digest}"
        )
    body = load_json(path)
    if not isinstance(body, dict):
        raise EvidenceError(f"{path}: cargo-mutants outcomes must be an object")
    count_fields = (
        "caught",
        "missed",
        "timeout",
        "unviable",
        "success",
        "total_mutants",
    )
    for field in count_fields:
        if type(body.get(field)) is not int or body[field] < 0:
            raise EvidenceError(f"{path}: invalid cargo-mutants count {field}")
    outcomes = body.get("outcomes")
    if not isinstance(outcomes, list) or not outcomes:
        raise EvidenceError(f"{path}: missing cargo-mutants outcome records")
    baseline = [
        outcome
        for outcome in outcomes
        if isinstance(outcome, dict) and outcome.get("scenario") == "Baseline"
    ]
    if len(baseline) != 1 or baseline[0].get("summary") != "Success":
        raise EvidenceError(f"{path}: baseline must succeed exactly once")
    mutants = [outcome for outcome in outcomes if outcome not in baseline]
    if len(mutants) != body["total_mutants"] or body["total_mutants"] == 0:
        raise EvidenceError(f"{path}: total mutant count is inconsistent or zero")
    semantic_selector = campaign.get("mutant")
    if semantic_selector is not None and body["total_mutants"] != 1:
        raise EvidenceError(
            f"{path}: semantic campaign did not execute exactly one mutant"
        )
    caught = 0
    for outcome in mutants:
        if not isinstance(outcome, dict) or outcome.get("summary") != "CaughtMutant":
            raise EvidenceError(
                f"{path}: missed, timed out, unviable, or surviving mutant"
            )
        scenario = outcome.get("scenario")
        mutant = scenario.get("Mutant") if isinstance(scenario, dict) else None
        if not isinstance(mutant, dict):
            raise EvidenceError(f"{path}: malformed native mutant record")
        if not bind_identity:
            pass
        elif semantic_selector is None:
            function = mutant.get("function")
            function_name = (
                function.get("function_name") if isinstance(function, dict) else None
            )
            if (
                mutant.get("package") != campaign["package"]
                or mutant.get("file") != campaign["source"]
                or not isinstance(function_name, str)
                or campaign["function"] != function_name
            ):
                raise EvidenceError(
                    f"{path}: mutant escaped its package, source, or function binding"
                )
        else:
            matches, _original = semantic_match(
                mutant, campaign, source_path, f"{path}: outcome mutant"
            )
            if not matches:
                raise EvidenceError(
                    f"{path}: native mutation identity differs from its manifest"
                )
            if selected is not None and mutant != selected.native:
                raise EvidenceError(
                    f"{path}: outcome mutant differs from its preflight record"
                )
        caught += 1
    if caught < campaign["minimum_caught"] or body["caught"] != caught:
        raise EvidenceError(f"{path}: caught-mutant threshold or count mismatch")
    if any(body[field] != 0 for field in ("missed", "timeout", "unviable", "success")):
        raise EvidenceError(f"{path}: non-caught cargo-mutants count is nonzero")


def validate_case(
    root: Path,
    package_dirs: dict[str, Path],
    path: Path,
    require_complete: bool,
    refresh_campaign: str | None = None,
    outcome_overrides: dict[str, Path] | None = None,
) -> LoadedCase:
    body = load_json(path)
    if not isinstance(body, dict):
        raise EvidenceError(f"{path}: case must be an object")
    exact_keys(
        body,
        {
            "schema_version",
            "id",
            "class",
            "expected_verdict",
            "expected_reason",
            "threat_id",
            "pending",
            "artifact",
        },
        {"notes"},
        str(path),
    )
    if body["schema_version"] != 1 or type(body["schema_version"]) is not int:
        raise EvidenceError(f"{path}: unsupported case schema")
    case_id = require_string(body["id"], CASE_ID, f"{path}: case id")
    if path.stem != case_id:
        raise EvidenceError(f"{path}: case id does not match filename")
    attack_class = body["class"]
    required = SECURITY_CASES.get(attack_class)
    if required is None:
        raise EvidenceError(f"{path}: not a registered security evidence class")
    if body["expected_verdict"] != "DENY":
        raise EvidenceError(f"{path}: adversarial verdict must be DENY")
    if type(body["pending"]) is not bool:
        raise EvidenceError(f"{path}: pending must be boolean")
    if require_complete and body["pending"]:
        raise EvidenceError(
            f"{path}: pending case cannot pass the release evidence gate"
        )
    artifact = body["artifact"]
    if not isinstance(artifact, dict):
        raise EvidenceError(f"{path}: evidence artifact is not an object")
    exact_keys(
        artifact, {"schema", "controls", "campaigns"}, set(), f"{case_id}: artifact"
    )
    if artifact["schema"] != SCHEMA:
        raise EvidenceError(f"{path}: unsupported mutation evidence schema")
    control_values = artifact["controls"]
    campaign_values = artifact["campaigns"]
    if (
        not isinstance(control_values, list)
        or not 1 <= len(control_values) <= 16
        or not isinstance(campaign_values, list)
        or not 1 <= len(campaign_values) <= 16
    ):
        raise EvidenceError(f"{path}: control or mutation campaign count is invalid")
    controls: dict[str, dict[str, Any]] = {}
    for value in control_values:
        control = validate_control(root, package_dirs, value, case_id)
        if control["id"] in controls:
            raise EvidenceError(f"{path}: duplicate control id {control['id']}")
        controls[control["id"]] = control
    campaigns: dict[str, dict[str, Any]] = {}
    outcome_paths: set[str] = set()
    referenced_controls: set[str] = set()
    for value in campaign_values:
        campaign = validate_campaign(root, package_dirs, value, controls, case_id)
        campaign_id = campaign["id"]
        if campaign_id in campaigns:
            raise EvidenceError(f"{path}: duplicate mutation id {campaign_id}")
        outcome_path = campaign["outcomes"]["path"]
        if outcome_path in outcome_paths:
            raise EvidenceError(f"{path}: duplicate mutation outcome path")
        campaigns[campaign_id] = campaign
        outcome_paths.add(outcome_path)
        referenced_controls.add(campaign["control_id"])
    if set(campaigns) != set(required):
        raise EvidenceError(
            f"{path}: exact mutations differ, expected={sorted(required)}, observed={sorted(campaigns)}"
        )
    if referenced_controls != set(controls):
        raise EvidenceError(f"{path}: every behavioral control must be referenced")
    for campaign in campaigns.values():
        outcomes = campaign["outcomes"]
        evidence_path = (
            outcome_overrides.get(campaign["id"], root / outcomes["path"])
            if outcome_overrides is not None
            else root / outcomes["path"]
        )
        digest = outcomes.get("sha256")
        if digest is None:
            if evidence_path.exists():
                raise EvidenceError(
                    f"{evidence_path}: outcome exists without a bound digest"
                )
            if not body["pending"]:
                raise EvidenceError(
                    f"{path}: completed case lacks a mutation outcome digest"
                )
            continue
        expected_inputs_digest = campaign_input_digest(
            root,
            package_dirs,
            campaign,
            controls[campaign["control_id"]],
            path,
        )
        stale_inputs = outcomes["inputs_sha256"] != expected_inputs_digest
        # Refresh mode may need to repair several independently stale campaigns
        # one at a time. It relaxes only freshness and current semantic binding
        # for stale stored outcomes; their recorded digest and caught-only shape
        # remain mandatory, and the ordinary validation path still rejects them.
        if stale_inputs and refresh_campaign is None:
            raise EvidenceError(
                f"{path}: stale mutation input binding for {campaign['id']}, "
                f"expected {expected_inputs_digest}, observed {outcomes['inputs_sha256']}"
            )
        if not evidence_path.is_file():
            raise EvidenceError(f"{evidence_path}: bound mutation outcome is absent")
        validate_outcomes(
            evidence_path,
            campaign,
            digest,
            root / campaign["source"],
            bind_identity=not stale_inputs,
        )
    expected_pending = any(
        campaign["outcomes"].get("sha256") is None for campaign in campaigns.values()
    )
    if body["pending"] != expected_pending:
        raise EvidenceError(
            f"{path}: pending state does not match mutation evidence completeness"
        )
    return LoadedCase(path=path, body=body, controls=controls, campaigns=campaigns)


def validate_manifest(root: Path, cases: list[LoadedCase]) -> None:
    path = root / "crates/core/chio-adversarial-suite/manifest.json"
    body = load_json(path)
    if not isinstance(body, dict) or not isinstance(body.get("cases"), list):
        raise EvidenceError(f"{path}: invalid adversarial manifest")
    entries = body["cases"]
    if body.get("case_count") != len(entries):
        raise EvidenceError(f"{path}: case count does not match entries")
    by_id = {
        entry.get("id"): entry
        for entry in entries
        if isinstance(entry, dict) and isinstance(entry.get("id"), str)
    }
    for case in cases:
        case_id = case.body["id"]
        entry = by_id.get(case_id)
        if case.body["pending"]:
            if entry is not None:
                raise EvidenceError(
                    f"{path}: pending case {case_id} is coverage-eligible"
                )
            continue
        if entry is None:
            raise EvidenceError(f"{path}: completed case {case_id} is absent")
        expected_hash = hashlib.sha256(case.path.read_bytes()).hexdigest()
        expected_path = case.path.relative_to(
            root / "crates/core/chio-adversarial-suite"
        ).as_posix()
        if (
            entry.get("class") != case.body["class"]
            or entry.get("expected_verdict") != "DENY"
            or entry.get("expected_reason") != case.body["expected_reason"]
            or entry.get("threat_id") != case.body["threat_id"]
            or entry.get("path") != expected_path
            or entry.get("content_sha256") != expected_hash
        ):
            raise EvidenceError(f"{path}: manifest binding mismatch for {case_id}")


def render_manifest_after_promotion(
    root: Path,
    case_path: Path,
    case_body: dict[str, Any],
) -> tuple[Path, bytes]:
    manifest_path = root / "crates/core/chio-adversarial-suite/manifest.json"
    manifest = load_json(manifest_path)
    if not isinstance(manifest, dict):
        raise EvidenceError(f"{manifest_path}: invalid adversarial manifest")
    exact_keys(
        manifest,
        {"schema_version", "producer", "case_count", "cases"},
        set(),
        str(manifest_path),
    )
    entries = manifest["cases"]
    if (
        manifest["schema_version"] != MANIFEST_SCHEMA_VERSION
        or manifest["producer"] != MANIFEST_PRODUCER
        or not isinstance(entries, list)
        or manifest["case_count"] != len(entries)
    ):
        raise EvidenceError(f"{manifest_path}: invalid adversarial manifest")
    entry_order = (
        "id",
        "class",
        "expected_verdict",
        "expected_reason",
        "threat_id",
        "path",
        "content_sha256",
    )
    entry_fields = set(entry_order)
    normalized_entries: list[dict[str, Any]] = []
    entry_ids: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise EvidenceError(
                f"{manifest_path}: manifest entry {index} is not an object"
            )
        exact_keys(
            entry, entry_fields, set(), f"{manifest_path}: manifest entry {index}"
        )
        entry_id = require_string(entry["id"], CASE_ID, f"{manifest_path}: manifest id")
        if entry_id in entry_ids:
            raise EvidenceError(f"{manifest_path}: duplicate manifest id {entry_id}")
        entry_ids.add(entry_id)
        normalized_entries.append(
            {
                "id": entry["id"],
                "class": entry["class"],
                "expected_verdict": entry["expected_verdict"],
                "expected_reason": entry["expected_reason"],
                "threat_id": entry["threat_id"],
                "path": entry["path"],
                "content_sha256": entry["content_sha256"],
            }
        )

    case_id = case_body["id"]
    if case_id in entry_ids:
        raise EvidenceError(
            f"{manifest_path}: pending promotion target {case_id} is already coverage-eligible"
        )
    if not case_body["pending"]:
        suite_root = root / "crates/core/chio-adversarial-suite"
        try:
            relative_path = (
                case_path.resolve().relative_to(suite_root.resolve()).as_posix()
            )
        except ValueError as error:
            raise EvidenceError(
                f"{case_path}: case is outside the adversarial suite"
            ) from error
        normalized_entries.append(
            {
                "id": case_id,
                "class": case_body["class"],
                "expected_verdict": case_body["expected_verdict"],
                "expected_reason": case_body["expected_reason"],
                "threat_id": case_body["threat_id"],
                "path": relative_path,
                "content_sha256": hashlib.sha256(
                    canonical_json_bytes(case_body)
                ).hexdigest(),
            }
        )
    normalized_entries.sort(key=lambda entry: entry["id"])
    rendered = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "producer": MANIFEST_PRODUCER,
        "case_count": len(normalized_entries),
        "cases": normalized_entries,
    }
    return manifest_path, canonical_json_bytes(rendered)


def manifest_case_entry(
    root: Path,
    case_path: Path,
    case_body: dict[str, Any],
    case_payload: bytes,
) -> dict[str, Any]:
    suite_root = root / "crates/core/chio-adversarial-suite"
    try:
        relative_path = case_path.resolve().relative_to(suite_root.resolve()).as_posix()
    except ValueError as error:
        raise EvidenceError(
            f"{case_path}: case is outside the adversarial suite"
        ) from error
    return {
        "id": case_body["id"],
        "class": case_body["class"],
        "expected_verdict": case_body["expected_verdict"],
        "expected_reason": case_body["expected_reason"],
        "threat_id": case_body["threat_id"],
        "path": relative_path,
        "content_sha256": hashlib.sha256(case_payload).hexdigest(),
    }


def render_manifest_after_refresh(
    root: Path,
    case_path: Path,
    old_case_body: dict[str, Any],
    old_case_payload: bytes,
    new_case_body: dict[str, Any],
    new_case_payload: bytes,
) -> tuple[Path, bytes]:
    manifest_path = root / "crates/core/chio-adversarial-suite/manifest.json"
    manifest = load_json(manifest_path)
    if not isinstance(manifest, dict):
        raise EvidenceError(f"{manifest_path}: invalid adversarial manifest")
    exact_keys(
        manifest,
        {"schema_version", "producer", "case_count", "cases"},
        set(),
        str(manifest_path),
    )
    entries = manifest["cases"]
    if (
        manifest["schema_version"] != MANIFEST_SCHEMA_VERSION
        or manifest["producer"] != MANIFEST_PRODUCER
        or not isinstance(entries, list)
        or manifest["case_count"] != len(entries)
    ):
        raise EvidenceError(f"{manifest_path}: invalid adversarial manifest")

    entry_order = (
        "id",
        "class",
        "expected_verdict",
        "expected_reason",
        "threat_id",
        "path",
        "content_sha256",
    )
    entry_fields = set(entry_order)
    normalized_entries: list[dict[str, Any]] = []
    matching_index: int | None = None
    entry_ids: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise EvidenceError(
                f"{manifest_path}: manifest entry {index} is not an object"
            )
        exact_keys(
            entry, entry_fields, set(), f"{manifest_path}: manifest entry {index}"
        )
        entry_id = require_string(entry["id"], CASE_ID, f"{manifest_path}: manifest id")
        if entry_id in entry_ids:
            raise EvidenceError(f"{manifest_path}: duplicate manifest id {entry_id}")
        entry_ids.add(entry_id)
        normalized = {field: entry[field] for field in entry_order}
        if entry_id == old_case_body["id"]:
            matching_index = len(normalized_entries)
        normalized_entries.append(normalized)

    old_entry = manifest_case_entry(root, case_path, old_case_body, old_case_payload)
    if old_case_body["pending"]:
        if matching_index is not None:
            raise EvidenceError(
                f"{manifest_path}: pending refresh target {old_case_body['id']} is coverage-eligible"
            )
    else:
        if matching_index is None or normalized_entries[matching_index] != old_entry:
            raise EvidenceError(
                f"{manifest_path}: manifest binding mismatch for {old_case_body['id']}"
            )
        normalized_entries[matching_index] = manifest_case_entry(
            root, case_path, new_case_body, new_case_payload
        )

    normalized_entries.sort(key=lambda entry: entry["id"])
    rendered = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "producer": MANIFEST_PRODUCER,
        "case_count": len(normalized_entries),
        "cases": normalized_entries,
    }
    return manifest_path, canonical_json_bytes(rendered)


def outcome_path(raw_path: str) -> Path:
    path = Path(raw_path)
    if path.is_dir():
        path = path / "mutants.out" / "outcomes.json"
    return path.resolve()


def promote_outcome(
    root: Path,
    package_dirs: dict[str, Path],
    record: tuple[LoadedCase, dict[str, Any], dict[str, Any]],
    raw_path: str,
) -> tuple[Path, str, bool]:
    case, campaign, control = record
    if campaign["outcomes"].get("sha256") is not None:
        raise EvidenceError(f"{campaign['id']}: already has a bound outcome digest")
    candidate = outcome_path(raw_path)
    validate_outcomes(candidate, campaign, None, root / campaign["source"])
    try:
        payload = candidate.read_bytes()
    except OSError as error:
        raise EvidenceError(
            f"{candidate}: unable to read promotion candidate: {error}"
        ) from error
    digest = hashlib.sha256(payload).hexdigest()
    inputs_digest = campaign_input_digest(
        root, package_dirs, campaign, control, case.path
    )
    destination = (root / campaign["outcomes"]["path"]).resolve()
    try:
        destination.relative_to(root)
    except ValueError as error:
        raise EvidenceError(
            f"{destination}: outcome destination escaped the repository"
        ) from error
    if destination.exists():
        raise EvidenceError(
            f"{destination}: refusing to overwrite promoted mutation evidence"
        )

    case_body = copy.deepcopy(case.body)
    promoted = False
    for value in case_body["artifact"]["campaigns"]:
        if value["id"] == campaign["id"]:
            value["outcomes"]["sha256"] = digest
            value["outcomes"]["inputs_sha256"] = inputs_digest
            promoted = True
            break
    if not promoted:
        raise EvidenceError(
            f"{campaign['id']}: mutation campaign disappeared during promotion"
        )
    complete = all(
        value["outcomes"].get("sha256") is not None
        for value in case_body["artifact"]["campaigns"]
    )
    case_body["pending"] = not complete
    case_payload = canonical_json_bytes(case_body)
    manifest_path, manifest_payload = render_manifest_after_promotion(
        root, case.path, case_body
    )
    try:
        original_case = case.path.read_bytes()
        original_manifest = manifest_path.read_bytes()
    except OSError as error:
        raise EvidenceError(
            f"unable to snapshot promotion metadata: {error}"
        ) from error

    destination_written = False
    try:
        atomic_write(destination, payload)
        destination_written = True
        atomic_write(case.path, case_payload)
        atomic_write(manifest_path, manifest_payload)
    except Exception:
        if destination_written:
            destination.unlink(missing_ok=True)
        atomic_write(case.path, original_case)
        atomic_write(manifest_path, original_manifest)
        raise
    return destination, digest, complete


def validate_staged_refresh(
    root: Path,
    package_dirs: dict[str, Path],
    case: LoadedCase,
    campaign_id: str,
    outcome_payload: bytes,
    case_payload: bytes,
    manifest_payload: bytes,
) -> None:
    with tempfile.TemporaryDirectory(prefix="chio-security-evidence-stage-") as raw:
        stage = Path(raw)
        staged_outcome_path = stage / "outcomes.json"
        staged_case_path = stage / case.path.name
        staged_manifest_path = stage / "manifest.json"
        atomic_write(staged_outcome_path, outcome_payload)
        atomic_write(staged_case_path, case_payload)
        atomic_write(staged_manifest_path, manifest_payload)

        staged_case_body = load_json(staged_case_path)
        if canonical_json_bytes(staged_case_body) != case_payload:
            raise EvidenceError(f"{case.path}: refreshed case is not canonical JSON")
        validated = validate_case(
            root,
            package_dirs,
            staged_case_path,
            False,
            refresh_campaign=campaign_id,
            outcome_overrides={campaign_id: staged_outcome_path},
        )

        staged_manifest = load_json(staged_manifest_path)
        if canonical_json_bytes(staged_manifest) != manifest_payload:
            raise EvidenceError("refreshed adversarial manifest is not canonical JSON")
        entries = (
            staged_manifest.get("cases") if isinstance(staged_manifest, dict) else None
        )
        if not isinstance(entries, list):
            raise EvidenceError("refreshed adversarial manifest lacks case entries")
        matching = [
            entry
            for entry in entries
            if isinstance(entry, dict) and entry.get("id") == validated.body["id"]
        ]
        if validated.body["pending"]:
            if matching:
                raise EvidenceError("pending refreshed case became coverage-eligible")
        else:
            expected = manifest_case_entry(
                root, case.path, validated.body, case_payload
            )
            if matching != [expected]:
                raise EvidenceError(
                    "refreshed manifest does not bind the staged case bytes"
                )


def refresh_outcome(
    root: Path,
    package_dirs: dict[str, Path],
    record: tuple[LoadedCase, dict[str, Any], dict[str, Any]],
    environment: dict[str, str],
) -> tuple[Path, str, str]:
    """Rerun and transactionally replace one already-promoted outcome."""

    case, campaign, control = record
    old_digest = campaign["outcomes"].get("sha256")
    if old_digest is None:
        raise EvidenceError(
            f"{campaign['id']}: does not have promoted mutation evidence"
        )

    raw_destination = root / campaign["outcomes"]["path"]
    if raw_destination.is_symlink():
        raise EvidenceError(f"{raw_destination}: promoted outcome cannot be a symlink")
    destination = raw_destination.resolve()
    try:
        destination.relative_to(root)
    except ValueError as error:
        raise EvidenceError(
            f"{destination}: outcome destination escaped the repository"
        ) from error

    with refresh_lock(root):
        old_case_payload = read_regular_file(case.path, str(case.path))
        if load_json(case.path) != case.body:
            raise EvidenceError(f"{case.path}: changed after refresh validation")
        manifest_path = root / "crates/core/chio-adversarial-suite/manifest.json"
        old_manifest_payload = read_regular_file(manifest_path, str(manifest_path))
        old_outcome_payload = read_regular_file(destination, str(destination))
        observed_old_digest = hashlib.sha256(old_outcome_payload).hexdigest()
        if observed_old_digest != old_digest:
            raise EvidenceError(
                f"{destination}: digest mismatch, expected {old_digest}, "
                f"observed {observed_old_digest}"
            )

        inputs_before = campaign_input_digest(
            root, package_dirs, campaign, control, case.path
        )
        with tempfile.TemporaryDirectory(
            prefix=f"chio-security-evidence-refresh-{campaign['id']}-"
        ) as raw:
            output_root = Path(raw) / campaign["id"]
            outcome_candidate = run_campaign(
                root, campaign, control, output_root, environment
            )
            expected_candidate = output_root / "mutants.out/outcomes.json"
            if outcome_candidate != expected_candidate:
                raise EvidenceError(
                    f"{campaign['id']}: campaign returned a noncanonical outcome path"
                )
            if outcome_candidate.is_symlink():
                raise EvidenceError(
                    f"{campaign['id']}: rerun outcome cannot be a symlink"
                )
            validate_outcomes(
                outcome_candidate,
                campaign,
                None,
                root / campaign["source"],
            )
            outcome_payload = read_regular_file(
                outcome_candidate, f"{campaign['id']}: rerun outcome"
            )

            inputs_after = campaign_input_digest(
                root, package_dirs, campaign, control, case.path
            )
            if inputs_after != inputs_before:
                raise EvidenceError(
                    f"{campaign['id']}: source or control contract changed during rerun"
                )
            digest = hashlib.sha256(outcome_payload).hexdigest()

            case_body = copy.deepcopy(case.body)
            matches = 0
            for value in case_body["artifact"]["campaigns"]:
                if value["id"] == campaign["id"]:
                    value["outcomes"]["sha256"] = digest
                    value["outcomes"]["inputs_sha256"] = inputs_after
                    matches += 1
            if matches != 1:
                raise EvidenceError(
                    f"{campaign['id']}: campaign was not unique during refresh"
                )
            case_payload = canonical_json_bytes(case_body)
            rendered_manifest_path, manifest_payload = render_manifest_after_refresh(
                root,
                case.path,
                case.body,
                old_case_payload,
                case_body,
                case_payload,
            )
            if rendered_manifest_path != manifest_path:
                raise EvidenceError(
                    "refresh selected an unexpected adversarial manifest"
                )
            if (
                read_regular_file(manifest_path, str(manifest_path))
                != old_manifest_payload
            ):
                raise EvidenceError(
                    f"{manifest_path}: changed while refresh was running"
                )

            validate_staged_refresh(
                root,
                package_dirs,
                case,
                campaign["id"],
                outcome_payload,
                case_payload,
                manifest_payload,
            )
            if (
                campaign_input_digest(
                    root, package_dirs, campaign, control, case.path
                )
                != inputs_after
            ):
                raise EvidenceError(
                    f"{campaign['id']}: source or control contract changed before commit"
                )
            atomic_replace_many(
                [
                    (destination, outcome_payload),
                    (case.path, case_payload),
                    (manifest_path, manifest_payload),
                ],
                {
                    destination: old_outcome_payload,
                    case.path: old_case_payload,
                    manifest_path: old_manifest_payload,
                },
            )
    return destination, digest, inputs_after


def load_cases(
    root: Path,
    cases_path: Path,
    require_complete: bool,
    fixture: bool,
    refresh_campaign: str | None = None,
) -> tuple[
    list[LoadedCase], dict[str, tuple[LoadedCase, dict[str, Any], dict[str, Any]]]
]:
    package_dirs = package_roots(root)
    paths = sorted(
        path
        for path in cases_path.rglob("*.json")
        if path.parent.name in SECURITY_CASES
    )
    if not paths:
        raise EvidenceError(f"{cases_path}: no security adversarial cases")
    cases = [
        validate_case(
            root,
            package_dirs,
            path,
            require_complete,
            refresh_campaign=refresh_campaign,
        )
        for path in paths
    ]
    observed_classes = [case.body["class"] for case in cases]
    if not fixture:
        if len(cases) != len(SECURITY_CASES) or set(observed_classes) != set(
            SECURITY_CASES
        ):
            raise EvidenceError(
                "security adversarial suite must contain exactly one case per class"
            )
        if len(observed_classes) != len(set(observed_classes)):
            raise EvidenceError("security adversarial suite contains a duplicate class")
        validate_manifest(root, cases)
    index: dict[str, tuple[LoadedCase, dict[str, Any], dict[str, Any]]] = {}
    for case in cases:
        for campaign_id, campaign in case.campaigns.items():
            if campaign_id in index:
                raise EvidenceError(
                    f"duplicate mutation id across cases: {campaign_id}"
                )
            index[campaign_id] = (
                case,
                campaign,
                case.controls[campaign["control_id"]],
            )
    return cases, index


def run_checked(command: list[str], root: Path, environment: dict[str, str]) -> str:
    rendered = " ".join(command)
    print(f"+ {rendered}", file=sys.stderr)
    completed = subprocess.run(
        command,
        cwd=root,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if completed.returncode != 0:
        sys.stderr.write(completed.stdout)
        raise EvidenceError(
            f"command failed with status {completed.returncode}: {rendered}"
        )
    return completed.stdout


def run_json_checked(
    command: list[str], root: Path, environment: dict[str, str]
) -> Any:
    rendered = " ".join(command)
    print(f"+ {rendered}", file=sys.stderr)
    completed = subprocess.run(
        command,
        cwd=root,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        sys.stderr.write(completed.stderr)
        sys.stderr.write(completed.stdout)
        raise EvidenceError(
            f"command failed with status {completed.returncode}: {rendered}"
        )
    if completed.stderr:
        sys.stderr.write(completed.stderr)
    try:
        return json.loads(completed.stdout, object_pairs_hook=reject_duplicate_keys)
    except json.JSONDecodeError as error:
        raise EvidenceError(
            f"command returned invalid JSON: {rendered}: {error}"
        ) from error


def run_control(
    root: Path, control: dict[str, Any], environment: dict[str, str]
) -> None:
    required_os = control.get("required_target_os")
    if required_os is not None and platform.system().lower() != required_os:
        raise EvidenceError(
            f"{control['id']}: requires {required_os}, observed {platform.system().lower()}"
        )
    command = ["cargo", "test", "--package", control["package"]]
    if control["features"]:
        command.extend(["--features", ",".join(control["features"])])
    if control["target_kind"] == "lib":
        command.append("--lib")
    else:
        command.extend(["--test", control["target"]])
    command.extend(["--", control["test_name"], "--exact"])
    output = run_checked(command, root, environment)
    if re.search(r"test result: ok\. 1 passed;", output) is None:
        sys.stderr.write(output)
        raise EvidenceError(
            f"{control['id']}: exact behavioral control did not execute once"
        )


def run_campaign(
    root: Path,
    campaign: dict[str, Any],
    control: dict[str, Any],
    output_root: Path,
    environment: dict[str, str],
) -> Path:
    if output_root.exists():
        raise EvidenceError(
            f"{output_root}: refusing to overwrite existing mutation output"
        )
    source_path = root / campaign["source"]
    try:
        source_digest = hashlib.sha256(source_path.read_bytes()).digest()
    except OSError as error:
        raise EvidenceError(
            f"{source_path}: unable to read mutation source: {error}"
        ) from error
    selector = campaign.get("mutant")
    if selector is None:
        raise EvidenceError(
            f"{campaign['id']}: campaign lacks a semantic mutant selector"
        )
    list_command = [
        "cargo",
        "mutants",
        "--no-config",
        "--package",
        campaign["package"],
        "--file",
        campaign["source"],
        "--list",
        "--json",
        "--no-shuffle",
    ]
    if selector.get("error") is not None:
        list_command.extend(["--error", selector["error"]])
    if control["features"]:
        list_command.extend(["--features", ",".join(control["features"])])
    selected = select_native_mutant(
        run_json_checked(list_command, root, environment), campaign, source_path
    )
    require_statically_viable_mutant(selected, campaign)
    mutation_name = native_mutant_list_name(selected, campaign)

    run_control(root, control, environment)
    output_root.mkdir(parents=True, exist_ok=False)
    output_path = output_root / "mutants.out"
    command = [
        "cargo",
        "mutants",
        "--no-config",
        "--package",
        campaign["package"],
        "--file",
        campaign["source"],
        "--re",
        rf"^{re.escape(mutation_name)}$",
        "--line-col=true",
        "--no-shuffle",
        "--in-place",
        "--jobserver-tasks=1",
        "--output",
        str(output_root),
    ]
    if selector.get("error") is not None:
        command.extend(["--error", selector["error"]])
    cross_package_control = control["package"] != campaign["package"]
    if cross_package_control:
        command.extend(["--test-package", control["package"]])
    if control["features"]:
        command.extend(["--features", ",".join(control["features"])])
    # A Cargo target selector is global to every package in cargo-mutants'
    # test invocation. Applying the control package's integration-test name
    # to a different mutated package makes the unmutated baseline fail before
    # the selected mutant runs. The exact test-name filter remains sufficient
    # for cross-package controls; same-package controls keep the narrower
    # target selector.
    if not cross_package_control:
        if control["target_kind"] == "lib":
            command.append("--cargo-arg=--lib")
        else:
            command.append(f"--cargo-arg=--test={control['target']}")
    command.extend(["--", control["test_name"], "--", "--exact"])
    try:
        run_checked(command, root, environment)
        outcomes_path = output_path / "outcomes.json"
        validate_outcomes(outcomes_path, campaign, None, source_path, selected)
        return outcomes_path
    finally:
        try:
            final_source_digest = hashlib.sha256(source_path.read_bytes()).digest()
        except OSError as error:
            raise EvidenceError(
                f"{campaign['id']}: in-place mutation left the source changed or unreadable: {error}"
            ) from error
        if final_source_digest != source_digest:
            raise EvidenceError(
                f"{campaign['id']}: in-place mutation left the source changed"
            )


def run_release_verification(
    root: Path,
    index: dict[str, tuple[LoadedCase, dict[str, Any], dict[str, Any]]],
    environment: dict[str, str],
) -> tuple[int, int, int]:
    """Execute every promoted and pending campaign against the current tree."""

    promoted = {
        campaign_id: record
        for campaign_id, record in index.items()
        if record[1]["outcomes"].get("sha256") is not None
    }
    pending = {
        campaign_id: record
        for campaign_id, record in index.items()
        if record[1]["outcomes"].get("sha256") is None
    }
    if not promoted and not pending:
        raise EvidenceError("release evidence suite contains no mutation campaigns")

    control_contracts: dict[bytes, dict[str, Any]] = {}
    for record in index.values():
        control = record[2]
        identity = canonical_json_bytes(control)
        control_contracts.setdefault(identity, control)
    for identity in sorted(control_contracts):
        run_control(root, control_contracts[identity], environment)

    with tempfile.TemporaryDirectory(
        prefix="chio-security-adversarial-release-"
    ) as temp:
        temporary = Path(temp)
        for campaign_id in sorted(index):
            record = index[campaign_id]
            run_campaign(
                root,
                record[1],
                record[2],
                temporary / campaign_id,
                environment,
            )
    return len(promoted), len(control_contracts), len(pending)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path)
    parser.add_argument("--cases", type=Path)
    parser.add_argument("--fixture", action="store_true")
    parser.add_argument("--require-complete", action="store_true")
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--release", action="store_true")
    action.add_argument("--campaign")
    parser.add_argument("--output", type=Path)
    action.add_argument("--verify-outcome", nargs=2, metavar=("MUTATION_ID", "PATH"))
    action.add_argument("--promote-outcome", nargs=2, metavar=("MUTATION_ID", "PATH"))
    action.add_argument("--refresh-outcome", metavar="MUTATION_ID")
    action.add_argument("--list-pending", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = (args.root or Path(__file__).resolve().parents[1]).resolve()
    cases_path = (
        args.cases or root / "crates/core/chio-adversarial-suite/cases"
    ).resolve()
    if args.output is not None and args.campaign is None:
        raise EvidenceError("--output requires --campaign")
    require_complete = args.require_complete
    cases, index = load_cases(
        root,
        cases_path,
        require_complete,
        args.fixture,
        refresh_campaign=args.refresh_outcome,
    )
    package_dirs = package_roots(root)
    if args.list_pending:
        for campaign_id in sorted(index):
            if index[campaign_id][1]["outcomes"].get("sha256") is None:
                print(campaign_id)
        return 0
    if args.verify_outcome:
        campaign_id, raw_path = args.verify_outcome
        record = index.get(campaign_id)
        if record is None:
            raise EvidenceError(f"unknown mutation id: {campaign_id}")
        validate_outcomes(
            outcome_path(raw_path), record[1], None, root / record[1]["source"]
        )
        print(f"verified caught-only mutation outcome: {campaign_id}")
        return 0
    if args.promote_outcome:
        campaign_id, raw_path = args.promote_outcome
        record = index.get(campaign_id)
        if record is None:
            raise EvidenceError(f"unknown mutation id: {campaign_id}")
        destination, digest, complete = promote_outcome(
            root, package_dirs, record, raw_path
        )
        load_cases(root, cases_path, False, args.fixture)
        print(f"promoted caught-only mutation outcome: {campaign_id}")
        print(f"outcomes: {destination.relative_to(root)}")
        print(f"sha256: {digest}")
        print(f"case: {'complete' if complete else 'pending additional campaigns'}")
        return 0
    environment = os.environ.copy()
    environment["CARGO_INCREMENTAL"] = "0"
    environment["CARGO_BUILD_JOBS"] = "1"
    if args.refresh_outcome:
        record = index.get(args.refresh_outcome)
        if record is None:
            raise EvidenceError(f"unknown mutation id: {args.refresh_outcome}")
        destination, digest, inputs_digest = refresh_outcome(
            root, package_dirs, record, environment
        )
        load_cases(
            root,
            cases_path,
            False,
            args.fixture,
            refresh_campaign=args.refresh_outcome,
        )
        print(f"refreshed caught-only mutation outcome: {args.refresh_outcome}")
        print(f"outcomes: {destination.relative_to(root)}")
        print(f"sha256: {digest}")
        print(f"inputs_sha256: {inputs_digest}")
        return 0
    if args.campaign:
        record = index.get(args.campaign)
        if record is None:
            raise EvidenceError(f"unknown mutation id: {args.campaign}")
        output = (
            args.output
            or Path(tempfile.gettempdir()) / f"chio-security-mutants-{args.campaign}"
        )
        outcome = run_campaign(
            root, record[1], record[2], output.resolve(), environment
        )
        print(outcome)
        return 0
    if args.release:
        promoted_count, control_count, pending_count = run_release_verification(
            root, index, environment
        )
        print(
            f"reran {promoted_count} promoted and {pending_count} pending caught-only "
            f"mutation selections with {control_count} current behavioral controls"
        )
        return 0
    print(
        f"validated {len(cases)} security adversarial cases and {len(index)} mutation selections"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except EvidenceError as error:
        print(f"security adversarial evidence rejected: {error}", file=sys.stderr)
        raise SystemExit(1)
