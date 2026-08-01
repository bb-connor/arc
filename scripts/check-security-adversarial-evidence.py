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
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib
from contextlib import contextmanager
from dataclasses import dataclass, field as dataclass_field
from datetime import datetime, timezone
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
INPUT_BINDING_SCHEMA = "chio.adversarial-mutation-inputs.v6"
DERIVED_CASES_ROOT = PurePosixPath("crates/core/chio-adversarial-suite/cases")
DERIVED_MANIFEST_PATH = PurePosixPath(
    "crates/core/chio-adversarial-suite/manifest.json"
)
DERIVED_MUTATION_ROOT = PurePosixPath("audits/evidence/mutants/security")
DERIVED_THREATS_ROOT = PurePosixPath("audits/evidence/threats")
REFRESH_STATE_ROOTS = frozenset(
    {
        ".chio-security-adversarial-evidence.refresh-transaction",
        ".chio-security-adversarial-evidence.refresh.lock",
    }
)
GENERATED_INPUT_PARTS = frozenset(
    {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".venv",
        "__pycache__",
        "_apalache-out",
        "node_modules",
        "target",
    }
)


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


def parse_json_payload(payload: bytes, label: str) -> Any:
    try:
        return json.loads(payload, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"{label}: invalid JSON: {error}") from error


def canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def utc_timestamp() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


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
) -> tuple[set[Path], set[Path], set[Path]]:
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
        manifests[manifest_path] = bool(prior_included_dev or include_dev_dependencies)
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
    optional_paths = {
        root / "rust-toolchain",
        root / "rust-toolchain.toml",
        root / ".cargo/config",
        root / ".cargo/config.toml",
        root / ".cargo/mutants.toml",
    }
    absent_optional_paths: set[Path] = set()
    for optional in optional_paths:
        if optional.exists():
            inputs.add(optional.resolve())
        else:
            absent_optional_paths.add(optional)
    visited_directories: set[Path] = set()

    def collect_path(raw_path: Path) -> None:
        try:
            path = raw_path.resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise EvidenceError(
                f"{raw_path}: Cargo input path cannot be resolved: {error}"
            ) from error
        try:
            relative = path.relative_to(root)
        except ValueError as error:
            raise EvidenceError(
                f"{raw_path}: Cargo input symlink escaped the repository"
            ) from error
        if any(part in {".git", "target"} for part in relative.parts):
            return
        if path.is_file():
            inputs.add(path)
            return
        if not path.is_dir():
            raise EvidenceError(
                f"{raw_path}: Cargo input path is not a regular file or directory"
            )
        if path in visited_directories:
            return
        visited_directories.add(path)
        try:
            children = sorted(path.iterdir(), key=lambda child: child.name)
        except OSError as error:
            raise EvidenceError(
                f"{raw_path}: Cargo input directory cannot be read: {error}"
            ) from error
        for child in children:
            if child.name in {".git", "target"}:
                continue
            collect_path(child)

    for manifest_path in manifests:
        collect_path(manifest_path.parent)
    return inputs, visited_directories, absent_optional_paths


def relative_input_path(root: Path, path: Path) -> PurePosixPath | None:
    try:
        relative = path.relative_to(root)
    except ValueError:
        return None
    return PurePosixPath(relative.as_posix())


def is_derived_or_state_input(relative: PurePosixPath) -> bool:
    """Return whether a repository path is excluded from mutation inputs."""

    parts = relative.parts
    if not parts:
        return False
    if any(part in GENERATED_INPUT_PARTS for part in parts):
        return True
    if parts[0] in REFRESH_STATE_ROOTS:
        return True
    if relative == DERIVED_MANIFEST_PATH:
        return True
    if relative == DERIVED_CASES_ROOT or DERIVED_CASES_ROOT in relative.parents:
        return True
    if relative == DERIVED_THREATS_ROOT or DERIVED_THREATS_ROOT in relative.parents:
        return True
    if DERIVED_MUTATION_ROOT in relative.parents:
        mutation_tail = parts[len(DERIVED_MUTATION_ROOT.parts) :]
        if mutation_tail and mutation_tail[0] != ".gitignore":
            return True
    return False


def repository_input_closure(root: Path) -> tuple[set[Path], set[Path]]:
    """Inventory every non-derived regular file and directory in the repository."""

    inputs: set[Path] = set()
    directories: set[Path] = set()

    def collect(path: Path) -> None:
        relative = relative_input_path(root, path)
        if relative is None:
            raise EvidenceError(f"{path}: repository input escaped the repository")
        if relative.parts and relative.parts[0] == ".git":
            return
        if is_derived_or_state_input(relative):
            return
        try:
            metadata = path.lstat()
        except OSError as error:
            raise EvidenceError(
                f"{path}: repository input cannot be inspected: {error}"
            ) from error
        if stat.S_ISLNK(metadata.st_mode):
            return
        if stat.S_ISREG(metadata.st_mode):
            inputs.add(path)
            return
        if not stat.S_ISDIR(metadata.st_mode):
            return
        directories.add(path)
        try:
            children = sorted(path.iterdir(), key=lambda child: child.name)
        except OSError as error:
            raise EvidenceError(
                f"{path}: repository input directory cannot be read: {error}"
            ) from error
        for child in children:
            collect(child)

    collect(root)
    return inputs, directories


def infer_repository_root(path: Path) -> Path | None:
    """Find the nearest enclosing Cargo workspace for directory guard filtering."""

    current = path if path.is_dir() else path.parent
    nearest_manifest_root: Path | None = None
    for candidate in (current, *current.parents):
        manifest = candidate / "Cargo.toml"
        if manifest.is_symlink() or not manifest.is_file():
            continue
        if nearest_manifest_root is None:
            nearest_manifest_root = candidate
        try:
            text = manifest.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        if re.search(r"(?m)^\s*\[workspace\]\s*$", text) is not None:
            return candidate
    return nearest_manifest_root


INCLUDE_PATH = re.compile(
    r'\binclude(?:_str|_bytes)?!\s*\(\s*"([^"\\]*(?:\\.[^"\\]*)*)"'
)
RUST_STRING = re.compile(r'"([^"\\]*(?:\\.[^"\\]*)*)"')


def reject_excluded_compile_references(
    root: Path,
    path: Path,
    payload: bytes,
) -> None:
    """Reject literal compile inputs that point into derived evidence state."""

    if path.suffix not in {".inc", ".rs"}:
        return
    try:
        source = payload.decode("utf-8")
    except UnicodeError as error:
        raise EvidenceError(f"{path}: Rust input is not UTF-8: {error}") from error
    raw_paths = [match.group(1) for match in INCLUDE_PATH.finditer(source)]
    if path.name == "build.rs":
        raw_paths.extend(match.group(1) for match in RUST_STRING.finditer(source))
    for raw_path in raw_paths:
        if "\\" in raw_path or "$" in raw_path or "{" in raw_path:
            continue
        for base in (path.parent, root):
            candidate = (base / raw_path).resolve(strict=False)
            relative = relative_input_path(root, candidate)
            if relative is not None and is_derived_or_state_input(relative):
                raise EvidenceError(
                    f"{path}: participating compile input references excluded "
                    f"generated or derived input `{relative.as_posix()}`"
                )


READ_GUARD_SCHEMA = "chio.read-guard.v2"
MISSING_GUARD_PAYLOAD = canonical_json_bytes(
    {"schema": READ_GUARD_SCHEMA, "kind": "missing"}
)


def regular_file_guard_payload(payload: bytes) -> bytes:
    return canonical_json_bytes(
        {
            "schema": READ_GUARD_SCHEMA,
            "kind": "regular-file",
            "length": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
    )


def read_guard_payload(path: Path, label: str) -> bytes:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return MISSING_GUARD_PAYLOAD
    except OSError as error:
        raise EvidenceError(
            f"{label}: unable to inspect read guard: {error}"
        ) from error
    if stat.S_ISLNK(metadata.st_mode):
        raise EvidenceError(f"{label}: read guard cannot be a symlink")
    if stat.S_ISREG(metadata.st_mode):
        return regular_file_guard_payload(read_regular_file_no_follow(path, label))
    if not stat.S_ISDIR(metadata.st_mode):
        raise EvidenceError(f"{label}: read guard is not a file or directory")
    repository_root = infer_repository_root(path)
    entries: list[dict[str, str]] = []
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        with os.scandir(descriptor) as iterator:
            children = sorted(iterator, key=lambda child: child.name)
    except OSError as error:
        if descriptor is not None:
            os.close(descriptor)
            descriptor = None
        raise EvidenceError(
            f"{label}: unable to read guarded directory: {error}"
        ) from error
    try:
        for child in children:
            child_path = path / child.name
            if repository_root is not None:
                relative = relative_input_path(repository_root, child_path)
                if relative is not None and is_derived_or_state_input(relative):
                    continue
            try:
                child_metadata = child.stat(follow_symlinks=False)
            except OSError as error:
                raise EvidenceError(
                    f"{child_path}: unable to stat guarded entry: {error}"
                ) from error
            if stat.S_ISREG(child_metadata.st_mode):
                kind = "file"
            elif stat.S_ISDIR(child_metadata.st_mode):
                kind = "directory"
            elif stat.S_ISLNK(child_metadata.st_mode):
                try:
                    target = os.readlink(child.name, dir_fd=descriptor)
                except OSError as error:
                    raise EvidenceError(
                        f"{child_path}: unable to read guarded symlink: {error}"
                    ) from error
                entries.append(
                    {"kind": "symlink", "name": child.name, "target": target}
                )
                continue
            else:
                kind = "other"
            entries.append({"kind": kind, "name": child.name})
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return canonical_json_bytes(
        {"schema": READ_GUARD_SCHEMA, "kind": "directory", "entries": entries}
    )


def campaign_input_snapshot(
    root: Path,
    package_dirs: dict[str, Path],
    campaign: dict[str, Any],
    control: dict[str, Any],
    case_path: Path,
    *,
    captured_files: dict[Path, bytes | None] | None = None,
) -> tuple[str, dict[Path, bytes]]:
    """Bind caught evidence to the exact mutation and behavioral-control inputs."""

    participating_inputs, _participating_directories, absent_optional_paths = (
        package_input_closure(
            root,
            package_dirs,
            {campaign["package"], control["package"]},
        )
    )
    participating_derived = []
    for path in participating_inputs:
        relative = relative_input_path(root, path)
        if relative is not None and is_derived_or_state_input(relative):
            participating_derived.append(relative.as_posix())
    if participating_derived:
        rendered = ", ".join(sorted(participating_derived))
        raise EvidenceError(
            f"{campaign['id']}: mutation evidence output entered its Cargo input "
            f"closure: {rendered}"
        )
    input_paths, input_directories = repository_input_closure(root)
    input_paths.update(
        {
            root / campaign["source"],
            root / control["test_source"],
        }
    )
    derived_inputs = []
    for path in input_paths:
        relative = relative_input_path(root, path)
        if relative is not None and is_derived_or_state_input(relative):
            derived_inputs.append(relative.as_posix())
    if derived_inputs:
        rendered = ", ".join(sorted(derived_inputs))
        raise EvidenceError(
            f"{campaign['id']}: derived evidence entered the repository input "
            f"closure: {rendered}"
        )
    guards: dict[Path, bytes] = {}
    files: list[dict[str, str]] = []
    requested_captures = set(captured_files) if captured_files is not None else set()
    for path in sorted(input_paths, key=lambda item: item.as_posix()):
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError as error:
            raise EvidenceError(
                f"{path}: input binding file escaped the repository"
            ) from error
        file_payload = read_regular_file_no_follow(path, relative, root=root)
        if path in participating_inputs:
            reject_excluded_compile_references(root, path, file_payload)
        payload = regular_file_guard_payload(file_payload)
        guards[path] = payload
        if captured_files is not None and path in requested_captures:
            captured_files[path] = file_payload
        files.append(
            {
                "path": relative,
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    if captured_files is not None:
        missing_captures = [
            path for path in requested_captures if captured_files[path] is None
        ]
        if missing_captures:
            rendered = ", ".join(sorted(path.as_posix() for path in missing_captures))
            raise EvidenceError(
                f"input binding did not capture requested files: {rendered}"
            )
    directories: list[dict[str, str]] = []
    for path in sorted(input_directories, key=lambda item: item.as_posix()):
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError as error:
            raise EvidenceError(
                f"{path}: input inventory directory escaped the repository"
            ) from error
        payload = read_guard_payload(path, relative)
        guards[path] = payload
        directories.append(
            {"path": relative, "sha256": hashlib.sha256(payload).hexdigest()}
        )
    absent: list[str] = []
    for path in sorted(absent_optional_paths, key=lambda item: item.as_posix()):
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError as error:
            raise EvidenceError(
                f"{path}: absent input guard escaped the repository"
            ) from error
        payload = read_guard_payload(path, relative)
        if payload != MISSING_GUARD_PAYLOAD:
            raise EvidenceError(f"{relative}: absent input appeared during snapshot")
        guards[path] = payload
        absent.append(relative)

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
        "directories": directories,
        "absent": absent,
    }
    return hashlib.sha256(canonical_json_bytes(binding)).hexdigest(), guards


def campaign_input_digest(
    root: Path,
    package_dirs: dict[str, Path],
    campaign: dict[str, Any],
    control: dict[str, Any],
    case_path: Path,
    *,
    captured_files: dict[Path, bytes | None] | None = None,
) -> str:
    return campaign_input_snapshot(
        root,
        package_dirs,
        campaign,
        control,
        case_path,
        captured_files=captured_files,
    )[0]


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
        fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError as error:
        raise EvidenceError(
            f"{path}: unable to open directory for fsync: {error}"
        ) from error
    try:
        os.fsync(descriptor)
    except OSError as error:
        raise EvidenceError(f"{path}: unable to fsync directory: {error}") from error
    finally:
        os.close(descriptor)


def write_new_fsynced(path: Path, payload: bytes, mode: int) -> None:
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    except OSError as error:
        raise EvidenceError(
            f"{path}: unable to create transaction artifact: {error}"
        ) from error
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


TRANSACTION_DIRECTORY = ".chio-security-adversarial-evidence.refresh-transaction"
TRANSACTION_SCHEMA = "chio.security-adversarial-refresh-transaction.v1"


def lexical_path_below_root(
    root: Path,
    path: Path,
    label: str,
    *,
    allow_missing_parents: bool = False,
    allow_root: bool = False,
) -> Path:
    root = root.resolve()
    candidate = path if path.is_absolute() else root / path
    try:
        relative = candidate.relative_to(root)
    except ValueError as error:
        raise EvidenceError(f"{label}: path escaped the transaction root") from error
    canonical_repository_path(relative.as_posix(), label, allow_root=allow_root)
    current = root
    for component in relative.parts[:-1]:
        current = current / component
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            if allow_missing_parents:
                return root / relative
            raise EvidenceError(f"{label}: parent path is absent") from None
        except OSError as error:
            raise EvidenceError(f"{label}: parent path is absent: {error}") from error
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise EvidenceError(f"{label}: parent path is not a no-follow directory")
    final_path = root / relative
    if final_path.is_symlink():
        raise EvidenceError(f"{label}: final path cannot be a symlink")
    return final_path


def open_parent_directory_below_root(root: Path, path: Path, label: str) -> int:
    root = root.resolve()
    candidate = lexical_path_below_root(root, path, label)
    relative = candidate.relative_to(root)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(root, flags)
        for component in relative.parts[:-1]:
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
    except OSError as error:
        if descriptor is not None:
            os.close(descriptor)
        raise EvidenceError(
            f"{label}: unable to open no-follow parent: {error}"
        ) from error
    return descriptor


def read_regular_file_below_root(root: Path, path: Path, label: str) -> bytes:
    """Read a repository file through a pinned, no-follow parent descriptor."""

    parent = open_parent_directory_below_root(root, path, label)
    descriptor: int | None = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(path.name, flags, dir_fd=parent)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise EvidenceError(f"{label}: expected a regular file")
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = None
            return handle.read()
    except OSError as error:
        raise EvidenceError(
            f"{label}: unable to read no-follow file: {error}"
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)


def read_regular_file_no_follow(
    path: Path,
    label: str,
    *,
    root: Path | None = None,
) -> bytes:
    """Read one immutable regular-file payload through a no-follow descriptor."""

    if root is not None:
        candidate = path if path.is_absolute() else root / path
        try:
            candidate.relative_to(root)
        except ValueError:
            pass
        else:
            return read_regular_file_below_root(root, candidate, label)
    parent_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    parent_flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    file_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    file_flags |= getattr(os, "O_CLOEXEC", 0)
    parent: int | None = None
    descriptor: int | None = None
    try:
        parent = os.open(path.parent, parent_flags)
        descriptor = os.open(path.name, file_flags, dir_fd=parent)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise EvidenceError(f"{label}: expected a regular file")
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = None
            return handle.read()
    except OSError as error:
        raise EvidenceError(
            f"{label}: unable to read no-follow file: {error}"
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if parent is not None:
            os.close(parent)


def read_regular_file(path: Path, label: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise EvidenceError(f"{label}: expected a regular file")
    try:
        return path.read_bytes()
    except OSError as error:
        raise EvidenceError(f"{label}: unable to read file: {error}") from error


def snapshot_threat_aggregates(root: Path) -> dict[Path, bytes]:
    """Snapshot every threat aggregate before a mutation refresh starts."""

    evidence_dir = root / "audits/evidence/threats"
    if not evidence_dir.exists():
        return {}
    if evidence_dir.is_symlink() or not evidence_dir.is_dir():
        raise EvidenceError(f"{evidence_dir}: threat evidence directory is invalid")
    snapshots: dict[Path, bytes] = {}
    for path in sorted(evidence_dir.glob("*.json")):
        snapshots[path] = read_regular_file(path, str(path))
    return snapshots


def caught_only_count(payload: bytes, label: str) -> int:
    """Return the caught count only for a structurally caught-only outcome."""

    try:
        body = json.loads(payload, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise EvidenceError(
            f"{label}: invalid mutation outcome JSON: {error}"
        ) from error
    if not isinstance(body, dict):
        raise EvidenceError(f"{label}: mutation outcome must be an object")
    counts: dict[str, int] = {}
    for field in (
        "caught",
        "missed",
        "timeout",
        "unviable",
        "success",
        "total_mutants",
    ):
        value = body.get(field)
        if type(value) is not int or value < 0:
            raise EvidenceError(f"{label}: invalid mutation count {field}")
        counts[field] = value
    if (
        counts["caught"] < 1
        or counts["missed"] != 0
        or counts["timeout"] != 0
        or counts["unviable"] != 0
        or counts["success"] != 0
        or counts["total_mutants"] != counts["caught"]
    ):
        raise EvidenceError(f"{label}: aggregate child is not caught-only evidence")
    outcomes = body.get("outcomes")
    if not isinstance(outcomes, list) or not outcomes:
        raise EvidenceError(f"{label}: aggregate child has no native outcomes")
    return counts["caught"]


def canonical_repository_path(
    value: Any,
    label: str,
    *,
    allow_root: bool = False,
) -> str:
    if not isinstance(value, str):
        raise EvidenceError(f"{label}: expected a repository-relative path")
    parsed = PurePosixPath(value)
    if allow_root and value == ".":
        return value
    if (
        parsed.is_absolute()
        or value != parsed.as_posix()
        or value == "."
        or "." in parsed.parts
        or ".." in parsed.parts
        or "\\" in value
    ):
        raise EvidenceError(f"{label}: invalid repository-relative path")
    return value


def render_threat_aggregate_note(counts: list[tuple[str, int]]) -> str:
    details = " and ".join(
        f"{campaign_id} caught {caught}" for campaign_id, caught in counts
    )
    return (
        "Digest-bound caught-only cargo-mutants outcomes cover the closed sub-vector: "
        f"{details}, with zero missed, timed-out, or unviable mutants."
    )


def render_threat_aggregate_replacements(
    root: Path,
    case: LoadedCase,
    refreshed_campaign: dict[str, Any],
    refreshed_outcome_payload: bytes,
    snapshots: dict[Path, bytes],
    refreshed_at: str,
) -> tuple[list[tuple[Path, bytes]], dict[Path, bytes]]:
    """Repair every threat aggregate that cites the refreshed campaign."""

    campaign_id = refreshed_campaign["id"]
    campaign_path = refreshed_campaign["outcomes"]["path"]
    case_threat_id = require_string(
        case.body["threat_id"], SAFE_ID, f"{case.path}: threat id"
    )
    try:
        case_relative_path = case.path.relative_to(root).as_posix()
    except ValueError as error:
        raise EvidenceError(f"{case.path}: case escaped the repository") from error

    replacements: list[tuple[Path, bytes]] = []
    read_guards: dict[Path, bytes] = {}
    for threat_path, original_payload in sorted(snapshots.items()):
        try:
            body = json.loads(original_payload, object_pairs_hook=reject_duplicate_keys)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise EvidenceError(
                f"{threat_path}: invalid threat evidence JSON: {error}"
            ) from error
        if not isinstance(body, dict):
            raise EvidenceError(f"{threat_path}: threat evidence must be an object")
        if "outcomes" not in body:
            continue
        raw_records = body["outcomes"]
        if not isinstance(raw_records, list) or not raw_records:
            raise EvidenceError(
                f"{threat_path}: aggregate outcomes must be a nonempty array"
            )
        for offset, raw_record in enumerate(raw_records):
            label = f"{threat_path}: outcomes[{offset}]"
            if not isinstance(raw_record, dict):
                raise EvidenceError(f"{label}: aggregate outcome must be an object")
            exact_keys(raw_record, {"id", "path", "sha256"}, set(), label)
            require_string(raw_record["id"], SAFE_ID, f"{label}: id")
            canonical_repository_path(raw_record["path"], f"{label}: path")
            require_string(raw_record["sha256"], SHA256, f"{label}: sha256")
        cites_target = any(
            record["id"] == campaign_id or record["path"] == campaign_path
            for record in raw_records
        )
        if not cites_target:
            continue
        if threat_path.stem != case_threat_id:
            raise EvidenceError(
                f"{threat_path}: refreshed campaign belongs to threat {case_threat_id}"
            )
        mutation_case_path = canonical_repository_path(
            body.get("mutation_case_path"), f"{threat_path}: mutation_case_path"
        )
        if mutation_case_path != case_relative_path:
            raise EvidenceError(
                f"{threat_path}: mutation_case_path does not identify the campaign case"
            )
        observed_ids: set[str] = set()
        rendered_records: list[dict[str, str]] = []
        rendered_counts: list[tuple[str, int]] = []
        target_matches = 0
        for offset, raw_record in enumerate(raw_records):
            label = f"{threat_path}: outcomes[{offset}]"
            if not isinstance(raw_record, dict):
                raise EvidenceError(f"{label}: aggregate outcome must be an object")
            exact_keys(raw_record, {"id", "path", "sha256"}, set(), label)
            record_id = require_string(raw_record["id"], SAFE_ID, f"{label}: id")
            record_path = canonical_repository_path(
                raw_record["path"], f"{label}: path"
            )
            if record_id in observed_ids:
                raise EvidenceError(f"{label}: duplicate aggregate campaign id")
            observed_ids.add(record_id)
            bound_campaign = case.campaigns.get(record_id)
            if bound_campaign is None:
                raise EvidenceError(
                    f"{label}: campaign is not mapped by the aggregate mutation case"
                )
            expected_path = bound_campaign["outcomes"]["path"]
            if record_path != expected_path:
                raise EvidenceError(
                    f"{label}: path differs from its mapped campaign outcome"
                )
            if record_id == campaign_id:
                target_matches += 1
                child_payload = refreshed_outcome_payload
            else:
                child_path = (root / record_path).resolve()
                try:
                    child_path.relative_to(root)
                except ValueError as error:
                    raise EvidenceError(
                        f"{label}: child outcome escaped the repository"
                    ) from error
                child_payload = read_regular_file(child_path, label)
                prior_guard = read_guards.get(child_path)
                if prior_guard is not None and prior_guard != child_payload:
                    raise EvidenceError(
                        f"{label}: sibling outcome changed during aggregate rendering"
                    )
                read_guards[child_path] = regular_file_guard_payload(child_payload)
                expected_digest = bound_campaign["outcomes"].get("sha256")
                observed_digest = hashlib.sha256(child_payload).hexdigest()
                if expected_digest != observed_digest:
                    raise EvidenceError(
                        f"{label}: child differs from its adversarial case binding"
                    )
            caught = caught_only_count(child_payload, label)
            digest = hashlib.sha256(child_payload).hexdigest()
            rendered_records.append(
                {"id": record_id, "path": record_path, "sha256": digest}
            )
            rendered_counts.append((record_id, caught))
        if target_matches != 1:
            raise EvidenceError(
                f"{threat_path}: refreshed campaign must be cited exactly once"
            )
        survivors = body.get("survivors")
        if survivors not in (None, []):
            raise EvidenceError(
                f"{threat_path}: caught-only aggregate cannot retain survivors"
            )

        rendered = copy.deepcopy(body)
        rendered["caught"] = sum(caught for _campaign, caught in rendered_counts)
        rendered["outcomes"] = rendered_records
        rendered["note"] = render_threat_aggregate_note(rendered_counts)
        rendered["reproduction_command"] = " && ".join(
            "./scripts/check-security-adversarial-evidence.sh "
            f"--verify-outcome {record['id']} {record['path']}"
            for record in rendered_records
        )
        rendered["ran_at"] = refreshed_at
        rendered["timestamp_kind"] = "command-wall-clock"
        rendered["timestamp_note"] = (
            "The timestamp records completion of caught-only mutation rerun "
            "validation. Native outcomes retain cargo-mutants phase records and "
            "durations."
        )
        replacements.append((threat_path, canonical_json_bytes(rendered)))
    return replacements, read_guards


# Trusted refresh state is isolated from the repository.
# Version 2 retains callable names and rejects repository-local transaction state.
LEGACY_TRANSACTION_DIRECTORY = TRANSACTION_DIRECTORY
STATE_DIRECTORY_PREFIX = ".chio-security-adversarial-evidence.state.v2."
TRANSACTION_DIRECTORY = "refresh-transaction"
LOCK_DIRECTORY = "refresh.lock"
TRANSACTION_SCHEMA = "chio.security-adversarial-refresh-transaction.v2"


@dataclass(frozen=True)
class FileSnapshot:
    payload: bytes
    mode: int
    device: int
    inode: int


@dataclass
class TrustedState:
    root: Path
    root_metadata: os.stat_result
    path: Path
    parent_descriptor: int
    descriptor: int
    identity: tuple[int, int]


def metadata_identity(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


def require_owned_directory_metadata(
    metadata: os.stat_result, label: str, expected_mode: int = 0o700
) -> None:
    if not stat.S_ISDIR(metadata.st_mode):
        raise EvidenceError(f"{label}: expected a directory")
    if metadata.st_uid != os.geteuid():
        raise EvidenceError(f"{label}: owner differs from the current user")
    if stat.S_IMODE(metadata.st_mode) != expected_mode:
        raise EvidenceError(f"{label}: directory mode must be {expected_mode:04o}")


def require_owned_file_metadata(
    metadata: os.stat_result,
    label: str,
    expected_mode: int,
    *,
    allowed_links: frozenset[int] = frozenset((1,)),
) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise EvidenceError(f"{label}: expected a regular file")
    if metadata.st_uid != os.geteuid():
        raise EvidenceError(f"{label}: owner differs from the current user")
    if stat.S_IMODE(metadata.st_mode) != expected_mode:
        raise EvidenceError(f"{label}: file mode must be {expected_mode:04o}")
    if metadata.st_nlink not in allowed_links:
        raise EvidenceError(f"{label}: unexpected hard-link count")


def repository_identity(root: Path) -> tuple[Path, os.stat_result, dict[str, Any]]:
    try:
        canonical_root = root.resolve(strict=True)
        metadata = canonical_root.lstat()
        parent_metadata = canonical_root.parent.stat()
    except (OSError, RuntimeError) as error:
        raise EvidenceError(
            f"{root}: unable to identify repository root: {error}"
        ) from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise EvidenceError(f"{canonical_root}: repository root is not a directory")
    if parent_metadata.st_dev != metadata.st_dev:
        raise EvidenceError(
            f"{canonical_root}: external transaction state cannot share its filesystem"
        )
    identity = {
        "canonical_path": str(canonical_root),
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
    }
    return canonical_root, metadata, identity


def trusted_state_path(root: Path) -> Path:
    canonical_root, _metadata, identity = repository_identity(root)
    digest = hashlib.sha256(canonical_json_bytes(identity)).hexdigest()
    return canonical_root.parent / f"{STATE_DIRECTORY_PREFIX}{digest}"


def transaction_directory(root: Path) -> Path:
    return trusted_state_path(root) / TRANSACTION_DIRECTORY


def trusted_transaction_exists(root: Path) -> bool:
    with open_trusted_state(root, create=False) as state:
        if state is None:
            return False
        try:
            metadata = os.stat(
                TRANSACTION_DIRECTORY,
                dir_fd=state.descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return False
        require_owned_directory_metadata(
            metadata, str(state.path / TRANSACTION_DIRECTORY)
        )
        return True


def reject_in_root_transaction_state(root: Path) -> None:
    legacy = root.resolve() / LEGACY_TRANSACTION_DIRECTORY
    try:
        legacy.lstat()
    except FileNotFoundError:
        return
    except OSError as error:
        raise EvidenceError(
            f"{legacy}: unable to inspect untrusted transaction state: {error}"
        ) from error
    raise EvidenceError(
        f"{legacy}: untrusted in-repository transaction state is preserved for inspection"
    )


@contextmanager
def open_trusted_state(root: Path, *, create: bool) -> Iterator[TrustedState | None]:
    canonical_root, root_metadata, _identity = repository_identity(root)
    path = trusted_state_path(canonical_root)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    parent_descriptor: int | None = None
    state_descriptor: int | None = None
    state: TrustedState | None = None
    try:
        try:
            parent_descriptor = os.open(canonical_root.parent, flags)
            named_root = os.stat(
                canonical_root.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            if metadata_identity(named_root) != metadata_identity(root_metadata):
                raise EvidenceError(f"{canonical_root}: repository identity changed")
            if create:
                try:
                    os.mkdir(path.name, 0o700, dir_fd=parent_descriptor)
                    os.fsync(parent_descriptor)
                except FileExistsError:
                    pass
            named_state: os.stat_result | None
            try:
                named_state = os.stat(
                    path.name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                if create:
                    raise
                named_state = None
            if named_state is not None:
                require_owned_directory_metadata(named_state, str(path))
                state_descriptor = os.open(path.name, flags, dir_fd=parent_descriptor)
                opened_state = os.fstat(state_descriptor)
                require_owned_directory_metadata(opened_state, str(path))
                if (
                    metadata_identity(opened_state) != metadata_identity(named_state)
                    or opened_state.st_dev != root_metadata.st_dev
                ):
                    raise EvidenceError(f"{path}: trusted-state identity changed")
                repeated_state = os.stat(
                    path.name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                if metadata_identity(repeated_state) != metadata_identity(opened_state):
                    raise EvidenceError(f"{path}: trusted-state name was replaced")
                state = TrustedState(
                    root=canonical_root,
                    root_metadata=root_metadata,
                    path=path,
                    parent_descriptor=parent_descriptor,
                    descriptor=state_descriptor,
                    identity=metadata_identity(opened_state),
                )
        except OSError as error:
            raise EvidenceError(f"{path}: unable to open trusted state: {error}") from error
        yield state
    finally:
        if state_descriptor is not None:
            os.close(state_descriptor)
        if parent_descriptor is not None:
            os.close(parent_descriptor)


@contextmanager
def open_owned_directory_at(
    parent_descriptor: int, name: str, label: str
) -> Iterator[tuple[int, tuple[int, int]]]:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor: int | None = None
    try:
        try:
            named = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
            require_owned_directory_metadata(named, label)
            descriptor = os.open(name, flags, dir_fd=parent_descriptor)
            opened = os.fstat(descriptor)
            require_owned_directory_metadata(opened, label)
            if metadata_identity(opened) != metadata_identity(named):
                raise EvidenceError(f"{label}: identity changed while opening")
            repeated = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
            if metadata_identity(repeated) != metadata_identity(opened):
                raise EvidenceError(f"{label}: directory name was replaced")
        except OSError as error:
            raise EvidenceError(
                f"{label}: unable to open no-follow directory: {error}"
            ) from error
        yield descriptor, metadata_identity(opened)
    finally:
        if descriptor is not None:
            os.close(descriptor)


def write_new_fsynced_at(
    directory_descriptor: int,
    name: str,
    payload: bytes,
    mode: int,
    label: str,
) -> None:
    if PurePosixPath(name).name != name or name in {".", ".."}:
        raise EvidenceError(f"{label}: invalid trusted-state entry name")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor: int | None = None
    created_identity: tuple[int, int] | None = None
    try:
        descriptor = os.open(name, flags, mode, dir_fd=directory_descriptor)
        created_identity = metadata_identity(os.fstat(descriptor))
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            os.fchmod(descriptor, mode)
            handle.write(payload)
            handle.flush()
            os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        require_owned_file_metadata(metadata, label, mode)
        named = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
        if metadata_identity(named) != metadata_identity(metadata):
            raise EvidenceError(f"{label}: file name was replaced")
    except OSError as error:
        if created_identity is not None:
            try:
                named = os.stat(
                    name,
                    dir_fd=directory_descriptor,
                    follow_symlinks=False,
                )
                if metadata_identity(named) == created_identity:
                    os.unlink(name, dir_fd=directory_descriptor)
            except OSError:
                pass
        raise EvidenceError(
            f"{label}: unable to create trusted-state file: {error}"
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def read_owned_file_at(
    directory_descriptor: int,
    name: str,
    label: str,
    expected_mode: int,
    *,
    allowed_links: frozenset[int] = frozenset((1,)),
) -> tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(name, flags, dir_fd=directory_descriptor)
        before = os.fstat(descriptor)
        require_owned_file_metadata(
            before, label, expected_mode, allowed_links=allowed_links
        )
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            payload = handle.read()
        after = os.fstat(descriptor)
        if (
            metadata_identity(after) != metadata_identity(before)
            or after.st_size != before.st_size
            or after.st_mtime_ns != before.st_mtime_ns
            or after.st_ctime_ns != before.st_ctime_ns
        ):
            raise EvidenceError(f"{label}: file changed while reading")
        named = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
        if metadata_identity(named) != metadata_identity(after):
            raise EvidenceError(f"{label}: file name was replaced")
        return payload, after
    except OSError as error:
        raise EvidenceError(
            f"{label}: unable to read trusted-state file: {error}"
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def parse_trusted_json(payload: bytes, label: str) -> Any:
    try:
        return json.loads(payload, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"{label}: invalid JSON: {error}") from error


def retire_owned_directory(
    state: TrustedState,
    name: str,
    descriptor: int,
    identity: tuple[int, int],
) -> None:
    label = str(state.path / name)
    entries = os.listdir(descriptor)
    entry_metadata: dict[str, tuple[int, int, int, int, int, int, int, int]] = {}
    for entry in entries:
        metadata = os.stat(entry, dir_fd=descriptor, follow_symlinks=False)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid():
            raise EvidenceError(f"{label}: unsafe entry prevents removal")
        entry_metadata[entry] = (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_uid,
            stat.S_IMODE(metadata.st_mode),
            metadata.st_nlink,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )
    named = os.stat(name, dir_fd=state.descriptor, follow_symlinks=False)
    require_owned_directory_metadata(named, label)
    if metadata_identity(named) != identity:
        raise EvidenceError(f"{label}: identity changed before retirement")
    retired_name = f".{name}.retired.{secrets.token_hex(16)}"
    os.rename(
        name,
        retired_name,
        src_dir_fd=state.descriptor,
        dst_dir_fd=state.descriptor,
    )
    os.fsync(state.descriptor)
    retired = os.stat(retired_name, dir_fd=state.descriptor, follow_symlinks=False)
    require_owned_directory_metadata(retired, label)
    if metadata_identity(retired) != identity:
        raise EvidenceError(f"{label}: wrong directory was retired")
    if set(os.listdir(descriptor)) != set(entries):
        raise EvidenceError(f"{label}: inventory changed during retirement")
    for entry in entries:
        current = os.stat(entry, dir_fd=descriptor, follow_symlinks=False)
        if not stat.S_ISREG(current.st_mode) or current.st_uid != os.geteuid():
            raise EvidenceError(f"{label}: entry changed during retirement")
        current_metadata = (
            current.st_dev,
            current.st_ino,
            current.st_uid,
            stat.S_IMODE(current.st_mode),
            current.st_nlink,
            current.st_size,
            current.st_mtime_ns,
            current.st_ctime_ns,
        )
        if current_metadata != entry_metadata[entry]:
            raise EvidenceError(f"{label}: entry identity changed during retirement")
        os.unlink(entry, dir_fd=descriptor)
    os.fsync(descriptor)
    final = os.stat(retired_name, dir_fd=state.descriptor, follow_symlinks=False)
    require_owned_directory_metadata(final, label)
    if metadata_identity(final) != identity:
        raise EvidenceError(f"{label}: retired directory identity changed")
    os.rmdir(retired_name, dir_fd=state.descriptor)
    os.fsync(state.descriptor)


def ensure_parent_directories_below_root(root: Path, path: Path, label: str) -> None:
    root = root.resolve()
    candidate = path if path.is_absolute() else root / path
    try:
        relative = candidate.relative_to(root)
    except ValueError as error:
        raise EvidenceError(f"{label}: path escaped the transaction root") from error
    canonical_repository_path(relative.as_posix(), label)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(root, flags)
        for component in relative.parts[:-1]:
            try:
                next_descriptor = os.open(component, flags, dir_fd=descriptor)
            except FileNotFoundError:
                os.mkdir(component, 0o755, dir_fd=descriptor)
                os.fsync(descriptor)
                next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
    except OSError as error:
        raise EvidenceError(
            f"{label}: unable to create no-follow parent: {error}"
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def read_file_snapshot_below_root(
    root: Path, path: Path, label: str, *, allow_missing: bool
) -> FileSnapshot | None:
    parent = open_parent_directory_below_root(root, path, label)
    try:
        return read_file_snapshot_at(
            parent, path.name, label, allow_missing=allow_missing
        )
    finally:
        os.close(parent)


def read_file_snapshot_at(
    parent: int, name: str, label: str, *, allow_missing: bool
) -> FileSnapshot | None:
    descriptor: int | None = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_CLOEXEC", 0)
        try:
            descriptor = os.open(name, flags, dir_fd=parent)
        except FileNotFoundError:
            if allow_missing:
                return None
            raise
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise EvidenceError(f"{label}: expected a regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            payload = handle.read()
        after = os.fstat(descriptor)
        if (
            metadata_identity(after) != metadata_identity(before)
            or after.st_size != before.st_size
            or after.st_mtime_ns != before.st_mtime_ns
            or after.st_ctime_ns != before.st_ctime_ns
        ):
            raise EvidenceError(f"{label}: file changed while reading")
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if metadata_identity(named) != metadata_identity(after):
            raise EvidenceError(f"{label}: file identity changed while reading")
        return FileSnapshot(
            payload,
            stat.S_IMODE(after.st_mode),
            after.st_dev,
            after.st_ino,
        )
    except OSError as error:
        raise EvidenceError(
            f"{label}: unable to read no-follow file: {error}"
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def remove_transaction_directory(root: Path, path: Path) -> None:
    root = root.resolve()
    expected = transaction_directory(root)
    if path != expected:
        raise EvidenceError(f"{path}: unexpected trusted transaction path")
    with open_trusted_state(root, create=False) as state:
        if state is None:
            return
        try:
            with open_owned_directory_at(
                state.descriptor, TRANSACTION_DIRECTORY, str(expected)
            ) as (descriptor, identity):
                retire_owned_directory(
                    state, TRANSACTION_DIRECTORY, descriptor, identity
                )
        except EvidenceError as error:
            try:
                os.stat(
                    TRANSACTION_DIRECTORY,
                    dir_fd=state.descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                return
            raise error


def prepare_transaction_journal(
    root: Path,
    replacements: list[tuple[Path, bytes]],
    originals: dict[Path, bytes | None],
    guards: dict[Path, bytes],
) -> tuple[
    Path,
    list[tuple[Path, Path]],
    dict[Path, int | None],
    dict[Path, int],
]:
    root = root.resolve()
    reject_in_root_transaction_state(root)
    journal = transaction_directory(root)
    entries: list[dict[str, Any]] = []
    guard_entries: list[dict[str, str]] = []
    staged: list[tuple[Path, Path]] = []
    original_modes: dict[Path, int | None] = {}
    replacement_modes: dict[Path, int] = {}
    transaction_id = secrets.token_hex(32)
    created_journal = False
    try:
        with open_trusted_state(root, create=True) as state:
            if state is None:
                raise EvidenceError("unable to create trusted transaction state")
            try:
                os.mkdir(TRANSACTION_DIRECTORY, 0o700, dir_fd=state.descriptor)
                created_journal = True
                os.fsync(state.descriptor)
            except FileExistsError as error:
                raise EvidenceError(
                    f"{journal}: unrecovered transaction journal exists"
                ) from error
            with open_owned_directory_at(
                state.descriptor, TRANSACTION_DIRECTORY, str(journal)
            ) as (journal_descriptor, _journal_identity):
                for offset, (path, replacement) in enumerate(replacements):
                    destination = lexical_path_below_root(
                        root, path, f"{path}: transaction destination"
                    )
                    observed = read_file_snapshot_below_root(
                        root,
                        destination,
                        str(destination),
                        allow_missing=True,
                    )
                    original = originals[path]
                    replacement_name = f"replacement-{offset:04}.bin"
                    if original is None:
                        if observed is not None:
                            raise EvidenceError(
                                f"{destination}: appeared while transaction was prepared"
                            )
                        original_state = "absent"
                        backup_name: str | None = None
                        original_digest: str | None = None
                        original_mode: int | None = None
                        replacement_mode = 0o644
                    else:
                        if observed is None or observed.payload != original:
                            raise EvidenceError(
                                f"{destination}: changed while transaction was prepared"
                            )
                        original_state = "present"
                        backup_name = f"original-{offset:04}.bin"
                        original_digest = hashlib.sha256(original).hexdigest()
                        original_mode = observed.mode
                        replacement_mode = observed.mode
                        write_new_fsynced_at(
                            journal_descriptor,
                            backup_name,
                            original,
                            0o600,
                            str(journal / backup_name),
                        )
                    write_new_fsynced_at(
                        journal_descriptor,
                        replacement_name,
                        replacement,
                        replacement_mode,
                        str(journal / replacement_name),
                    )
                    original_modes[path] = original_mode
                    replacement_modes[path] = replacement_mode
                    staged.append((path, journal / replacement_name))
                    entries.append(
                        {
                            "destination": destination.relative_to(root).as_posix(),
                            "original_state": original_state,
                            "original_backup": backup_name,
                            "original_sha256": original_digest,
                            "original_mode": original_mode,
                            "replacement_stage": replacement_name,
                            "replacement_sha256": hashlib.sha256(
                                replacement
                            ).hexdigest(),
                            "replacement_mode": replacement_mode,
                        }
                    )
                for path, payload in sorted(guards.items()):
                    guard_path = lexical_path_below_root(
                        root,
                        path,
                        f"{path}: transaction read guard",
                        allow_missing_parents=True,
                        allow_root=True,
                    )
                    guard_entries.append(
                        {
                            "path": guard_path.relative_to(root).as_posix(),
                            "sha256": hashlib.sha256(payload).hexdigest(),
                        }
                    )
                manifest = {
                    "schema": TRANSACTION_SCHEMA,
                    "transaction_id": transaction_id,
                    "repository": repository_identity(root)[2],
                    "entries": entries,
                    "read_guards": guard_entries,
                }
                manifest_payload = canonical_json_bytes(manifest)
                write_new_fsynced_at(
                    journal_descriptor,
                    "manifest.json",
                    manifest_payload,
                    0o600,
                    str(journal / "manifest.json"),
                )
                os.fsync(journal_descriptor)
                prepared_payload = canonical_json_bytes(
                    {
                        "transaction_id": transaction_id,
                        "manifest_sha256": hashlib.sha256(manifest_payload).hexdigest(),
                    }
                )
                write_new_fsynced_at(
                    journal_descriptor,
                    "prepared.tmp",
                    prepared_payload,
                    0o600,
                    str(journal / "prepared.tmp"),
                )
                os.replace(
                    "prepared.tmp",
                    "prepared",
                    src_dir_fd=journal_descriptor,
                    dst_dir_fd=journal_descriptor,
                )
                os.fsync(journal_descriptor)
                os.fsync(state.descriptor)
    except BaseException:
        if created_journal:
            try:
                remove_transaction_directory(root, journal)
            except EvidenceError:
                pass
        raise
    return journal, staged, original_modes, replacement_modes


def load_transaction_manifest_at(
    journal_descriptor: int, journal: Path
) -> tuple[dict[str, Any], bytes]:
    payload, _metadata = read_owned_file_at(
        journal_descriptor,
        "manifest.json",
        str(journal / "manifest.json"),
        0o600,
    )
    manifest = parse_trusted_json(payload, str(journal / "manifest.json"))
    if not isinstance(manifest, dict):
        raise EvidenceError(f"{journal}: transaction manifest must be an object")
    if payload != canonical_json_bytes(manifest):
        raise EvidenceError(f"{journal}: transaction manifest is not canonical")
    return manifest, payload


def transaction_entry_for_stage(
    manifest: dict[str, Any], source_name: str, destination: str
) -> dict[str, Any]:
    raw_entries = manifest.get("entries")
    if not isinstance(raw_entries, list):
        raise EvidenceError("transaction manifest has no entries")
    matches = [
        entry
        for entry in raw_entries
        if isinstance(entry, dict)
        and entry.get("replacement_stage") == source_name
        and entry.get("destination") == destination
    ]
    if len(matches) != 1:
        raise EvidenceError("replacement stage is not authorized by the transaction")
    return matches[0]


def publication_marker_name(stage_name: str) -> str:
    match = re.fullmatch(r"replacement-([0-9]{4})\.bin", stage_name)
    if match is None:
        raise EvidenceError(f"{stage_name}: invalid replacement stage name")
    return f"published-{match.group(1)}.json"


def validate_publication_marker(
    payload: bytes,
    label: str,
    *,
    transaction_id: str,
    destination: str,
    replacement_digest: str,
    replacement_mode: int,
) -> tuple[int, int]:
    marker = parse_trusted_json(payload, label)
    if not isinstance(marker, dict):
        raise EvidenceError(f"{label}: publication marker must be an object")
    if payload != canonical_json_bytes(marker):
        raise EvidenceError(f"{label}: publication marker is not canonical")
    exact_keys(
        marker,
        {
            "transaction_id",
            "destination",
            "device",
            "inode",
            "replacement_sha256",
            "replacement_mode",
        },
        set(),
        label,
    )
    if marker["transaction_id"] != transaction_id:
        raise EvidenceError(f"{label}: transaction mismatch")
    if marker["destination"] != destination:
        raise EvidenceError(f"{label}: destination mismatch")
    if marker["replacement_sha256"] != replacement_digest:
        raise EvidenceError(f"{label}: replacement digest mismatch")
    if marker["replacement_mode"] != replacement_mode:
        raise EvidenceError(f"{label}: replacement mode mismatch")
    device = marker["device"]
    inode = marker["inode"]
    if type(device) is not int or device < 0 or type(inode) is not int or inode <= 0:
        raise EvidenceError(f"{label}: invalid publication identity")
    return device, inode


def trusted_publication_identity(root: Path, source: Path) -> tuple[int, int]:
    journal = transaction_directory(root)
    if source.parent != journal:
        raise EvidenceError(f"{source}: stage is outside trusted transaction state")
    marker_name = publication_marker_name(source.name)
    marker_temporary = f"{marker_name}.tmp"
    with open_trusted_state(root, create=False) as state:
        if state is None:
            raise EvidenceError("trusted transaction state disappeared")
        with open_owned_directory_at(
            state.descriptor, TRANSACTION_DIRECTORY, str(journal)
        ) as (journal_descriptor, _journal_identity):
            manifest, _manifest_payload = load_transaction_manifest_at(
                journal_descriptor, journal
            )
            raw_entries = manifest.get("entries")
            if not isinstance(raw_entries, list):
                raise EvidenceError(f"{journal}: transaction manifest has no entries")
            matches = [
                entry
                for entry in raw_entries
                if isinstance(entry, dict)
                and entry.get("replacement_stage") == source.name
            ]
            if len(matches) != 1:
                raise EvidenceError(
                    f"{source}: replacement stage is not uniquely authorized"
                )
            entry = matches[0]
            if entry.get("original_state") != "absent":
                raise EvidenceError(f"{source}: publication marker requires a new file")
            destination = canonical_repository_path(
                entry.get("destination"), f"{source}: destination"
            )
            replacement_digest = require_string(
                entry.get("replacement_sha256"),
                SHA256,
                f"{source}: replacement digest",
            )
            replacement_mode = entry.get("replacement_mode")
            if type(replacement_mode) is not int or not (
                0 <= replacement_mode <= 0o7777
            ):
                raise EvidenceError(f"{source}: invalid replacement mode")
            transaction_id = require_string(
                manifest.get("transaction_id"),
                re.compile(r"^[a-f0-9]{64}$"),
                f"{journal}: transaction id",
            )
            try:
                os.stat(
                    marker_name,
                    dir_fd=journal_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                try:
                    os.stat(
                        marker_temporary,
                        dir_fd=journal_descriptor,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    pass
                else:
                    read_owned_file_at(
                        journal_descriptor,
                        marker_temporary,
                        str(journal / marker_temporary),
                        0o600,
                    )
                stage_payload, stage_metadata = read_owned_file_at(
                    journal_descriptor,
                    source.name,
                    str(source),
                    replacement_mode,
                    allowed_links=frozenset((1, 2)),
                )
                if hashlib.sha256(stage_payload).hexdigest() != replacement_digest:
                    raise EvidenceError(f"{source}: replacement digest mismatch")
                return metadata_identity(stage_metadata)
            try:
                os.stat(
                    marker_temporary,
                    dir_fd=journal_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                pass
            else:
                raise EvidenceError(
                    f"{journal}: final and provisional publication markers coexist"
                )
            marker_payload, _marker_metadata = read_owned_file_at(
                journal_descriptor,
                marker_name,
                str(journal / marker_name),
                0o600,
            )
            published_identity = validate_publication_marker(
                marker_payload,
                str(journal / marker_name),
                transaction_id=transaction_id,
                destination=destination,
                replacement_digest=replacement_digest,
                replacement_mode=replacement_mode,
            )
            try:
                os.stat(
                    source.name,
                    dir_fd=journal_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                return published_identity
            stage_payload, stage_metadata = read_owned_file_at(
                journal_descriptor,
                source.name,
                str(source),
                replacement_mode,
                allowed_links=frozenset((1, 2)),
            )
            if hashlib.sha256(stage_payload).hexdigest() != replacement_digest:
                raise EvidenceError(f"{source}: replacement digest mismatch")
            if metadata_identity(stage_metadata) != published_identity:
                raise EvidenceError(f"{source}: stage differs from publication marker")
            return published_identity


def replace_below_root(
    root: Path,
    source: Path,
    destination: Path,
    expected_destination: bytes | None,
) -> None:
    root = root.resolve()
    journal = transaction_directory(root)
    if source.parent != journal:
        raise EvidenceError(f"{source}: replacement source is outside trusted state")
    destination = lexical_path_below_root(
        root, destination, f"{destination}: replacement destination"
    )
    relative = destination.relative_to(root).as_posix()
    with open_trusted_state(root, create=False) as state:
        if state is None:
            raise EvidenceError("trusted transaction state disappeared")
        with open_owned_directory_at(
            state.descriptor, TRANSACTION_DIRECTORY, str(journal)
        ) as (journal_descriptor, _journal_identity):
            manifest, _manifest_payload = load_transaction_manifest_at(
                journal_descriptor, journal
            )
            entry = transaction_entry_for_stage(manifest, source.name, relative)
            replacement_mode = entry.get("replacement_mode")
            if type(replacement_mode) is not int:
                raise EvidenceError(f"{source}: invalid replacement mode")
            stage_payload, stage_metadata = read_owned_file_at(
                journal_descriptor,
                source.name,
                str(source),
                replacement_mode,
            )
            if hashlib.sha256(stage_payload).hexdigest() != entry.get(
                "replacement_sha256"
            ):
                raise EvidenceError(f"{source}: replacement digest mismatch")
            parent = open_parent_directory_below_root(
                root, destination, f"{destination}: replacement destination"
            )
            try:
                current = read_file_snapshot_at(
                    parent,
                    destination.name,
                    str(destination),
                    allow_missing=True,
                )
                named_stage = os.stat(
                    source.name,
                    dir_fd=journal_descriptor,
                    follow_symlinks=False,
                )
                if metadata_identity(named_stage) != metadata_identity(stage_metadata):
                    raise EvidenceError(f"{source}: stage identity changed")
                if entry.get("original_state") == "absent":
                    if expected_destination is not None or current is not None:
                        raise EvidenceError(
                            f"{destination}: appeared immediately before publication"
                        )
                    os.link(
                        source.name,
                        destination.name,
                        src_dir_fd=journal_descriptor,
                        dst_dir_fd=parent,
                        follow_symlinks=False,
                    )
                    published = read_file_snapshot_at(
                        parent,
                        destination.name,
                        str(destination),
                        allow_missing=False,
                    )
                    if (
                        published is None
                        or (published.device, published.inode)
                        != metadata_identity(stage_metadata)
                        or hashlib.sha256(published.payload).hexdigest()
                        != entry.get("replacement_sha256")
                        or published.mode != replacement_mode
                    ):
                        raise EvidenceError(
                            f"{destination}: new destination differs from its trusted stage"
                        )
                    marker_name = publication_marker_name(source.name)
                    marker_temporary = f"{marker_name}.tmp"
                    marker_payload = canonical_json_bytes(
                        {
                            "transaction_id": manifest["transaction_id"],
                            "destination": relative,
                            "device": published.device,
                            "inode": published.inode,
                            "replacement_sha256": entry["replacement_sha256"],
                            "replacement_mode": replacement_mode,
                        }
                    )
                    write_new_fsynced_at(
                        journal_descriptor,
                        marker_temporary,
                        marker_payload,
                        0o600,
                        str(journal / marker_temporary),
                    )
                    os.replace(
                        marker_temporary,
                        marker_name,
                        src_dir_fd=journal_descriptor,
                        dst_dir_fd=journal_descriptor,
                    )
                    os.fsync(journal_descriptor)
                    os.unlink(source.name, dir_fd=journal_descriptor)
                    os.fsync(journal_descriptor)
                elif entry.get("original_state") == "present":
                    if current is None or current.payload != expected_destination:
                        raise EvidenceError(
                            f"{destination}: changed immediately before replacement"
                        )
                    if current.mode != entry.get("original_mode"):
                        raise EvidenceError(
                            f"{destination}: mode changed immediately before replacement"
                        )
                    named_destination = os.stat(
                        destination.name, dir_fd=parent, follow_symlinks=False
                    )
                    if metadata_identity(named_destination) != (
                        current.device,
                        current.inode,
                    ):
                        raise EvidenceError(
                            f"{destination}: identity changed immediately before replacement"
                        )
                    os.replace(
                        source.name,
                        destination.name,
                        src_dir_fd=journal_descriptor,
                        dst_dir_fd=parent,
                    )
                    os.fsync(journal_descriptor)
                else:
                    raise EvidenceError(f"{source}: invalid original state")
                os.fsync(parent)
            except FileExistsError as error:
                raise EvidenceError(
                    f"{destination}: appeared immediately before publication"
                ) from error
            finally:
                os.close(parent)


def restore_bytes_below_root(
    root: Path,
    destination: Path,
    payload: bytes,
    expected_destination_sha256: str,
    *,
    restore_mode: int | None = None,
    expected_destination_mode: int | None = None,
) -> None:
    parent = open_parent_directory_below_root(
        root, destination, f"{destination}: rollback destination"
    )
    temporary_name = f".{destination.name}.rollback.{secrets.token_hex(16)}"
    temporary_descriptor: int | None = None
    destination_descriptor: int | None = None
    try:
        preliminary = os.stat(destination.name, dir_fd=parent, follow_symlinks=False)
        if not stat.S_ISREG(preliminary.st_mode):
            raise EvidenceError(f"{destination}: rollback destination is not regular")
        observed_mode = stat.S_IMODE(preliminary.st_mode)
        if (
            expected_destination_mode is not None
            and observed_mode != expected_destination_mode
        ):
            raise EvidenceError(
                f"{destination}: mode changed immediately before rollback"
            )
        target_mode = restore_mode if restore_mode is not None else observed_mode
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        temporary_descriptor = os.open(temporary_name, flags, 0o600, dir_fd=parent)
        with os.fdopen(temporary_descriptor, "wb", closefd=False) as handle:
            handle.write(payload)
            handle.flush()
            os.fchmod(temporary_descriptor, target_mode)
            os.fsync(temporary_descriptor)
        destination_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        destination_flags |= getattr(os, "O_CLOEXEC", 0)
        destination_descriptor = os.open(
            destination.name, destination_flags, dir_fd=parent
        )
        metadata = os.fstat(destination_descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise EvidenceError(f"{destination}: rollback destination is not regular")
        if stat.S_IMODE(metadata.st_mode) != observed_mode:
            raise EvidenceError(
                f"{destination}: mode changed immediately before rollback"
            )
        with os.fdopen(destination_descriptor, "rb", closefd=False) as handle:
            observed = handle.read()
        if hashlib.sha256(observed).hexdigest() != expected_destination_sha256:
            raise EvidenceError(f"{destination}: changed immediately before rollback")
        named = os.stat(destination.name, dir_fd=parent, follow_symlinks=False)
        if metadata_identity(named) != metadata_identity(metadata):
            raise EvidenceError(f"{destination}: identity changed before rollback")
        os.replace(
            temporary_name,
            destination.name,
            src_dir_fd=parent,
            dst_dir_fd=parent,
        )
        os.fsync(parent)
    except OSError as error:
        raise EvidenceError(
            f"{destination}: unable to restore bytes: {error}"
        ) from error
    finally:
        if temporary_descriptor is not None:
            os.close(temporary_descriptor)
        if destination_descriptor is not None:
            os.close(destination_descriptor)
        try:
            os.unlink(temporary_name, dir_fd=parent)
        except FileNotFoundError:
            pass
        finally:
            os.close(parent)


def remove_created_file_below_root(
    root: Path,
    destination: Path,
    expected_destination_sha256: str,
    expected_destination_mode: int,
    expected_inode: tuple[int, int] | None,
) -> None:
    parent = open_parent_directory_below_root(
        root, destination, f"{destination}: rollback destination"
    )
    descriptor: int | None = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(destination.name, flags, dir_fd=parent)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise EvidenceError(f"{destination}: rollback destination is not regular")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            payload = handle.read()
        if hashlib.sha256(payload).hexdigest() != expected_destination_sha256:
            raise EvidenceError(f"{destination}: changed immediately before rollback")
        if stat.S_IMODE(metadata.st_mode) != expected_destination_mode:
            raise EvidenceError(
                f"{destination}: mode changed immediately before rollback"
            )
        if expected_inode is not None and metadata_identity(metadata) != expected_inode:
            raise EvidenceError(f"{destination}: identity changed before rollback")
        named = os.stat(destination.name, dir_fd=parent, follow_symlinks=False)
        if metadata_identity(named) != metadata_identity(metadata):
            raise EvidenceError(f"{destination}: identity changed before rollback")
        os.unlink(destination.name, dir_fd=parent)
        os.fsync(parent)
    except OSError as error:
        raise EvidenceError(
            f"{destination}: unable to remove transaction-created file: {error}"
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)


def validate_transaction_manifest(
    root: Path,
    journal: Path,
    journal_descriptor: int,
) -> tuple[
    list[
        tuple[
            Path,
            bytes | None,
            str,
            str | None,
            int | None,
            str,
            int,
            FileSnapshot | None,
        ]
    ],
    bool,
]:
    manifest, manifest_payload = load_transaction_manifest_at(
        journal_descriptor, journal
    )
    exact_keys(
        manifest,
        {"schema", "transaction_id", "repository", "entries", "read_guards"},
        set(),
        str(journal / "manifest.json"),
    )
    if manifest["schema"] != TRANSACTION_SCHEMA:
        raise EvidenceError(f"{journal}: unsupported transaction schema")
    if manifest["repository"] != repository_identity(root)[2]:
        raise EvidenceError(f"{journal}: repository identity mismatch")
    transaction_id = require_string(
        manifest["transaction_id"], re.compile(r"^[a-f0-9]{64}$"), "transaction id"
    )
    prepared_payload, _prepared_metadata = read_owned_file_at(
        journal_descriptor,
        "prepared",
        str(journal / "prepared"),
        0o600,
    )
    prepared = parse_trusted_json(prepared_payload, str(journal / "prepared"))
    if not isinstance(prepared, dict):
        raise EvidenceError(f"{journal}: invalid prepared marker")
    exact_keys(
        prepared,
        {"transaction_id", "manifest_sha256"},
        set(),
        str(journal / "prepared"),
    )
    if (
        prepared["transaction_id"] != transaction_id
        or prepared["manifest_sha256"] != hashlib.sha256(manifest_payload).hexdigest()
    ):
        raise EvidenceError(
            f"{journal}: prepared marker does not authenticate manifest"
        )
    raw_entries = manifest["entries"]
    if not isinstance(raw_entries, list) or not raw_entries:
        raise EvidenceError(f"{journal}: transaction entries are empty")
    parsed_entries: list[
        tuple[
            Path,
            bytes | None,
            str,
            str | None,
            int | None,
            str,
            int,
            FileSnapshot | None,
        ]
    ] = []
    observed_paths: set[Path] = set()
    expected_files = {"manifest.json", "prepared"}
    for offset, raw_entry in enumerate(raw_entries):
        label = f"{journal}: entries[{offset}]"
        if not isinstance(raw_entry, dict):
            raise EvidenceError(f"{label}: entry must be an object")
        exact_keys(
            raw_entry,
            {
                "destination",
                "original_state",
                "original_backup",
                "original_sha256",
                "original_mode",
                "replacement_stage",
                "replacement_sha256",
                "replacement_mode",
            },
            set(),
            label,
        )
        relative = canonical_repository_path(
            raw_entry["destination"], f"{label}: destination"
        )
        destination = lexical_path_below_root(
            root, root / relative, f"{label}: destination"
        )
        if destination in observed_paths:
            raise EvidenceError(f"{label}: duplicate destination")
        observed_paths.add(destination)
        replacement_name = raw_entry["replacement_stage"]
        if replacement_name != f"replacement-{offset:04}.bin":
            raise EvidenceError(f"{label}: invalid replacement stage")
        replacement_digest = require_string(
            raw_entry["replacement_sha256"], SHA256, f"{label}: replacement digest"
        )
        replacement_mode = raw_entry["replacement_mode"]
        if type(replacement_mode) is not int or not (0 <= replacement_mode <= 0o7777):
            raise EvidenceError(f"{label}: invalid replacement mode")
        stage_snapshot: FileSnapshot | None = None
        try:
            stage_payload, stage_metadata = read_owned_file_at(
                journal_descriptor,
                replacement_name,
                str(journal / replacement_name),
                replacement_mode,
                allowed_links=frozenset((1, 2)),
            )
        except EvidenceError as error:
            try:
                os.stat(
                    replacement_name,
                    dir_fd=journal_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                stage_payload = None
            else:
                raise error
        if stage_payload is not None:
            if hashlib.sha256(stage_payload).hexdigest() != replacement_digest:
                raise EvidenceError(f"{label}: replacement digest mismatch")
            stage_snapshot = FileSnapshot(
                stage_payload,
                stat.S_IMODE(stage_metadata.st_mode),
                stage_metadata.st_dev,
                stage_metadata.st_ino,
            )
            expected_files.add(replacement_name)
        marker_name = publication_marker_name(replacement_name)
        marker_temporary = f"{marker_name}.tmp"
        marker_identity: tuple[int, int] | None = None
        publication_artifacts: set[str] = set()
        for publication_name in (marker_name, marker_temporary):
            try:
                publication_payload, _publication_metadata = read_owned_file_at(
                    journal_descriptor,
                    publication_name,
                    str(journal / publication_name),
                    0o600,
                )
            except EvidenceError as error:
                try:
                    os.stat(
                        publication_name,
                        dir_fd=journal_descriptor,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    continue
                else:
                    raise error
            publication_artifacts.add(publication_name)
            expected_files.add(publication_name)
            if publication_name == marker_name:
                marker_identity = validate_publication_marker(
                    publication_payload,
                    str(journal / publication_name),
                    transaction_id=transaction_id,
                    destination=relative,
                    replacement_digest=replacement_digest,
                    replacement_mode=replacement_mode,
                )
        if publication_artifacts == {marker_name, marker_temporary}:
            raise EvidenceError(
                f"{label}: final and provisional publication markers coexist"
            )
        original_state = raw_entry["original_state"]
        if original_state == "present":
            if publication_artifacts:
                raise EvidenceError(
                    f"{label}: existing destination has a publication marker"
                )
            backup_name = raw_entry["original_backup"]
            if backup_name != f"original-{offset:04}.bin":
                raise EvidenceError(f"{label}: invalid original backup")
            original_digest = require_string(
                raw_entry["original_sha256"], SHA256, f"{label}: original digest"
            )
            original_mode = raw_entry["original_mode"]
            if type(original_mode) is not int or not (0 <= original_mode <= 0o7777):
                raise EvidenceError(f"{label}: invalid original mode")
            backup, _backup_metadata = read_owned_file_at(
                journal_descriptor,
                backup_name,
                str(journal / backup_name),
                0o600,
            )
            if hashlib.sha256(backup).hexdigest() != original_digest:
                raise EvidenceError(f"{label}: backup digest mismatch")
            expected_files.add(backup_name)
        elif original_state == "absent":
            if any(
                raw_entry[name] is not None
                for name in ("original_backup", "original_sha256", "original_mode")
            ):
                raise EvidenceError(f"{label}: absent original has metadata")
            if marker_temporary in publication_artifacts and stage_snapshot is None:
                raise EvidenceError(
                    f"{label}: provisional publication marker lost its stage"
                )
            if marker_identity is not None:
                if (
                    stage_snapshot is not None
                    and (
                        stage_snapshot.device,
                        stage_snapshot.inode,
                    )
                    != marker_identity
                ):
                    raise EvidenceError(
                        f"{label}: publication marker differs from its stage"
                    )
                stage_snapshot = FileSnapshot(
                    b"",
                    replacement_mode,
                    marker_identity[0],
                    marker_identity[1],
                )
            elif stage_snapshot is None:
                raise EvidenceError(
                    f"{label}: absent original lost its publication identity"
                )
            backup = None
            original_digest = None
            original_mode = None
        else:
            raise EvidenceError(f"{label}: invalid original state")
        parsed_entries.append(
            (
                destination,
                backup,
                original_state,
                original_digest,
                original_mode,
                replacement_digest,
                replacement_mode,
                stage_snapshot,
            )
        )
    raw_guards = manifest["read_guards"]
    if not isinstance(raw_guards, list):
        raise EvidenceError(f"{journal}: read guards must be an array")
    guards_unchanged = True
    observed_guards: set[Path] = set()
    for offset, raw_guard in enumerate(raw_guards):
        label = f"{journal}: read_guards[{offset}]"
        if not isinstance(raw_guard, dict):
            raise EvidenceError(f"{label}: guard must be an object")
        exact_keys(raw_guard, {"path", "sha256"}, set(), label)
        relative = canonical_repository_path(
            raw_guard["path"],
            f"{label}: path",
            allow_root=True,
        )
        guard_path = lexical_path_below_root(
            root,
            root / relative,
            f"{label}: guard",
            allow_missing_parents=True,
            allow_root=True,
        )
        if guard_path in observed_guards or guard_path in observed_paths:
            raise EvidenceError(f"{label}: overlapping guard")
        observed_guards.add(guard_path)
        expected_digest = require_string(
            raw_guard["sha256"], SHA256, f"{label}: digest"
        )
        try:
            current_digest = hashlib.sha256(
                read_guard_payload(guard_path, str(guard_path))
            ).hexdigest()
        except EvidenceError:
            guards_unchanged = False
        else:
            if current_digest != expected_digest:
                guards_unchanged = False
    if set(os.listdir(journal_descriptor)) != expected_files:
        raise EvidenceError(f"{journal}: journal inventory mismatch")
    return parsed_entries, guards_unchanged


def recover_atomic_replace_journal(root: Path) -> str | None:
    """Recover only descriptor-authenticated state outside the checkout."""

    root = root.resolve()
    reject_in_root_transaction_state(root)
    journal = transaction_directory(root)
    discard_unprepared = False
    parsed_entries: list[
        tuple[
            Path,
            bytes | None,
            str,
            str | None,
            int | None,
            str,
            int,
            FileSnapshot | None,
        ]
    ] = []
    guards_unchanged = True
    with open_trusted_state(root, create=False) as state:
        if state is None:
            return None
        try:
            with open_owned_directory_at(
                state.descriptor, TRANSACTION_DIRECTORY, str(journal)
            ) as (journal_descriptor, _journal_identity):
                try:
                    os.stat(
                        "prepared",
                        dir_fd=journal_descriptor,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    discard_unprepared = True
                if not discard_unprepared:
                    parsed_entries, guards_unchanged = validate_transaction_manifest(
                        root, journal, journal_descriptor
                    )
        except EvidenceError as error:
            try:
                os.stat(
                    TRANSACTION_DIRECTORY,
                    dir_fd=state.descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                return None
            raise error
    if discard_unprepared:
        remove_transaction_directory(root, journal)
        return "discarded-unprepared"

    states: list[str] = []
    for entry in parsed_entries:
        (
            destination,
            _backup,
            original_state,
            original_digest,
            original_mode,
            replacement_digest,
            replacement_mode,
            stage_snapshot,
        ) = entry
        current = read_file_snapshot_below_root(
            root, destination, str(destination), allow_missing=True
        )
        if original_state == "absent":
            if current is None:
                states.append("original")
            elif (
                hashlib.sha256(current.payload).hexdigest() == replacement_digest
                and current.mode == replacement_mode
                and stage_snapshot is not None
                and (current.device, current.inode)
                == (stage_snapshot.device, stage_snapshot.inode)
            ):
                states.append("replacement")
            else:
                raise EvidenceError(
                    f"{destination}: differs from both journaled transaction states"
                )
        elif current is None:
            raise EvidenceError(
                f"{destination}: differs from both journaled transaction states"
            )
        else:
            current_digest = hashlib.sha256(current.payload).hexdigest()
            if (
                current_digest == original_digest
                and current.mode == original_mode
                and original_digest == replacement_digest
                and original_mode == replacement_mode
            ):
                states.append("unchanged")
            elif current_digest == original_digest and current.mode == original_mode:
                states.append("original")
            elif (
                current_digest == replacement_digest
                and current.mode == replacement_mode
            ):
                states.append("replacement")
            else:
                raise EvidenceError(
                    f"{destination}: differs from both journaled transaction states"
                )

    changed_states = [state for state in states if state != "unchanged"]
    if (
        guards_unchanged
        and changed_states
        and all(state == "replacement" for state in changed_states)
    ):
        remove_transaction_directory(root, journal)
        return "committed"

    for entry, state in zip(reversed(parsed_entries), reversed(states), strict=True):
        if state != "replacement":
            continue
        (
            destination,
            backup,
            original_state,
            _original_digest,
            original_mode,
            replacement_digest,
            replacement_mode,
            stage_snapshot,
        ) = entry
        if original_state == "absent":
            remove_created_file_below_root(
                root,
                destination,
                replacement_digest,
                replacement_mode,
                (
                    None
                    if stage_snapshot is None
                    else (stage_snapshot.device, stage_snapshot.inode)
                ),
            )
        else:
            if backup is None or original_mode is None:
                raise EvidenceError(f"{destination}: incomplete rollback metadata")
            restore_bytes_below_root(
                root,
                destination,
                backup,
                replacement_digest,
                restore_mode=original_mode,
                expected_destination_mode=replacement_mode,
            )
    for entry in parsed_entries:
        destination, backup, original_state, original_digest, original_mode, *_rest = (
            entry
        )
        current = read_file_snapshot_below_root(
            root, destination, str(destination), allow_missing=True
        )
        if original_state == "absent":
            if current is not None:
                raise EvidenceError(f"{destination}: rollback failed")
        elif (
            current is None
            or backup is None
            or hashlib.sha256(current.payload).hexdigest() != original_digest
            or current.mode != original_mode
        ):
            raise EvidenceError(f"{destination}: rollback failed")
    remove_transaction_directory(root, journal)
    return "rolled-back"


def atomic_replace_many(
    replacements: list[tuple[Path, bytes]],
    originals: dict[Path, bytes | None],
    guards: dict[Path, bytes] | None = None,
    journal_root: Path | None = None,
) -> None:
    """Publish a descriptor-authenticated, crash-recoverable file set."""

    replacement_paths = [path for path, _payload in replacements]
    if len(replacement_paths) != len(set(replacement_paths)):
        raise EvidenceError("transaction contains a duplicate destination")
    if set(replacement_paths) != set(originals):
        raise EvidenceError("transaction originals do not match its destinations")
    read_guards = guards or {}
    if set(replacement_paths) & set(read_guards):
        raise EvidenceError("transaction read guards overlap its destinations")
    resolved_root = journal_root.resolve() if journal_root is not None else None
    if resolved_root is None and any(value is None for value in originals.values()):
        raise EvidenceError("new destinations require a durable transaction journal")
    if resolved_root is not None:
        reject_in_root_transaction_state(resolved_root)

    def require_unchanged_guards() -> None:
        for path, payload in read_guards.items():
            if resolved_root is not None:
                lexical_path_below_root(
                    resolved_root,
                    path,
                    f"{path}: transaction read guard",
                    allow_missing_parents=True,
                    allow_root=True,
                )
            if read_guard_payload(path, str(path)) != payload:
                raise EvidenceError(f"{path}: transaction read guard changed")

    def current_snapshot(path: Path) -> FileSnapshot | None:
        if resolved_root is None:
            if not path.exists():
                return None
            payload = read_regular_file_no_follow(path, str(path))
            metadata = path.stat()
            return FileSnapshot(
                payload,
                stat.S_IMODE(metadata.st_mode),
                metadata.st_dev,
                metadata.st_ino,
            )
        return read_file_snapshot_below_root(
            resolved_root, path, str(path), allow_missing=True
        )

    def require_original(path: Path) -> FileSnapshot | None:
        observed = current_snapshot(path)
        original = originals[path]
        if original is None:
            if observed is not None:
                raise EvidenceError(f"{path}: appeared while transaction was running")
        elif observed is None or observed.payload != original:
            raise EvidenceError(f"{path}: changed while transaction was running")
        return observed

    staged: list[tuple[Path, Path]] = []
    journal: Path | None = None
    original_modes: dict[Path, int | None] = {}
    replacement_modes: dict[Path, int] = {}
    try:
        require_unchanged_guards()
        for path in replacement_paths:
            require_original(path)
        if resolved_root is not None:
            journal, staged, original_modes, replacement_modes = (
                prepare_transaction_journal(
                    resolved_root,
                    replacements,
                    originals,
                    read_guards,
                )
            )
        else:
            for path, payload in replacements:
                observed = require_original(path)
                if observed is None:
                    raise EvidenceError(f"{path}: absent nonjournal destination")
                original_modes[path] = observed.mode
                replacement_modes[path] = observed.mode
                descriptor, temporary_name = tempfile.mkstemp(
                    prefix=f".{path.name}.refresh.", dir=path.parent
                )
                temporary = Path(temporary_name)
                try:
                    with os.fdopen(descriptor, "wb") as handle:
                        os.fchmod(handle.fileno(), observed.mode)
                        handle.write(payload)
                        handle.flush()
                        os.fsync(handle.fileno())
                except BaseException:
                    temporary.unlink(missing_ok=True)
                    raise
                staged.append((path, temporary))

        for path in replacement_paths:
            observed = require_original(path)
            expected_mode = original_modes[path]
            if observed is not None and observed.mode != expected_mode:
                raise EvidenceError(
                    f"{path}: mode changed while transaction was staged"
                )
        require_unchanged_guards()

        replaced: list[tuple[Path, Path]] = []
        try:
            for path, temporary in staged:
                require_unchanged_guards()
                observed = require_original(path)
                expected_mode = original_modes[path]
                if observed is not None and observed.mode != expected_mode:
                    raise EvidenceError(
                        f"{path}: mode changed while transaction was committed"
                    )
                replaced.append((path, temporary))
                if resolved_root is not None:
                    replace_below_root(
                        resolved_root,
                        temporary,
                        path,
                        originals[path],
                    )
                else:
                    os.replace(temporary, path)
                    fsync_directory(path.parent)
            require_unchanged_guards()
            for path, payload in replacements:
                observed = current_snapshot(path)
                if (
                    observed is None
                    or observed.payload != payload
                    or observed.mode != replacement_modes[path]
                ):
                    raise EvidenceError(
                        f"{path}: replacement changed before transaction completion"
                    )
                if (
                    resolved_root is not None
                    and originals[path] is None
                    and (observed.device, observed.inode)
                    != trusted_publication_identity(resolved_root, dict(staged)[path])
                ):
                    raise EvidenceError(
                        f"{path}: new destination identity differs from its trusted stage"
                    )
            if journal is not None and resolved_root is not None:
                remove_transaction_directory(resolved_root, journal)
                journal = None
        except BaseException as error:
            rollback_errors: list[str] = []
            replacement_payloads = dict(replacements)
            staged_paths = dict(staged)
            for path, _temporary in reversed(replaced):
                try:
                    observed = current_snapshot(path)
                    original = originals[path]
                    if original is None and observed is None:
                        continue
                    if (
                        original is not None
                        and observed is not None
                        and observed.payload == original
                        and observed.mode == original_modes[path]
                    ):
                        continue
                    if (
                        observed is None
                        or observed.payload != replacement_payloads[path]
                        or observed.mode != replacement_modes[path]
                    ):
                        rollback_errors.append(
                            f"{path}: changed after transaction replacement"
                        )
                        continue
                    if originals[path] is None:
                        if resolved_root is None:
                            rollback_errors.append(
                                f"{path}: absent rollback lacks a trusted journal"
                            )
                            continue
                        remove_created_file_below_root(
                            resolved_root,
                            path,
                            hashlib.sha256(replacement_payloads[path]).hexdigest(),
                            replacement_modes[path],
                            trusted_publication_identity(
                                resolved_root, staged_paths[path]
                            ),
                        )
                    elif resolved_root is None:
                        atomic_write(path, originals[path])
                    else:
                        restore_mode = original_modes[path]
                        if restore_mode is None:
                            raise EvidenceError(
                                f"{path}: present original lacks its mode"
                            )
                        restore_bytes_below_root(
                            resolved_root,
                            path,
                            originals[path],
                            hashlib.sha256(replacement_payloads[path]).hexdigest(),
                            restore_mode=restore_mode,
                            expected_destination_mode=replacement_modes[path],
                        )
                except BaseException as rollback_error:
                    rollback_errors.append(f"{path}: {rollback_error}")
            if (
                not rollback_errors
                and journal is not None
                and resolved_root is not None
            ):
                try:
                    remove_transaction_directory(resolved_root, journal)
                    journal = None
                except BaseException as rollback_error:
                    rollback_errors.append(f"{journal}: {rollback_error}")
            if rollback_errors:
                raise EvidenceError(
                    "refresh commit failed and rollback was incomplete: "
                    f"commit error: {error}; rollback errors: "
                    + "; ".join(rollback_errors)
                ) from error
            if isinstance(error, OSError):
                raise EvidenceError(f"refresh commit failed: {error}") from error
            raise
    finally:
        if resolved_root is None:
            for _path, temporary in staged:
                temporary.unlink(missing_ok=True)


def process_start_fingerprint(pid: int) -> str | None:
    proc_stat = Path(f"/proc/{pid}/stat")
    if proc_stat.is_file() and not proc_stat.is_symlink():
        try:
            raw = proc_stat.read_text(encoding="utf-8")
            fields = raw[raw.rfind(")") + 2 :].split()
        except (OSError, UnicodeError):
            return None
        if len(fields) >= 20 and fields[19].isdigit():
            return f"proc-stat-v1:{fields[19]}"
        return None
    ps_path = Path("/bin/ps")
    if not ps_path.is_file():
        ps_path = Path("/usr/bin/ps")
    if not ps_path.is_file():
        return None
    completed = subprocess.run(
        [str(ps_path), "-o", "lstart=", "-p", str(pid)],
        env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    rendered = " ".join(completed.stdout.split())
    if completed.returncode != 0 or not rendered:
        return None
    return f"ps-lstart-v1:{rendered}"


@contextmanager
def refresh_lock(root: Path) -> Iterator[None]:
    root = root.resolve()
    reject_in_root_transaction_state(root)
    current_fingerprint = process_start_fingerprint(os.getpid())
    if current_fingerprint is None:
        raise EvidenceError("unable to determine refresh lock process fingerprint")
    owner_record = {
        "pid": os.getpid(),
        "process_start": current_fingerprint,
        "nonce": secrets.token_hex(32),
    }
    owner_payload = canonical_json_bytes(owner_record)

    with open_trusted_state(root, create=True) as state:
        if state is None:
            raise EvidenceError("unable to create trusted refresh-lock state")
        lock_path = state.path / LOCK_DIRECTORY
        acquired = False
        lock_descriptor: int | None = None
        lock_identity: tuple[int, int] | None = None
        try:
            for attempt in range(2):
                try:
                    os.mkdir(LOCK_DIRECTORY, 0o700, dir_fd=state.descriptor)
                    os.fsync(state.descriptor)
                    with open_owned_directory_at(
                        state.descriptor, LOCK_DIRECTORY, str(lock_path)
                    ) as (opened_descriptor, opened_identity):
                        lock_descriptor = os.dup(opened_descriptor)
                        lock_identity = opened_identity
                    write_new_fsynced_at(
                        lock_descriptor,
                        "owner.json",
                        owner_payload,
                        0o600,
                        str(lock_path / "owner.json"),
                    )
                    os.fsync(lock_descriptor)
                    os.fsync(state.descriptor)
                    acquired = True
                    break
                except FileExistsError as error:
                    if attempt != 0:
                        raise EvidenceError(
                            f"{lock_path}: unable to reclaim stale refresh lock"
                        ) from error
                    with open_owned_directory_at(
                        state.descriptor, LOCK_DIRECTORY, str(lock_path)
                    ) as (stale_descriptor, stale_identity):
                        stale_payload, _stale_metadata = read_owned_file_at(
                            stale_descriptor,
                            "owner.json",
                            str(lock_path / "owner.json"),
                            0o600,
                        )
                        stale_owner = parse_trusted_json(
                            stale_payload, str(lock_path / "owner.json")
                        )
                        if (
                            not isinstance(stale_owner, dict)
                            or set(stale_owner) != {"pid", "process_start", "nonce"}
                            or type(stale_owner["pid"]) is not int
                            or stale_owner["pid"] <= 0
                            or not isinstance(stale_owner["process_start"], str)
                            or not stale_owner["process_start"]
                            or not isinstance(stale_owner["nonce"], str)
                            or re.fullmatch(r"[a-f0-9]{64}", stale_owner["nonce"])
                            is None
                        ):
                            raise EvidenceError(
                                f"{lock_path / 'owner.json'}: invalid lock owner"
                            )
                        observed = process_start_fingerprint(stale_owner["pid"])
                        if observed == stale_owner["process_start"]:
                            raise EvidenceError(
                                f"{lock_path}: another refresh is active under pid "
                                f"{stale_owner['pid']}"
                            )
                        if observed is None:
                            try:
                                os.kill(stale_owner["pid"], 0)
                            except ProcessLookupError:
                                pass
                            except PermissionError:
                                raise EvidenceError(
                                    f"{lock_path}: cannot authenticate live lock owner"
                                ) from error
                            else:
                                raise EvidenceError(
                                    f"{lock_path}: live owner has no process fingerprint"
                                ) from error
                        repeated_payload, repeated_metadata = read_owned_file_at(
                            stale_descriptor,
                            "owner.json",
                            str(lock_path / "owner.json"),
                            0o600,
                        )
                        if repeated_payload != stale_payload:
                            raise EvidenceError(
                                f"{lock_path}: lock owner changed before reclaim"
                            )
                        named_owner = os.stat(
                            "owner.json",
                            dir_fd=stale_descriptor,
                            follow_symlinks=False,
                        )
                        if metadata_identity(named_owner) != metadata_identity(
                            repeated_metadata
                        ):
                            raise EvidenceError(
                                f"{lock_path}: lock owner identity changed"
                            )
                        retire_owned_directory(
                            state,
                            LOCK_DIRECTORY,
                            stale_descriptor,
                            stale_identity,
                        )
            if not acquired or lock_descriptor is None or lock_identity is None:
                raise EvidenceError(f"{lock_path}: unable to acquire refresh lock")
            yield
        finally:
            if acquired and lock_descriptor is not None and lock_identity is not None:
                try:
                    observed_payload, observed_metadata = read_owned_file_at(
                        lock_descriptor,
                        "owner.json",
                        str(lock_path / "owner.json"),
                        0o600,
                    )
                    if observed_payload != owner_payload:
                        raise EvidenceError(f"{lock_path}: lock ownership changed")
                    named_owner = os.stat(
                        "owner.json",
                        dir_fd=lock_descriptor,
                        follow_symlinks=False,
                    )
                    if metadata_identity(named_owner) != metadata_identity(
                        observed_metadata
                    ):
                        raise EvidenceError(f"{lock_path}: lock owner identity changed")
                    retire_owned_directory(
                        state,
                        LOCK_DIRECTORY,
                        lock_descriptor,
                        lock_identity,
                    )
                finally:
                    os.close(lock_descriptor)


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
        or pure.suffix not in (".rs", ".inc")
        or ".." in pure.parts
        or "." in pure.parts
        or any(not character.isprintable() for character in value)
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


PINNED_CARGO_MUTANTS_VERSION = "cargo-mutants 25.3.1"
TRUSTED_CARGO_MUTANTS = Path("/usr/local/cargo/bin/cargo-mutants")
TRUSTED_CARGO_MUTANTS_ANCESTORS = (
    Path("/"),
    Path("/usr"),
    Path("/usr/local"),
    Path("/usr/local/cargo"),
    Path("/usr/local/cargo/bin"),
)


@dataclass
class CargoMutantsSourceInventory:
    executable: Path | None = None
    version_checked: bool = False
    verified_identity: tuple[int, int] | None = None
    packages: dict[str, frozenset[str]] = dataclass_field(default_factory=dict)


def cargo_mutants_output(
    command: list[str],
    root: Path,
    label: str,
    environment: dict[str, str] | None = None,
    expected_identity: tuple[int, int] | None = None,
) -> tuple[str, tuple[int, int] | None]:
    try:
        with cargo_mutants_subprocess_options(
            root, command, environment, expected_identity
        ) as (execution_options, observed_identity):
            completed = subprocess.run(
                command,
                cwd=root,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                **execution_options,
            )
    except OSError as error:
        raise EvidenceError(
            f"{label}: unable to execute cargo-mutants: {error}"
        ) from error
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise EvidenceError(
            f"{label}: cargo-mutants failed with status {completed.returncode}: {detail}"
        )
    return completed.stdout, observed_identity


def require_trusted_cargo_mutants_ancestor(
    metadata: os.stat_result, path: Path
) -> None:
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o755
    ):
        raise EvidenceError(f"{path}: cargo-mutants ancestor is mutable or aliased")


def require_trusted_cargo_mutants_file(metadata: os.stat_result, path: Path) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o555
    ):
        raise EvidenceError(f"{path}: cargo-mutants executable is mutable or aliased")


def require_host_cargo_mutants_file(metadata: os.stat_result, path: Path) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) & 0o111 == 0
    ):
        raise EvidenceError(
            f"{path}: host cargo-mutants executable is mutable or aliased"
        )


def require_unchanged_cargo_mutants_identity(
    before: os.stat_result, after: os.stat_result, path: Path
) -> None:
    if metadata_identity(before) != metadata_identity(after):
        raise EvidenceError(f"{path}: cargo-mutants identity changed")


def enterprise_security_runner(
    environment: dict[str, str] | None = None,
) -> bool:
    return (os.environ if environment is None else environment).get(
        "CHIO_ENTERPRISE_SECURITY_RUNNER"
    ) == "1"


def enterprise_cargo_mutants_executable(root: Path) -> Path:
    """Authenticate the fixed verifier-owned cargo-mutants executable."""

    root = root.resolve()
    executable = TRUSTED_CARGO_MUTANTS
    if (
        not executable.is_absolute()
        or executable.parent != TRUSTED_CARGO_MUTANTS_ANCESTORS[-1]
    ):
        raise EvidenceError("cargo-mutants executable authority is not exact")
    try:
        ancestor_snapshots = {
            path: path.lstat() for path in TRUSTED_CARGO_MUTANTS_ANCESTORS
        }
        executable_snapshot = executable.lstat()
        resolved = executable.resolve(strict=True)
        executable.relative_to(root)
    except ValueError:
        pass
    except (OSError, RuntimeError) as error:
        raise EvidenceError(
            f"{executable}: unable to authenticate cargo-mutants: {error}"
        ) from error
    else:
        raise EvidenceError(
            f"{executable}: cargo-mutants executable cannot be workspace-owned"
        )
    if resolved != executable:
        raise EvidenceError(f"{executable}: cargo-mutants path is aliased")
    for path, metadata in ancestor_snapshots.items():
        require_trusted_cargo_mutants_ancestor(metadata, path)
    require_trusted_cargo_mutants_file(executable_snapshot, executable)
    try:
        repeated_ancestors = {
            path: path.lstat() for path in TRUSTED_CARGO_MUTANTS_ANCESTORS
        }
        repeated_executable = executable.lstat()
    except OSError as error:
        raise EvidenceError(
            f"{executable}: cargo-mutants identity changed: {error}"
        ) from error
    for path in TRUSTED_CARGO_MUTANTS_ANCESTORS:
        require_unchanged_cargo_mutants_identity(
            ancestor_snapshots[path], repeated_ancestors[path], path
        )
    require_unchanged_cargo_mutants_identity(
        executable_snapshot, repeated_executable, executable
    )
    for path, metadata in repeated_ancestors.items():
        require_trusted_cargo_mutants_ancestor(metadata, path)
    require_trusted_cargo_mutants_file(repeated_executable, executable)
    return executable


def host_cargo_mutants_executable(root: Path) -> Path:
    """Resolve a local developer's non-workspace cargo-mutants executable."""

    located = shutil.which("cargo-mutants")
    if located is None:
        raise EvidenceError("cargo-mutants executable is absent from PATH")
    executable = Path(located)
    if not executable.is_absolute() or os.fspath(executable) != located:
        raise EvidenceError("host cargo-mutants executable path is not canonical")
    root = root.resolve()
    try:
        snapshot = executable.lstat()
        resolved = executable.resolve(strict=True)
        executable.relative_to(root)
    except ValueError:
        pass
    except (OSError, RuntimeError) as error:
        raise EvidenceError(
            f"{executable}: unable to authenticate host cargo-mutants: {error}"
        ) from error
    else:
        raise EvidenceError(
            f"{executable}: cargo-mutants executable cannot be workspace-owned"
        )
    if resolved != executable:
        raise EvidenceError(f"{executable}: cargo-mutants path is aliased")
    require_host_cargo_mutants_file(snapshot, executable)
    try:
        repeated = executable.lstat()
    except OSError as error:
        raise EvidenceError(
            f"{executable}: cargo-mutants identity changed: {error}"
        ) from error
    require_unchanged_cargo_mutants_identity(snapshot, repeated, executable)
    require_host_cargo_mutants_file(repeated, executable)
    return executable


def cargo_mutants_executable(
    root: Path,
    cache: CargoMutantsSourceInventory,
    environment: dict[str, str] | None = None,
) -> Path:
    enterprise = enterprise_security_runner(environment)
    if cache.executable is not None:
        if enterprise:
            authenticated = enterprise_cargo_mutants_executable(root)
            if cache.executable != authenticated:
                raise EvidenceError(
                    "enterprise cargo-mutants executable authority is not exact"
                )
            cache.executable = authenticated
        return cache.executable
    executable = (
        enterprise_cargo_mutants_executable(root)
        if enterprise
        else host_cargo_mutants_executable(root)
    )
    cache.executable = executable
    return executable


@contextmanager
def cargo_mutants_subprocess_options(
    root: Path,
    command: list[str],
    environment: dict[str, str] | None,
    expected_identity: tuple[int, int] | None = None,
) -> Iterator[tuple[dict[str, Any], tuple[int, int] | None]]:
    if len(command) < 2 or command[1] != "mutants":
        raise EvidenceError("cargo-mutants command lacks its direct binary prefix")
    executable = Path(command[0])
    if not executable.is_absolute():
        raise EvidenceError("cargo-mutants command executable is not absolute")
    if not enterprise_security_runner(environment):
        if expected_identity is not None:
            raise EvidenceError(
                "host cargo-mutants command received an enterprise identity binding"
            )
        yield {}, None
        return
    if executable != TRUSTED_CARGO_MUTANTS:
        raise EvidenceError("enterprise cargo-mutants command authority is not exact")

    authenticated = enterprise_cargo_mutants_executable(root)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    descriptor: int | None = None
    opened: os.stat_result | None = None
    try:
        descriptor = os.open(authenticated, flags)
        opened = os.fstat(descriptor)
        require_trusted_cargo_mutants_file(opened, authenticated)
        opened_identity = metadata_identity(opened)
        if expected_identity is not None and opened_identity != expected_identity:
            raise EvidenceError(
                f"{authenticated}: cargo-mutants differs from the version-verified inode"
            )
        named = authenticated.lstat()
        require_trusted_cargo_mutants_file(named, authenticated)
        require_unchanged_cargo_mutants_identity(opened, named, authenticated)
        enterprise_cargo_mutants_executable(root)
        yield (
            {
                "executable": f"/proc/self/fd/{descriptor}",
                "pass_fds": (descriptor,),
            },
            opened_identity,
        )
    except OSError as error:
        raise EvidenceError(
            f"{authenticated}: unable to pin cargo-mutants executable: {error}"
        ) from error
    finally:
        if descriptor is not None:
            try:
                if opened is not None:
                    repeated = authenticated.lstat()
                    require_trusted_cargo_mutants_file(repeated, authenticated)
                    require_unchanged_cargo_mutants_identity(
                        opened, repeated, authenticated
                    )
                    enterprise_cargo_mutants_executable(root)
            except OSError as error:
                raise EvidenceError(
                    f"{authenticated}: cargo-mutants identity changed: {error}"
                ) from error
            finally:
                os.close(descriptor)


def require_cargo_mutants_version(
    executable: Path,
    root: Path,
    environment: dict[str, str] | None = None,
) -> tuple[int, int] | None:
    observed_version_output, observed_identity = cargo_mutants_output(
        [os.fspath(executable), "mutants", "--version"],
        root,
        "cargo-mutants version",
        environment,
    )
    observed_version = observed_version_output.strip()
    if observed_version != PINNED_CARGO_MUTANTS_VERSION:
        raise EvidenceError(
            "cargo-mutants version mismatch: "
            f"expected {PINNED_CARGO_MUTANTS_VERSION}, observed {observed_version}"
        )
    if enterprise_security_runner(environment) and observed_identity is None:
        raise EvidenceError("enterprise cargo-mutants version lacks an inode binding")
    return observed_identity


def cargo_mutants_source_inventory(
    root: Path,
    package_dir: Path,
    package: str,
    cache: CargoMutantsSourceInventory,
    environment: dict[str, str] | None = None,
) -> frozenset[str]:
    executable = cargo_mutants_executable(root, cache, environment)
    cached = cache.packages.get(package)
    if cached is not None:
        return cached
    if not cache.version_checked:
        cache.verified_identity = require_cargo_mutants_version(
            executable, root, environment
        )
        cache.version_checked = True
    elif enterprise_security_runner(environment) and cache.verified_identity is None:
        raise EvidenceError(
            "enterprise cargo-mutants inventory lacks a version-verified inode"
        )

    package_dir = package_dir.resolve()
    root = root.resolve()
    try:
        package_prefix = PurePosixPath(package_dir.relative_to(root).as_posix())
    except ValueError as error:
        raise EvidenceError(
            f"{package}: Cargo package escaped the repository"
        ) from error
    output, _observed_identity = cargo_mutants_output(
        [
            os.fspath(executable),
            "mutants",
            "--no-config",
            "-p",
            package,
            "--list-files",
            "--json",
        ],
        root,
        f"{package}: cargo-mutants source inventory",
        environment,
        cache.verified_identity,
    )
    try:
        entries = json.loads(output, object_pairs_hook=reject_duplicate_keys)
    except (json.JSONDecodeError, UnicodeError) as error:
        raise EvidenceError(
            f"{package}: cargo-mutants source inventory is invalid JSON: {error}"
        ) from error
    if not isinstance(entries, list) or not entries:
        raise EvidenceError(f"{package}: cargo-mutants source inventory is empty")
    sources: set[str] = set()
    for index, entry in enumerate(entries):
        label = f"{package}: cargo-mutants source {index}"
        if not isinstance(entry, dict):
            raise EvidenceError(f"{label}: source inventory entry is not an object")
        exact_keys(entry, {"path", "package"}, set(), label)
        if entry["package"] != package:
            raise EvidenceError(f"{label}: source inventory package binding differs")
        raw_path = entry["path"]
        if not isinstance(raw_path, str):
            raise EvidenceError(f"{label}: source inventory path is not a string")
        path = canonical_repository_path(raw_path, label)
        safe_rust_path(path, label)
        parsed = PurePosixPath(path)
        if package_prefix != parsed and package_prefix not in parsed.parents:
            raise EvidenceError(
                f"{package}: cargo-mutants source escaped its Cargo package: {path}"
            )
        if path in sources:
            raise EvidenceError(f"{label}: duplicate source inventory path")
        sources.add(path)
    inventory = frozenset(sources)
    cache.packages[package] = inventory
    return inventory


def require_mutation_source_discoverable(
    root: Path,
    package_dir: Path,
    package: str,
    source: str,
    cache: CargoMutantsSourceInventory,
    label: str,
) -> bytes:
    source_path = lexical_path_below_root(root, root / source, label)
    source_payload = read_regular_file_below_root(root, source_path, label)
    inventory = cargo_mutants_source_inventory(root, package_dir, package, cache)
    if source not in inventory:
        raise EvidenceError(
            f"{label}: source is not cargo-mutants-discoverable for package {package}"
        )
    return source_payload


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


def rust_function_exists(
    path: Path,
    selector: str,
    label: str,
    *,
    source_payload: bytes | None = None,
) -> None:
    leaf = selector.rsplit("::", 1)[-1]
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", leaf):
        raise EvidenceError(f"{label}: selector does not end in a Rust function name")
    if source_payload is None:
        source = path.read_text(encoding="utf-8")
    else:
        try:
            source = source_payload.decode("utf-8")
        except UnicodeError as error:
            raise EvidenceError(f"{label}: invalid UTF-8 Rust source") from error
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
    source_inventory: CargoMutantsSourceInventory | None = None,
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
    if source_inventory is None:
        source_inventory = CargoMutantsSourceInventory()
    production_path = require_under_package(root, package_dirs, package, source)
    production_payload = require_mutation_source_discoverable(
        root,
        package_dirs[package],
        package,
        source,
        source_inventory,
        f"{case_id}: mutation source",
    )
    rust_function_exists(
        production_path,
        selector,
        f"{case_id}: mutation target",
        source_payload=production_payload,
    )
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


def source_lines(payload: bytes, source_path: Path) -> list[str]:
    try:
        return payload.decode("utf-8").splitlines()
    except UnicodeError as error:
        raise EvidenceError(
            f"{source_path}: unable to decode mutation source: {error}"
        ) from error


def source_fragment(lines: list[str], source_path: Path, span: Any, label: str) -> str:
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
    if start_line > len(lines):
        raise EvidenceError(f"{label}: native source span escaped the source file")
    line = lines[start_line - 1]
    if end_column - 1 > len(line):
        raise EvidenceError(f"{label}: native source span escaped its source line")
    return line[start_column - 1 : end_column - 1]


def native_mutant_semantics(
    native: Any, lines: list[str], source_path: Path, label: str
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
        else source_fragment(lines, source_path, native.get("span"), label)
    )
    return function_name, genre, original, replacement


def semantic_match(
    native: Any,
    campaign: dict[str, Any],
    lines: list[str],
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
        native, lines, source_path, label
    )
    matches = (
        genre == selector["genre"]
        and replacement == selector["replacement"]
        and original == selector.get("original")
    )
    return matches, original


def select_native_mutant(
    body: Any,
    campaign: dict[str, Any],
    lines: list[str],
    source_path: Path,
) -> SelectedMutant:
    if not isinstance(body, list) or not body:
        raise EvidenceError(
            f"{campaign['id']}: cargo-mutants preflight returned no native list"
        )
    candidates: list[SelectedMutant] = []
    for index, native in enumerate(body):
        matches, original = semantic_match(
            native,
            campaign,
            lines,
            source_path,
            f"{campaign['id']}: preflight mutant {index}",
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
    root: Path | None = None,
    source_payload: bytes | None = None,
) -> bytes:
    payload = read_regular_file_no_follow(
        path,
        f"{path}: cargo-mutants outcomes",
        root=root,
    )
    actual_digest = hashlib.sha256(payload).hexdigest()
    if expected_digest is not None and actual_digest != expected_digest:
        raise EvidenceError(
            f"{path}: digest mismatch, expected {expected_digest}, observed {actual_digest}"
        )
    body = parse_json_payload(payload, str(path))
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
    if bind_identity and semantic_selector is not None and body["total_mutants"] != 1:
        raise EvidenceError(
            f"{path}: semantic campaign did not execute exactly one mutant"
        )
    semantic_lines: list[str] | None = None
    if bind_identity and semantic_selector is not None:
        if source_payload is None:
            source_payload = read_regular_file_no_follow(
                source_path,
                f"{source_path}: mutation source",
                root=root,
            )
        semantic_lines = source_lines(source_payload, source_path)
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
            if semantic_lines is None:
                raise EvidenceError(f"{path}: mutation source was not captured")
            matches, _original = semantic_match(
                mutant,
                campaign,
                semantic_lines,
                source_path,
                f"{path}: outcome mutant",
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
    return payload


def validate_case(
    root: Path,
    package_dirs: dict[str, Path],
    path: Path,
    require_complete: bool,
    refresh_campaign: str | None = None,
    outcome_overrides: dict[str, Path] | None = None,
    source_inventory: CargoMutantsSourceInventory | None = None,
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
    if source_inventory is None:
        source_inventory = CargoMutantsSourceInventory()
    campaigns: dict[str, dict[str, Any]] = {}
    outcome_paths: set[str] = set()
    referenced_controls: set[str] = set()
    for value in campaign_values:
        campaign = validate_campaign(
            root,
            package_dirs,
            value,
            controls,
            case_id,
            source_inventory,
        )
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
        source_path = root / campaign["source"]
        captured_files: dict[Path, bytes | None] = {source_path: None}
        if refresh_campaign is not None and campaign["id"] != refresh_campaign:
            # Targeted refresh deliberately permits other promoted campaigns to
            # remain stale until their own genuine rerun. Recomputing the full
            # conservative repository closure for those untouched campaigns is
            # both redundant and quadratic across a multi-campaign refresh.
            # Their stored outcome digest and caught-only shape are still
            # verified below, while ordinary validation remains fully strict.
            stale_inputs = True
            captured_files[source_path] = read_regular_file_no_follow(
                source_path,
                campaign["source"],
                root=root,
            )
        else:
            expected_inputs_digest = campaign_input_digest(
                root,
                package_dirs,
                campaign,
                controls[campaign["control_id"]],
                path,
                captured_files=captured_files,
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
        source_payload = captured_files[source_path]
        if source_payload is None:
            raise EvidenceError(f"{source_path}: mutation source was not captured")
        validate_outcomes(
            evidence_path,
            campaign,
            digest,
            source_path,
            bind_identity=not stale_inputs,
            root=root,
            source_payload=source_payload,
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
    *,
    expected_outcome_payload: bytes | None = None,
    expected_inputs_snapshot: tuple[str, dict[Path, bytes]] | None = None,
) -> tuple[Path, str, bool]:
    case, campaign, control = record
    if campaign["outcomes"].get("sha256") is not None:
        raise EvidenceError(f"{campaign['id']}: already has a bound outcome digest")
    root = root.resolve()
    reject_in_root_transaction_state(root)
    candidate = outcome_path(raw_path)
    raw_destination = root / campaign["outcomes"]["path"]
    destination = lexical_path_below_root(
        root,
        raw_destination,
        f"{raw_destination}: outcome destination",
        allow_missing_parents=True,
    )

    with refresh_lock(root):
        recover_atomic_replace_journal(root)
        if destination.exists() or destination.is_symlink():
            raise EvidenceError(
                f"{destination}: refusing to overwrite promoted mutation evidence"
            )

        source_path = root / campaign["source"]
        source_payload = read_regular_file_no_follow(
            source_path,
            f"{source_path}: promotion source",
            root=root,
        )
        payload = validate_outcomes(
            candidate,
            campaign,
            None,
            source_path,
            root=root,
            source_payload=source_payload,
        )
        if expected_outcome_payload is not None and payload != expected_outcome_payload:
            raise EvidenceError(
                f"{campaign['id']}: outcome changed after the promotion run"
            )
        digest = hashlib.sha256(payload).hexdigest()
        inputs_digest, input_guards = campaign_input_snapshot(
            root, package_dirs, campaign, control, case.path
        )
        if expected_inputs_snapshot is not None and (
            inputs_digest != expected_inputs_snapshot[0]
            or input_guards != expected_inputs_snapshot[1]
        ):
            raise EvidenceError(
                f"{campaign['id']}: source or control changed before promotion"
            )

        original_case = read_regular_file_below_root(root, case.path, str(case.path))
        if parse_json_payload(original_case, str(case.path)) != case.body:
            raise EvidenceError(f"{case.path}: changed after promotion validation")
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
        manifest_path = lexical_path_below_root(
            root, manifest_path, f"{manifest_path}: adversarial manifest"
        )
        original_manifest = read_regular_file_below_root(
            root, manifest_path, str(manifest_path)
        )
        if (
            read_regular_file_no_follow(
                source_path,
                f"{source_path}: promotion source",
                root=root,
            )
            != source_payload
        ):
            raise EvidenceError(f"{source_path}: changed during promotion")
        ensure_parent_directories_below_root(
            root, destination, f"{destination}: outcome destination"
        )
        destination = lexical_path_below_root(
            root, destination, f"{destination}: outcome destination"
        )
        if (
            read_file_snapshot_below_root(
                root, destination, str(destination), allow_missing=True
            )
            is not None
        ):
            raise EvidenceError(
                f"{destination}: refusing to overwrite promoted mutation evidence"
            )
        atomic_replace_many(
            [
                (destination, payload),
                (case.path, case_payload),
                (manifest_path, manifest_payload),
            ],
            {
                destination: None,
                case.path: original_case,
                manifest_path: original_manifest,
            },
            input_guards,
            root,
        )
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


def promote_pending_outcome(
    root: Path,
    package_dirs: dict[str, Path],
    record: tuple[LoadedCase, dict[str, Any], dict[str, Any]],
    environment: dict[str, str],
) -> tuple[Path, str, bool]:
    """Run and promote one pending campaign without reusing external output."""

    case, campaign, control = record
    if campaign["outcomes"].get("sha256") is not None:
        raise EvidenceError(f"{campaign['id']}: already has promoted mutation evidence")
    verifier_root = verifier_artifact_root(environment)
    inputs_before, input_read_guards = campaign_input_snapshot(
        root, package_dirs, campaign, control, case.path
    )
    with mutation_output_workspace(
        environment, f"chio-security-evidence-promotion-{campaign['id']}"
    ) as temporary:
        output_root = temporary / campaign["id"]
        outcome_candidate = run_campaign(
            root, campaign, control, output_root, environment
        )
        expected_candidate = output_root / "mutants.out/outcomes.json"
        if outcome_candidate != expected_candidate:
            raise EvidenceError(
                f"{campaign['id']}: campaign returned a noncanonical outcome path"
            )
        inputs_after, input_read_guards_after = campaign_input_snapshot(
            root, package_dirs, campaign, control, case.path
        )
        if (
            inputs_after != inputs_before
            or input_read_guards_after != input_read_guards
        ):
            raise EvidenceError(
                f"{campaign['id']}: source or control contract changed during promotion"
            )
        outcome_payload = read_regular_file_no_follow(
            outcome_candidate,
            f"{outcome_candidate}: promotion run outcome",
            root=verifier_root,
        )
        return promote_outcome(
            root,
            package_dirs,
            record,
            os.fspath(outcome_candidate),
            expected_outcome_payload=outcome_payload,
            expected_inputs_snapshot=(inputs_after, input_read_guards_after),
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
        recover_atomic_replace_journal(root)
        old_case_payload = read_regular_file(case.path, str(case.path))
        if load_json(case.path) != case.body:
            raise EvidenceError(f"{case.path}: changed after refresh validation")
        manifest_path = root / "crates/core/chio-adversarial-suite/manifest.json"
        old_manifest_payload = read_regular_file(manifest_path, str(manifest_path))
        old_outcome_payload = read_regular_file(destination, str(destination))
        old_threat_payloads = snapshot_threat_aggregates(root)
        observed_old_digest = hashlib.sha256(old_outcome_payload).hexdigest()
        if observed_old_digest != old_digest:
            raise EvidenceError(
                f"{destination}: digest mismatch, expected {old_digest}, "
                f"observed {observed_old_digest}"
            )

        inputs_before, input_read_guards = campaign_input_snapshot(
            root, package_dirs, campaign, control, case.path
        )
        verifier_root = verifier_artifact_root(environment)
        with mutation_output_workspace(
            environment, f"chio-security-evidence-refresh-{campaign['id']}"
        ) as temporary:
            output_root = temporary / campaign["id"]
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
            outcome_payload = validate_outcomes(
                outcome_candidate,
                campaign,
                None,
                root / campaign["source"],
                root=verifier_root,
            )

            inputs_after, input_read_guards_after = campaign_input_snapshot(
                root, package_dirs, campaign, control, case.path
            )
            if (
                inputs_after != inputs_before
                or input_read_guards_after != input_read_guards
            ):
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
            final_inputs, final_input_read_guards = campaign_input_snapshot(
                root, package_dirs, campaign, control, case.path
            )
            if (
                final_inputs != inputs_after
                or final_input_read_guards != input_read_guards
            ):
                raise EvidenceError(
                    f"{campaign['id']}: source or control contract changed before commit"
                )
            threat_replacements, threat_read_guards = (
                render_threat_aggregate_replacements(
                    root,
                    case,
                    campaign,
                    outcome_payload,
                    old_threat_payloads,
                    utc_timestamp(),
                )
            )
            if snapshot_threat_aggregates(root) != old_threat_payloads:
                raise EvidenceError(
                    "threat evidence changed while mutation refresh was running"
                )
            transaction_read_guards = dict(input_read_guards)
            for guard_path, guard_payload in threat_read_guards.items():
                prior_payload = transaction_read_guards.get(guard_path)
                if prior_payload is not None and prior_payload != guard_payload:
                    raise EvidenceError(
                        f"{guard_path}: conflicting transaction read guards"
                    )
                transaction_read_guards[guard_path] = guard_payload
            replacements = [
                (destination, outcome_payload),
                (case.path, case_payload),
                (manifest_path, manifest_payload),
                *threat_replacements,
            ]
            originals = {
                destination: old_outcome_payload,
                case.path: old_case_payload,
                manifest_path: old_manifest_payload,
                **{
                    threat_path: old_threat_payloads[threat_path]
                    for threat_path, _payload in threat_replacements
                },
            }
            atomic_replace_many(
                replacements,
                originals,
                transaction_read_guards,
                root,
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
    source_inventory = CargoMutantsSourceInventory()
    cases = [
        validate_case(
            root,
            package_dirs,
            path,
            require_complete,
            refresh_campaign=refresh_campaign,
            source_inventory=source_inventory,
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


def run_checked(
    command: list[str],
    root: Path,
    environment: dict[str, str],
    *,
    execution_options: dict[str, Any] | None = None,
) -> str:
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
        **(execution_options or {}),
    )
    if completed.returncode != 0:
        sys.stderr.write(completed.stdout)
        raise EvidenceError(
            f"command failed with status {completed.returncode}: {rendered}"
        )
    return completed.stdout


def run_json_checked(
    command: list[str],
    root: Path,
    environment: dict[str, str],
    *,
    execution_options: dict[str, Any] | None = None,
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
        **(execution_options or {}),
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


ENTERPRISE_STATE_ROOT = Path("/baseline/candidate-state")
ENTERPRISE_VERIFIER_UID = 65533
ENTERPRISE_VERIFIER_GID = 65533
ENTERPRISE_BASELINE_MODE = 0o555


def require_directory_authority(
    metadata: os.stat_result,
    path: Path,
    *,
    uid: int,
    gid: int,
    mode: int,
) -> None:
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != uid
        or metadata.st_gid != gid
        or stat.S_IMODE(metadata.st_mode) != mode
    ):
        raise EvidenceError(f"{path}: directory authority is mutable or aliased")


def verifier_artifact_root(environment: dict[str, str]) -> Path | None:
    enterprise = environment.get("CHIO_ENTERPRISE_SECURITY_RUNNER") == "1"
    legacy = environment.get("CHIO_SECURITY_CANDIDATE_ARTIFACTS")
    raw = environment.get("CHIO_SECURITY_VERIFIER_ARTIFACTS")
    if legacy is not None:
        raise EvidenceError("candidate artifact authority is forbidden")
    if not enterprise:
        if raw is not None:
            raise EvidenceError(
                "verifier artifact authority is only valid in the enterprise boundary"
            )
        return None
    if raw is None:
        raise EvidenceError("enterprise verifier artifact authority is absent")
    artifact_root = Path(raw)
    if not artifact_root.is_absolute() or os.fspath(artifact_root) != raw:
        raise EvidenceError("enterprise verifier artifact authority is not canonical")
    try:
        relative = artifact_root.relative_to(ENTERPRISE_STATE_ROOT)
    except ValueError as error:
        raise EvidenceError(
            "enterprise verifier artifact authority escaped its state root"
        ) from error
    if (
        len(relative.parts) != 3
        or len(relative.parts[0]) != 64
        or any(character not in "0123456789abcdef" for character in relative.parts[0])
        or relative.parts[1:] != ("verifier", "artifacts")
    ):
        raise EvidenceError("enterprise verifier artifact authority is not exact")
    gate_root = ENTERPRISE_STATE_ROOT / relative.parts[0]
    verifier_root = gate_root / "verifier"
    authority = (
        (Path("/baseline"), 0, 0, ENTERPRISE_BASELINE_MODE),
        (ENTERPRISE_STATE_ROOT, 0, 0, 0o711),
        (gate_root, 0, 0, 0o711),
        (verifier_root, 0, ENTERPRISE_VERIFIER_GID, 0o770),
        (
            artifact_root,
            ENTERPRISE_VERIFIER_UID,
            ENTERPRISE_VERIFIER_GID,
            0o700,
        ),
    )
    try:
        snapshots = {path: path.lstat() for path, _uid, _gid, _mode in authority}
        resolved = artifact_root.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise EvidenceError(
            f"{artifact_root}: verifier artifact authority is unavailable: {error}"
        ) from error
    if resolved != artifact_root:
        raise EvidenceError(f"{artifact_root}: verifier artifact authority is aliased")
    for path, uid, gid, mode in authority:
        require_directory_authority(snapshots[path], path, uid=uid, gid=gid, mode=mode)
    if any(
        metadata.st_dev != snapshots[artifact_root].st_dev
        for metadata in snapshots.values()
    ):
        raise EvidenceError(
            f"{artifact_root}: verifier artifact authority crossed filesystems"
        )
    try:
        repeated = {path: path.lstat() for path, _uid, _gid, _mode in authority}
    except OSError as error:
        raise EvidenceError(
            f"{artifact_root}: verifier artifact authority changed: {error}"
        ) from error
    for path, uid, gid, mode in authority:
        if metadata_identity(snapshots[path]) != metadata_identity(repeated[path]):
            raise EvidenceError(
                f"{artifact_root}: verifier artifact authority changed at {path}"
            )
        require_directory_authority(repeated[path], path, uid=uid, gid=gid, mode=mode)
    if any(
        metadata.st_dev != repeated[artifact_root].st_dev
        for metadata in repeated.values()
    ):
        raise EvidenceError(
            f"{artifact_root}: verifier artifact authority crossed filesystems"
        )
    return artifact_root


def create_owned_directory_below_root(root: Path, path: Path, label: str) -> None:
    parent = open_parent_directory_below_root(root, path, label)
    try:
        try:
            os.mkdir(path.name, 0o700, dir_fd=parent)
        except FileExistsError as error:
            raise EvidenceError(f"{path}: refusing to reuse existing directory") from error
        metadata = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        require_owned_directory_metadata(metadata, label)
        os.fsync(parent)
    except OSError as error:
        raise EvidenceError(f"{label}: unable to create owned directory: {error}") from error
    finally:
        os.close(parent)


@contextmanager
def mutation_output_workspace(
    environment: dict[str, str], prefix: str
) -> Iterator[Path]:
    verifier_root = verifier_artifact_root(environment)
    if verifier_root is not None:
        output = verifier_root / f"{prefix}-{secrets.token_hex(16)}"
        if output.exists() or output.is_symlink():
            raise EvidenceError(f"{output}: verifier output identity already exists")
        create_owned_directory_below_root(
            verifier_root, output, f"{output}: verifier output workspace"
        )
        yield output
        return
    with tempfile.TemporaryDirectory(prefix=f"{prefix}-") as raw:
        yield Path(raw).resolve()


def validate_mutation_output_root(
    output_root: Path, environment: dict[str, str]
) -> Path | None:
    verifier_root = verifier_artifact_root(environment)
    if verifier_root is None:
        return None
    if not output_root.is_absolute():
        raise EvidenceError("enterprise mutation output must be absolute")
    try:
        output_root.relative_to(verifier_root)
    except ValueError as error:
        raise EvidenceError(
            "enterprise mutation output escapes verifier artifacts"
        ) from error
    if output_root == verifier_root:
        raise EvidenceError(
            "enterprise mutation output cannot alias its authority root"
        )
    lexical_path_below_root(
        verifier_root,
        output_root,
        f"{output_root}: enterprise mutation output",
        allow_missing_parents=True,
    )
    return verifier_root


def run_campaign(
    root: Path,
    campaign: dict[str, Any],
    control: dict[str, Any],
    output_root: Path,
    environment: dict[str, str],
) -> Path:
    output_root = output_root.resolve(strict=False)
    output_authority = validate_mutation_output_root(output_root, environment)
    cargo_mutants = cargo_mutants_executable(
        root, CargoMutantsSourceInventory(), environment
    )
    verified_cargo_mutants_identity = require_cargo_mutants_version(
        cargo_mutants, root, environment
    )
    if output_root.exists():
        raise EvidenceError(
            f"{output_root}: refusing to overwrite existing mutation output"
        )
    output_parent = output_authority or output_root.parent.resolve()
    create_owned_directory_below_root(
        output_parent, output_root, f"{output_root}: mutation output"
    )
    source_path = root / campaign["source"]
    source_payload = read_regular_file_no_follow(
        source_path,
        f"{source_path}: mutation source",
        root=root,
    )
    source_digest = hashlib.sha256(source_payload).digest()
    captured_source_lines = source_lines(source_payload, source_path)
    selector = campaign.get("mutant")
    if selector is None:
        raise EvidenceError(
            f"{campaign['id']}: campaign lacks a semantic mutant selector"
        )
    list_command = [
        os.fspath(cargo_mutants),
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
    with cargo_mutants_subprocess_options(
        root,
        list_command,
        environment,
        verified_cargo_mutants_identity,
    ) as (execution_options, _preflight_identity):
        selected = select_native_mutant(
            run_json_checked(
                list_command,
                root,
                environment,
                execution_options=execution_options,
            ),
            campaign,
            captured_source_lines,
            source_path,
        )
    require_statically_viable_mutant(selected, campaign)
    mutation_name = native_mutant_list_name(selected, campaign)

    run_control(root, control, environment)
    output_path = output_root / "mutants.out"
    command = [
        os.fspath(cargo_mutants),
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
        with cargo_mutants_subprocess_options(
            root,
            command,
            environment,
            verified_cargo_mutants_identity,
        ) as (execution_options, _campaign_identity):
            run_checked(
                command,
                root,
                environment,
                execution_options=execution_options,
            )
        outcomes_path = output_path / "outcomes.json"
        validate_outcomes(
            outcomes_path,
            campaign,
            None,
            source_path,
            selected,
            root=output_authority,
            source_payload=source_payload,
        )
        return outcomes_path
    finally:
        final_source_payload = read_regular_file_no_follow(
            source_path,
            f"{campaign['id']}: restored mutation source",
            root=root,
        )
        final_source_digest = hashlib.sha256(final_source_payload).digest()
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

    with mutation_output_workspace(
        environment, "chio-security-adversarial-release"
    ) as temporary:
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
    action.add_argument("--promote-pending-outcome", metavar="MUTATION_ID")
    action.add_argument("--refresh-outcome", metavar="MUTATION_ID")
    action.add_argument("--list-pending", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    environment = os.environ.copy()
    environment["CARGO_INCREMENTAL"] = "0"
    environment["CARGO_BUILD_JOBS"] = "1"
    if args.promote_outcome and enterprise_security_runner(environment):
        raise EvidenceError(
            "legacy --promote-outcome is forbidden in the enterprise boundary"
        )
    root = (args.root or Path(__file__).resolve().parents[1]).resolve()
    reject_in_root_transaction_state(root)
    if trusted_transaction_exists(root):
        with refresh_lock(root):
            recover_atomic_replace_journal(root)
    cases_path = (
        args.cases or root / "crates/core/chio-adversarial-suite/cases"
    ).resolve()
    if args.output is not None and args.campaign is None:
        raise EvidenceError("--output requires --campaign")
    require_complete = args.require_complete or args.release
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
            outcome_path(raw_path),
            record[1],
            None,
            root / record[1]["source"],
            root=root,
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
    if args.promote_pending_outcome:
        record = index.get(args.promote_pending_outcome)
        if record is None:
            raise EvidenceError(f"unknown mutation id: {args.promote_pending_outcome}")
        destination, digest, complete = promote_pending_outcome(
            root, package_dirs, record, environment
        )
        load_cases(root, cases_path, False, args.fixture)
        print(
            "ran and promoted caught-only mutation outcome: "
            f"{args.promote_pending_outcome}"
        )
        print(f"outcomes: {destination.relative_to(root)}")
        print(f"sha256: {digest}")
        print(f"case: {'complete' if complete else 'pending additional campaigns'}")
        return 0
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
        verifier_root = verifier_artifact_root(environment)
        output = args.output or (
            verifier_root / f"chio-security-mutants-{args.campaign}"
            if verifier_root is not None
            else Path(tempfile.gettempdir()) / f"chio-security-mutants-{args.campaign}"
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
