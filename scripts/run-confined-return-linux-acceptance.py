#!/usr/bin/env python3
"""Run current, source-bound Linux x86_64 confined-return acceptance.

Historical acceptance packages are never updated. A successful build, empty
test selection, or registered-but-ignored test cannot satisfy this campaign.
"""

from __future__ import annotations

import argparse
from collections import Counter, deque
from contextlib import ExitStack, contextmanager
import errno
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import stat
import subprocess
import time
import tomllib


ROOT = Path(__file__).resolve().parents[1]
CASE_PREFIX = "recovery::tests::knowledge::confinement::linux::"
CASES = tuple(CASE_PREFIX + name for name in (
    "linux_absolute_deadline_kills_a_held_handle_without_parent_io",
    "linux_acknowledgement_retains_delivery_after_cancel_and_authority_change",
    "linux_cancellation_reports_an_already_ordered_parent_return",
    "linux_channel_canaries_never_reach_parent_or_bypass_projection",
    "linux_duplicate_launch_and_cancel_preserve_the_observation_and_consumed_slot",
    "linux_fixed_environment_rejects_parent_controlled_channels",
    "linux_launch_cutpoints_never_duplicate_measurement_or_reset_observation",
    "linux_parent_cancellation_withholds_returns_before_and_after_native_join",
    "linux_rejected_projection_leaves_no_candidate_blob_or_extra_charge",
    "linux_return_cutpoints_reopen_the_native_writer_without_second_disclosure",
    "linux_sink_attempt_is_durably_uncertain_before_first_byte",
    "linux_staged_return_survives_execution_deadline",
    "linux_staging_receipt_and_return_preparation_enforce_source_audience",
    "linux_terminal_dispositions_survive_cancellation",
    "linux_true_and_false_returns_preserve_identical_parent_storage_availability",
    "linux_unknown_input_provenance_withholds_a_correct_projection",
    "linux_useful_decision_exact_authority_and_parent_join_before_first_byte",
    "linux_valid_signatures_cannot_authorize_cross_parent_epoch_or_stale_returns",
))
MODES = ("error", "log", "progress", "stream", "file", "callback", "wrong-predicate", "overflow", "hang")
MODE_RECORD_PREFIX = b"CHIO-CONFINED-CANARY-MODE-V1:"
MODE_FIELD_BYTES = 32
ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
# Keep the metadata-only categories aligned with local command provenance.
# Acceptance binds Rust-profile candidate inputs, never SDK dependency caches.
CACHE_PARTS = {
    ".git", ".cache", ".ignored-cache", "__pycache__", ".pytest_cache",
    ".mypy_cache", ".ruff_cache", ".next", ".turbo", "node_modules", ".venv", "venv",
}
SECRET_NAMES = {
    "credentials", "credentials.json", "credentials.toml", ".git-credentials", ".netrc", ".npmrc", ".pypirc",
    "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", ".aws", ".ssh", ".gnupg", ".secrets",
    ".auth", ".password-store",
}
SECRET_SUFFIXES = {".key", ".pem", ".p12", ".pfx", ".keystore"}
ARCHIVE_SUFFIXES = ('.7z', '.tar', '.tar.bz2', '.tar.gz', '.tar.xz', '.tar.zst', '.tbz', '.tbz2', '.tgz', '.txz', '.tzst', '.zip')
ARTIFACT_PREFIXES = (
    'audits/evidence',
    'docs/architecture/recoverable-agent-runtime/implementation/p0/evidence',
    'docs/architecture/recoverable-agent-runtime/implementation/p1/evidence',
    'docs/architecture/recoverable-agent-runtime/implementation/p2/evidence',
    'docs/architecture/recoverable-agent-runtime/implementation/p3/evidence',
    'docs/architecture/recoverable-agent-runtime/implementation/p4/evidence',
    'docs/architecture/recoverable-agent-runtime/implementation/p5/evidence',
    'docs/architecture/recoverable-agent-runtime/implementation/p6/evidence',
    'docs/evidence',
    'docs/integrations/acceptance',
    'docs/integrations/session-credentials/evidence',
    'docs/research/openappa-2026-10-01/evidence',
    'formal/mutation/evidence',
    'labs/openappa-recovery/evidence',
    'sdks/python/chio-hermes/evidence',
)
PREPARATION_SCHEMA = "chio.confined-return-linux-compilation-preparation.v1"
PREPARATION_COMMAND_TIMEOUT_SECONDS = 3600
PREPARATION_TOTAL_BUDGET_SECONDS = 21600
PREPARED_CACHE_TARGETS = {name: "target/compiled/" + name for name in ("cage-lab", "static", "host")}


class AcceptanceError(RuntimeError):
    """The current campaign did not establish its exact acceptance contract."""


def file_identity(metadata: os.stat_result) -> tuple:
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_size,
            metadata.st_mtime_ns, metadata.st_ctime_ns)


@contextmanager
def input_parent(path: Path, root: Path | None = None, parent_identities: list | None = None):
    """Anchor every parent component without following substituted links."""
    absolute = Path(path).absolute()
    root_parts = root.absolute().parts if root is not None else ()
    if ".." in absolute.parts or root is not None and absolute.parts[:len(root_parts)] != root_parts:
        raise AcceptanceError("regular input is outside its declared root")
    directories = []
    descriptors = []
    try:
        parent = os.open(absolute.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(parent)
        prefix = Path(absolute.anchor) if parent_identities is not None else None
        anchor = os.fstat(parent)
        identities = [(str(prefix), (anchor.st_dev, anchor.st_ino, anchor.st_mode))] if prefix is not None else []
        for component in absolute.parts[1:-1]:
            directory = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            descriptors.append(directory)
            opened = os.fstat(directory)
            directories.append((parent, component, directory, (opened.st_dev, opened.st_ino, opened.st_mode)))
            if prefix is not None:
                prefix /= component
                identities.append((str(prefix), (opened.st_dev, opened.st_ino, opened.st_mode)))
            parent = directory
        if parent_identities is not None:
            parent_identities.extend(identities)
        yield parent, absolute.name
        for parent_fd, component, directory_fd, identity in directories:
            held = os.fstat(directory_fd)
            located = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
            if (held.st_dev, held.st_ino, held.st_mode) != identity or (located.st_dev, located.st_ino, located.st_mode) != identity:
                raise AcceptanceError("regular input parent changed during its read")
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


@contextmanager
def regular_file(path: Path, root: Path | None = None):
    """Hold a regular input through no-follow lookup and stable read checks."""
    with input_parent(path, root) as (parent, leaf):
        located = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
        if not stat.S_ISREG(located.st_mode):
            raise AcceptanceError("regular input is symbolic or not a regular file")
        descriptor = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or file_identity(opened) != file_identity(located):
                raise AcceptanceError("regular input changed while being opened")
            yield descriptor, opened
            after = os.fstat(descriptor)
            located = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
            if file_identity(opened) != file_identity(after) or file_identity(after) != file_identity(located):
                raise AcceptanceError("regular input changed during its read")
        finally:
            os.close(descriptor)


def directory_identity(metadata: os.stat_result) -> tuple:
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid, metadata.st_gid)


@contextmanager
def held_directory(path: Path, root: Path):
    """Hold a writable cache directory without allowing its path to be replaced."""
    with input_parent(path, root) as (parent, leaf):
        located = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
        if not stat.S_ISDIR(located.st_mode) or located.st_uid != os.getuid() or located.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID):
            raise AcceptanceError("prepared cache directory is symbolic or unsafe")
        descriptor = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            opened = os.fstat(descriptor)
            if directory_identity(opened) != directory_identity(located):
                raise AcceptanceError("prepared cache directory changed while being opened")
            yield descriptor, opened
            if directory_identity(opened) != directory_identity(os.fstat(descriptor)) or directory_identity(opened) != directory_identity(os.stat(leaf, dir_fd=parent, follow_symlinks=False)):
                raise AcceptanceError("prepared cache directory changed during execution")
        finally:
            os.close(descriptor)


def candidate_location(root: Path) -> dict:
    with held_directory(root, root) as (_, metadata):
        return {"schema": "chio.source-location.v1", "repository": str(root),
                "host": {"system": platform.system(), "machine": platform.machine(), "node": platform.node()},
                "root": {"device": metadata.st_dev, "inode": metadata.st_ino,
                         "uid": metadata.st_uid, "mode": stat.S_IMODE(metadata.st_mode)}}


def compilation_commands() -> list[dict]:
    """Compile the declared lanes without claiming native execution success."""
    build = ["cargo", "build", "--offline", "--locked", "--target", "x86_64-unknown-linux-musl", "-p", "chio-cage"]
    test = ["cargo", "test", "--offline", "--locked", "-p", "chio-cage"]
    return [
        {"name": "strict-static-normal", "cache_lane": "cage-lab/static-pie", "command": [*build, "--bin", "chio-cage-init", "--features", "real-linux-enforcement"]},
        {"name": "strict-native-all-targets", "cache_lane": "cage-lab", "command": [*test, "--all-targets", "--features", "real-linux-enforcement", "--no-run"]},
        {"name": "strict-static-mutants", "cache_lane": "cage-lab/static-pie", "command": [*build, "--bin", "chio-cage-init", "--features", "real-linux-enforcement,enforcement-mutants"]},
        {"name": "strict-native-mutants", "cache_lane": "cage-lab", "command": [*test, "--test", "linux_enforcement", "--features", "real-linux-enforcement,enforcement-mutants", "--no-run"]},
        {"name": "static-tools", "cache_lane": "static", "command": [*build, "--bin", "chio-cage-init", "--bin", "chio-confined-reader"]},
        *({"name": "canary-" + mode, "cache_lane": "static", "mode": mode, "command": [*build, "--example", "confined-return-canary"]} for mode in MODES),
        {"name": "control-plane-library", "cache_lane": "host", "command": ["cargo", "test", "--offline", "--locked", "-p", "chio-control-plane", "--lib", CASE_PREFIX, "--no-run"]},
        {"name": "store-library", "cache_lane": "host", "command": ["cargo", "test", "--offline", "--locked", "-p", "chio-store-sqlite", "--lib", "--no-run"]},
    ]


def unique_json_object(pairs: list[tuple]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise AcceptanceError("duplicate compilation preparation field")
        result[key] = value
    return result


def bounded_duration(value, maximum: int) -> bool:
    return (type(value) is int or type(value) is float and math.isfinite(value)) and 0 <= value <= maximum


@contextmanager
def prepared_cache(receipt: Path, root: Path, inventory: list, versions: dict, profile: dict):
    """Bind cache custody and a preparation record, then rerun every acceptance command."""
    receipt = receipt.absolute()
    if not receipt.is_relative_to(root / "target") or ".." in receipt.parts:
        raise AcceptanceError("prepared cache receipt is outside the candidate target directory")
    with ExitStack() as custody:
        descriptor, metadata = custody.enter_context(regular_file(receipt, root))
        if metadata.st_uid != os.getuid() or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID) or not 0 < metadata.st_size <= 1024 * 1024:
            raise AcceptanceError("prepared cache receipt permissions or size are unsafe")
        data = descriptor_bytes(descriptor)
        with input_parent(receipt, root) as (parent, leaf):
            if file_identity(metadata) != file_identity(os.fstat(descriptor)) or file_identity(metadata) != file_identity(os.stat(leaf, dir_fd=parent, follow_symlinks=False)):
                raise AcceptanceError("prepared cache receipt changed during its read")
        preparation = json.loads(data, object_pairs_hook=unique_json_object)
        if not isinstance(preparation, dict) or preparation.get("schema") != PREPARATION_SCHEMA or preparation.get("status") != "prepared" or type(preparation.get("exit_code")) is not int or preparation["exit_code"] != 0:
            raise AcceptanceError("compilation preparation was not successful")
        current_binding = binding(inventory)
        if preparation.get("source_binding") != current_binding or preparation.get("source_binding_after") != current_binding or preparation.get("source_inventory_policy") != source_inventory_policy():
            raise AcceptanceError("prepared cache source binding does not match")
        location = candidate_location(root)
        if preparation.get("source_location") != location:
            raise AcceptanceError("prepared cache candidate location does not match")
        if preparation.get("toolchain") != versions or preparation.get("build_profile") != profile or preparation.get("build_environment") != {"CARGO_INCREMENTAL": "0", "CARGO_BUILD_JOBS": "2", "CARGO_NET_OFFLINE": "true"}:
            raise AcceptanceError("prepared cache profile does not match")
        if preparation.get("cache_targets") != PREPARED_CACHE_TARGETS:
            raise AcceptanceError("prepared cache targets are outside the fixed candidate layout")
        if preparation.get("per_command_timeout_seconds") != PREPARATION_COMMAND_TIMEOUT_SECONDS or preparation.get("total_preparation_budget_seconds") != PREPARATION_TOTAL_BUDGET_SECONDS or not bounded_duration(preparation.get("duration_seconds"), PREPARATION_TOTAL_BUDGET_SECONDS):
            raise AcceptanceError("compilation preparation budgets do not match")
        commands = preparation.get("commands")
        expected = compilation_commands()
        if not isinstance(commands, list) or len(commands) != len(expected):
            raise AcceptanceError("compilation preparation command inventory does not match")
        for observed, required in zip(commands, expected):
            if not isinstance(observed, dict) or any(observed.get(key) != value for key, value in required.items()) or type(observed.get("exit_code")) is not int or observed["exit_code"] != 0 or not bounded_duration(observed.get("duration_seconds"), PREPARATION_COMMAND_TIMEOUT_SECONDS):
                raise AcceptanceError("compilation preparation command failed or does not match")
        command_seconds = sum(entry["duration_seconds"] for entry in commands)
        if command_seconds > PREPARATION_TOTAL_BUDGET_SECONDS or command_seconds > preparation["duration_seconds"] + 0.000001:
            raise AcceptanceError("compilation preparation exceeds its total budget")
        targets = {lane: root / path for lane, path in PREPARED_CACHE_TARGETS.items()}
        for lane in sorted({entry["cache_lane"] for entry in expected}):
            custody.enter_context(held_directory(root / "target/compiled" / lane, root))
        witness = {"receipt": str(receipt.relative_to(root)), "sha256": hashlib.sha256(data).hexdigest(),
                   "source_binding": current_binding, "source_location": location,
                   "cache_targets": dict(PREPARED_CACHE_TARGETS),
                   "scope": "Compilation preparation only; all native acceptance commands execute again."}
        yield targets, witness


def source_link_text(path: Path, root: Path, observation: dict | None = None) -> str:
    parents = []
    with input_parent(path, root, parents) as (parent, leaf):
        before = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
        if not stat.S_ISLNK(before.st_mode):
            raise AcceptanceError("source link changed before its text was read")
        text = os.readlink(leaf, dir_fd=parent)
        after = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
        if file_identity(before) != file_identity(after):
            raise AcceptanceError("source link changed during its text read")
    if observation is not None:
        observation.update(text=text, identity=file_identity(before), parents=parents)
    return text


def verify_source_links(root: Path, observations: dict) -> None:
    for path, observed in observations.items():
        current = {}
        source_link_text(path, root, current)
        if current != observed:
            raise AcceptanceError("source link identity changed during its resolution: " + str(path.relative_to(root)))


def descriptor_bytes(descriptor: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    return b"".join(iter(lambda: os.read(descriptor, 1024 * 1024), b""))


def digest(path: Path, root: Path | None = None, descriptor: int | None = None) -> str:
    if descriptor is None:
        with regular_file(path, root) as (held, _metadata):
            return digest(path, root, descriptor=held)
    value = hashlib.sha256()
    os.lseek(descriptor, 0, os.SEEK_SET)
    for block in iter(lambda: os.read(descriptor, 1024 * 1024), b""):
        value.update(block)
    return value.hexdigest()


def source_inventory_policy() -> dict:
    return {
        "schema": "chio.confined-return-source-inventory.v2",
        "profile": "rust-confined-return-linux",
        "coverage": 'Overinclusive Git-visible candidate inputs with declared metadata-only secret, archive and artifact exclusions; not a resolved dependency graph or Python/TypeScript SDK dependency qualification.',
        "discovery": "Cached and nonignored untracked Git paths; ignored untracked inputs are not discovered.",
        "excluded_cache_parts": sorted(CACHE_PARTS),
        "excluded_secret_names": sorted(SECRET_NAMES),
        "excluded_secret_suffixes": sorted(SECRET_SUFFIXES),
        "excluded_secret_patterns": [".env", ".env.*", "secrets", "secrets.*", "private-key*"],
        "excluded_archive_suffixes": sorted(ARCHIVE_SUFFIXES),
        "excluded_artifact_prefixes": sorted(ARTIFACT_PREFIXES),
        "excluded_target_parts": ["target"],
        "excluded_ignored_tracked_inputs": "metadata-only",
        "excluded_link_coverage": 'Secret, archive and artifact exclusions have metadata-only coverage without link text or referent reads. Other excluded nonsecret links retain text only; referents are never traversed or hashed.',
        "source_link_coverage": "Relative internal links only, with exact text and independently hashed Git-visible target files.",
    }


def source_exclusion(relative: Path, ignored: bool = False) -> str | None:
    parts = [part.lower() for part in relative.parts]
    possible_suffixes = tuple(SECRET_SUFFIXES)
    if any(part in SECRET_NAMES or part == ".env" or part.startswith(".env.")
           or part == "secrets" or part.startswith("secrets.") or part.startswith("private-key")
           or part.endswith(possible_suffixes) and Path(part).suffix in SECRET_SUFFIXES for part in parts):
        return "secret-path-policy"
    name = relative.as_posix()
    if any(name == prefix or name.startswith(prefix + "/") for prefix in ARTIFACT_PREFIXES):
        return "artifact-tree-policy"
    if relative.name.lower().endswith(ARCHIVE_SUFFIXES):
        return "archive-file-policy"
    if ignored:
        return "ignored-but-tracked"
    if "target" in parts:
        return "target-tree-policy"
    if any(part in CACHE_PARTS for part in parts):
        return "cache-tree-policy"
    return None


def excluded_source_input(root: Path, relative: Path, reason: str) -> dict:
    """Inspect excluded metadata without opening content or following links."""
    entry = {"path": str(relative), "content_coverage": "metadata-only", "exclusion_reason": reason}
    parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in relative.parts[:-1]:
            try:
                directory = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            except OSError as error:
                if error.errno in (errno.ENOENT, errno.ENOTDIR, errno.ELOOP):
                    return {**entry, "state": "unreachable", "reason": "missing-or-nondirectory-parent"}
                raise
            os.close(parent)
            parent = directory
        try:
            before = os.stat(relative.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return {**entry, "state": "missing"}
        kind = ("file" if stat.S_ISREG(before.st_mode) else "symlink" if stat.S_ISLNK(before.st_mode)
                else "directory" if stat.S_ISDIR(before.st_mode) else "special")
        entry.update(state=kind, mode=stat.S_IMODE(before.st_mode))
        if kind == "symlink" and reason not in {"secret-path-policy", "archive-file-policy", "artifact-tree-policy"}:
            entry["link_text"] = os.readlink(relative.name, dir_fd=parent)
            after = os.stat(relative.name, dir_fd=parent, follow_symlinks=False)
            if (before.st_ino, before.st_mtime_ns, before.st_ctime_ns) != (after.st_ino, after.st_mtime_ns, after.st_ctime_ns):
                raise AcceptanceError("excluded source link changed during inspection: " + str(relative))
        return entry
    finally:
        os.close(parent)


def resolve_source_input(root: Path, relative: Path, observations: dict | None = None, ignored_paths: set | None = None) -> Path:
    """Resolve relative source links without traversing an external hop."""
    pending = deque(relative.parts)
    current = root
    links = 0
    verify_local = observations is None
    if observations is None:
        observations = {}
    while pending:
        component = pending.popleft()
        if component == "..":
            if current == root:
                raise AcceptanceError("source link escapes the candidate: " + str(relative))
            current = current.parent
            continue
        candidate = current / component
        candidate_relative = candidate.relative_to(root)
        reason = source_exclusion(candidate_relative, ignored_paths is not None and str(candidate_relative) in ignored_paths)
        if reason == "archive-file-policy":
            # An archive-shaped directory name does not hide ordinary source below it.
            with input_parent(candidate, root) as (parent, leaf):
                metadata = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
            if not stat.S_ISDIR(metadata.st_mode):
                raise AcceptanceError("source alias enters an excluded archive: " + str(relative))
        elif reason is not None:
            raise AcceptanceError("source alias enters an excluded input: " + str(relative))
        if candidate in observations or candidate.is_symlink():
            links += 1
            if links > 40:
                raise AcceptanceError("source link cycle or excessive indirection: " + str(relative))
            if candidate not in observations:
                observed = {}
                source_link_text(candidate, root, observed)
                observations[candidate] = observed
            target = Path(observations[candidate]["text"])
            if target.is_absolute():
                raise AcceptanceError("absolute source link: " + str(relative))
            pending.extendleft(reversed(target.parts))
        else:
            current = candidate
    if verify_local:
        verify_source_links(root, observations)
    return current


def source_inventory(root: Path, regular_measurements: dict | None = None) -> list[dict]:
    root = root.resolve(strict=True)
    paths = subprocess.check_output(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=root
    ).decode("utf-8").split("\0")
    names = sorted(set(paths) - {""})
    ignored = subprocess.run(["git", "check-ignore", "--no-index", "--stdin", "-z"], cwd=root,
        input=("\0".join(names) + "\0").encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if ignored.returncode not in (0, 1):
        raise AcceptanceError("cannot classify ignored tracked source inputs")
    ignored_names = set(ignored.stdout.decode("utf-8").split("\0")) - {""}
    inventory = []
    links = []
    independent_files = set()
    observations = {}
    for name in names:
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise AcceptanceError("invalid source inventory path")
        reason = source_exclusion(relative, name in ignored_names)
        if reason is not None:
            inventory.append(excluded_source_input(root, relative, reason))
            continue
        path = root / relative
        resolved = resolve_source_input(root, relative, observations, ignored_paths=ignored_names)
        if path in observations:
            text = observations[path]["text"]
            if not resolved.is_file() and not resolved.is_dir():
                raise AcceptanceError("source link target is missing or unsupported: " + name)
            inventory.append({"path": name, "link_text": text, "target": str(resolved.relative_to(root))})
            links.append((name, resolved))
        elif resolved.is_file():
            if regular_measurements is None:
                checksum = digest(resolved, root=root)
            else:
                with regular_file(resolved, root) as (descriptor, metadata):
                    checksum = digest(resolved, root=root, descriptor=descriptor)
                    detail = {"mode": stat.S_IMODE(metadata.st_mode), "size": metadata.st_size}
                regular_measurements[name] = detail
            inventory.append({"path": name, "sha256": checksum})
            if resolved == path:
                independent_files.add(resolved)
        elif not resolved.exists():
            inventory.append({"path": name, "deleted": True})
        else:
            raise AcceptanceError("non-file source input: " + name)
    for name, target in links:
        if target.is_file():
            covered = target in independent_files
        else:
            covered = any(path.is_relative_to(target) for path in independent_files)
        if not covered:
            raise AcceptanceError("source link target has no independent Git-visible file inventory: " + name)
    if not inventory:
        raise AcceptanceError("source inventory is empty")
    verify_source_links(root, observations)
    return inventory


def binding(inventory: list[dict]) -> str:
    encoded = json.dumps({"policy": source_inventory_policy(), "inputs": inventory}, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def clean_lines(text: str) -> list[str]:
    return [ANSI_ESCAPE.sub("", line).strip() for line in text.splitlines()]


def verify_list(text: str) -> None:
    observed = []
    for line in clean_lines(text):
        if match := re.fullmatch(r"([A-Za-z0-9_:]+): test", line):
            observed.append(match[1])
        elif line.endswith(": test") or line.endswith(": benchmark"):
            raise AcceptanceError("malformed or benchmark entry in selected inventory")
    if Counter(observed) != Counter(CASES):
        raise AcceptanceError("current confined-return test inventory differs")


def verify_execution(text: str) -> dict:
    passed = []
    running = []
    summaries = []
    pending = None
    for line in clean_lines(text):
        if match := re.fullmatch(r"running ([0-9]+) tests?", line):
            running.append(int(match[1]))
        elif match := re.fullmatch(r"test ([A-Za-z0-9_:]+) \.\.\. ok", line):
            if pending is not None:
                raise AcceptanceError("selected test started before its predecessor completed")
            passed.append(match[1])
        elif match := re.fullmatch(r"test ([A-Za-z0-9_:]+) \.\.\.", line):
            if pending is not None:
                raise AcceptanceError("selected test did not complete")
            pending = match[1]
        elif line == "ok" and pending is not None:
            passed.append(pending)
            pending = None
        elif line.startswith("test ") and " ..." in line:
            raise AcceptanceError("selected test did not succeed: " + line)
        elif line.startswith("test result:"):
            match = re.fullmatch(
                r"test result: ok\. " + str(len(CASES)) + r" passed; 0 failed; 0 ignored; 0 measured; "
                r"([0-9]+) filtered out; finished in [0-9]+(?:\.[0-9]+)?s", line
            )
            if match is None:
                raise AcceptanceError("selected run summary is not exact")
            summaries.append(int(match[1]))
    if pending is not None or Counter(passed) != Counter(CASES):
        raise AcceptanceError("selected execution identities are missing, unexpected, or duplicated")
    if running != [len(CASES)] or len(summaries) != 1:
        raise AcceptanceError("selected run denominator or summary is absent, duplicated, or wrong")
    return {"passed": len(passed), "failed": 0, "ignored": 0, "measured": 0, "filtered_out": summaries[0]}


def verify_cage_challenge(text: str, challenge: str) -> None:
    observed = [line for line in clean_lines(text) if line.startswith("CHIO_CAGE_REAL_LINUX_EVIDENCE")]
    expected = "CHIO_CAGE_REAL_LINUX_EVIDENCE challenge=" + challenge + " all_targets=72 probes=27 mutations=10"
    if observed != [expected]:
        raise AcceptanceError("strict cage output lacks the current challenge and complete inventories")


def verify_mode_record(data: bytes, requested: str) -> None:
    modes = []
    offset = 0
    while (position := data.find(MODE_RECORD_PREFIX, offset)) >= 0:
        start = position + len(MODE_RECORD_PREFIX)
        field = data[start:start + MODE_FIELD_BYTES]
        mode, separator, padding = field.partition(b"\0")
        if len(field) == MODE_FIELD_BYTES and separator and not padding.strip(b"\0"):
            if re.fullmatch(rb"[a-z-]+", mode):
                modes.append(mode.decode("ascii"))
        offset = start
    if requested not in MODES or not modes or set(modes) != {requested}:
        raise AcceptanceError("measured canary mode does not match its explicit build: " + requested)


def measured_file(path: Path, root: Path, mode: str | None = None, static_pie: bool = False) -> dict:
    with regular_file(path, root) as (descriptor, metadata):
        permissions = metadata.st_mode
        if permissions & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID) or not permissions & stat.S_IXUSR:
            raise AcceptanceError("measured executable permissions are unsafe")
        if mode is not None:
            verify_mode_record(descriptor_bytes(descriptor), mode)
        if static_pie:
            verify_static_pie(descriptor)
        result = {"path": str(path.relative_to(root)), "sha256": digest(path, root=root, descriptor=descriptor), "permissions": oct(stat.S_IMODE(permissions))}
    if mode is not None:
        result["mode"] = mode
    return result


def verify_static_pie(descriptor: int) -> None:
    path = "/proc/self/fd/" + str(descriptor)
    header = subprocess.check_output(["readelf", "-hW", path], text=True, pass_fds=(descriptor,))
    program = subprocess.check_output(["readelf", "-lW", path], text=True, pass_fds=(descriptor,))
    dynamic = subprocess.check_output(["readelf", "-dW", path], text=True, pass_fds=(descriptor,))
    if (
        not re.search(r"Class:\s+ELF64\b", header)
        or not re.search(r"Type:\s+DYN\b", header)
        or not re.search(r"Machine:\s+Advanced Micro Devices X86-64\b", header)
        or re.search(r"\bINTERP\b", program)
        or re.search(r"\((?:NEEDED|RPATH|RUNPATH)\)", dynamic)
    ):
        raise AcceptanceError("measured image is not interpreter-free x86_64 static PIE")


def native_test_image(text: str, root: Path, target: Path) -> Path:
    headers = []
    for line in clean_lines(text):
        if line.startswith("Running "):
            match = re.fullmatch(r"Running unittests src/lib\.rs \((.+)\)", line)
            if match is None:
                raise AcceptanceError("unexpected native test invocation")
            path = Path(match[1])
            if not path.is_absolute():
                path = root / path
            if path.is_symlink():
                raise AcceptanceError("symbolic native test executable")
            path = path.resolve(strict=True)
            if path.parent != (target / "debug/deps").resolve() or not path.name.startswith("chio_control_plane-"):
                raise AcceptanceError("native test invocation does not use the campaign's library executable")
            headers.append(path)
    if len(headers) != 1:
        raise AcceptanceError("native test invocation is missing or duplicated")
    return headers[0]


class Campaign:
    def __init__(self, root: Path, output: Path, timeout: int):
        self.root = root
        self.output = output
        self.timeout = timeout
        self.commands = []

    def run(self, name: str, command: list[str], environment: dict) -> str:
        path = self.output / (name + ".log")
        entry = {"command": command, "cwd": ".", "log": path.name, "started_unix_seconds": time.time()}
        self.commands.append(entry)
        try:
            with path.open("xb") as stream:
                subprocess.run(command, cwd=self.root, env=environment, stdout=stream,
                    stderr=subprocess.STDOUT, check=True, timeout=self.timeout)
            entry["exit_code"] = 0
        except subprocess.CalledProcessError as error:
            entry["exit_code"] = error.returncode
            raise
        finally:
            entry["duration_seconds"] = round(time.time() - entry["started_unix_seconds"], 3)
            if path.is_file():
                entry["log_sha256"] = digest(path)
        return path.read_text(encoding="utf-8")


def positive_integer(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, required=True, help="fresh directory under the candidate's target directory")
    parser.add_argument("--command-timeout-seconds", type=positive_integer, default=3600)
    parser.add_argument("--prepared-cache", type=Path, help="successful source-bound compilation preparation receipt within this candidate")
    args = parser.parse_args(argv)
    root = args.root.resolve(strict=True)
    output = args.output.absolute()
    # Resolve parents without silently accepting a preexisting/symbolic result.
    if output.exists() or output.is_symlink():
        parser.error("output already exists; retained campaigns must not be overwritten")
    output = output.parent.resolve() / output.name
    if not output.is_relative_to(root / "target") or output == root / "target":
        parser.error("output must be a fresh directory below the candidate's target directory")
    os.umask(0o022)
    output.mkdir(parents=True, exist_ok=False)
    started = time.time()
    result = {
        "schema": "chio.confined-return-linux-acceptance.v1", "status": "failed", "exit_code": 1,
        "started_unix_seconds": started, "host": {"system": platform.system(), "machine": platform.machine()},
        "scope": "Current Boolean-only, model-disabled Linux x86_64 confined returns; no broader release qualification.",
        "source_inventory_policy": source_inventory_policy(),
        "expected_tests": list(CASES), "command_timeout_seconds": args.command_timeout_seconds,
    }
    campaign = Campaign(root, output, args.command_timeout_seconds)
    inventory = None
    images = []
    native_binding = None
    custody = ExitStack()
    try:
        inventory = source_inventory(root)
        result["source_binding"] = binding(inventory)
        (output / "source-inputs.json").write_text(json.dumps(inventory, indent=2) + "\n")
        if (platform.system(), platform.machine()) != ("Linux", "x86_64"):
            result.update(status="blocked", exit_code=64, reason="Real Linux x86_64 is required")
        else:
            for tool in ("python3", "bash", "awk", "cargo", "rustc", "cc", "ldd", "readelf", "readlink", "sha256sum", "seq", "grep"):
                if shutil.which(tool) is None:
                    raise AcceptanceError("required Linux tool absent: " + tool)
            versions = {name: subprocess.check_output(command, cwd=root, text=True).strip() for name, command in {
                "rustc": ["rustc", "--version", "--verbose"], "cargo": ["cargo", "--version"],
                "cc": ["cc", "--version"], "readelf": ["readelf", "--version"],
            }.items()}
            pinned_rust = tomllib.loads((root / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
            if "release: " + pinned_rust not in versions["rustc"].splitlines() or "host: x86_64-unknown-linux-gnu" not in versions["rustc"].splitlines():
                raise AcceptanceError("actual Rust toolchain does not match the pinned native GNU profile")
            result.update(kernel=platform.release(), toolchain=versions)
            challenge = secrets.token_hex(32)
            temporary = output / "tmp"
            temporary.mkdir()
            environment = {**os.environ, "CARGO_INCREMENTAL": "0", "CARGO_BUILD_JOBS": "2",
                "CARGO_NET_OFFLINE": "true", "CARGO_TERM_COLOR": "never", "TMPDIR": str(temporary.resolve()),
                "CHIO_CAGE_EVIDENCE_CHALLENGE": challenge, "CARGO_TARGET_DIR": str(output / "cage-lab"),
                "CHIO_CONFINED_CANARY_MODE": "error"}
            for name in ("CARGO_BUILD_TARGET", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
                         "RUSTC", "CARGO_BUILD_RUSTC", "CARGO_BUILD_RUSTC_WRAPPER", "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER"):
                if environment.get(name):
                    raise AcceptanceError("unreviewed build override: " + name)
            result["cage_challenge"] = challenge
            result["build_profile"] = {name: environment.get(name, "default") for name in ("CARGO_PROFILE_DEV_DEBUG", "CARGO_PROFILE_TEST_DEBUG")}
            targets = {name: output / name for name in ("cage-lab", "static", "host")}
            if args.prepared_cache is not None:
                for name in ("CHIO_ENTERPRISE_SECURITY_RUNNER", "CHIO_SECURITY_WORKSPACE", "CHIO_SECURITY_CAGE_INVENTORY_CHECKER",
                             "CHIO_SECURITY_CANDIDATE_ARTIFACTS", "CHIO_SECURITY_VERIFIER_ARTIFACTS"):
                    if environment.get(name):
                        raise AcceptanceError("prepared cache does not support enterprise cage selector: " + name)
                targets, witness = custody.enter_context(prepared_cache(args.prepared_cache, root, inventory, versions, result["build_profile"]))
                result["compilation_preparation"] = witness
                environment["CARGO_TARGET_DIR"] = str(targets["cage-lab"])
            cage = campaign.run("cage-enforcement", ["bash", "crates/security/chio-cage/scripts/check-linux-enforcement.sh"], environment)
            verify_cage_challenge(cage, challenge)
            static = targets["static"]
            environment["CARGO_TARGET_DIR"] = str(static)
            build = ["cargo", "build", "--offline", "--locked", "--target", "x86_64-unknown-linux-musl", "-p", "chio-cage"]
            campaign.run("static-tools", [*build, "--bin", "chio-cage-init", "--bin", "chio-confined-reader"], environment)
            binaries = static / "x86_64-unknown-linux-musl/debug"
            canaries = output / "images"
            canaries.mkdir()
            for mode in MODES:
                campaign.run("canary-" + mode, [*build, "--example", "confined-return-canary"], {**environment, "CHIO_CONFINED_CANARY_MODE": mode})
                image = canaries / mode
                shutil.copyfile(binaries / "examples/confined-return-canary", image)
                image.chmod(0o755)
                images.append(measured_file(image, root, mode, static_pie=True))
            for image in (binaries / "chio-cage-init", binaries / "chio-confined-reader"):
                images.append(measured_file(image, root, static_pie=True))
            environment.update(CHIO_CAGE_TEST_HELPER=str(binaries / "chio-cage-init"),
                CHIO_CONFINED_READER=str(binaries / "chio-confined-reader"), CHIO_CONFINED_CANARY_DIR=str(canaries),
                CARGO_TARGET_DIR=str(targets["host"]))
            tests = ["cargo", "test", "--offline", "--locked", "-p", "chio-control-plane", "--lib", CASE_PREFIX, "--"]
            listed = campaign.run("recovery-list", [*tests, "--list"], environment)
            verify_list(listed)
            native_image = native_test_image(listed, root, targets["host"])
            native_binding = measured_file(native_image, root)
            result["native_test_executable"] = native_binding
            executed = campaign.run("recovery-run", [*tests, "--test-threads=1"], environment)
            if native_test_image(executed, root, targets["host"]) != native_image or measured_file(native_image, root) != native_binding:
                raise AcceptanceError("native test executable changed between listing and execution")
            counts = verify_execution(executed)
            result.update(status="passed", exit_code=0, linux_tests=counts["passed"], execution=counts)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError, AcceptanceError) as error:
        result.update(status="failed", exit_code=1, reason=str(error))
    finally:
        try:
            custody.close()
        except (OSError, ValueError, AcceptanceError) as error:
            result.update(status="failed", exit_code=1, reason=str(error))
        result["commands"] = campaign.commands
        result["measured_images"] = images
        if inventory is not None:
            try:
                after = source_inventory(root)
                result["source_binding_after"] = binding(after)
                if after != inventory:
                    raise AcceptanceError("source changed during Linux acceptance")
                for image in images:
                    current = measured_file(root / image["path"], root, image.get("mode"))
                    if current != image:
                        raise AcceptanceError("measured executable changed during Linux acceptance")
                if native_binding is not None and measured_file(root / native_binding["path"], root) != native_binding:
                    raise AcceptanceError("native library executable changed during Linux acceptance")
            except (OSError, ValueError, subprocess.SubprocessError, AcceptanceError) as error:
                result.update(status="failed", exit_code=1, reason=str(error))
        result["duration_seconds"] = round(time.time() - started, 3)
        (output / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print("Confined-return Linux acceptance:", result["status"], result.get("reason", ""))
    return result["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
