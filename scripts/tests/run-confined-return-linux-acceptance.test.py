#!/usr/bin/env python3
"""Exercise the actual acceptance runner with controlled external tool results.

These tests establish harness behavior, never native Linux enforcement. Cargo,
readelf, and the enforcement campaign are replaced at their subprocess boundary;
source files, build outputs, hashes, logs, and result records remain real files.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts/run-confined-return-linux-acceptance.py"
LEGACY = False
REAL_RUN = subprocess.run
REAL_CHECK_OUTPUT = subprocess.check_output
PREFIX = "recovery::tests::knowledge::confinement::linux::"
CASES = [
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
]
ADDED_CASES = {
    "linux_acknowledgement_retains_delivery_after_cancel_and_authority_change",
    "linux_cancellation_reports_an_already_ordered_parent_return",
    "linux_rejected_projection_leaves_no_candidate_blob_or_extra_charge",
    "linux_sink_attempt_is_durably_uncertain_before_first_byte",
    "linux_staged_return_survives_execution_deadline",
    "linux_staging_receipt_and_return_preparation_enforce_source_audience",
    "linux_terminal_dispositions_survive_cancellation",
    "linux_true_and_false_returns_preserve_identical_parent_storage_availability",
}


def load_runner():
    spec = importlib.util.spec_from_file_location("confined_acceptance_runner", RUNNER)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load acceptance runner")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    # The historical runner imports its adjacent inventory helper. Importing it
    # does not execute a campaign or write into its historical evidence directory.
    with patch.object(sys, "path", [str(RUNNER.parent), *sys.path]):
        spec.loader.exec_module(module)
    return module


class ExternalTools:
    def __init__(self, root: Path, scenario: str):
        self.root = root
        self.scenario = scenario
        self.observed_commands = []
        self.names = [PREFIX + ("p5_" if LEGACY else "") + name for name in CASES]
        if scenario == "stale_registered_inventory":
            self.names = [name for name in self.names if name.removeprefix(PREFIX) not in ADDED_CASES]
        self.listed = "\n".join(name + ": test" for name in self.names) + "\n"
        if scenario == "missing_list_case":
            self.listed = "\n".join(name + ": test" for name in self.names[:-1]) + "\n"
        executed_names = self.names
        if scenario == "stale_execution_inventory":
            executed_names = [name for name in self.names if name.removeprefix(PREFIX) not in ADDED_CASES]
        self.executed = "\n".join([
            "running " + str(len(executed_names)) + " tests",
            *("test " + name + " ... ok" for name in executed_names),
            "test result: ok. " + str(len(executed_names)) + " passed; 0 failed; 0 ignored; 0 measured; "
            "200 filtered out; finished in 0.01s",
        ]) + "\n"
        if scenario == "zero_execution":
            self.executed = (
                "running 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored; "
                "0 measured; 210 filtered out; finished in 0.01s\n"
            )
        elif scenario == "ignored_execution":
            self.executed = self.executed.replace(" ... ok", " ... ignored", 1).replace(
                str(len(executed_names)) + " passed; 0 failed; 0 ignored",
                str(len(executed_names) - 1) + " passed; 0 failed; 1 ignored"
            )
        elif scenario == "duplicate_execution":
            self.executed += "test " + self.names[0] + " ... ok\n"
        elif scenario == "missing_summary":
            self.executed = self.executed.split("test result:")[0]
        elif scenario == "unexpected_execution":
            self.executed = self.executed.replace(self.names[0], PREFIX + "unregistered_case")
        elif scenario == "duplicate_summary":
            self.executed += self.executed[self.executed.index("test result:"):]
        elif scenario == "wrong_running_count":
            self.executed = self.executed.replace("running " + str(len(executed_names)) + " tests", "running 0 tests")

    def output(self, command, **kwargs):
        command = [str(part) for part in command]
        environment = kwargs.get("env", os.environ)
        if command[0] == "git":
            return REAL_CHECK_OUTPUT(command, **kwargs)
        if command[:2] == ["rustc", "--version"]:
            value = (
                "rustc 1.94.1 (test-fixture)\nhost: x86_64-unknown-linux-gnu\n"
                "release: 1.94.1\n"
            )
            if self.scenario == "different_controller_toolchain" and kwargs.get("cwd") != self.root:
                value = value.replace("1.94.1", "1.95.0")
        elif "--version" in command:
            value = command[0] + " test-fixture\n"
        elif command[0] == "readelf":
            if self.scenario == "held_readelf_descriptor":
                descriptors = kwargs.get("pass_fds", ())
                assert len(descriptors) == 1, "readelf reopened a filesystem path instead of the measured descriptor"
                assert command[-1] == "/proc/self/fd/" + str(descriptors[0])
                assert stat.S_ISREG(os.fstat(descriptors[0]).st_mode)
            if "-hW" in command:
                value = "Class: ELF64\nType: DYN (Position-Independent Executable file)\nMachine: Advanced Micro Devices X86-64\n"
            elif "-lW" in command:
                value = "LOAD\n"
            else:
                value = "There is no dynamic section in this file.\n"
        elif command[:2] == ["cargo", "test"] and "--list" in command:
            value = self.listed
        else:
            raise AssertionError("unexpected external query: " + repr(command))
        return value if kwargs.get("text") or kwargs.get("encoding") else value.encode()

    def run(self, command, **kwargs):
        command = [str(part) for part in command]
        if command[0] == "git":
            return REAL_RUN(command, **kwargs)
        environment = kwargs.get("env", os.environ)
        self.observed_commands.append({"command": command, "target": environment.get("CARGO_TARGET_DIR"),
                                       "mode": environment.get("CHIO_CONFINED_CANARY_MODE"), "timeout": kwargs.get("timeout")})
        value = ""
        returncode = 0
        if command[0] == "bash":
            challenge = environment["CHIO_CAGE_EVIDENCE_CHALLENGE"]
            value = (
                "CHIO_CAGE_REAL_LINUX_EVIDENCE challenge=" + challenge
                + " all_targets=72 probes=27 mutations=10\n"
            )
            if self.scenario == "wrong_cage_challenge":
                value = value.replace(challenge, "0" * 64)
        elif command[:2] == ["cargo", "build"]:
            target = Path(environment["CARGO_TARGET_DIR"]) / "x86_64-unknown-linux-musl/debug"
            target.mkdir(parents=True, exist_ok=True)
            if "--example" in command:
                image = target / "examples/confined-return-canary"
                image.parent.mkdir(parents=True, exist_ok=True)
                mode = environment.get("CHIO_CONFINED_CANARY_MODE", "error")
                if self.scenario == "wrong_image_mode" or self.scenario == "mode_record_link_swap" and mode == "log":
                    mode = "error"
                image.write_bytes(
                    b"fixture executable\0CHIO-CONFINED-CANARY-MODE-V1:"
                    + mode.encode().ljust(32, b"\0") + b"\0end"
                )
                image.chmod(0o755)
            else:
                for name in ["chio-cage-init", "chio-confined-reader"]:
                    image = target / name
                    image.write_bytes(b"fixture executable " + name.encode())
                    image.chmod(0o755)
        elif command[:2] == ["cargo", "test"]:
            native = Path(environment["CARGO_TARGET_DIR"]) / "debug/deps/chio_control_plane-fixture"
            native.parent.mkdir(parents=True, exist_ok=True)
            native.write_bytes(b"native library harness fixture")
            native.chmod(0o755)
            if "--list" in command:
                value = self.listed
            else:
                value = self.executed
                if self.scenario == "command_failure":
                    returncode = 101
                if self.scenario == "source_drift":
                    (self.root / "src/input.rs").write_text("changed during execution\n")
                if self.scenario == "internal_link_target_drift":
                    (self.root / "src/input.rs").write_text("changed linked candidate source\n")
                if self.scenario == "internal_link_retarget":
                    alias = self.root / "aliases/input.rs"
                    alias.unlink()
                    alias.symlink_to("../src/equivalent.rs")
                if self.scenario == "external_cache_contents_drift":
                    (self.root.parent / "dependencies/package.js").write_text("changed excluded dependency bytes\n")
                if self.scenario == "external_cache_link_retarget":
                    cache = self.root / "sdk/node_modules"
                    cache.unlink()
                    cache.symlink_to(self.root.parent / "other-dependencies", target_is_directory=True)
                if self.scenario == "image_drift":
                    legacy_canary_directory = "CHIO_" + "P" + str(5) + "_CANARY_DIR"
                    canaries = environment.get("CHIO_CONFINED_CANARY_DIR") or environment.get(legacy_canary_directory)
                    with (Path(canaries) / "hang").open("ab") as stream:
                        stream.write(b"changed during execution")
                if self.scenario == "native_image_drift":
                    native.write_bytes(b"different native library harness")
            if self.scenario != "missing_native_invocation":
                value = "Running unittests src/lib.rs (" + str(native) + ")\n" + value
        elif command[0] == "readelf" or "--version" in command:
            value = self.output(command, **{**kwargs, "text": True})
        else:
            raise AssertionError("unexpected external command: " + repr(command))
        data = value if kwargs.get("text") or kwargs.get("encoding") else value.encode()
        destination = kwargs.get("stdout")
        if hasattr(destination, "write"):
            destination.write(data)
            destination.flush()
        completed = subprocess.CompletedProcess(command, returncode, stdout=data, stderr="" if isinstance(data, str) else b"")
        if returncode and kwargs.get("check"):
            raise subprocess.CalledProcessError(returncode, command, output=data)
        return completed


class AcceptanceRunnerTests(unittest.TestCase):
    def invoke(self, scenario: str = "valid"):
        module = load_runner()
        with tempfile.TemporaryDirectory(prefix="confined-acceptance-runner-") as directory:
            root = Path(directory).resolve() / "candidate"
            root.mkdir()
            (root / "src").mkdir()
            (root / "src/input.rs").write_text("unchanged candidate source\n")
            (root / ".gitignore").write_text("target/\n")
            (root / "Cargo.toml").write_text("[workspace]\nmembers=[]\n")
            (root / "Cargo.lock").write_text("version = 4\n")
            (root / "rust-toolchain.toml").write_text('[toolchain]\nchannel="1.94.1"\n')
            cache_link_text = None
            if scenario in {"external_cache_link", "external_cache_contents_drift", "external_cache_link_retarget"}:
                (root / "sdk").mkdir()
                dependencies = root.parent / "dependencies"
                dependencies.mkdir()
                (dependencies / "package.js").write_text("external dependency bytes must never be hashed\n")
                cache = root / "sdk/node_modules"
                cache.symlink_to(dependencies, target_is_directory=True)
                cache_link_text = os.readlink(cache)
            if scenario == "private_environment":
                (root / ".env").write_text("synthetic secret fixture must never be hashed\n")
            if scenario == "source_alias_to_cache":
                (root / "aliases").mkdir()
                (root / ".cache").mkdir()
                (root / ".cache/hidden.rs").write_text("excluded cache bytes must never be hashed\n")
                (root / "aliases/input.rs").symlink_to("../.cache/hidden.rs")
            if scenario in {
                "internal_file_link", "internal_directory_link", "external_relative_link",
                "external_link_chain", "absolute_internal_link", "internal_link_retarget",
                "internal_link_target_drift", "unlisted_link_target",
                "source_link_text_swap",
                "source_link_multi_cycle_swap",
            }:
                (root / "aliases").mkdir()
                alias = root / "aliases/input.rs"
                if scenario == "internal_directory_link":
                    (root / "aliases/source").symlink_to("../src", target_is_directory=True)
                elif scenario == "external_relative_link":
                    (root.parent / "outside.rs").write_text("external bytes must never be hashed\n")
                    alias.symlink_to("../../outside.rs")
                elif scenario == "external_link_chain":
                    (root.parent / "outside.rs").write_text("external bytes must never be hashed\n")
                    alias.symlink_to("../src/escape.rs")
                    (root / "src/escape.rs").symlink_to("../../outside.rs")
                elif scenario == "absolute_internal_link":
                    alias.symlink_to(root / "src/input.rs")
                elif scenario == "unlisted_link_target":
                    (root / ".gitignore").write_text("target/\nsrc/unlisted.rs\n")
                    (root / "src/unlisted.rs").write_text("ignored bytes must not enter the source binding\n")
                    alias.symlink_to("../src/unlisted.rs")
                else:
                    alias.symlink_to("../src/input.rs")
                    if scenario == "internal_link_retarget":
                        (root / "src/equivalent.rs").write_text("unchanged candidate source\n")
            REAL_RUN(["git", "init", "--quiet", str(root)], check=True, capture_output=True)
            REAL_RUN(["git", "-C", str(root), "add", "."], check=True, capture_output=True)
            credential_path = root / "config/credentials.toml"
            if scenario in {"private_credentials", "private_credentials_link"}:
                credential_path.parent.mkdir()
                (credential_path.parent / "credentials.toml.example").write_text("public template fixture\n")
                if scenario == "private_credentials_link":
                    outside = root.parent / "synthetic-credential-referent.toml"
                    outside.write_text("synthetic excluded referent fixture\n")
                    credential_path.symlink_to(outside)
                else:
                    credential_path.write_text("synthetic excluded credentials fixture\n")
            output = root / "target/campaign"
            prepared = scenario.startswith("prepared_")
            prepared_targets = {lane: root / "target/compiled" / lane for lane in ("cage-lab", "static", "host")}
            receipt = root / "target/preparation/result.json"
            if prepared:
                for path in prepared_targets.values():
                    path.mkdir(parents=True)
                (prepared_targets["cage-lab"] / "static-pie").mkdir()
                receipt.parent.mkdir(parents=True)
                inputs = module.source_inventory(root)
                versions = {
                    "rustc": "rustc 1.94.1 (test-fixture)\nhost: x86_64-unknown-linux-gnu\nrelease: 1.94.1",
                    "cargo": "cargo test-fixture", "cc": "cc test-fixture", "readelf": "readelf test-fixture",
                }
                metadata = root.stat()
                location = {"schema": "chio.source-location.v1", "repository": str(root),
                    "host": {"system": "Linux", "machine": "x86_64", "node": module.platform.node()},
                    "root": {"device": metadata.st_dev, "inode": metadata.st_ino,
                             "uid": metadata.st_uid, "mode": stat.S_IMODE(metadata.st_mode)}}
                build = ["cargo", "build", "--offline", "--locked", "--target", "x86_64-unknown-linux-musl", "-p", "chio-cage"]
                compile_commands = [
                    {"name": "strict-static-normal", "cache_lane": "cage-lab/static-pie", "command": [*build, "--bin", "chio-cage-init", "--features", "real-linux-enforcement"]},
                    {"name": "strict-native-all-targets", "cache_lane": "cage-lab", "command": ["cargo", "test", "--offline", "--locked", "-p", "chio-cage", "--all-targets", "--features", "real-linux-enforcement", "--no-run"]},
                    {"name": "strict-static-mutants", "cache_lane": "cage-lab/static-pie", "command": [*build, "--bin", "chio-cage-init", "--features", "real-linux-enforcement,enforcement-mutants"]},
                    {"name": "strict-native-mutants", "cache_lane": "cage-lab", "command": ["cargo", "test", "--offline", "--locked", "-p", "chio-cage", "--test", "linux_enforcement", "--features", "real-linux-enforcement,enforcement-mutants", "--no-run"]},
                    {"name": "static-tools", "cache_lane": "static", "command": [*build, "--bin", "chio-cage-init", "--bin", "chio-confined-reader"]},
                    *({"name": "canary-" + mode, "cache_lane": "static", "mode": mode,
                       "command": [*build, "--example", "confined-return-canary"]} for mode in ("error", "log", "progress", "stream", "file", "callback", "wrong-predicate", "overflow", "hang")),
                    {"name": "control-plane-library", "cache_lane": "host", "command": ["cargo", "test", "--offline", "--locked", "-p", "chio-control-plane", "--lib", PREFIX, "--no-run"]},
                    {"name": "store-library", "cache_lane": "host", "command": ["cargo", "test", "--offline", "--locked", "-p", "chio-store-sqlite", "--lib", "--no-run"]},
                ]
                preparation = {"schema": "chio.confined-return-linux-compilation-preparation.v1", "status": "prepared", "exit_code": 0,
                    "source_location": location, "source_binding": module.binding(inputs), "source_binding_after": module.binding(inputs),
                    "source_inventory_policy": module.source_inventory_policy(), "toolchain": versions,
                    "build_profile": {"CARGO_PROFILE_DEV_DEBUG": "default", "CARGO_PROFILE_TEST_DEBUG": "default"},
                    "build_environment": {"CARGO_INCREMENTAL": "0", "CARGO_BUILD_JOBS": "2", "CARGO_NET_OFFLINE": "true"},
                    "cache_targets": {lane: str(path.relative_to(root)) for lane, path in prepared_targets.items()},
                    "per_command_timeout_seconds": 3600, "total_preparation_budget_seconds": 21600, "duration_seconds": 0.016,
                    "commands": [{**entry, "exit_code": 0, "duration_seconds": 0.001} for entry in compile_commands]}
                if scenario == "prepared_wrong_source":
                    preparation["source_binding"] = preparation["source_binding_after"] = "0" * 64
                elif scenario == "prepared_wrong_profile":
                    preparation["build_profile"]["CARGO_PROFILE_TEST_DEBUG"] = "0"
                elif scenario == "prepared_failed":
                    preparation.update(status="failed", exit_code=1)
                elif scenario == "prepared_external":
                    external_cache = root.parent / "outside-cache"
                    external_cache.mkdir()
                    preparation["cache_targets"]["host"] = str(external_cache)
                elif scenario == "prepared_symlink":
                    prepared_targets["host"].rmdir()
                    external_cache = root.parent / "outside-cache"
                    external_cache.mkdir()
                    prepared_targets["host"].symlink_to(external_cache, target_is_directory=True)
                elif scenario == "prepared_excess_total":
                    for entry in preparation["commands"]:
                        entry["duration_seconds"] = 2000
                elif scenario == "prepared_static_symlink":
                    strict_static = prepared_targets["cage-lab"] / "static-pie"
                    strict_static.rmdir()
                    external_cache = root.parent / "outside-static-cache"
                    external_cache.mkdir()
                    strict_static.symlink_to(external_cache, target_is_directory=True)
                if scenario != "prepared_missing":
                    receipt.write_text(json.dumps(preparation))
            external = ExternalTools(root, scenario)
            original_digest = getattr(module, "digest", None)
            original_mode_record = getattr(module, "verify_mode_record", None)
            original_readlink = module.os.readlink
            original_source_link_text = getattr(module, "source_link_text", None)
            original_descriptor_bytes = getattr(module, "descriptor_bytes", None)
            original_open = module.os.open
            exercised_races = []
            credential_reads = {"open": [], "hash": [], "readlink": []}
            held_cache_descriptors = []
            link_read_count = 0

            def is_credential_path(path, options):
                return Path(path) == credential_path or (
                    str(path) == credential_path.name and options.get("dir_fd") is not None
                    and credential_path.parent.exists()
                    and os.fstat(options["dir_fd"]).st_ino == credential_path.parent.stat().st_ino)

            def observed_credential_open(path, flags, *arguments, **options):
                if is_credential_path(path, options):
                    credential_reads["open"].append(str(path))
                return original_open(path, flags, *arguments, **options)

            def observed_credential_readlink(path, **options):
                if is_credential_path(path, options):
                    credential_reads["readlink"].append(str(path))
                return original_readlink(path, **options)

            def swapped_leaf(path, operation):
                before = path.read_bytes()
                permissions = path.stat().st_mode & 0o777
                outside = root.parent / "outside.rs"
                outside.write_bytes(b"synthetic external fixture\0CHIO-CONFINED-CANARY-MODE-V1:log" + b"\0" * 29)
                path.unlink()
                path.symlink_to(os.path.relpath(outside, path.parent))
                exercised_races.append(str(path.relative_to(root)))
                try:
                    return operation()
                finally:
                    path.unlink()
                    path.write_bytes(before)
                    path.chmod(permissions)

            def candidate_digest(path, *arguments, **options):
                if Path(path) == credential_path:
                    credential_reads["hash"].append(str(path))
                self.assertTrue(Path(path).resolve().is_relative_to(root), "external source bytes were hashed")
                self.assertNotIn(Path(path), {root / ".env", root / ".cache/hidden.rs"}, "excluded private/cache bytes were hashed")
                operation = lambda: original_digest(path, *arguments, **options)
                if scenario == "source_leaf_link_swap" and Path(path) == root / "src/input.rs":
                    return swapped_leaf(Path(path), operation)
                if scenario == "measured_digest_link_swap" and Path(path) == output / "images/log":
                    return swapped_leaf(Path(path), operation)
                if scenario == "source_parent_link_swap" and Path(path) == root / "src/input.rs":
                    source = root / "src"
                    preserved = root / "preserved-source"
                    outside = root.parent / "outside-source"
                    outside.mkdir(exist_ok=True)
                    (outside / "input.rs").write_text("synthetic external parent fixture\n")
                    source.rename(preserved)
                    source.symlink_to(outside, target_is_directory=True)
                    exercised_races.append("src parent")
                    try:
                        return operation()
                    finally:
                        source.unlink()
                        preserved.rename(source)
                return operation()

            def measured_mode_record(data, requested):
                if scenario == "mode_record_link_swap" and requested == "log":
                    return swapped_leaf(output / "images/log", lambda: original_mode_record(data, requested))
                return original_mode_record(data, requested)

            def stable_source_readlink(path, **options):
                nonlocal link_read_count
                victim = root / "aliases/input.rs"
                selected = Path(path) == victim or (str(path) == "input.rs" and options.get("dir_fd") is not None
                    and os.fstat(options["dir_fd"]).st_ino == victim.parent.stat().st_ino)
                if scenario != "source_link_text_swap" or not selected:
                    return original_readlink(path, **options)
                link_read_count += 1
                if link_read_count % 2:
                    return original_readlink(path, **options)
                previous = original_readlink(victim)
                victim.unlink()
                victim.symlink_to("../../outside.rs")
                exercised_races.append("source link text")
                try:
                    return original_readlink(path, **options)
                finally:
                    victim.unlink()
                    victim.symlink_to(previous)

            def alternating_source_link_text(path, *arguments, **options):
                nonlocal link_read_count
                victim = root / "aliases/input.rs"
                if Path(path) == victim:
                    link_read_count += 1
                    victim.unlink()
                    victim.symlink_to("../src/input.rs" if link_read_count % 2 else "../../outside.rs")
                    exercised_races.append("source link cycle " + str(link_read_count))
                return original_source_link_text(path, *arguments, **options)

            def replaced_receipt_bytes(descriptor):
                if receipt.exists() and os.fstat(descriptor).st_ino == receipt.stat().st_ino:
                    before = receipt.read_bytes()
                    receipt.unlink()
                    receipt.write_bytes(before)
                    exercised_races.append("prepared receipt replaced with equal bytes")
                return original_descriptor_bytes(descriptor)

            def observed_cache_open(path, flags, *arguments, **options):
                descriptor = original_open(path, flags, *arguments, **options)
                if options.get("dir_fd") is not None and (str(path) == "host" and os.fstat(options["dir_fd"]).st_ino == (root / "target/compiled").stat().st_ino
                        or str(path) == "static-pie" and os.fstat(options["dir_fd"]).st_ino == prepared_targets["cage-lab"].stat().st_ino):
                    held_cache_descriptors.append(descriptor)
                return descriptor

            def replaced_cache_run(command, **options):
                if command[0] == "bash":
                    nested = scenario == "prepared_static_replacement"
                    selected = prepared_targets["cage-lab"] / "static-pie" if nested else prepared_targets["host"]
                    held = [descriptor for descriptor in held_cache_descriptors if os.fstat(descriptor).st_ino == selected.stat().st_ino]
                    if not nested:
                        self.assertTrue(held, "cache directory was not held through command execution")
                    selected.rename(selected.with_name("retained-" + selected.name))
                    selected.mkdir()
                    exercised_races.append("held strict static cache directory replaced" if nested else "held host cache directory replaced")
                return external.run(command, **options)

            patches = [
                patch.object(module.platform, "system", return_value="Linux"),
                patch.object(module.platform, "machine", return_value="x86_64"),
                patch.object(module.platform, "release", return_value="test-kernel"),
                patch.object(module.shutil, "which", side_effect=lambda tool: "/fixture/bin/" + tool),
                patch.object(module.subprocess, "run", side_effect=external.run),
                patch.object(module.subprocess, "check_output", side_effect=external.output),
            ]
            if original_digest is not None:
                patches.append(patch.object(module, "digest", side_effect=candidate_digest))
            if original_mode_record is not None:
                patches.append(patch.object(module, "verify_mode_record", side_effect=measured_mode_record))
            if scenario == "source_link_text_swap":
                patches.append(patch.object(module.os, "readlink", side_effect=stable_source_readlink))
            if scenario == "source_link_multi_cycle_swap":
                patches.append(patch.object(module, "source_link_text", side_effect=alternating_source_link_text))
            if scenario in {"private_credentials", "private_credentials_link"}:
                patches.append(patch.object(module.os, "open", side_effect=observed_credential_open))
                patches.append(patch.object(module.os, "readlink", side_effect=observed_credential_readlink))
            if scenario == "prepared_replacement":
                patches.append(patch.object(module, "descriptor_bytes", side_effect=replaced_receipt_bytes))
            if scenario in {"prepared_directory_replacement", "prepared_static_replacement"}:
                patches.append(patch.object(module.os, "open", side_effect=observed_cache_open))
                patches.append(patch.object(module.subprocess, "run", side_effect=replaced_cache_run))
            if scenario.startswith("override_"):
                patches.append(patch.dict(module.os.environ, {scenario.removeprefix("override_"): "/synthetic/unreviewed-compiler-selector"}))
            if scenario.startswith("prepared_override_"):
                selector = scenario.removeprefix("prepared_override_")
                patches.append(patch.dict(module.os.environ, {selector: "1" if selector == "CHIO_ENTERPRISE_SECURITY_RUNNER" else "/synthetic/enterprise-cage-path"}))
            if scenario == "cold_enterprise_environment":
                patches.append(patch.dict(module.os.environ, {"CHIO_ENTERPRISE_SECURITY_RUNNER": "1"}))
            if LEGACY:
                output.mkdir(parents=True)
                copied_runner = root / "scripts" / RUNNER.name
                copied_runner.parent.mkdir()
                copied_runner.write_bytes(RUNNER.read_bytes())
                module.__file__ = str(copied_runner)
                module.ROOT = root
                module.EVIDENCE = output
                module.TARGET = output / "build"
                module.source_binding = lambda: hashlib.sha256((root / "src/input.rs").read_bytes()).hexdigest()
            for context in patches:
                context.start()
            try:
                arguments = ["--root", str(root), "--output", str(output)]
                if prepared:
                    arguments += ["--prepared-cache", str(receipt)]
                try:
                    status = module.main() if LEGACY else module.main(arguments)
                except SystemExit as error:
                    if not prepared:
                        raise
                    return error.code, {"status": "argument-refused", "reason": "prepared cache interface unavailable", "commands": [], "exercised_fixture_races": exercised_races}
            finally:
                for context in reversed(patches):
                    context.stop()
            result_path = output / ("linux-acceptance.result.json" if LEGACY else "result.json")
            self.assertTrue(result_path.is_file(), "runner did not retain a result record")
            result = json.loads(result_path.read_text())
            inputs = output / "source-inputs.json"
            if inputs.is_file():
                result["retained_source_inputs"] = json.loads(inputs.read_text())
            if cache_link_text is not None:
                result["fixture_cache_link_text"] = cache_link_text
            result["exercised_fixture_races"] = exercised_races
            if scenario in {"private_credentials", "private_credentials_link"}:
                result["fixture_credential_reads"] = credential_reads
            if prepared:
                result["fixture_prepared_targets"] = {lane: str(path) for lane, path in prepared_targets.items()}
                result["fixture_observed_commands"] = external.observed_commands
            return status, result

    def require_refused(self, scenario):
        status, result = self.invoke(scenario)
        self.assertNotEqual(status, 0, "runner accepted " + scenario)
        self.assertNotEqual(result["status"], "passed", "runner recorded a false success for " + scenario)

    def test_complete_success_requires_every_registered_identity(self):
        status, result = self.invoke()
        self.assertEqual(status, 0)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["linux_tests"], len(CASES))

    def test_stale_registered_inventory_is_refused(self):
        self.require_refused("stale_registered_inventory")

    def test_stale_execution_inventory_after_current_list_is_refused(self):
        self.require_refused("stale_execution_inventory")

    def test_registered_identity_contract_matches_current_linux_source(self):
        source = ROOT / "crates/platform/chio-control-plane/src/recovery/tests/knowledge/confinement/linux.rs"
        actual = re.findall(r"(?m)^fn (linux_[A-Za-z0-9_]+)\(", source.read_text())
        self.assertCountEqual(actual, CASES)
        self.assertEqual(len(actual), 18)

    def test_zero_execution_after_valid_inventory_is_refused(self):
        self.require_refused("zero_execution")

    def test_ignored_selected_case_is_refused(self):
        self.require_refused("ignored_execution")

    def test_duplicate_executed_case_is_refused(self):
        self.require_refused("duplicate_execution")

    def test_missing_run_summary_is_refused(self):
        self.require_refused("missing_summary")

    def test_unexpected_executed_identity_is_refused(self):
        self.require_refused("unexpected_execution")

    def test_duplicate_summary_is_refused(self):
        self.require_refused("duplicate_summary")

    def test_wrong_running_denominator_is_refused(self):
        self.require_refused("wrong_running_count")

    def test_missing_listed_case_is_refused(self):
        self.require_refused("missing_list_case")

    def test_nonzero_command_cannot_reuse_successful_result_text(self):
        self.require_refused("command_failure")

    def test_changed_candidate_source_is_refused(self):
        self.require_refused("source_drift")

    def test_changed_measured_image_is_refused(self):
        self.require_refused("image_drift")

    def test_requested_canary_mode_must_match_measured_image(self):
        self.require_refused("wrong_image_mode")

    def test_enforcement_output_must_bind_the_current_challenge(self):
        self.require_refused("wrong_cage_challenge")

    def test_results_without_a_native_test_invocation_are_refused(self):
        self.require_refused("missing_native_invocation")

    def test_changed_native_test_executable_is_refused(self):
        self.require_refused("native_image_drift")

    def test_toolchain_is_observed_in_the_candidate_workspace(self):
        status, result = self.invoke("different_controller_toolchain")
        self.assertEqual(status, 0, "controller working directory selected an unrelated Rust toolchain")
        self.assertEqual(result["status"], "passed")

    def test_internal_relative_file_link_binds_link_text_and_independent_target_bytes(self):
        status, result = self.invoke("internal_file_link")
        self.assertEqual(status, 0, result.get("reason"))
        inputs = {entry["path"]: entry for entry in result["retained_source_inputs"]}
        self.assertEqual(inputs["aliases/input.rs"]["link_text"], "../src/input.rs")
        self.assertEqual(inputs["src/input.rs"]["sha256"], hashlib.sha256(b"unchanged candidate source\n").hexdigest())

    def test_internal_relative_directory_link_binds_link_text_and_independent_descendants(self):
        status, result = self.invoke("internal_directory_link")
        self.assertEqual(status, 0, result.get("reason"))
        inputs = {entry["path"]: entry for entry in result["retained_source_inputs"]}
        self.assertEqual(inputs["aliases/source"]["link_text"], "../src")
        self.assertEqual(inputs["src/input.rs"]["sha256"], hashlib.sha256(b"unchanged candidate source\n").hexdigest())

    def test_relative_source_link_cannot_escape_the_candidate(self):
        self.require_refused("external_relative_link")

    def test_source_link_chain_cannot_escape_the_candidate(self):
        self.require_refused("external_link_chain")

    def test_absolute_source_link_is_refused_even_when_its_target_is_inside(self):
        self.require_refused("absolute_internal_link")

    def test_link_retargeting_to_equal_bytes_is_refused_after_execution(self):
        status, result = self.invoke("internal_link_retarget")
        self.assertNotEqual(status, 0)
        self.assertEqual(result.get("reason"), "source changed during Linux acceptance")
        self.assertEqual(result["commands"][-1]["log"], "recovery-run.log")

    def test_linked_target_byte_changes_are_refused_after_execution(self):
        status, result = self.invoke("internal_link_target_drift")
        self.assertNotEqual(status, 0)
        self.assertEqual(result.get("reason"), "source changed during Linux acceptance")
        self.assertEqual(result["commands"][-1]["log"], "recovery-run.log")

    def test_link_target_must_be_independently_inventoried(self):
        self.require_refused("unlisted_link_target")

    def test_external_node_modules_link_is_bound_as_explicit_excluded_metadata(self):
        status, result = self.invoke("external_cache_link")
        self.assertEqual(status, 0, result.get("reason"))
        inputs = {entry["path"]: entry for entry in result["retained_source_inputs"]}
        cache = inputs["sdk/node_modules"]
        self.assertEqual(cache["exclusion_reason"], "cache-tree-policy")
        self.assertEqual(cache["content_coverage"], "metadata-only")
        self.assertEqual(cache["link_text"], result["fixture_cache_link_text"])
        self.assertNotIn("sha256", cache)
        self.assertEqual(result["source_inventory_policy"]["profile"], "rust-confined-return-linux")

    def test_excluded_dependency_content_changes_do_not_claim_dependency_coverage(self):
        status, result = self.invoke("external_cache_contents_drift")
        self.assertEqual(status, 0, result.get("reason"))
        self.assertEqual(result["source_binding"], result["source_binding_after"])
        self.assertIn("not a resolved dependency graph", result["source_inventory_policy"]["coverage"])

    def test_excluded_cache_link_retargeting_is_refused_after_execution(self):
        status, result = self.invoke("external_cache_link_retarget")
        self.assertNotEqual(status, 0)
        self.assertEqual(result.get("reason"), "source changed during Linux acceptance")
        self.assertEqual(result["commands"][-1]["log"], "recovery-run.log")

    def test_private_environment_input_is_metadata_only_and_never_hashed(self):
        status, result = self.invoke("private_environment")
        self.assertEqual(status, 0, result.get("reason"))
        inputs = {entry["path"]: entry for entry in result["retained_source_inputs"]}
        self.assertEqual(inputs[".env"]["exclusion_reason"], "secret-path-policy")
        self.assertEqual(inputs[".env"]["content_coverage"], "metadata-only")
        self.assertNotIn("sha256", inputs[".env"])

    def test_credentials_file_is_metadata_only_without_body_open(self):
        status, result = self.invoke("private_credentials")
        self.assertEqual(status, 0, result.get("reason"))
        self.assertEqual(result["fixture_credential_reads"]["open"], [], "credentials body was opened")
        inputs = {entry["path"]: entry for entry in result["retained_source_inputs"]}
        credentials = inputs["config/credentials.toml"]
        self.assertEqual(credentials["content_coverage"], "metadata-only")
        self.assertEqual(credentials["exclusion_reason"], "secret-path-policy")
        self.assertIn("credentials.toml", result["source_inventory_policy"]["excluded_secret_names"])

    def test_credentials_file_never_enters_source_hashes(self):
        status, result = self.invoke("private_credentials")
        self.assertEqual(status, 0, result.get("reason"))
        self.assertEqual(result["fixture_credential_reads"]["hash"], [], "credentials body was hashed")
        inputs = {entry["path"]: entry for entry in result["retained_source_inputs"]}
        self.assertNotIn("sha256", inputs["config/credentials.toml"])
        self.assertEqual(inputs["config/credentials.toml.example"]["sha256"],
            hashlib.sha256(b"public template fixture\n").hexdigest())

    def test_credentials_link_never_reads_text_or_referent(self):
        status, result = self.invoke("private_credentials_link")
        self.assertEqual(status, 0, result.get("reason"))
        self.assertEqual(result["fixture_credential_reads"], {"open": [], "hash": [], "readlink": []})
        inputs = {entry["path"]: entry for entry in result["retained_source_inputs"]}
        credentials = inputs["config/credentials.toml"]
        self.assertEqual(credentials["content_coverage"], "metadata-only")
        self.assertEqual(credentials["state"], "symlink")
        self.assertNotIn("link_text", credentials)
        self.assertNotIn("sha256", credentials)

    def test_ordinary_source_link_cannot_use_an_excluded_cache_as_its_bound_target(self):
        self.require_refused("source_alias_to_cache")

    def require_race_refused(self, scenario):
        status, result = self.invoke(scenario)
        self.assertTrue(result["exercised_fixture_races"], "the actual read boundary was not exercised")
        self.assertNotEqual(status, 0, "runner accepted the exercised replacement: " + scenario
            + " (" + str(len(result["exercised_fixture_races"])) + " mutations)")
        self.assertNotEqual(result["status"], "passed")

    def test_regular_source_leaf_replacement_cannot_bind_external_bytes(self):
        self.require_race_refused("source_leaf_link_swap")

    def test_regular_source_parent_replacement_cannot_bind_external_bytes(self):
        self.require_race_refused("source_parent_link_swap")

    def test_measured_executable_leaf_replacement_cannot_bind_external_bytes(self):
        self.require_race_refused("measured_digest_link_swap")

    def test_canary_mode_validation_cannot_read_a_replacement_link(self):
        self.require_race_refused("mode_record_link_swap")

    def test_source_link_text_must_stay_stable_through_resolution(self):
        self.require_race_refused("source_link_text_swap")

    def test_static_image_inspection_uses_the_held_descriptor(self):
        status, result = self.invoke("held_readelf_descriptor")
        self.assertEqual(status, 0, result.get("reason"))

    def test_source_link_resolution_and_record_share_one_identity_across_alternating_reads(self):
        self.require_race_refused("source_link_multi_cycle_swap")

    def require_compiler_selector_refused(self, selector):
        status, result = self.invoke("override_" + selector)
        self.assertNotEqual(status, 0, "runner accepted Cargo's direct compiler selector: " + selector)
        self.assertEqual(result.get("reason"), "unreviewed build override: " + selector)

    def test_rustc_environment_selector_is_refused(self):
        self.require_compiler_selector_refused("RUSTC")

    def test_cargo_build_rustc_selector_is_refused(self):
        self.require_compiler_selector_refused("CARGO_BUILD_RUSTC")

    def test_cargo_build_rustc_wrapper_selector_is_refused(self):
        self.require_compiler_selector_refused("CARGO_BUILD_RUSTC_WRAPPER")

    def test_cargo_build_rustc_workspace_wrapper_selector_is_refused(self):
        self.require_compiler_selector_refused("CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER")

    def test_prepared_cache_reuses_bound_targets_and_runs_every_build_and_test(self):
        status, result = self.invoke("prepared_valid")
        self.assertEqual(status, 0, result.get("reason"))
        self.assertEqual(result["linux_tests"], 18)
        self.assertEqual(len(result["commands"]), 13)
        self.assertEqual(result["command_timeout_seconds"], 3600)
        self.assertEqual(result["compilation_preparation"]["cache_targets"], {
            lane: "target/compiled/" + lane for lane in ("cage-lab", "static", "host")})
        self.assertEqual(result["native_test_executable"]["path"], "target/compiled/host/debug/deps/chio_control_plane-fixture")
        self.assertTrue(all(row["exit_code"] == 0 for row in result["commands"]))
        self.assertEqual(result["commands"][0]["command"], ["bash", "crates/security/chio-cage/scripts/check-linux-enforcement.sh"])
        self.assertEqual(result["commands"][-1]["command"], ["cargo", "test", "--offline", "--locked", "-p", "chio-control-plane", "--lib", PREFIX, "--", "--test-threads=1"])
        observed = result["fixture_observed_commands"]
        self.assertEqual([entry["target"] for entry in observed], [result["fixture_prepared_targets"]["cage-lab"],
            *([result["fixture_prepared_targets"]["static"]] * 10), *([result["fixture_prepared_targets"]["host"]] * 2)])
        self.assertEqual([entry["mode"] for entry in observed[2:11]], ["error", "log", "progress", "stream", "file", "callback", "wrong-predicate", "overflow", "hang"])
        self.assertTrue(all(entry["timeout"] == 3600 for entry in observed))

    def require_preparation_refused(self, scenario, reason):
        status, result = self.invoke(scenario)
        self.assertNotEqual(status, 0)
        self.assertIn(reason, result.get("reason", ""))
        self.assertEqual(result["commands"], [], "invalid preparation reached build or native commands")

    def test_prepared_cache_wrong_source_is_refused_before_commands(self):
        self.require_preparation_refused("prepared_wrong_source", "prepared cache source binding does not match")

    def test_prepared_cache_wrong_profile_is_refused_before_commands(self):
        self.require_preparation_refused("prepared_wrong_profile", "prepared cache profile does not match")

    def test_failed_compilation_preparation_is_refused_before_commands(self):
        self.require_preparation_refused("prepared_failed", "compilation preparation was not successful")

    def test_missing_prepared_cache_receipt_is_refused_before_commands(self):
        self.require_preparation_refused("prepared_missing", "No such file")

    def test_external_prepared_cache_is_refused_before_commands(self):
        self.require_preparation_refused("prepared_external", "prepared cache targets are outside the fixed candidate layout")

    def test_symbolic_prepared_cache_is_refused_before_commands(self):
        self.require_preparation_refused("prepared_symlink", "prepared cache directory is symbolic or unsafe")

    def test_equal_byte_preparation_receipt_replacement_is_refused(self):
        status, result = self.invoke("prepared_replacement")
        self.assertTrue(result["exercised_fixture_races"], "receipt was not replaced at its held read boundary")
        self.assertNotEqual(status, 0)
        self.assertIn("prepared cache receipt changed during its read", result.get("reason", ""))
        self.assertEqual(result["commands"], [])

    def test_held_prepared_cache_directory_replacement_is_refused(self):
        status, result = self.invoke("prepared_directory_replacement")
        self.assertEqual(result["exercised_fixture_races"], ["held host cache directory replaced"], "held cache directory replacement was not exercised")
        self.assertNotEqual(status, 0)
        self.assertIn("prepared cache directory changed during execution", result.get("reason", ""))
        self.assertTrue(result["commands"], "cache replacement did not occur during the real campaign path")

    def test_preparation_command_durations_cannot_exceed_the_total_budget(self):
        self.require_preparation_refused("prepared_excess_total", "compilation preparation exceeds its total budget")

    def test_nested_strict_static_cache_cannot_be_an_external_symlink(self):
        self.require_preparation_refused("prepared_static_symlink", "prepared cache directory is symbolic or unsafe")

    def test_nested_strict_static_cache_replacement_is_refused(self):
        status, result = self.invoke("prepared_static_replacement")
        self.assertEqual(result["exercised_fixture_races"], ["held strict static cache directory replaced"])
        self.assertNotEqual(status, 0, "runner accepted the exercised strict static cache replacement")
        self.assertIn("prepared cache directory changed during execution", result.get("reason", ""))

    def require_enterprise_selector_refused(self, selector):
        self.require_preparation_refused("prepared_override_" + selector,
            "prepared cache does not support enterprise cage selector: " + selector)

    def test_prepared_cache_refuses_enterprise_source_and_cache_selection(self):
        self.require_enterprise_selector_refused("CHIO_ENTERPRISE_SECURITY_RUNNER")

    def test_prepared_cache_refuses_enterprise_workspace(self):
        self.require_enterprise_selector_refused("CHIO_SECURITY_WORKSPACE")

    def test_prepared_cache_refuses_enterprise_inventory_checker(self):
        self.require_enterprise_selector_refused("CHIO_SECURITY_CAGE_INVENTORY_CHECKER")

    def test_prepared_cache_refuses_enterprise_candidate_artifact_root(self):
        self.require_enterprise_selector_refused("CHIO_SECURITY_CANDIDATE_ARTIFACTS")

    def test_prepared_cache_refuses_enterprise_verifier_artifact_root(self):
        self.require_enterprise_selector_refused("CHIO_SECURITY_VERIFIER_ARTIFACTS")

    def test_default_cold_campaign_preserves_its_existing_environment_behavior(self):
        status, result = self.invoke("cold_enterprise_environment")
        self.assertEqual(status, 0, result.get("reason"))
        self.assertNotIn("compilation_preparation", result)


class SourcePolicyClassificationTests(unittest.TestCase):
    def test_secret_suffix_and_exclusion_priority_preserve_path_semantics(self):
        module = load_runner()
        cases = [
            ("crates/core/reader.rs", False, None),
            ("fixture/.key", False, None),
            ("fixture/.pem", False, None),
            ("fixture/.hidden.key", False, "secret-path-policy"),
            ("fixture/certificate.PEM", False, "secret-path-policy"),
            ("fixture/certificate.pem.", False, None),
            ("fixture/key.key/source.rs", False, "secret-path-policy"),
            ("target/private-key-fixture", False, "secret-path-policy"),
            ("node_modules/.env.config", False, "secret-path-policy"),
            ("fixture/credentials.json", True, "secret-path-policy"),
            ("target/input.rs", True, "ignored-but-tracked"),
            ("target/node_modules/input.rs", False, "target-tree-policy"),
            ("sdk/node_modules/input.js", False, "cache-tree-policy"),
        ]
        for name, ignored, expected in cases:
            with self.subTest(path=name, ignored=ignored):
                self.assertEqual(module.source_exclusion(Path(name), ignored), expected)

    def test_ordinary_source_classification_avoids_per_component_path_construction(self):
        module = load_runner()
        relative = Path("crates/core/reader.rs")
        constructed = []

        def observe_path(*arguments, **options):
            constructed.append(arguments)
            return Path(*arguments, **options)

        with patch.object(module, "Path", side_effect=observe_path):
            self.assertIsNone(module.source_exclusion(relative))
        self.assertEqual(constructed, [],
            "ordinary source classification constructs one Path per component to check impossible secret suffixes")


class ProtectedSourceReadTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="protected-source-read-")
        self.base = Path(self.temporary.name).resolve()
        self.root = self.base / "candidate"
        self.path = self.root / "deep/tree/source/input.rs"
        self.path.parent.mkdir(parents=True)
        self.data = b"protected regular source fixture\n"
        self.path.write_bytes(self.data)
        self.module = load_runner()

    def tearDown(self):
        self.temporary.cleanup()

    def test_regular_reads_do_not_construct_unused_parent_path_observations(self):
        ancestry = []
        parent_paths = []
        original_ancestry = Path.is_relative_to
        original_join = Path.__truediv__

        def observe_ancestry(path, other):
            ancestry.append((str(path), str(other)))
            return original_ancestry(path, other)

        def observe_parent_path(path, other):
            parent_paths.append((str(path), str(other)))
            return original_join(path, other)

        with patch.object(Path, "is_relative_to", new=observe_ancestry), patch.object(Path, "__truediv__", new=observe_parent_path):
            actual = self.module.digest(self.path, root=self.root)
        self.assertEqual(actual, hashlib.sha256(self.data).hexdigest())
        self.assertEqual((len(ancestry), len(parent_paths)), (0, 0),
            "regular FD reads build generic ancestry and per-parent Path observations they never use")

    def test_root_containment_requires_whole_components(self):
        sibling = self.base / "candidate-copy/input.rs"
        sibling.parent.mkdir()
        sibling.write_bytes(self.data)
        self.assertEqual(self.module.digest(self.path, root=self.root), hashlib.sha256(self.data).hexdigest())
        with patch.object(self.module.os, "open", side_effect=AssertionError("outside-root input was opened")):
            with self.assertRaisesRegex(self.module.AcceptanceError, "outside its declared root"):
                self.module.digest(sibling, root=self.root)

    def test_dot_dot_is_refused_before_any_file_descriptor_lookup(self):
        spelled = self.root / "deep/tree/source/../source/input.rs"
        for root in (self.root, None):
            with self.subTest(root=root), patch.object(self.module.os, "open", side_effect=AssertionError("dot-dot input was opened")):
                with self.assertRaisesRegex(self.module.AcceptanceError, "outside its declared root"):
                    self.module.digest(spelled, root=root)

    def test_requested_parent_observations_retain_every_full_directory_identity(self):
        observed = []
        with self.module.input_parent(self.path, self.root, observed) as (parent, leaf):
            metadata = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
            self.assertTrue(stat.S_ISREG(metadata.st_mode))
        expected = []
        prefix = Path(self.path.anchor)
        for component in (None, *self.path.parts[1:-1]):
            if component is not None:
                prefix /= component
            metadata = prefix.stat()
            expected.append((str(prefix), (metadata.st_dev, metadata.st_ino, metadata.st_mode)))
        self.assertEqual(observed, expected)

    def test_regular_reader_retains_all_before_after_custody_syscalls(self):
        originals = {name: getattr(os, name) for name in ("open", "stat", "fstat", "close")}
        parent_count = len(self.path.parts[1:-1])
        for root in (self.root, None):
            with self.subTest(root=root):
                calls = {name: [] for name in originals}

                def observed(name):
                    def invoke(*arguments, **options):
                        calls[name].append((arguments, options))
                        return originals[name](*arguments, **options)
                    return invoke

                with patch.object(os, "open", new=observed("open")), patch.object(os, "stat", new=observed("stat")), \
                        patch.object(os, "fstat", new=observed("fstat")), patch.object(os, "close", new=observed("close")):
                    actual = self.module.digest(self.path, root=root)
                self.assertEqual(actual, hashlib.sha256(self.data).hexdigest())
                self.assertGreaterEqual(len(calls["open"]), parent_count + 2)
                self.assertEqual(len(calls["close"]), len(calls["open"]))
                self.assertGreaterEqual(len(calls["fstat"]), 2 * parent_count + 3)
                self.assertGreaterEqual(len(calls["stat"]), parent_count + 2)
                self.assertTrue(all(options.get("follow_symlinks") is False for _, options in calls["stat"]))
                self.assertTrue(all(arguments[1] & os.O_NOFOLLOW for arguments, _ in calls["open"]))
                leaf_flags = calls["open"][-1][0][1]
                self.assertTrue(leaf_flags & os.O_NONBLOCK)


class SourceProjectionInventoryTests(unittest.TestCase):
    """Exercise policy boundaries with real Git discovery and descriptor reads."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="source-projection-boundary-")
        self.root = Path(self.temporary.name).resolve()
        self.module = load_runner()
        self.protected = set()
        self.reads = {"open": [], "hash": [], "link_text": []}
        self.put("src/lib.rs", b"ordinary source fixture\n")

    def tearDown(self):
        self.temporary.cleanup()

    def put(self, name, body=b"synthetic excluded fixture\n", *, link=None, protected=False):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if link is None:
            path.write_bytes(body)
        else:
            path.symlink_to(link)
        if protected:
            self.protected.add(path)
        return path

    def inventory(self):
        for command in (["git", "init", "--quiet"], ["git", "add", "."]):
            REAL_RUN(command, cwd=self.root, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        original_open, original_link, original_digest = os.open, os.readlink, self.module.digest
        def matched(path, options):
            for protected in self.protected:
                if Path(path) == protected:
                    return True
                if str(path) == protected.name and options.get("dir_fd") is not None:
                    metadata = os.fstat(options["dir_fd"])
                    parent = protected.parent.lstat()
                    if (metadata.st_dev, metadata.st_ino) == (parent.st_dev, parent.st_ino):
                        return True
            return False
        def opened(path, flags, *arguments, **options):
            if not flags & os.O_DIRECTORY and matched(path, options):
                self.reads["open"].append(str(path))
            return original_open(path, flags, *arguments, **options)
        def linked(path, *arguments, **options):
            if matched(path, options):
                self.reads["link_text"].append(str(path))
            return original_link(path, *arguments, **options)
        def digested(path, *arguments, **options):
            if Path(path) in self.protected:
                self.reads["hash"].append(str(path))
            return original_digest(path, *arguments, **options)
        with patch.object(self.module.os, "open", side_effect=opened), \
                patch.object(self.module.os, "readlink", side_effect=linked), \
                patch.object(self.module, "digest", side_effect=digested):
            return {row["path"]: row for row in self.module.source_inventory(self.root)}

    def test_archive_and_exact_artifact_bodies_are_metadata_only_without_reads(self):
        self.put("packages/retained.tar.gz", protected=True)
        self.put("docs/evidence/trace.json", protected=True)
        entries = self.inventory()
        self.assertEqual(self.reads, {"open": [], "hash": [], "link_text": []})
        for name, reason in (("packages/retained.tar.gz", "archive-file-policy"),
                             ("docs/evidence/trace.json", "artifact-tree-policy")):
            self.assertEqual(entries[name]["content_coverage"], "metadata-only")
            self.assertEqual(entries[name]["exclusion_reason"], reason)
            self.assertNotIn("sha256", entries[name])

    def test_excluded_archive_and_artifact_links_never_read_text_or_referent(self):
        self.put("packages/retained.zip", link="../src/lib.rs", protected=True)
        self.put("docs/evidence/trace-link.json", link="../../src/lib.rs", protected=True)
        entries = self.inventory()
        self.assertEqual(self.reads, {"open": [], "hash": [], "link_text": []})
        for name in ("packages/retained.zip", "docs/evidence/trace-link.json"):
            self.assertEqual(entries[name]["state"], "symlink")
            self.assertNotIn("link_text", entries[name])
            self.assertNotIn("sha256", entries[name])

    def test_source_alias_refuses_archive_before_any_body_read(self):
        self.put("packages/retained.tar.gz", protected=True)
        self.put("aliases/input.rs", link="../packages/retained.tar.gz")
        with self.assertRaises(self.module.AcceptanceError):
            self.inventory()
        self.assertEqual(self.reads, {"open": [], "hash": [], "link_text": []})

    def test_source_alias_refuses_artifact_before_any_body_read(self):
        self.put("docs/evidence/trace.json", protected=True)
        self.put("aliases/input.rs", link="../docs/evidence/trace.json")
        with self.assertRaises(self.module.AcceptanceError):
            self.inventory()
        self.assertEqual(self.reads, {"open": [], "hash": [], "link_text": []})

    def test_source_alias_refuses_excluded_hop_before_reading_its_link_text(self):
        self.put("docs/evidence/trace-link.json", link="../../src/lib.rs", protected=True)
        self.put("aliases/input.rs", link="../docs/evidence/trace-link.json")
        with self.assertRaises(self.module.AcceptanceError):
            self.inventory()
        self.assertEqual(self.reads, {"open": [], "hash": [], "link_text": []})

    def test_ordinary_similar_names_and_archive_shaped_directories_keep_byte_binding(self):
        paths = [self.put("src/evidence/parser.rs"), self.put("docs/evidence-extra/parser.rs"),
                 self.put("src/package.tar.gz/parser.rs"), self.put("packages/data.zip.example")]
        entries = self.inventory()
        for path in paths:
            self.assertEqual(entries[str(path.relative_to(self.root))]["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())

    def test_secret_artifact_archive_priority_precedes_existing_ignore_policy(self):
        for name, reason in (("docs/evidence/credentials.toml", "secret-path-policy"),
                             ("docs/evidence/bundle.zip", "artifact-tree-policy"),
                             ("packages/BUNDLE.TAR.GZ", "archive-file-policy")):
            with self.subTest(name=name):
                self.assertEqual(self.module.source_exclusion(Path(name), ignored=True), reason)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--legacy-runner", type=Path)
    args, remaining = parser.parse_known_args()
    if args.legacy_runner:
        RUNNER = args.legacy_runner.resolve()
        LEGACY = True
    unittest.main(argv=[sys.argv[0], *remaining])
