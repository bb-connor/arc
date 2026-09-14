#!/usr/bin/env python3
"""Trusted fixed-operation entrypoint for isolated security evidence execution."""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import errno
import hashlib
import json
import os
import posixpath
import selectors
import secrets
import signal
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path


class EntrypointError(RuntimeError):
    pass


MAX_LOG_BYTES = 16 * 1024 * 1024
CANDIDATE_UID = 65532
CANDIDATE_GID = 65532
VERIFIER_UID = 65533
VERIFIER_GID = 65533
TRUSTED_STATE_DIRECTORY_PREFIX = ".chio-security-adversarial-evidence.state.v2."
SOURCE = Path("/source")
LINUX_CAMPAIGNS = (
    "broker_plaintext_custody",
    "sandbox_fd_leak",
    "sandbox_helper_substitution",
    "sandbox_path_swap",
    "sandbox_symlink_escape",
    "sandbox_syscall_escape",
)
ALL_REFRESH_INVENTORY = (
    (
        "approval_plan_field_omission",
        "audits/evidence/mutants/security/approval_plan_field_omission/mutants.out/outcomes.json",
        "crates/core/chio-adversarial-suite/cases/containment_rollback/containment-rollback-001.json",
    ),
    (
        "broker_destination_rebinding",
        "audits/evidence/mutants/security/broker_destination_rebinding/mutants.out/outcomes.json",
        "crates/core/chio-adversarial-suite/cases/broker_destination_rebinding/broker-destination-rebinding-001.json",
    ),
    (
        "broker_execution_overspend",
        "audits/evidence/mutants/security/broker_execution_overspend/mutants.out/outcomes.json",
        "crates/core/chio-adversarial-suite/cases/broker_execution_overspend/broker-execution-overspend-001.json",
    ),
    (
        "broker_orphan_hold",
        "audits/evidence/mutants/security/broker_orphan_hold/mutants.out/outcomes.json",
        "crates/core/chio-adversarial-suite/cases/broker_orphan_hold/broker-orphan-hold-001.json",
    ),
    (
        "broker_parent_double_charge",
        "audits/evidence/mutants/security/broker_parent_double_charge/mutants.out/outcomes.json",
        "crates/core/chio-adversarial-suite/cases/broker_parent_double_charge/broker-parent-double-charge-001.json",
    ),
    (
        "broker_plaintext_custody",
        "audits/evidence/mutants/security/broker_plaintext_custody/mutants.out/outcomes.json",
        "crates/core/chio-adversarial-suite/cases/broker_plaintext_custody/broker-plaintext-custody-001.json",
    ),
    (
        "broker_proof_replay",
        "audits/evidence/mutants/security/broker_proof_replay/mutants.out/outcomes.json",
        "crates/core/chio-adversarial-suite/cases/broker_proof_replay/broker-proof-replay-001.json",
    ),
    (
        "broker_revocation_race",
        "audits/evidence/mutants/security/broker_revocation_race/mutants.out/outcomes.json",
        "crates/core/chio-adversarial-suite/cases/broker_revocation_race/broker-revocation-race-001.json",
    ),
    (
        "broker_secret_boundary_crossing",
        "audits/evidence/mutants/security/broker_secret_boundary_crossing/mutants.out/outcomes.json",
        "crates/core/chio-adversarial-suite/cases/broker_secret_boundary_crossing/broker-secret-boundary-crossing-001.json",
    ),
    (
        "broker_unbound_headers",
        "audits/evidence/mutants/security/broker_unbound_headers/mutants.out/outcomes.json",
        "crates/core/chio-adversarial-suite/cases/broker_unbound_headers/broker-unbound-headers-001.json",
    ),
    (
        "false_lifted_status",
        "audits/evidence/mutants/security/false_lifted_status/mutants.out/outcomes.json",
        "crates/core/chio-adversarial-suite/cases/containment_rollback/containment-rollback-001.json",
    ),
    (
        "grant_replay",
        "audits/evidence/mutants/security/grant_replay/mutants.out/outcomes.json",
        "crates/core/chio-adversarial-suite/cases/label_downgrade/label-downgrade-001.json",
    ),
    (
        "ignored_store_error",
        "audits/evidence/mutants/security/ignored_store_error/mutants.out/outcomes.json",
        "crates/core/chio-adversarial-suite/cases/label_downgrade/label-downgrade-001.json",
    ),
    (
        "ingest_time_substitution",
        "audits/evidence/mutants/security/ingest_time_substitution/mutants.out/outcomes.json",
        "crates/core/chio-adversarial-suite/cases/temporal_evasion/temporal-evasion-001.json",
    ),
    (
        "key_log_inconsistent_growth",
        "audits/evidence/mutants/security/key_log_inconsistent_growth/mutants.out/outcomes.json",
        "crates/core/chio-adversarial-suite/cases/key_log_inconsistent_growth/key-log-inconsistent-growth-001.json",
    ),
    (
        "key_log_noncontiguous_sync",
        "audits/evidence/mutants/security/key_log_noncontiguous_sync/mutants.out/outcomes.json",
        "crates/core/chio-adversarial-suite/cases/key_log_noncontiguous_sync/key-log-noncontiguous-sync-001.json",
    ),
    (
        "key_log_omission",
        "audits/evidence/mutants/security/key_log_omission/mutants.out/outcomes.json",
        "crates/core/chio-adversarial-suite/cases/key_log_omission/key-log-omission-001.json",
    ),
    (
        "key_log_split_view",
        "audits/evidence/mutants/security/key_log_split_view/mutants.out/outcomes.json",
        "crates/core/chio-adversarial-suite/cases/key_log_split_view/key-log-split-view-001.json",
    ),
    (
        "missing_clearance_allow",
        "audits/evidence/mutants/security/missing_clearance_allow/mutants.out/outcomes.json",
        "crates/core/chio-adversarial-suite/cases/label_downgrade/label-downgrade-001.json",
    ),
    (
        "old_key_backdating",
        "audits/evidence/mutants/security/old_key_backdating/mutants.out/outcomes.json",
        "crates/core/chio-adversarial-suite/cases/old_key_backdating/old-key-backdating-001.json",
    ),
    (
        "reader_subset_direction",
        "audits/evidence/mutants/security/reader_subset_direction/mutants.out/outcomes.json",
        "crates/core/chio-adversarial-suite/cases/label_downgrade/label-downgrade-001.json",
    ),
    (
        "root_only_lift",
        "audits/evidence/mutants/security/root_only_lift/mutants.out/outcomes.json",
        "crates/core/chio-adversarial-suite/cases/containment_rollback/containment-rollback-001.json",
    ),
    (
        "rotation_partial_commit",
        "audits/evidence/mutants/security/rotation_partial_commit/mutants.out/outcomes.json",
        "crates/core/chio-adversarial-suite/cases/rotation_partial_commit/rotation-partial-commit-001.json",
    ),
    (
        "rotation_unwitnessed_signing",
        "audits/evidence/mutants/security/rotation_unwitnessed_signing/mutants.out/outcomes.json",
        "crates/core/chio-adversarial-suite/cases/rotation_unwitnessed_signing/rotation-unwitnessed-signing-001.json",
    ),
    (
        "sandbox_env_leak",
        "audits/evidence/mutants/security/sandbox_env_leak/mutants.out/outcomes.json",
        "crates/core/chio-adversarial-suite/cases/sandbox_fd_or_env_leak/sandbox-fd-or-env-leak-001.json",
    ),
    (
        "sandbox_false_exec_success",
        "audits/evidence/mutants/security/sandbox_false_exec_success/mutants.out/outcomes.json",
        "crates/core/chio-adversarial-suite/cases/sandbox_false_exec_success/sandbox-false-exec-success-001.json",
    ),
    (
        "sandbox_fd_leak",
        "audits/evidence/mutants/security/sandbox_fd_leak/mutants.out/outcomes.json",
        "crates/core/chio-adversarial-suite/cases/sandbox_fd_or_env_leak/sandbox-fd-or-env-leak-001.json",
    ),
    (
        "sandbox_helper_substitution",
        "audits/evidence/mutants/security/sandbox_helper_substitution/mutants.out/outcomes.json",
        "crates/core/chio-adversarial-suite/cases/sandbox_helper_substitution/sandbox-helper-substitution-001.json",
    ),
    (
        "sandbox_partial_enforcement",
        "audits/evidence/mutants/security/sandbox_partial_enforcement/mutants.out/outcomes.json",
        "crates/core/chio-adversarial-suite/cases/sandbox_partial_enforcement/sandbox-partial-enforcement-001.json",
    ),
    (
        "sandbox_path_swap",
        "audits/evidence/mutants/security/sandbox_path_swap/mutants.out/outcomes.json",
        "crates/core/chio-adversarial-suite/cases/sandbox_path_swap/sandbox-path-swap-001.json",
    ),
    (
        "sandbox_symlink_escape",
        "audits/evidence/mutants/security/sandbox_symlink_escape/mutants.out/outcomes.json",
        "crates/core/chio-adversarial-suite/cases/sandbox_symlink_escape/sandbox-symlink-escape-001.json",
    ),
    (
        "sandbox_syscall_escape",
        "audits/evidence/mutants/security/sandbox_syscall_escape/mutants.out/outcomes.json",
        "crates/core/chio-adversarial-suite/cases/sandbox_syscall_escape/sandbox-syscall-escape-001.json",
    ),
    (
        "sandbox_unsigned_manifest",
        "audits/evidence/mutants/security/sandbox_unsigned_manifest/mutants.out/outcomes.json",
        "crates/core/chio-adversarial-suite/cases/sandbox_unsigned_manifest/sandbox-unsigned-manifest-001.json",
    ),
    (
        "tripwire_after_dispatch",
        "audits/evidence/mutants/security/tripwire_after_dispatch/mutants.out/outcomes.json",
        "crates/core/chio-adversarial-suite/cases/canary_evasion/canary-evasion-001.json",
    ),
    (
        "truncation_ignored",
        "audits/evidence/mutants/security/truncation_ignored/mutants.out/outcomes.json",
        "crates/core/chio-adversarial-suite/cases/containment_rollback/containment-rollback-001.json",
    ),
)
ALL_CAMPAIGNS = tuple(campaign for campaign, _outcome, _case in ALL_REFRESH_INVENTORY)
OUTCOME_PATH_BY_CAMPAIGN = {
    campaign: outcome for campaign, outcome, _case in ALL_REFRESH_INVENTORY
}
ALL_OUTCOME_PATHS = tuple(
    OUTCOME_PATH_BY_CAMPAIGN[campaign] for campaign in ALL_CAMPAIGNS
)
LINUX_OUTCOME_PATHS = tuple(
    OUTCOME_PATH_BY_CAMPAIGN[campaign] for campaign in LINUX_CAMPAIGNS
)
ALL_REFRESH_PATHS = tuple(
    sorted(
        {
            "crates/core/chio-adversarial-suite/manifest.json",
            *(outcome for _campaign, outcome, _case in ALL_REFRESH_INVENTORY),
            *(case for _campaign, _outcome, case in ALL_REFRESH_INVENTORY),
        }
    )
)
REFRESH_PATHS = (
    "audits/evidence/mutants/security/broker_plaintext_custody/mutants.out/outcomes.json",
    "audits/evidence/mutants/security/sandbox_fd_leak/mutants.out/outcomes.json",
    "audits/evidence/mutants/security/sandbox_helper_substitution/mutants.out/outcomes.json",
    "audits/evidence/mutants/security/sandbox_path_swap/mutants.out/outcomes.json",
    "audits/evidence/mutants/security/sandbox_symlink_escape/mutants.out/outcomes.json",
    "audits/evidence/mutants/security/sandbox_syscall_escape/mutants.out/outcomes.json",
    "crates/core/chio-adversarial-suite/cases/broker_plaintext_custody/broker-plaintext-custody-001.json",
    "crates/core/chio-adversarial-suite/cases/sandbox_fd_or_env_leak/sandbox-fd-or-env-leak-001.json",
    "crates/core/chio-adversarial-suite/cases/sandbox_helper_substitution/sandbox-helper-substitution-001.json",
    "crates/core/chio-adversarial-suite/cases/sandbox_path_swap/sandbox-path-swap-001.json",
    "crates/core/chio-adversarial-suite/cases/sandbox_symlink_escape/sandbox-symlink-escape-001.json",
    "crates/core/chio-adversarial-suite/cases/sandbox_syscall_escape/sandbox-syscall-escape-001.json",
    "crates/core/chio-adversarial-suite/manifest.json",
)
REFRESH_CONTRACT_SPINES = (
    "audits",
    "audits/evidence",
    "audits/evidence/mutants",
    "crates",
    "crates/core",
    "crates/core/chio-adversarial-suite",
)
REFRESH_CONTRACT_TREES = (
    "audits/evidence/mutants/security",
    "audits/evidence/threats",
    "crates/core/chio-adversarial-suite/cases",
)
REFRESH_CONTRACT_FILES = (
    "crates/core/chio-adversarial-suite/manifest.json",
)
TRUSTED_CHECKER = Path("/opt/chio-security/check-security-adversarial-evidence.py")
TRUSTED_CARGO_MUTANTS = Path("/usr/local/cargo/bin/cargo-mutants")
TRUSTED_GATE_ROOT = Path("/opt/chio-security/gates")
TRUSTED_ENTRYPOINT = Path("/opt/chio-security/entrypoint.py")
TRUSTED_COMMAND_CLIENT = Path("/opt/chio-security/command-client.py")
TRUSTED_SECCOMP_PROFILE = Path("/opt/chio-security/security-evidence-seccomp.json")
TRUSTED_GATES = (
    "check-cage-all-target-inventory.py",
    "check-cage-enforcement.sh",
    "check-cage-linux-enforcement.sh",
    "check-exact-cargo-test-inventory.py",
    "check-keyring-transparency.sh",
    "check-linux-enforcement-stack.py",
    "check-secret-broker-boundary.sh",
)
WORKSPACE = Path("/private/candidate")
OUTPUT = Path("/output")
VERIFIER_ROOT = Path("/baseline/verifier")
CANDIDATE_STATE_ROOT = Path("/baseline/candidate-state")
BROKER_BIN = Path("/opt/chio-security/verifier-bin")
COMMAND_EXECUTABLES = {
    "cargo": "/usr/local/cargo/bin/cargo",
    "cc": "/usr/bin/cc",
    "ldd": "/usr/bin/ldd",
}


def numeric_environment(name: str) -> int:
    raw = os.environ.get(name, "")
    if not raw.isdigit():
        raise EntrypointError(f"{name} is not a numeric identity")
    value = int(raw)
    if value < 1 or value > 2**31 - 1:
        raise EntrypointError(f"{name} is outside the trusted identity bound")
    return value


def candidate_process_options() -> dict[str, object]:
    return {
        "extra_groups": [],
        "group": CANDIDATE_GID,
        "user": CANDIDATE_UID,
    }


def verifier_process_options() -> dict[str, object]:
    return {
        "extra_groups": [],
        "group": VERIFIER_GID,
        "user": VERIFIER_UID,
    }


def workspace_copy_process_options() -> dict[str, object]:
    return {
        "extra_groups": [],
        "group": VERIFIER_GID,
        "user": CANDIDATE_UID,
    }


def validate_trusted_regular_file(
    path: Path, *, expected_mode: int, description: str
) -> None:
    try:
        observed = path.lstat()
    except OSError as error:
        raise EntrypointError(f"{description} is unavailable") from error
    if (
        not stat.S_ISREG(observed.st_mode)
        or stat.S_ISLNK(observed.st_mode)
        or observed.st_nlink != 1
        or observed.st_uid != 0
        or observed.st_gid != 0
        or stat.S_IMODE(observed.st_mode) != expected_mode
    ):
        raise EntrypointError(f"{description} is mutable or aliased")


def validate_trusted_directory(
    path: Path, *, expected_mode: int, description: str
) -> None:
    try:
        observed = path.lstat()
    except OSError as error:
        raise EntrypointError(f"{description} is unavailable") from error
    if (
        not stat.S_ISDIR(observed.st_mode)
        or stat.S_ISLNK(observed.st_mode)
        or observed.st_uid != 0
        or observed.st_gid != 0
        or stat.S_IMODE(observed.st_mode) != expected_mode
    ):
        raise EntrypointError(f"{description} is mutable or aliased")


def validate_trusted_cargo_mutants() -> None:
    for ancestor in (
        Path("/"),
        Path("/usr"),
        Path("/usr/local"),
        Path("/usr/local/cargo"),
        Path("/usr/local/cargo/bin"),
    ):
        validate_trusted_directory(
            ancestor,
            expected_mode=0o755,
            description=f"trusted cargo-mutants ancestor {ancestor}",
        )
    validate_trusted_regular_file(
        TRUSTED_CARGO_MUTANTS,
        expected_mode=0o555,
        description="trusted cargo-mutants executable",
    )


@contextlib.contextmanager
def effective_identity(uid: int, gid: int):
    original_uid = os.geteuid()
    original_gid = os.getegid()
    os.setegid(gid)
    os.seteuid(uid)
    try:
        yield
    finally:
        os.seteuid(original_uid)
        os.setegid(original_gid)


def assign_owned_group(path: Path, gid: int) -> None:
    with effective_identity(0, gid):
        os.chown(path, -1, gid)


def candidate_gate_root(gate_root: Path) -> Path:
    return gate_root / "candidate"


def verifier_gate_root(gate_root: Path) -> Path:
    return gate_root / "verifier"


def configure_child_subreaper() -> None:
    set_child_subreaper = 36
    get_child_subreaper = 37
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.argtypes = [
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]
    prctl.restype = ctypes.c_int
    if prctl(set_child_subreaper, 1, 0, 0, 0) != 0:
        raise EntrypointError(
            f"unable to configure child subreaper: errno {ctypes.get_errno()}"
        )
    observed = ctypes.c_int(0)
    if (
        prctl(get_child_subreaper, ctypes.addressof(observed), 0, 0, 0) != 0
        or observed.value != 1
    ):
        raise EntrypointError("trusted supervisor child subreaper is not active")


class CapabilityHeader(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]


class CapabilityData(ctypes.Structure):
    _fields_ = [
        ("effective", ctypes.c_uint32),
        ("permitted", ctypes.c_uint32),
        ("inheritable", ctypes.c_uint32),
    ]


def require_supervisor_capabilities(expected: str, description: str) -> None:
    status = Path("/proc/self/status").read_text(encoding="ascii")
    observed = {
        line.split(":", 1)[0]: line.split("\t", 1)[1]
        for line in status.splitlines()
        if line.startswith(("CapEff:\t", "CapPrm:\t", "CapInh:\t", "CapAmb:\t"))
    }
    if observed != {
        "CapEff": expected,
        "CapPrm": expected,
        "CapInh": "0000000000000000",
        "CapAmb": "0000000000000000",
    }:
        raise EntrypointError(f"trusted supervisor capability set is not {description}")


def drop_setup_chown_capability() -> None:
    if sys.platform != "linux":
        raise EntrypointError("setup capability retirement requires Linux")
    linux_capability_version_3 = 0x20080522
    cap_chown_mask = 1
    header = CapabilityHeader(linux_capability_version_3, 0)
    data = (CapabilityData * 2)()
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        capget = libc.capget
        capset = libc.capset
    except AttributeError as error:
        raise EntrypointError(
            "Linux libc does not expose portable capget/capset wrappers"
        ) from error
    capget.argtypes = [
        ctypes.POINTER(CapabilityHeader),
        ctypes.POINTER(CapabilityData),
    ]
    capget.restype = ctypes.c_int
    capset.argtypes = [
        ctypes.POINTER(CapabilityHeader),
        ctypes.POINTER(CapabilityData),
    ]
    capset.restype = ctypes.c_int
    if capget(ctypes.byref(header), data) != 0:
        raise EntrypointError(
            f"unable to read setup capabilities: errno {ctypes.get_errno()}"
        )
    if (
        data[0].effective & cap_chown_mask == 0
        or data[0].permitted & cap_chown_mask == 0
        or data[0].inheritable & cap_chown_mask != 0
    ):
        raise EntrypointError("setup-only CHOWN capability is unavailable")
    data[0].effective &= ~cap_chown_mask
    data[0].permitted &= ~cap_chown_mask
    data[0].inheritable &= ~cap_chown_mask
    if capset(ctypes.byref(header), data) != 0:
        raise EntrypointError(
            f"unable to drop setup-only CHOWN capability: errno {ctypes.get_errno()}"
        )
    require_supervisor_capabilities(
        "00000000000000c0", "SETUID/SETGID only after private-state setup"
    )


def validate_supervisor_boundary(*, setup: bool) -> tuple[int, int]:
    if os.geteuid() != 0 or os.getegid() != 0:
        raise EntrypointError("trusted supervisor must start as container root")
    os.setgroups([])
    configure_child_subreaper()
    host_uid = numeric_environment("CHIO_HOST_UID")
    host_gid = numeric_environment("CHIO_HOST_GID")
    if host_uid in (CANDIDATE_UID, VERIFIER_UID) or host_gid in (
        CANDIDATE_GID,
        VERIFIER_GID,
    ):
        raise EntrypointError("host, candidate, and verifier identities must be distinct")
    status = Path("/proc/self/status").read_text(encoding="ascii")
    if "NoNewPrivs:\t1\n" not in status or "Seccomp:\t2\n" not in status:
        raise EntrypointError("trusted supervisor lacks no-new-privileges or seccomp")
    if setup:
        require_supervisor_capabilities(
            "00000000000000c1", "setup-only CHOWN plus SETUID/SETGID"
        )
    else:
        require_supervisor_capabilities(
            "00000000000000c0", "internal broker SETUID/SETGID only"
        )
    return host_uid, host_gid


def candidate_environment(
    state_root: Path | None = None,
    forwarded: dict[str, str] | None = None,
) -> dict[str, str]:
    gate_root = state_root or CANDIDATE_STATE_ROOT / "direct"
    home = candidate_gate_root(gate_root) / "home"
    target = Path("/target/build")
    environment = {
        "CARGO_BUILD_JOBS": "1",
        "CARGO_HOME": "/cargo-home",
        "CARGO_INCREMENTAL": "0",
        "CARGO_NET_OFFLINE": "true",
        "CARGO_PROFILE_DEV_DEBUG": "0",
        "CARGO_PROFILE_TEST_DEBUG": "0",
        "CARGO_TARGET_DIR": os.fspath(target),
        "CARGO_TERM_COLOR": "never",
        "CHIO_ENTERPRISE_SECURITY_RUNNER": "1",
        "CHIO_SECURITY_CAGE_INVENTORY_CHECKER": "/opt/chio-security/gates/check-cage-all-target-inventory.py",
        "CHIO_SECURITY_CAGE_LINUX_RUNNER": "/opt/chio-security/gates/check-cage-linux-enforcement.sh",
        "CHIO_SECURITY_EXACT_INVENTORY_CHECKER": "/opt/chio-security/gates/check-exact-cargo-test-inventory.py",
        "CHIO_SECURITY_LINUX_STACK_CHECKER": "/opt/chio-security/gates/check-linux-enforcement-stack.py",
        "CHIO_SECURITY_IMAGE_ID": os.environ.get("CHIO_SECURITY_IMAGE_ID", ""),
        "CHIO_SECURITY_WORKSPACE": "/private/candidate",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "safe.directory",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_VALUE_0": "/private/candidate",
        "GIT_DIR": "/baseline/git",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_WORK_TREE": "/private/candidate",
        "HOME": os.fspath(home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "PYTHONNOUSERSITE": "1",
        "PYTHONSAFEPATH": "1",
        "RUSTUP_HOME": "/usr/local/rustup",
        "SOURCE_SHA": os.environ.get("SOURCE_SHA", ""),
        "TMPDIR": "/target/tmp",
    }
    if forwarded:
        for key, value in forwarded.items():
            if key.startswith("CHIO_CAGE_"):
                environment[key] = value
            elif key == "RUSTFLAGS":
                environment[key] = value
            elif key == "LC_ALL" and value == "C":
                environment[key] = value
            elif key == "CARGO_TARGET_DIR":
                requested = Path(value)
                persistent_cage_target = Path(
                    "/target/artifacts/static-pie-target"
                )
                if not requested.is_absolute() or not (
                    requested.is_relative_to(target)
                    or requested == persistent_cage_target
                ):
                    raise EntrypointError("candidate target override escapes gate state")
                environment[key] = value
            else:
                raise EntrypointError("candidate command requested an unsafe environment")
    return environment


def verifier_environment(socket_path: Path, token: str, gate_root: Path) -> dict[str, str]:
    verifier_root = verifier_gate_root(gate_root)
    return {
        "CARGO_BUILD_JOBS": "1",
        "CARGO_INCREMENTAL": "0",
        "CARGO_TARGET_DIR": "/target/build",
        "CARGO_TERM_COLOR": "never",
        "CHIO_ENTERPRISE_SECURITY_RUNNER": "1",
        "CHIO_SECURITY_BROKER_SOCKET": os.fspath(socket_path),
        "CHIO_SECURITY_BROKER_TOKEN": token,
        "CHIO_SECURITY_CAGE_INVENTORY_CHECKER": "/opt/chio-security/gates/check-cage-all-target-inventory.py",
        "CHIO_SECURITY_CAGE_LINUX_RUNNER": "/opt/chio-security/gates/check-cage-linux-enforcement.sh",
        "CHIO_SECURITY_EXACT_INVENTORY_CHECKER": "/opt/chio-security/gates/check-exact-cargo-test-inventory.py",
        "CHIO_SECURITY_LINUX_STACK_CHECKER": "/opt/chio-security/gates/check-linux-enforcement-stack.py",
        "CHIO_SECURITY_VERIFIER_ARTIFACTS": os.fspath(
            verifier_root / "artifacts"
        ),
        "CHIO_SECURITY_WORKSPACE": os.fspath(WORKSPACE),
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "safe.directory",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_VALUE_0": os.fspath(WORKSPACE),
        "GIT_DIR": "/baseline/git",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_WORK_TREE": os.fspath(WORKSPACE),
        "HOME": os.fspath(verifier_root / "home"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": f"{BROKER_BIN}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "PYTHONNOUSERSITE": "1",
        "PYTHONSAFEPATH": "1",
        "RUSTUP_HOME": "/usr/local/rustup",
        "SOURCE_SHA": os.environ.get("SOURCE_SHA", ""),
        "TMPDIR": os.fspath(verifier_root / "tmp"),
    }


def trusted_refresh_state_path(workspace: Path | None = None) -> Path:
    selected = workspace or WORKSPACE
    try:
        canonical_workspace = selected.resolve(strict=True)
        workspace_metadata = canonical_workspace.lstat()
        parent_metadata = canonical_workspace.parent.lstat()
    except (OSError, RuntimeError) as error:
        raise EntrypointError("trusted refresh workspace identity is unavailable") from error
    if (
        canonical_workspace != selected
        or not stat.S_ISDIR(workspace_metadata.st_mode)
        or stat.S_ISLNK(workspace_metadata.st_mode)
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or stat.S_ISLNK(parent_metadata.st_mode)
        or parent_metadata.st_dev != workspace_metadata.st_dev
    ):
        raise EntrypointError("trusted refresh workspace identity is invalid")
    identity = {
        "canonical_path": os.fspath(canonical_workspace),
        "device": workspace_metadata.st_dev,
        "inode": workspace_metadata.st_ino,
    }
    payload = (json.dumps(identity, indent=2, ensure_ascii=False) + "\n").encode(
        "utf-8"
    )
    digest = hashlib.sha256(payload).hexdigest()
    return canonical_workspace.parent / f"{TRUSTED_STATE_DIRECTORY_PREFIX}{digest}"


def validate_trusted_refresh_state(path: Path) -> None:
    expected = trusted_refresh_state_path()
    try:
        metadata = path.lstat()
        workspace_metadata = WORKSPACE.lstat()
    except OSError as error:
        raise EntrypointError("trusted refresh state is unavailable") from error
    if (
        path != expected
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != VERIFIER_UID
        or metadata.st_gid != VERIFIER_GID
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or metadata.st_nlink != 2
        or metadata.st_dev != workspace_metadata.st_dev
    ):
        raise EntrypointError("trusted refresh state identity is invalid")


def require_candidate_cannot_replace_trusted_state(path: Path) -> None:
    renamed = path.with_name(f"{path.name}.candidate-replaced")
    with effective_identity(CANDIDATE_UID, CANDIDATE_GID):
        try:
            os.rename(path, renamed)
        except PermissionError:
            pass
        else:
            raise EntrypointError("candidate can rename trusted refresh state")
        try:
            path.rmdir()
        except PermissionError:
            pass
        else:
            raise EntrypointError("candidate can remove trusted refresh state")


def candidate_workspace_inventory() -> tuple[
    tuple[str, str, int, int, int, str | None], ...
]:
    try:
        canonical_workspace = WORKSPACE.resolve(strict=True)
        workspace_metadata = WORKSPACE.lstat()
    except (OSError, RuntimeError) as error:
        raise EntrypointError("candidate workspace identity is unavailable") from error
    if (
        not WORKSPACE.is_absolute()
        or canonical_workspace != WORKSPACE
        or not stat.S_ISDIR(workspace_metadata.st_mode)
        or stat.S_ISLNK(workspace_metadata.st_mode)
        or workspace_metadata.st_uid != CANDIDATE_UID
        or workspace_metadata.st_gid != VERIFIER_GID
    ):
        raise EntrypointError("candidate workspace identity is invalid")
    workspace_device = workspace_metadata.st_dev
    entries: list[tuple[str, str, int, int, int, str | None]] = []

    def inspect(path: Path) -> str:
        try:
            metadata = path.lstat()
        except OSError as error:
            raise EntrypointError(
                f"candidate workspace path is unavailable: {path}"
            ) from error
        try:
            relative = "." if path == WORKSPACE else path.relative_to(WORKSPACE).as_posix()
        except ValueError as error:
            raise EntrypointError("candidate workspace inventory escaped its root") from error
        if (
            metadata.st_dev != workspace_device
            or metadata.st_uid != CANDIDATE_UID
            or metadata.st_gid != VERIFIER_GID
        ):
            raise EntrypointError(
                f"candidate workspace path ownership changed: {relative}"
            )
        mode = stat.S_IMODE(metadata.st_mode)
        link_target: str | None = None
        if stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
            kind = "directory"
        elif stat.S_ISREG(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
            if metadata.st_nlink != 1:
                raise EntrypointError(
                    f"candidate workspace regular file is aliased: {relative}"
                )
            kind = "regular"
        elif stat.S_ISLNK(metadata.st_mode):
            if metadata.st_nlink != 1:
                raise EntrypointError(
                    f"candidate workspace symbolic link is aliased: {relative}"
                )
            try:
                link_target = os.readlink(path)
                parsed_target = Path(link_target)
                lexical_target = posixpath.normpath(
                    posixpath.join(posixpath.dirname(relative), link_target)
                )
                resolved_target = (path.parent / parsed_target).resolve(strict=True)
                resolved_target.relative_to(WORKSPACE)
                target_metadata = resolved_target.lstat()
            except (OSError, RuntimeError, ValueError) as error:
                raise EntrypointError(
                    f"candidate workspace symbolic link escapes its root: {relative}"
                ) from error
            if (
                not link_target
                or "\x00" in link_target
                or parsed_target.is_absolute()
                or lexical_target == ".."
                or lexical_target.startswith("../")
                or target_metadata.st_dev != workspace_device
            ):
                raise EntrypointError(
                    f"candidate workspace symbolic link is invalid: {relative}"
                )
            kind = "symlink"
        else:
            raise EntrypointError(
                f"candidate workspace contains a special file: {relative}"
            )
        entries.append(
            (
                relative,
                kind,
                metadata.st_dev,
                metadata.st_ino,
                mode,
                link_target,
            )
        )
        return kind

    inspect(WORKSPACE)

    def walk_error(error: OSError) -> None:
        raise EntrypointError("unable to inventory candidate workspace") from error

    for current, directories, files in os.walk(
        WORKSPACE, topdown=True, followlinks=False, onerror=walk_error
    ):
        current_path = Path(current)
        directories.sort()
        files.sort()
        traversable: list[str] = []
        for name in directories:
            if inspect(current_path / name) == "directory":
                traversable.append(name)
        directories[:] = traversable
        for name in files:
            inspect(current_path / name)
    relatives = [entry[0] for entry in entries]
    if len(relatives) != len(set(relatives)):
        raise EntrypointError("candidate workspace inventory contains duplicate paths")
    return tuple(sorted(entries))


def validate_frozen_candidate_workspace(
    snapshot: tuple[tuple[str, str, int, int, int, str | None], ...]
) -> None:
    expected_relatives = {entry[0] for entry in snapshot}
    observed_relatives: set[str] = set()

    def walk_error(error: OSError) -> None:
        raise EntrypointError("unable to validate frozen candidate workspace") from error

    for relative, kind, device, inode, original_mode, link_target in snapshot:
        path = WORKSPACE if relative == "." else WORKSPACE / relative
        try:
            metadata = path.lstat()
        except OSError as error:
            raise EntrypointError(
                f"frozen candidate workspace path is unavailable: {relative}"
            ) from error
        observed_relatives.add(relative)
        expected_mode = 0o755 if kind == "directory" or original_mode & 0o111 else 0o644
        observed_kind = (
            "symlink"
            if stat.S_ISLNK(metadata.st_mode)
            else "directory"
            if stat.S_ISDIR(metadata.st_mode)
            else "regular"
            if stat.S_ISREG(metadata.st_mode)
            else "special"
        )
        if (
            observed_kind != kind
            or metadata.st_dev != device
            or metadata.st_ino != inode
            or metadata.st_uid != VERIFIER_UID
            or metadata.st_gid != VERIFIER_GID
            or (kind != "symlink" and stat.S_IMODE(metadata.st_mode) != expected_mode)
            or (kind in ("regular", "symlink") and metadata.st_nlink != 1)
        ):
            raise EntrypointError(
                f"frozen candidate workspace identity changed: {relative}"
            )
        if kind == "symlink":
            try:
                observed_target = os.readlink(path)
                resolved_target = (path.parent / observed_target).resolve(strict=True)
                resolved_target.relative_to(WORKSPACE)
            except (OSError, RuntimeError, ValueError) as error:
                raise EntrypointError(
                    f"frozen candidate workspace symbolic link changed: {relative}"
                ) from error
            if observed_target != link_target:
                raise EntrypointError(
                    f"frozen candidate workspace symbolic link changed: {relative}"
                )
    try:
        for current, directories, files in os.walk(
            WORKSPACE,
            topdown=True,
            followlinks=False,
            onerror=walk_error,
        ):
            current_path = Path(current)
            for name in (*directories, *files):
                path = current_path / name
                observed_relatives.add(path.relative_to(WORKSPACE).as_posix())
    except (OSError, ValueError) as error:
        raise EntrypointError("unable to validate frozen candidate workspace") from error
    if observed_relatives != expected_relatives:
        raise EntrypointError("frozen candidate workspace path inventory changed")


def freeze_candidate_workspace() -> tuple[
    tuple[str, str, int, int, int, str | None], ...
]:
    snapshot = candidate_workspace_inventory()
    try:
        with effective_identity(0, VERIFIER_GID):
            for relative, kind, _device, _inode, original_mode, _target in reversed(
                snapshot
            ):
                path = WORKSPACE if relative == "." else WORKSPACE / relative
                if kind != "symlink":
                    os.chown(
                        path,
                        0,
                        VERIFIER_GID,
                        follow_symlinks=False,
                    )
                    mode = (
                        0o755
                        if kind == "directory" or original_mode & 0o111
                        else 0o644
                    )
                    os.chmod(path, mode, follow_symlinks=False)
                os.chown(
                    path,
                    VERIFIER_UID,
                    VERIFIER_GID,
                    follow_symlinks=False,
                )
    except OSError as error:
        raise EntrypointError("unable to freeze candidate workspace") from error
    validate_frozen_candidate_workspace(snapshot)
    return snapshot


def require_candidate_cannot_mutate_workspace(
    snapshot: tuple[tuple[str, str, int, int, int, str | None], ...]
) -> None:
    denied_errors = {errno.EACCES, errno.EPERM, errno.EROFS}

    def require_denied(label: str, operation, rollback=None) -> None:
        try:
            descriptor = operation()
        except OSError as error:
            if error.errno in denied_errors:
                return
            raise EntrypointError(
                f"candidate workspace mutation probe failed unexpectedly: {label}"
            ) from error
        if isinstance(descriptor, int):
            os.close(descriptor)
        if rollback is not None:
            try:
                rollback()
            except OSError as error:
                raise EntrypointError(
                    f"candidate workspace mutation probe could not roll back: {label}"
                ) from error
        raise EntrypointError(f"candidate can mutate frozen workspace: {label}")

    regular_paths = [
        WORKSPACE / relative
        for relative, kind, _device, _inode, _mode, _target in snapshot
        if kind == "regular" and relative != "."
    ]
    symlink_paths = [
        WORKSPACE / relative
        for relative, kind, _device, _inode, _mode, _target in snapshot
        if kind == "symlink"
    ]
    directory_paths = [
        WORKSPACE if relative == "." else WORKSPACE / relative
        for relative, kind, _device, _inode, _mode, _target in snapshot
        if kind == "directory"
    ]
    protected_names = (
        WORKSPACE,
        *(WORKSPACE / relative for relative in REFRESH_CONTRACT_SPINES),
        *(WORKSPACE / relative for relative in REFRESH_CONTRACT_TREES),
        *(WORKSPACE / relative for relative in REFRESH_CONTRACT_FILES),
    )
    hardlink_root = WORKSPACE.parent / ".chio-candidate-workspace-link-probe"
    if hardlink_root.exists() or hardlink_root.is_symlink():
        raise EntrypointError("candidate workspace hardlink probe root already exists")
    hardlink_root.mkdir(mode=0o700)
    os.chmod(hardlink_root, 0o700)
    os.chown(hardlink_root, CANDIDATE_UID, CANDIDATE_GID)
    try:
        with effective_identity(CANDIDATE_UID, CANDIDATE_GID):
            for path in regular_paths:
                require_denied(
                    f"write {path}",
                    lambda path=path: os.open(
                        path,
                        os.O_WRONLY
                        | os.O_APPEND
                        | getattr(os, "O_CLOEXEC", 0)
                        | getattr(os, "O_NOFOLLOW", 0),
                    ),
                )
            for path in directory_paths:
                sentinel = path / ".chio-candidate-workspace-create-probe"
                require_denied(
                    f"create below {path}",
                    lambda sentinel=sentinel: os.open(
                        sentinel,
                        os.O_WRONLY
                        | os.O_CREAT
                        | os.O_EXCL
                        | getattr(os, "O_CLOEXEC", 0)
                        | getattr(os, "O_NOFOLLOW", 0),
                        0o600,
                    ),
                    lambda sentinel=sentinel: sentinel.unlink(),
                )
            for path in protected_names:
                replacement = path.with_name(
                    f"{path.name}.chio-candidate-workspace-rename-probe"
                )
                require_denied(
                    f"rename {path}",
                    lambda path=path, replacement=replacement: os.rename(
                        path, replacement
                    ),
                    lambda path=path, replacement=replacement: os.rename(
                        replacement, path
                    ),
                )
            for relative in REFRESH_CONTRACT_FILES:
                path = WORKSPACE / relative
                require_denied(
                    f"unlink {path}", lambda path=path: os.unlink(path)
                )
            for relative in REFRESH_CONTRACT_TREES:
                path = WORKSPACE / relative
                require_denied(
                    f"rmdir {path}", lambda path=path: os.rmdir(path)
                )
            for path in symlink_paths:
                target = os.readlink(path)
                require_denied(
                    f"retarget {path}",
                    lambda path=path: os.unlink(path),
                    lambda path=path, target=target: os.symlink(target, path),
                )
            if regular_paths:
                hardlink_probe = hardlink_root / "candidate-link"
                require_denied(
                    f"hardlink {regular_paths[0]}",
                    lambda: os.link(
                        regular_paths[0], hardlink_probe, follow_symlinks=False
                    ),
                    lambda: hardlink_probe.unlink(),
                )
                original_mode = stat.S_IMODE(regular_paths[0].lstat().st_mode)
                require_denied(
                    f"chmod {regular_paths[0]}",
                    lambda: os.chmod(regular_paths[0], 0o666),
                    lambda: os.chmod(regular_paths[0], original_mode),
                )
    finally:
        try:
            with effective_identity(CANDIDATE_UID, CANDIDATE_GID):
                for child in hardlink_root.iterdir():
                    child.unlink()
        finally:
            hardlink_root.rmdir()
    validate_frozen_candidate_workspace(snapshot)


def prepare_refresh_workspace() -> Path:
    if WORKSPACE != Path("/private/candidate"):
        raise EntrypointError("private candidate workspace authority changed")
    try:
        workspace_metadata = WORKSPACE.lstat()
        workspace_has_content = any(WORKSPACE.iterdir())
    except OSError as error:
        raise EntrypointError("isolated refresh workspace is unavailable") from error
    if (
        not stat.S_ISDIR(workspace_metadata.st_mode)
        or stat.S_ISLNK(workspace_metadata.st_mode)
        or workspace_metadata.st_uid != 0
        or workspace_metadata.st_gid != 0
        or stat.S_IMODE(workspace_metadata.st_mode) != 0o755
        or workspace_metadata.st_nlink != 2
        or workspace_has_content
    ):
        raise EntrypointError("isolated refresh workspace identity is invalid")
    try:
        os.chmod(WORKSPACE, 0o770)
        os.chown(WORKSPACE, CANDIDATE_UID, VERIFIER_GID)
        state = trusted_refresh_state_path()
        state.mkdir(mode=0o700)
        os.chmod(state, 0o700)
        os.chown(state, VERIFIER_UID, VERIFIER_GID)
    except OSError as error:
        raise EntrypointError("unable to create isolated refresh workspace") from error
    validate_trusted_refresh_state(state)
    require_candidate_cannot_replace_trusted_state(state)
    return state


def prepare_private_runtime() -> None:
    host_uid = numeric_environment("CHIO_HOST_UID")
    host_gid = numeric_environment("CHIO_HOST_GID")
    for path, uid, gid in (
        (Path("/private"), 0, 0),
        (Path("/baseline"), 0, 0),
        (Path("/cargo-home"), CANDIDATE_UID, CANDIDATE_GID),
        (Path("/target"), CANDIDATE_UID, CANDIDATE_GID),
        (OUTPUT, host_uid, host_gid),
    ):
        observed = path.lstat()
        if (
            not stat.S_ISDIR(observed.st_mode)
            or stat.S_ISLNK(observed.st_mode)
            or observed.st_uid != uid
            or observed.st_gid != gid
            or stat.S_IMODE(observed.st_mode)
            != (0o755 if path in (Path("/private"), Path("/baseline")) else 0o700)
        ):
            raise EntrypointError(f"private runtime mount identity is invalid: {path}")
    source_stat = SOURCE.lstat()
    if not stat.S_ISDIR(source_stat.st_mode) or stat.S_ISLNK(source_stat.st_mode):
        raise EntrypointError("isolated source mount is unavailable")
    with effective_identity(CANDIDATE_UID, CANDIDATE_GID):
        os.chmod("/target", 0o755)
    prepare_refresh_workspace()
    VERIFIER_ROOT.mkdir(mode=0o770, parents=True, exist_ok=False)
    assign_owned_group(VERIFIER_ROOT, VERIFIER_GID)
    os.chmod(VERIFIER_ROOT, 0o770)
    with effective_identity(VERIFIER_UID, VERIFIER_GID):
        for child in ("home", "tmp"):
            path = VERIFIER_ROOT / child
            path.mkdir(mode=0o700)
            os.chmod(path, 0o700)
    CANDIDATE_STATE_ROOT.mkdir(mode=0o711, parents=True, exist_ok=False)
    os.chmod(CANDIDATE_STATE_ROOT, 0o711)
    try:
        copy_source = subprocess.run(
            [
                "/bin/cp",
                "-a",
                "--no-preserve=ownership",
                f"{SOURCE}/.",
                os.fspath(WORKSPACE),
            ],
            check=False,
            env=candidate_environment(),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=300,
            **workspace_copy_process_options(),
        )
    finally:
        quiesce_process_namespace()
    if copy_source.returncode != 0:
        raise EntrypointError("unable to copy the isolated candidate source")
    workspace_snapshot = freeze_candidate_workspace()
    require_candidate_cannot_mutate_workspace(workspace_snapshot)
    validate_trusted_regular_file(
        TRUSTED_ENTRYPOINT,
        expected_mode=0o555,
        description="trusted security entrypoint",
    )
    validate_trusted_regular_file(
        TRUSTED_COMMAND_CLIENT,
        expected_mode=0o555,
        description="trusted candidate command client",
    )
    for executable in COMMAND_EXECUTABLES:
        validate_trusted_regular_file(
            BROKER_BIN / executable,
            expected_mode=0o555,
            description=f"trusted candidate command shim {executable}",
        )
    validate_trusted_regular_file(
        TRUSTED_CHECKER,
        expected_mode=0o444,
        description="trusted evidence checker",
    )
    for name in TRUSTED_GATES:
        gate = TRUSTED_GATE_ROOT / name
        validate_trusted_regular_file(
            gate,
            expected_mode=0o555,
            description=f"trusted gate {name}",
        )
    validate_trusted_regular_file(
        TRUSTED_SECCOMP_PROFILE,
        expected_mode=0o444,
        description="trusted seccomp profile",
    )
    validate_trusted_cargo_mutants()
    expected_seccomp = os.environ.get("CHIO_SECCOMP_PROFILE_SHA256", "")
    installed_seccomp = hashlib.sha256(TRUSTED_SECCOMP_PROFILE.read_bytes()).hexdigest()
    if expected_seccomp != installed_seccomp:
        raise EntrypointError(
            "trusted seccomp profile digest does not match the host binding"
        )
    drop_setup_chown_capability()


def initialize_baseline() -> None:
    baseline = Path("/baseline/git")
    baseline.mkdir(mode=0o770)
    assign_owned_group(baseline, VERIFIER_GID)
    os.chmod(baseline, 0o770)
    commands = (
        ["/usr/bin/git", "init", "--quiet", "--bare", "/baseline/git"],
        ["/usr/bin/git", "config", "core.bare", "false"],
        [
            "/usr/bin/git",
            "config",
            "core.worktree",
            os.fspath(WORKSPACE),
        ],
        ["/usr/bin/git", "config", "user.name", "Chio security boundary"],
        ["/usr/bin/git", "config", "user.email", "security-boundary@invalid"],
        ["/usr/bin/git", "config", "core.autocrlf", "false"],
        ["/usr/bin/git", "config", "core.hooksPath", "/dev/null"],
        ["/usr/bin/git", "add", "--force", "--all"],
        [
            "/usr/bin/git",
            "commit",
            "--quiet",
            "--no-gpg-sign",
            "-m",
            "isolated baseline",
        ],
    )
    for command in commands:
        environment = {
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_DIR": "/baseline/git",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_WORK_TREE": os.fspath(WORKSPACE),
            "HOME": os.fspath(VERIFIER_ROOT / "home"),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": "/usr/bin:/bin",
            "PYTHONNOUSERSITE": "1",
            "PYTHONSAFEPATH": "1",
            "TMPDIR": os.fspath(VERIFIER_ROOT / "tmp"),
        }
        if command[1] == "init":
            environment.pop("GIT_DIR")
            environment.pop("GIT_WORK_TREE")
        try:
            result = subprocess.run(
                command,
                cwd=WORKSPACE,
                env=environment,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=300,
                **verifier_process_options(),
            )
        finally:
            quiesce_process_namespace()
            quiesce_verifier_namespace()
        if result.returncode != 0:
            raise EntrypointError("unable to establish the isolated source baseline")
    for current, directories, files in os.walk("/baseline/git", topdown=False):
        with effective_identity(VERIFIER_UID, VERIFIER_GID):
            for name in files:
                os.chmod(Path(current) / name, 0o444)
            for name in directories:
                os.chmod(Path(current) / name, 0o555)
    os.chmod("/baseline/git", 0o555)
    os.chmod("/baseline", 0o555)
    for path in (VERIFIER_ROOT / "home", VERIFIER_ROOT / "tmp"):
        clear_identity_directory(path, VERIFIER_UID, VERIFIER_GID)
        with effective_identity(VERIFIER_UID, VERIFIER_GID):
            path.rmdir()


def terminate_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        with effective_identity(CANDIDATE_UID, CANDIDATE_GID):
            os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired as error:
        raise EntrypointError("candidate process group did not terminate") from error


def terminate_verifier_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        with effective_identity(VERIFIER_UID, VERIFIER_GID):
            os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired as error:
        raise EntrypointError("trusted verifier process group did not terminate") from error


def identity_process_ids(uid: int) -> list[int]:
    observed = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        try:
            status = (entry / "status").read_text(encoding="ascii")
        except (OSError, UnicodeError):
            continue
        uid_line = next(
            (line for line in status.splitlines() if line.startswith("Uid:\t")), ""
        )
        fields = uid_line.split()
        try:
            matches = len(fields) == 5 and uid in (int(fields[1]), int(fields[2]))
        except ValueError:
            matches = False
        if matches:
            observed.append(pid)
    return sorted(observed)


def quiesce_identity_processes(uid: int, gid: int, description: str) -> None:
    deadline = time.monotonic() + 10
    while True:
        observed = identity_process_ids(uid)
        if not observed:
            return
        with effective_identity(uid, gid):
            for pid in observed:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        for pid in observed:
            try:
                os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                pass
        survivors = identity_process_ids(uid)
        if not survivors:
            return
        if time.monotonic() >= deadline:
            raise EntrypointError(
                f"{description} descendants survived process-namespace kill and wait"
            )
        time.sleep(0.01)


def quiesce_process_namespace() -> None:
    quiesce_identity_processes(CANDIDATE_UID, CANDIDATE_GID, "candidate")


def quiesce_verifier_namespace() -> None:
    quiesce_identity_processes(VERIFIER_UID, VERIFIER_GID, "trusted verifier")


def prepare_candidate_state(name: str) -> Path:
    if len(name) != 64 or any(character not in "0123456789abcdef" for character in name):
        raise EntrypointError("candidate state identity is invalid")
    root = CANDIDATE_STATE_ROOT / name
    root.mkdir(mode=0o711)
    try:
        os.chmod(root, 0o711)
        candidate_root = candidate_gate_root(root)
        candidate_root.mkdir(mode=0o770)
        assign_owned_group(candidate_root, CANDIDATE_GID)
        os.chmod(candidate_root, 0o770)
        with effective_identity(CANDIDATE_UID, CANDIDATE_GID):
            home = candidate_root / "home"
            home.mkdir(mode=0o700)
            os.chmod(home, 0o700)
        verifier_root = verifier_gate_root(root)
        verifier_root.mkdir(mode=0o770)
        assign_owned_group(verifier_root, VERIFIER_GID)
        os.chmod(verifier_root, 0o770)
        with effective_identity(VERIFIER_UID, VERIFIER_GID):
            for child in ("home", "tmp", "artifacts"):
                path = verifier_root / child
                path.mkdir(mode=0o700)
                os.chmod(path, 0o700)
        for external_root in (Path("/cargo-home"), Path("/target")):
            clear_identity_directory(external_root, CANDIDATE_UID, CANDIDATE_GID)
        with effective_identity(CANDIDATE_UID, CANDIDATE_GID):
            for path, mode in (
                (Path("/target/build"), 0o755),
                (Path("/target/artifacts"), 0o755),
                (Path("/target/tmp"), 0o700),
            ):
                path.mkdir(mode=mode)
                os.chmod(path, mode)
            os.chmod("/target", 0o755)
        cache = Path("/opt/chio-security/cargo-cache")
        cargo_home = Path("/cargo-home")
        if cache.is_dir():
            try:
                copy = subprocess.run(
                    [
                        "/bin/cp",
                        "-a",
                        "--no-preserve=ownership",
                        f"{cache}/.",
                        os.fspath(cargo_home),
                    ],
                    check=False,
                    env={
                        "HOME": os.fspath(candidate_root / "home"),
                        "PATH": "/usr/bin:/bin",
                    },
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=300,
                    **candidate_process_options(),
                )
            finally:
                quiesce_process_namespace()
            if copy.returncode != 0:
                raise EntrypointError("unable to populate disposable Cargo state")
        execution_probe = Path("/target/build/.chio-execution-probe")
        try:
            copy_status, _ = run_candidate_capture(
                ["/bin/cp", "/usr/bin/python3", os.fspath(execution_probe)],
                30,
                state_root=root,
            )
            if copy_status != 0:
                raise EntrypointError("unable to materialize the target execution probe")
            probe_status, _ = run_candidate_capture(
                [os.fspath(execution_probe), "-I", "-c", "pass"],
                30,
                state_root=root,
            )
            if probe_status != 0:
                raise EntrypointError("candidate Cargo target is not executable")
        finally:
            with effective_identity(CANDIDATE_UID, CANDIDATE_GID):
                execution_probe.unlink(missing_ok=True)
        return root
    except BaseException as error:
        try:
            remove_candidate_state(root)
        except BaseException as cleanup_error:
            raise EntrypointError(
                "partial candidate state could not be removed"
            ) from cleanup_error
        raise error


def clear_identity_directory(
    root: Path,
    uid: int,
    gid: int,
    *,
    allowed_root_uids: frozenset[int] | None = None,
    allowed_root_gids: frozenset[int] | None = None,
) -> None:
    def remove(path: Path) -> None:
        observed = path.lstat()
        if stat.S_ISDIR(observed.st_mode) and not stat.S_ISLNK(observed.st_mode):
            os.chmod(path, 0o700)
            for child in list(path.iterdir()):
                remove(child)
            path.rmdir()
        else:
            path.unlink()

    root_metadata = root.lstat()
    if (
        not stat.S_ISDIR(root_metadata.st_mode)
        or stat.S_ISLNK(root_metadata.st_mode)
        or root_metadata.st_uid not in (allowed_root_uids or frozenset({uid}))
        or root_metadata.st_gid not in (allowed_root_gids or frozenset({gid}))
    ):
        raise EntrypointError("identity-owned cleanup root changed")
    with effective_identity(uid, gid):
        try:
            os.chmod(root, 0o700)
        except PermissionError:
            pass
        for child in list(root.iterdir()):
            remove(child)


def reset_candidate_command_state(root: Path) -> None:
    if root.parent != CANDIDATE_STATE_ROOT or not root.is_dir():
        raise EntrypointError("candidate command state is unavailable")
    candidate_root = candidate_gate_root(root)
    candidate_home = candidate_root / "home"
    clear_identity_directory(candidate_home, CANDIDATE_UID, CANDIDATE_GID)
    with effective_identity(CANDIDATE_UID, CANDIDATE_GID):
        os.chmod(candidate_home, 0o700)
    clear_identity_directory(Path("/cargo-home"), CANDIDATE_UID, CANDIDATE_GID)
    for path, mode in (
        (Path("/target/build"), 0o755),
        (Path("/target/tmp"), 0o700),
    ):
        clear_identity_directory(path, CANDIDATE_UID, CANDIDATE_GID)
        with effective_identity(CANDIDATE_UID, CANDIDATE_GID):
            os.chmod(path, mode)
    cache = Path("/opt/chio-security/cargo-cache")
    if cache.is_dir():
        try:
            copy = subprocess.run(
                [
                    "/bin/cp",
                    "-a",
                    "--no-preserve=ownership",
                    f"{cache}/.",
                    "/cargo-home",
                ],
                check=False,
                env={
                    "HOME": os.fspath(candidate_home),
                    "PATH": "/usr/bin:/bin",
                },
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=300,
                **candidate_process_options(),
            )
        finally:
            quiesce_process_namespace()
        if copy.returncode != 0:
            raise EntrypointError("unable to reset disposable Cargo state")
    execution_probe = Path("/target/build/.chio-execution-probe")
    try:
        copy_status, _ = run_candidate_capture(
            ["/bin/cp", "/usr/bin/python3", os.fspath(execution_probe)],
            30,
            state_root=root,
        )
        probe_status, _ = run_candidate_capture(
            [os.fspath(execution_probe), "-I", "-c", "pass"],
            30,
            state_root=root,
        )
        if copy_status != 0 or probe_status != 0:
            raise EntrypointError("disposable Cargo target is not executable")
    finally:
        with effective_identity(CANDIDATE_UID, CANDIDATE_GID):
            execution_probe.unlink(missing_ok=True)


def remove_candidate_state(root: Path) -> None:
    quiesce_process_namespace()
    quiesce_verifier_namespace()
    if (
        root.parent != CANDIDATE_STATE_ROOT
        or len(root.name) != 64
        or any(character not in "0123456789abcdef" for character in root.name)
    ):
        raise EntrypointError("refusing to remove an unbound candidate state")
    if not root.exists():
        return
    root_metadata = root.lstat()
    if (
        not stat.S_ISDIR(root_metadata.st_mode)
        or stat.S_ISLNK(root_metadata.st_mode)
        or root_metadata.st_uid != 0
        or root_metadata.st_gid != 0
    ):
        raise EntrypointError("candidate state root identity changed")
    candidate_root = candidate_gate_root(root)
    verifier_root = verifier_gate_root(root)
    clear_identity_directory(Path("/cargo-home"), CANDIDATE_UID, CANDIDATE_GID)
    clear_identity_directory(Path("/target"), CANDIDATE_UID, CANDIDATE_GID)
    with effective_identity(CANDIDATE_UID, CANDIDATE_GID):
        os.chmod("/target", 0o755)
    for state_root, uid, gid, allowed_groups in (
        (candidate_root, CANDIDATE_UID, CANDIDATE_GID, {0, CANDIDATE_GID}),
        (verifier_root, VERIFIER_UID, VERIFIER_GID, {0, VERIFIER_GID}),
    ):
        if not state_root.exists():
            continue
        metadata = state_root.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid not in allowed_groups
        ):
            raise EntrypointError("candidate substate identity changed")
        if metadata.st_gid == 0:
            assign_owned_group(state_root, gid)
        os.chmod(state_root, 0o770)
        clear_identity_directory(
            state_root,
            uid,
            gid,
            allowed_root_uids=frozenset({0}),
            allowed_root_gids=frozenset({gid}),
        )
        state_root.rmdir()
    root.rmdir()


def collect_bounded_process(
    process: subprocess.Popen[bytes],
    timeout_seconds: int,
    *,
    terminate,
) -> tuple[int, bytes]:
    if process.stdout is None:
        terminate(process)
        raise EntrypointError("isolated command did not expose bounded output")
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout_seconds
    output = bytearray()
    overflow = False
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                terminate(process)
                raise EntrypointError("isolated command timed out")
            events = selector.select(min(remaining, 1.0))
            for key, _ in events:
                chunk = os.read(key.fd, 65_536)
                if chunk:
                    if len(output) + len(chunk) > MAX_LOG_BYTES:
                        overflow = True
                    else:
                        output.extend(chunk)
                else:
                    selector.unregister(process.stdout)
            if process.poll() is not None and not selector.get_map():
                break
        return_code = process.wait(timeout=10)
    finally:
        selector.close()
    if overflow:
        raise EntrypointError("isolated command exceeded its output bound")
    return return_code, bytes(output)


def run_candidate_capture(
    command: list[str],
    timeout_seconds: int,
    *,
    state_root: Path,
    cwd: Path = WORKSPACE,
    forwarded: dict[str, str] | None = None,
) -> tuple[int, bytes]:
    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=candidate_environment(state_root, forwarded),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            **candidate_process_options(),
        )
    except OSError as error:
        raise EntrypointError(
            f"unable to start isolated command: {command[0]}"
        ) from error
    try:
        return collect_bounded_process(
            process, timeout_seconds, terminate=terminate_group
        )
    finally:
        quiesce_process_namespace()


def run_candidate_bounded(
    command: list[str], timeout_seconds: int, *, cwd: Path = WORKSPACE
) -> bytes:
    identity = secrets.token_hex(32)
    state_root = prepare_candidate_state(identity)
    try:
        return_code, output = run_candidate_capture(
            command,
            timeout_seconds,
            state_root=state_root,
            cwd=cwd,
        )
    finally:
        remove_candidate_state(state_root)
    if return_code != 0:
        raise EntrypointError(
            f"isolated command failed with status {return_code}: {command[0]}"
        )
    return output


def read_socket_line(connection: socket.socket) -> bytes:
    payload = bytearray()
    while True:
        chunk = connection.recv(1)
        if not chunk:
            raise EntrypointError("candidate command broker request was truncated")
        if chunk == b"\n":
            return bytes(payload)
        payload.extend(chunk)
        if len(payload) > 65_536:
            raise EntrypointError("candidate command broker request is oversized")


def validate_broker_request(
    request: object, token: str, gate_root: Path
) -> tuple[list[str], Path, dict[str, str]] | None:
    if not isinstance(request, dict) or request.get("token") != token:
        raise EntrypointError("candidate command broker token is invalid")
    if request.get("operation") == "stop":
        if set(request) != {"operation", "token"}:
            raise EntrypointError("candidate command broker stop shape is invalid")
        return None
    if set(request) != {
        "arguments",
        "cwd",
        "environment",
        "executable",
        "operation",
        "token",
    } or request.get("operation") != "run":
        raise EntrypointError("candidate command broker request shape is invalid")
    executable = request.get("executable")
    arguments = request.get("arguments")
    raw_cwd = request.get("cwd")
    environment = request.get("environment")
    if (
        executable not in COMMAND_EXECUTABLES
        or not isinstance(arguments, list)
        or len(arguments) > 512
        or any(
            not isinstance(argument, str)
            or not argument
            or "\x00" in argument
            or len(argument) > 16_384
            for argument in arguments
        )
        or not isinstance(raw_cwd, str)
        or not isinstance(environment, dict)
        or any(
            not isinstance(key, str)
            or not isinstance(value, str)
            or "\x00" in key
            or "\x00" in value
            or len(key) > 128
            or len(value) > 65_536
            for key, value in environment.items()
        )
    ):
        raise EntrypointError("candidate command broker request values are invalid")
    cwd = Path(raw_cwd).resolve(strict=True)
    if cwd != WORKSPACE and not cwd.is_relative_to(WORKSPACE):
        raise EntrypointError("candidate command broker cwd escapes the workspace")
    candidate_environment(gate_root, environment)
    return [COMMAND_EXECUTABLES[executable], *arguments], cwd, environment


def broker_server(
    socket_path: Path, token: str, gate_root: Path, timeout_seconds: int
) -> int:
    if os.geteuid() != 0 or os.getegid() != 0:
        raise EntrypointError("candidate command broker must retain root supervision")
    if socket_path.parent != VERIFIER_ROOT or gate_root.parent != CANDIDATE_STATE_ROOT:
        raise EntrypointError("candidate command broker paths are invalid")
    state_root = prepare_candidate_state(gate_root.name)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        with effective_identity(VERIFIER_UID, VERIFIER_GID):
            server.bind(os.fspath(socket_path))
            os.chmod(socket_path, 0o600)
        server.listen(1)
        while True:
            connection, _ = server.accept()
            with connection:
                try:
                    request = json.loads(read_socket_line(connection))
                    validated = validate_broker_request(request, token, state_root)
                    if validated is None:
                        connection.sendall(b'{"length":0,"returncode":0}\n')
                        if connection.recv(1) != b"":
                            raise EntrypointError(
                                "candidate command broker stop barrier changed"
                            )
                        break
                    command, cwd, environment = validated
                    reset_candidate_command_state(state_root)
                    returncode, output = run_candidate_capture(
                        command,
                        timeout_seconds,
                        state_root=state_root,
                        cwd=cwd,
                        forwarded=environment,
                    )
                except (EntrypointError, OSError, ValueError, json.JSONDecodeError) as error:
                    returncode = 125
                    output = f"candidate command broker rejected request: {error}\n".encode(
                        "utf-8", errors="replace"
                    )
                header = json.dumps(
                    {"length": len(output), "returncode": returncode},
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("ascii")
                connection.sendall(header + b"\n" + output)
    finally:
        server.close()
        socket_path.unlink(missing_ok=True)
        remove_candidate_state(state_root)
    return 0


def stop_broker(socket_path: Path, token: str) -> None:
    request = json.dumps(
        {"operation": "stop", "token": token},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(30)
        with effective_identity(VERIFIER_UID, VERIFIER_GID):
            connection.connect(os.fspath(socket_path))
            connection.sendall(request + b"\n")
            response = json.loads(read_socket_line(connection))
            if response != {"length": 0, "returncode": 0}:
                raise EntrypointError("candidate command broker refused shutdown")


def abandon_broker(
    broker: subprocess.Popen[bytes], socket_path: Path, gate_root: Path
) -> None:
    cleanup_error: BaseException | None = None
    try:
        if broker.poll() is None:
            broker.kill()
        broker.wait(timeout=10)
    except BaseException as error:
        cleanup_error = error
    for cleanup in (
        quiesce_process_namespace,
        lambda: socket_path.unlink(missing_ok=True),
        lambda: remove_candidate_state(gate_root) if gate_root.exists() else None,
    ):
        try:
            cleanup()
        except BaseException as error:
            if cleanup_error is None:
                cleanup_error = error
    if cleanup_error is not None:
        if isinstance(cleanup_error, subprocess.TimeoutExpired):
            raise EntrypointError(
                "candidate command broker did not terminate"
            ) from cleanup_error
        raise cleanup_error


def run_trusted_bounded(
    command: list[str], timeout_seconds: int, *, cwd: Path = WORKSPACE
) -> bytes:
    token = secrets.token_hex(32)
    state_identity = secrets.token_hex(32)
    gate_root = CANDIDATE_STATE_ROOT / state_identity
    socket_identity = secrets.token_hex(32)
    socket_path = VERIFIER_ROOT / f"broker-{socket_identity}.sock"
    broker_environment = {
        "CHIO_HOST_GID": os.environ.get("CHIO_HOST_GID", ""),
        "CHIO_HOST_UID": os.environ.get("CHIO_HOST_UID", ""),
        "CHIO_SECURITY_IMAGE_ID": os.environ.get("CHIO_SECURITY_IMAGE_ID", ""),
        "CHIO_SECURITY_BROKER_TOKEN": token,
        "CHIO_SECCOMP_PROFILE_SHA256": os.environ.get(
            "CHIO_SECCOMP_PROFILE_SHA256", ""
        ),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "PYTHONNOUSERSITE": "1",
        "PYTHONSAFEPATH": "1",
        "SOURCE_SHA": os.environ.get("SOURCE_SHA", ""),
    }
    broker = subprocess.Popen(
        [
            "/usr/bin/python3",
            "-I",
            os.fspath(TRUSTED_ENTRYPOINT),
            "--broker-server",
            os.fspath(socket_path),
            "--gate-root",
            os.fspath(gate_root),
            "--timeout-seconds",
            str(timeout_seconds),
        ],
        cwd="/",
        env=broker_environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    deadline = time.monotonic() + 30
    while not socket_path.exists():
        if broker.poll() is not None or time.monotonic() >= deadline:
            abandon_broker(broker, socket_path, gate_root)
            raise EntrypointError("candidate command broker did not become ready")
        time.sleep(0.01)
    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=verifier_environment(socket_path, token, gate_root),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            **verifier_process_options(),
        )
        return_code, output = collect_bounded_process(
            process, timeout_seconds, terminate=terminate_verifier_group
        )
        quiesce_verifier_namespace()
        stop_broker(socket_path, token)
        broker_status = broker.wait(timeout=300)
    except BaseException as primary_error:
        cleanup_errors: list[BaseException] = []
        for cleanup in (
            quiesce_verifier_namespace,
            lambda: abandon_broker(broker, socket_path, gate_root),
        ):
            try:
                cleanup()
            except BaseException as cleanup_error:
                cleanup_errors.append(cleanup_error)
        for cleanup_error in cleanup_errors:
            primary_error.add_note(
                f"security boundary cleanup also failed: {cleanup_error!r}"
            )
        raise
    if broker_status != 0:
        raise EntrypointError("candidate command broker failed closed")
    if return_code != 0:
        raise EntrypointError(
            f"trusted verifier failed with status {return_code}: {command[0]}"
        )
    return output


def run_sequence(
    commands: list[list[str]], timeout_seconds: int, *, cwd: Path = WORKSPACE
) -> bytes:
    output = bytearray()
    for command in commands:
        command_output = run_trusted_bounded(command, timeout_seconds, cwd=cwd)
        if len(output) + len(command_output) > MAX_LOG_BYTES:
            raise EntrypointError("isolated command sequence exceeded its output bound")
        output.extend(command_output)
    return bytes(output)


def trusted_checker_arguments(*arguments: str) -> list[str]:
    return [
        "/usr/bin/python3",
        "-I",
        os.fspath(TRUSTED_CHECKER),
        "--root",
        os.fspath(WORKSPACE),
        *arguments,
    ]


def pending_campaigns(timeout_seconds: int) -> frozenset[str]:
    payload = run_trusted_bounded(
        trusted_checker_arguments("--list-pending"), timeout_seconds
    )
    try:
        rendered = payload.decode("ascii")
    except UnicodeDecodeError as error:
        raise EntrypointError("pending campaign inventory is not ASCII") from error
    if rendered and not rendered.endswith("\n"):
        raise EntrypointError("pending campaign inventory is not line-delimited")
    observed = tuple(rendered.splitlines())
    if (
        observed != tuple(sorted(observed))
        or len(observed) != len(set(observed))
        or any(campaign not in ALL_CAMPAIGNS for campaign in observed)
    ):
        raise EntrypointError("pending campaign inventory is not exact")
    return frozenset(observed)


def decode_git_paths(payload: bytes, description: str) -> tuple[str, ...]:
    if not payload:
        return ()
    if not payload.endswith(b"\0"):
        raise EntrypointError(f"{description} is not NUL-delimited")
    try:
        observed = tuple(
            field.decode("utf-8") for field in payload.removesuffix(b"\0").split(b"\0")
        )
    except UnicodeDecodeError as error:
        raise EntrypointError(f"{description} is not UTF-8") from error
    if not observed or any(not field for field in observed):
        raise EntrypointError(f"{description} contains an empty path")
    return observed


def new_evidence_file_patch(
    relative_path: str,
    timeout_seconds: int,
    allowed_paths: tuple[str, ...],
) -> bytes:
    if allowed_paths not in (LINUX_OUTCOME_PATHS, ALL_OUTCOME_PATHS):
        raise EntrypointError("new evidence outcome allowlist is not a fixed mode")
    if relative_path not in allowed_paths:
        raise EntrypointError("new evidence path is outside the mode outcome allowlist")
    path = WORKSPACE / relative_path
    try:
        metadata = path.lstat()
    except OSError as error:
        raise EntrypointError("new Linux outcome is unavailable") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o644
        or metadata.st_uid != VERIFIER_UID
        or metadata.st_gid != VERIFIER_GID
        or metadata.st_nlink != 1
    ):
        raise EntrypointError("new Linux outcome identity is invalid")
    patch = run_trusted_bounded(
        [
            "/bin/bash",
            "-c",
            (
                "set -euo pipefail\n"
                "set +e\n"
                "/usr/bin/git diff --binary --no-ext-diff --no-textconv "
                "--no-renames --no-index -- /dev/null \"$1\"\n"
                "diff_status=$?\n"
                "set -e\n"
                "test \"${diff_status}\" -eq 1\n"
            ),
            "chio-new-linux-outcome-diff",
            relative_path,
        ],
        timeout_seconds,
    )
    expected_prefix = (
        f"diff --git a/{relative_path} b/{relative_path}\n"
        "new file mode 100644\n"
    ).encode("utf-8")
    expected_destination = f"--- /dev/null\n+++ b/{relative_path}\n".encode("utf-8")
    if not patch.startswith(expected_prefix) or expected_destination not in patch:
        raise EntrypointError("new Linux outcome patch identity is invalid")
    return patch


def execution_boundary_record() -> bytes:
    image_id = os.environ.get("CHIO_SECURITY_IMAGE_ID", "")
    seccomp_digest = os.environ.get("CHIO_SECCOMP_PROFILE_SHA256", "")
    if (
        len(image_id) != 71
        or not image_id.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in image_id[7:])
        or len(seccomp_digest) != 64
        or any(character not in "0123456789abcdef" for character in seccomp_digest)
    ):
        raise EntrypointError("execution image or seccomp identity is invalid")
    trusted_files = {
        "cargo-mutants": TRUSTED_CARGO_MUTANTS,
        "check-security-adversarial-evidence.py": TRUSTED_CHECKER,
        "command-client.py": TRUSTED_COMMAND_CLIENT,
        "entrypoint.py": TRUSTED_ENTRYPOINT,
        "security-evidence-seccomp.json": TRUSTED_SECCOMP_PROFILE,
        **{
            f"verifier-bin/{name}": BROKER_BIN / name
            for name in COMMAND_EXECUTABLES
        },
        **{name: TRUSTED_GATE_ROOT / name for name in TRUSTED_GATES},
    }
    record = {
        "image_id": image_id,
        "platform": "linux/amd64",
        "schema": "chio.security-execution-boundary.v1",
        "seccomp_profile_sha256": seccomp_digest,
        "trusted_file_sha256": {
            name: hashlib.sha256(path.read_bytes()).hexdigest()
            for name, path in sorted(trusted_files.items())
        },
    }
    return (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def repository_inventory(timeout_seconds: int) -> tuple[bytes, bytes, bytes]:
    patch = run_trusted_bounded(
        ["/usr/bin/git", "diff", "--binary", "--no-ext-diff", "HEAD", "--"],
        timeout_seconds,
    )
    untracked = run_trusted_bounded(
        ["/usr/bin/git", "ls-files", "--others", "--exclude-standard", "-z"],
        timeout_seconds,
    )
    ignored = run_trusted_bounded(
        [
            "/usr/bin/git",
            "ls-files",
            "--others",
            "--ignored",
            "--exclude-standard",
            "-z",
        ],
        timeout_seconds,
    )
    return patch, untracked, ignored


def require_exact_repository_inventory(
    expected: tuple[bytes, bytes, bytes], timeout_seconds: int
) -> None:
    if repository_inventory(timeout_seconds) != expected:
        raise EntrypointError(
            "candidate repository inventory changed before publication"
        )


def require_clean_repository(timeout_seconds: int) -> None:
    require_exact_repository_inventory((b"", b"", b""), timeout_seconds)


def publish_regular(name: str, payload: bytes) -> None:
    quiesce_process_namespace()
    if not name or "/" in name or len(payload) > MAX_LOG_BYTES * 4:
        raise EntrypointError("trusted output publication request is invalid")
    target = OUTPUT / name
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    host_uid = numeric_environment("CHIO_HOST_UID")
    host_gid = numeric_environment("CHIO_HOST_GID")
    with effective_identity(host_uid, host_gid):
        descriptor = os.open(target, flags, 0o600)
        try:
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise EntrypointError("trusted output publication made no progress")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def adversarial_release(timeout_seconds: int) -> None:
    log = run_trusted_bounded(trusted_checker_arguments("--release"), timeout_seconds)
    require_clean_repository(timeout_seconds)
    publish_regular("adversarial-evidence.log", execution_boundary_record() + log)


def linux_enforcement(timeout_seconds: int) -> None:
    runner_log = execution_boundary_record() + run_trusted_bounded(
        [
            "/usr/bin/python3",
            "-I",
            "/opt/chio-security/gates/check-linux-enforcement-stack.py",
            "--root",
            os.fspath(WORKSPACE),
        ],
        timeout_seconds,
    )
    committed_log = run_trusted_bounded(
        trusted_checker_arguments("--require-complete"), timeout_seconds
    )
    key_log = run_trusted_bounded(
        [
            "/bin/bash",
            "/opt/chio-security/gates/check-keyring-transparency.sh",
        ],
        timeout_seconds,
    )
    broker_log = run_trusted_bounded(
        [
            "/bin/bash",
            "/opt/chio-security/gates/check-secret-broker-boundary.sh",
            "--release",
        ],
        timeout_seconds,
    )
    cage_log = run_trusted_bounded(
        [
            "/bin/bash",
            "/opt/chio-security/gates/check-cage-enforcement.sh",
            "--release",
        ],
        timeout_seconds,
    )
    campaign_commands = []
    for campaign in LINUX_CAMPAIGNS:
        campaign_commands.append(
            trusted_checker_arguments(
                "--campaign",
                campaign,
            )
        )
    campaign_log = run_sequence(campaign_commands, timeout_seconds)
    migration_log = run_candidate_bounded(
        [
            "/usr/local/cargo/bin/cargo",
            "test",
            "--offline",
            "-p",
            "chio-store-sqlite",
            "--test",
            "enterprise_migration_state",
        ],
        timeout_seconds,
    )
    run_candidate_bounded(
        [
            "/usr/local/cargo/bin/cargo",
            "clippy",
            "--offline",
            "-p",
            "chio-cage",
            "--all-targets",
            "--features",
            "real-linux-enforcement",
            "--",
            "-D",
            "warnings",
        ],
        timeout_seconds,
    )
    require_clean_repository(timeout_seconds)
    for name, payload in (
        ("runner-contract.log", runner_log),
        ("committed-adversarial-evidence.log", committed_log),
        ("key-log-transparency.log", key_log),
        ("broker-boundary.log", broker_log),
        ("cage-enforcement.log", cage_log),
        ("linux-adversarial-controls.log", campaign_log),
        ("migration-state-store.log", migration_log),
    ):
        publish_regular(name, payload)


def refresh_evidence(
    timeout_seconds: int,
    campaigns: tuple[str, ...],
    paths: tuple[str, ...],
    *,
    full_inventory: bool,
) -> None:
    if full_inventory:
        expected_campaigns = ALL_CAMPAIGNS
        expected_paths = ALL_REFRESH_PATHS
        promotable_campaigns = ALL_CAMPAIGNS
        new_outcome_paths = ALL_OUTCOME_PATHS
    else:
        expected_campaigns = LINUX_CAMPAIGNS
        expected_paths = REFRESH_PATHS
        promotable_campaigns = LINUX_CAMPAIGNS
        new_outcome_paths = LINUX_OUTCOME_PATHS
    if campaigns != expected_campaigns or paths != expected_paths:
        raise EntrypointError("evidence refresh mode inventory is not exact")
    pending = pending_campaigns(timeout_seconds)
    commands = []
    for campaign in campaigns:
        if campaign in pending:
            if campaign not in promotable_campaigns:
                raise EntrypointError(
                    "campaign is outside the mode's initial promotion inventory"
                )
            commands.append(
                trusted_checker_arguments("--promote-pending-outcome", campaign)
            )
        else:
            commands.append(trusted_checker_arguments("--refresh-outcome", campaign))
    run_sequence(
        commands,
        timeout_seconds,
    )
    run_trusted_bounded(
        trusted_checker_arguments("--require-complete"), timeout_seconds
    )
    tracked_patch, untracked_payload, ignored = repository_inventory(timeout_seconds)
    names = run_trusted_bounded(
        ["/usr/bin/git", "diff", "--name-only", "-z", "--no-ext-diff", "HEAD", "--"],
        timeout_seconds,
    )
    tracked_paths = decode_git_paths(names, "refreshed tracked evidence inventory")
    untracked_paths = decode_git_paths(
        untracked_payload, "refreshed untracked evidence inventory"
    )
    if set(tracked_paths) & set(untracked_paths):
        raise EntrypointError("refreshed evidence path inventories overlap")
    expected_untracked = tuple(
        sorted(
            OUTCOME_PATH_BY_CAMPAIGN[campaign]
            for campaign in campaigns
            if campaign in pending
        )
    )
    if tuple(sorted(untracked_paths)) != expected_untracked:
        raise EntrypointError("initial promotion created an unexpected untracked path")
    observed = tuple(sorted((*tracked_paths, *untracked_paths)))
    if observed != tuple(sorted(paths)):
        raise EntrypointError(
            "refreshed evidence changed paths outside the exact allowlist"
        )
    if ignored:
        raise EntrypointError("refreshed evidence created an ignored path")
    new_file_patches = b"".join(
        new_evidence_file_patch(path, timeout_seconds, new_outcome_paths)
        for path in expected_untracked
    )
    patch = tracked_patch + new_file_patches
    if not patch:
        raise EntrypointError("refreshed evidence patch is empty")
    source_sha = candidate_environment()["SOURCE_SHA"]
    if len(source_sha) != 40 or any(
        character not in "0123456789abcdef" for character in source_sha
    ):
        raise EntrypointError("refreshed evidence source identity is invalid")
    checksum = hashlib.sha256(patch).hexdigest()
    patch_name = "all-evidence.patch" if full_inventory else "linux-evidence.patch"
    inventory_payload: bytes | None = None
    if full_inventory:
        inventory = {
            "campaign_count": len(campaigns),
            "campaigns": list(campaigns),
            "case_count": len(
                {case for _campaign, _outcome, case in ALL_REFRESH_INVENTORY}
            ),
            "outcome_count": len(ALL_REFRESH_INVENTORY),
            "patch_sha256": checksum,
            "paths": list(paths),
            "schema": "chio.security-evidence-refresh.v1",
            "source_sha": source_sha,
            "execution_boundary": json.loads(execution_boundary_record()),
        }
        inventory_payload = (
            json.dumps(inventory, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")
    require_exact_repository_inventory(
        (tracked_patch, untracked_payload, ignored), timeout_seconds
    )
    if inventory_payload is not None:
        publish_regular(
            "all-evidence-inventory.json",
            inventory_payload,
        )
    publish_regular(patch_name, patch)
    publish_regular(
        f"{patch_name}.sha256",
        f"{checksum}  {patch_name}\n".encode("ascii"),
    )
    publish_regular("source-sha.txt", f"{source_sha}\n".encode("ascii"))


def hostile_probe(timeout_seconds: int, cargo: bool) -> None:
    detached_sentinel = Path("/tmp/detached-candidate-poison")
    detached_sentinel.unlink(missing_ok=True)
    if cargo:
        log = run_trusted_bounded(
            [
                "/bin/bash",
                "-c",
                "set -euo pipefail\ncargo test --offline --locked\ncargo --version\n",
            ],
            timeout_seconds,
        )
    else:
        log = run_candidate_bounded(
            ["/usr/bin/python3", "probe.py"], timeout_seconds
        )
    # A detached candidate may create the sentinel while its command is still
    # authorized.  Quiescence is proven only if it cannot recreate the marker
    # after the supervisor has returned and removed that in-command write.
    detached_sentinel.unlink(missing_ok=True)
    time.sleep(2)
    if detached_sentinel.exists():
        raise EntrypointError("detached candidate process survived command quiescence")
    authority_log = run_trusted_bounded(
        ["/usr/bin/python3", "-I", os.fspath(TRUSTED_CHECKER), "--help"],
        timeout_seconds,
    )
    publish_regular(
        "probe.log",
        (log or b"probe completed\n")
        + b"detached candidate quiescence verified\n"
        + authority_log,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "operation",
        nargs="?",
        choices=(
            "adversarial-release",
            "hostile-cargo-probe",
            "hostile-probe",
            "linux-enforcement",
            "refresh-all-evidence",
            "refresh-linux-evidence",
        ),
    )
    parser.add_argument("--timeout-seconds", required=True, type=int)
    parser.add_argument("--broker-server", type=Path)
    parser.add_argument("--gate-root", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not 10 <= args.timeout_seconds <= 21600:
        raise EntrypointError("operation timeout is outside the trusted bound")
    internal_arguments = (
        args.broker_server,
        args.gate_root,
    )
    internal_invocation = any(value is not None for value in internal_arguments)
    validate_supervisor_boundary(setup=not internal_invocation)
    if internal_invocation:
        broker_token = os.environ.get("CHIO_SECURITY_BROKER_TOKEN", "")
        if (
            args.operation is not None
            or any(value is None for value in internal_arguments)
            or len(broker_token) != 64
            or any(
                character not in "0123456789abcdef"
                for character in broker_token
            )
            or len(args.gate_root.name) != 64
            or any(
                character not in "0123456789abcdef"
                for character in args.gate_root.name
            )
        ):
            raise EntrypointError("candidate command broker invocation is invalid")
        return broker_server(
            args.broker_server,
            broker_token,
            args.gate_root,
            args.timeout_seconds,
        )
    if args.operation is None:
        raise EntrypointError("security execution operation is required")
    prepare_private_runtime()
    initialize_baseline()
    if args.operation == "adversarial-release":
        adversarial_release(args.timeout_seconds)
    elif args.operation == "linux-enforcement":
        linux_enforcement(args.timeout_seconds)
    elif args.operation == "refresh-linux-evidence":
        refresh_evidence(
            args.timeout_seconds,
            LINUX_CAMPAIGNS,
            REFRESH_PATHS,
            full_inventory=False,
        )
    elif args.operation == "refresh-all-evidence":
        refresh_evidence(
            args.timeout_seconds,
            ALL_CAMPAIGNS,
            ALL_REFRESH_PATHS,
            full_inventory=True,
        )
    elif args.operation == "hostile-probe":
        hostile_probe(args.timeout_seconds, False)
    elif args.operation == "hostile-cargo-probe":
        hostile_probe(args.timeout_seconds, True)
    else:
        raise EntrypointError("unreachable operation")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except EntrypointError as error:
        print(f"security execution entrypoint failed: {error}", file=sys.stderr)
        raise SystemExit(1)
