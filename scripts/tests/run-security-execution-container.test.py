#!/usr/bin/env python3

from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER_PATH = ROOT / "scripts/run-security-execution-container.py"
ENTRYPOINT_PATH = ROOT / "scripts/security-execution-container-entrypoint.py"
DOCKERFILE_PATH = ROOT / "deploy/docker/Dockerfile.security-evidence-runner"
SECCOMP_PATH = ROOT / "deploy/docker/security-evidence-seccomp.json"
SPEC = importlib.util.spec_from_file_location(
    "security_execution_boundary", RUNNER_PATH
)
if SPEC is None or SPEC.loader is None:
    raise SystemExit("unable to load security execution boundary")
BOUNDARY = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BOUNDARY
SPEC.loader.exec_module(BOUNDARY)
ENTRYPOINT_SPEC = importlib.util.spec_from_file_location(
    "security_execution_entrypoint", ENTRYPOINT_PATH
)
if ENTRYPOINT_SPEC is None or ENTRYPOINT_SPEC.loader is None:
    raise SystemExit("unable to load security execution entrypoint")
ENTRYPOINT = importlib.util.module_from_spec(ENTRYPOINT_SPEC)
ENTRYPOINT_SPEC.loader.exec_module(ENTRYPOINT)


def run(
    command: list[str], *, cwd: Path, environment: dict[str, str] | None = None
) -> str:
    result = subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=180,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"command failed: {command!r}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result.stdout


def initialize_repository(
    root: Path, files: dict[str, str], executable: tuple[str, ...] = ()
) -> str:
    root.mkdir(parents=True)
    run(["git", "init", "--quiet"], cwd=root)
    run(["git", "config", "user.name", "Boundary test"], cwd=root)
    run(["git", "config", "user.email", "boundary-test@invalid"], cwd=root)
    for name, body in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    for name in executable:
        (root / name).chmod(0o755)
    run(["git", "add", "--all"], cwd=root)
    run(["git", "commit", "--quiet", "-m", "fixture"], cwd=root)
    return run(["git", "rev-parse", "HEAD"], cwd=root).strip()


def assert_rejected(label: str, callback) -> None:
    try:
        callback()
    except BOUNDARY.BoundaryError:
        return
    raise AssertionError(
        f"security execution boundary accepted hostile output: {label}"
    )


def static_contract_tests() -> None:
    dockerfile = DOCKERFILE_PATH.read_text(encoding="utf-8")
    expected_base = (
        "FROM --platform=linux/amd64 rust:1.93.0-alpine3.22@sha256:"
        "efc08a6cc70a6ad8bdcf24176e3e0bdbbc7b984e7471fabf78b90de33b136f51"
    )
    if expected_base not in dockerfile:
        raise AssertionError(
            "security image base is not pinned to the reviewed Rust 1.93 digest"
        )
    for marker in (
        "bash=5.2.37-r0",
        "security-evidence-apk.lock",
        "1148e06bad43e30705b952c61d5d3a493b19b67be02ac281d8008df22dc05503",
        "a78e673aa77a24f1e47fce31ba61cf4937450976da91e33c406476a5263742a1",
        "47040c9cded7996c38b9976af0a9c46c4902ec5eb59369fffec758410dba8028",
        "cargo install \\",
        "--path /tmp/cargo-mutants-25.3.1",
        "chmod 0755 /usr/local/cargo /usr/local/cargo/bin",
        "chmod 0555 /usr/local/cargo/bin/cargo-mutants",
        'test "$(rustc --version | cut -d\' \' -f1-2)" = "rustc 1.93.0"',
        'test "$(cargo clippy --version | cut -d\' \' -f1)" = "clippy"',
        'test "$(cargo fmt --version | cut -d\' \' -f1)" = "rustfmt"',
        'ENTRYPOINT ["/usr/bin/python3", "-I", "/opt/chio-security/entrypoint.py"]',
        "/opt/chio-security/command-client.py",
        "/opt/chio-security/verifier-bin/cargo",
        "security-evidence-seccomp.json",
        "/opt/chio-security/gates/check-cage-linux-enforcement.sh",
    ):
        if marker not in dockerfile:
            raise AssertionError(
                f"security image tooling contract is missing: {marker}"
            )

    entrypoint = ENTRYPOINT_PATH.read_text(encoding="utf-8")
    if "/private/candidate/scripts/check-security-adversarial-evidence" in entrypoint:
        raise AssertionError("candidate evidence checker is executable authority")
    if "/opt/chio-security/check-security-adversarial-evidence.py" not in entrypoint:
        raise AssertionError(
            "authorized evidence checker is not the container authority"
        )
    if "Path(\"/usr/local/cargo/bin/cargo-mutants\")" not in entrypoint:
        raise AssertionError("cargo-mutants is not a fixed trusted executable")
    profile = json.loads(SECCOMP_PATH.read_text(encoding="utf-8"))
    if profile != BOUNDARY.expected_seccomp_profile():
        raise AssertionError(
            "trusted seccomp profile is not the exact reviewed profile"
        )

    with tempfile.TemporaryDirectory(prefix="chio-boundary-static-") as raw:
        temporary = Path(raw)
        seccomp_mutations = []
        for label in (
            "default-action",
            "architecture",
            "syscall-inventory",
            "syscall-action",
            "syscall-errno",
            "clone-mask",
        ):
            mutation = json.loads(json.dumps(profile))
            if label == "default-action":
                mutation["defaultAction"] = "SCMP_ACT_ERRNO"
            elif label == "architecture":
                mutation["archMap"][0]["architecture"] = "SCMP_ARCH_AARCH64"
            elif label == "syscall-inventory":
                mutation["syscalls"][0]["names"].pop()
            elif label == "syscall-action":
                mutation["syscalls"][0]["action"] = "SCMP_ACT_LOG"
            elif label == "syscall-errno":
                mutation["syscalls"][0]["errnoRet"] = 13
            else:
                mutation["syscalls"][1]["args"][0]["valueTwo"] = 0
            seccomp_mutations.append((label, mutation))
        for label, mutation in seccomp_mutations:
            mutant = temporary / f"seccomp-{label}.json"
            mutant.write_text(json.dumps(mutation), encoding="utf-8")
            assert_rejected(
                f"seccomp {label} mutation",
                lambda mutant=mutant: BOUNDARY.validate_seccomp_profile(mutant),
            )

        arguments = BOUNDARY.container_create_arguments(
            name="chio-security-test",
            cidfile=temporary / "container.cid",
            authority_scope="a" * 24,
            state_identity="d" * 24,
            image="sha256:" + "b" * 64,
            operation="linux-enforcement",
            source=temporary / "private-work",
            output=temporary / "private-output",
            seccomp_profile=SECCOMP_PATH,
            source_sha="c" * 40,
            timeout_seconds=60,
        )
        uid = os.getuid()
        gid = os.getgid()
        expected_arguments = [
            "create",
            "--platform",
            "linux/amd64",
            "--name",
            "chio-security-test",
            "--cidfile",
            os.fspath(temporary / "container.cid"),
            "--label",
            BOUNDARY.MANAGED_LABEL,
            "--label",
            f"{BOUNDARY.AUTHORITY_LABEL}={'a' * 24}",
            "--label",
            f"{BOUNDARY.STATE_LABEL}={'d' * 24}",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--cap-add",
            "CHOWN",
            "--cap-add",
            "SETGID",
            "--cap-add",
            "SETUID",
            "--security-opt",
            "no-new-privileges",
            "--security-opt",
            f"seccomp={SECCOMP_PATH}",
            "--pids-limit",
            "512",
            "--memory",
            "12g",
            "--memory-swap",
            "12g",
            "--cpus",
            "4",
            "--ulimit",
            "core=0:0",
            "--ulimit",
            "fsize=1073741824:1073741824",
            "--ulimit",
            "nofile=1024:1024",
            "--init",
            "--log-driver",
            "none",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,size=536870912,mode=1777",
            "--tmpfs",
            "/private:rw,nosuid,nodev,size=2147483648,uid=0,gid=0,mode=0755",
            "--tmpfs",
            "/baseline:rw,nosuid,nodev,noexec,size=268435456,mode=0755",
            "--tmpfs",
            "/target:rw,nosuid,nodev,size=8589934592,uid=65532,gid=65532,mode=0700",
            "--tmpfs",
            "/cargo-home:rw,nosuid,nodev,noexec,size=2147483648,uid=65532,gid=65532,mode=0700",
            "--mount",
            f"type=bind,src={temporary / 'private-work'},dst=/source,readonly",
            "--mount",
            f"type=bind,src={temporary / 'private-output'},dst=/output",
        ]
        expected_environment = {
            "CARGO_BUILD_JOBS": "1",
            "CARGO_HOME": "/cargo-home",
            "CARGO_INCREMENTAL": "0",
            "CARGO_NET_OFFLINE": "true",
            "CARGO_PROFILE_DEV_DEBUG": "0",
            "CARGO_PROFILE_TEST_DEBUG": "0",
            "CARGO_TARGET_DIR": "/target",
            "CARGO_TERM_COLOR": "never",
            "CHIO_ENTERPRISE_SECURITY_RUNNER": "1",
            "CHIO_HOST_GID": str(gid),
            "CHIO_HOST_UID": str(uid),
            "CHIO_SECURITY_IMAGE_ID": "sha256:" + "b" * 64,
            "CHIO_SECCOMP_PROFILE_SHA256": hashlib.sha256(
                SECCOMP_PATH.read_bytes()
            ).hexdigest(),
            "HOME": "/tmp/home",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": "/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "RUSTUP_HOME": "/usr/local/rustup",
            "SOURCE_SHA": "c" * 40,
        }
        for key, value in sorted(expected_environment.items()):
            expected_arguments.extend(["--env", f"{key}={value}"])
        expected_arguments.extend(
            ["sha256:" + "b" * 64, "linux-enforcement", "--timeout-seconds", "60"]
        )
        if arguments != expected_arguments:
            raise AssertionError("Docker create argument contract changed")
        BOUNDARY.validate_container_create_arguments(arguments)
        create_mutations = {
            "duplicate network override": [
                *arguments[:14],
                "--network",
                "host",
                *arguments[14:],
            ],
            "extra mount": [
                *arguments[: arguments.index("sha256:" + "b" * 64)],
                "--mount",
                "type=bind,src=/,dst=/host,readonly",
                *arguments[arguments.index("sha256:" + "b" * 64) :],
            ],
            "relaxed pids": [
                "0" if index == arguments.index("--pids-limit") + 1 else value
                for index, value in enumerate(arguments)
            ],
            "relaxed memory": [
                "0" if index == arguments.index("--memory") + 1 else value
                for index, value in enumerate(arguments)
            ],
            "relaxed CPU": [
                "0" if index == arguments.index("--cpus") + 1 else value
                for index, value in enumerate(arguments)
            ],
        }
        for label, mutation in create_mutations.items():
            assert_rejected(
                label,
                lambda mutation=mutation: BOUNDARY.validate_container_create_arguments(
                    mutation
                ),
            )
        joined = "\n".join(arguments)
        for forbidden in (
            "/var/run/docker.sock",
            "GITHUB_TOKEN",
            "GH_TOKEN",
            "SSH_AUTH_SOCK",
            "RUSTC_WRAPPER=",
            "RUSTC_WORKSPACE_WRAPPER=",
            "seccomp=unconfined",
        ):
            if forbidden in joined:
                raise AssertionError(
                    f"container boundary leaks forbidden capability: {forbidden}"
                )


def copy_and_output_tests() -> None:
    with tempfile.TemporaryDirectory(prefix="chio-boundary-copy-") as raw:
        temporary = Path(raw).resolve()
        repository = temporary / "candidate"
        head = initialize_repository(
            repository,
            {"plain.txt": "authority\n", "bin/tool.sh": "#!/bin/sh\nexit 0\n"},
            executable=("bin/tool.sh",),
        )
        os.symlink("plain.txt", repository / "link.txt")
        run(["git", "add", "link.txt"], cwd=repository)
        run(["git", "commit", "--quiet", "--amend", "--no-edit"], cwd=repository)
        head = run(["git", "rev-parse", "HEAD"], cwd=repository).strip()
        identity = BOUNDARY.repository_identity(repository, head, None)
        private = temporary / "private"
        BOUNDARY.materialize_private_copy(identity, private)
        if (private / "plain.txt").read_bytes() != b"authority\n":
            raise AssertionError("private copy changed Git blob bytes")
        if (
            not (private / "link.txt").is_symlink()
            or os.readlink(private / "link.txt") != "plain.txt"
        ):
            raise AssertionError(
                "private copy did not preserve a candidate symlink as a symlink"
            )
        authority_stat = (repository / "plain.txt").stat()
        private_stat = (private / "plain.txt").stat()
        if (authority_stat.st_dev, authority_stat.st_ino) == (
            private_stat.st_dev,
            private_stat.st_ino,
        ):
            raise AssertionError("private candidate copy is hardlinked to authority")

        stage = temporary / "stage"
        stage.mkdir()
        (stage / "probe.log").write_bytes(b"bounded\n")
        image = "sha256:" + "b" * 64
        seccomp_digest = "c" * 64
        accepted = BOUNDARY.collect_outputs(
            stage, "hostile-probe", head, image, seccomp_digest
        )
        if accepted != {"probe.log": b"bounded\n"}:
            raise AssertionError("regular bounded output changed during import")

        (stage / "probe.log").unlink()
        os.symlink("missing", stage / "probe.log")
        assert_rejected(
            "symlink",
            lambda: BOUNDARY.collect_outputs(
                stage, "hostile-probe", head, image, seccomp_digest
            ),
        )
        (stage / "probe.log").unlink()
        os.mkfifo(stage / "probe.log")
        assert_rejected(
            "fifo",
            lambda: BOUNDARY.collect_outputs(
                stage, "hostile-probe", head, image, seccomp_digest
            ),
        )
        (stage / "probe.log").unlink()
        (stage / "probe.log").write_bytes(b"bounded\n")
        os.link(stage / "probe.log", stage / "hardlink")
        assert_rejected(
            "hardlink and extra path",
            lambda: BOUNDARY.collect_outputs(
                stage, "hostile-probe", head, image, seccomp_digest
            ),
        )
        (stage / "hardlink").unlink()
        (stage / "extra").write_bytes(b"extra")
        assert_rejected(
            "extra path",
            lambda: BOUNDARY.collect_outputs(
                stage, "hostile-probe", head, image, seccomp_digest
            ),
        )

        refresh_stage = temporary / "refresh-stage"
        refresh_stage.mkdir()
        patch = b"reviewed evidence patch\n"
        patch_sha = hashlib.sha256(patch).hexdigest()
        (refresh_stage / "all-evidence.patch").write_bytes(patch)
        (refresh_stage / "all-evidence.patch.sha256").write_text(
            f"{patch_sha}  all-evidence.patch\n", encoding="ascii"
        )
        (refresh_stage / "source-sha.txt").write_text(f"{head}\n", encoding="ascii")
        boundary_files = {
            name: "d" * 64 for name in BOUNDARY.TRUSTED_BOUNDARY_FILE_KEYS
        }
        if len(boundary_files) != 15 or "cargo-mutants" not in boundary_files:
            raise AssertionError("trusted boundary file inventory changed")

        def write_inventory(files: dict[str, str]) -> None:
            inventory = {
                "campaign_count": 35,
                "campaigns": [f"campaign-{index}" for index in range(35)],
                "case_count": 28,
                "execution_boundary": {
                    "image_id": image,
                    "platform": "linux/amd64",
                    "schema": "chio.security-execution-boundary.v1",
                    "seccomp_profile_sha256": seccomp_digest,
                    "trusted_file_sha256": files,
                },
                "outcome_count": 35,
                "patch_sha256": patch_sha,
                "paths": [f"path-{index}" for index in range(64)],
                "schema": "chio.security-evidence-refresh.v1",
                "source_sha": head,
            }
            (refresh_stage / "all-evidence-inventory.json").write_text(
                json.dumps(inventory, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )

        write_inventory(boundary_files)
        BOUNDARY.collect_outputs(
            refresh_stage, "refresh-all-evidence", head, image, seccomp_digest
        )
        inventory_path = refresh_stage / "all-evidence-inventory.json"
        invalid_boundary = json.loads(inventory_path.read_text(encoding="utf-8"))
        invalid_boundary["execution_boundary"]["schema"] = "untrusted.v1"
        inventory_path.write_text(
            json.dumps(invalid_boundary, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        assert_rejected(
            "invalid execution boundary schema",
            lambda: BOUNDARY.collect_outputs(
                refresh_stage,
                "refresh-all-evidence",
                head,
                image,
                seccomp_digest,
            ),
        )
        write_inventory(boundary_files)
        extra_boundary = json.loads(inventory_path.read_text(encoding="utf-8"))
        extra_boundary["execution_boundary"]["candidate_path"] = "/workspace/tool"
        inventory_path.write_text(
            json.dumps(extra_boundary, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        assert_rejected(
            "extra execution boundary authority",
            lambda: BOUNDARY.collect_outputs(
                refresh_stage,
                "refresh-all-evidence",
                head,
                image,
                seccomp_digest,
            ),
        )
        write_inventory(boundary_files)
        missing_files = dict(boundary_files)
        missing_files.pop("cargo-mutants")
        write_inventory(missing_files)
        assert_rejected(
            "missing trusted boundary hash",
            lambda: BOUNDARY.collect_outputs(
                refresh_stage,
                "refresh-all-evidence",
                head,
                image,
                seccomp_digest,
            ),
        )
        extra_files = dict(boundary_files)
        extra_files["candidate-controlled.py"] = "e" * 64
        write_inventory(extra_files)
        assert_rejected(
            "extra trusted boundary hash",
            lambda: BOUNDARY.collect_outputs(
                refresh_stage,
                "refresh-all-evidence",
                head,
                image,
                seccomp_digest,
            ),
        )
        substituted_files = dict(boundary_files)
        substituted_files["cargo-mutants"] = "not-a-sha256"
        write_inventory(substituted_files)
        assert_rejected(
            "substituted trusted boundary hash",
            lambda: BOUNDARY.collect_outputs(
                refresh_stage,
                "refresh-all-evidence",
                head,
                image,
                seccomp_digest,
            ),
        )

        escaping = temporary / "escaping"
        escaping_head = initialize_repository(escaping, {"plain.txt": "safe\n"})
        os.symlink("../../outside", escaping / "escape")
        run(["git", "add", "escape"], cwd=escaping)
        run(["git", "commit", "--quiet", "--amend", "--no-edit"], cwd=escaping)
        escaping_head = run(["git", "rev-parse", "HEAD"], cwd=escaping).strip()
        escaping_identity = BOUNDARY.repository_identity(escaping, escaping_head, None)
        assert_rejected(
            "escaping source symlink",
            lambda: BOUNDARY.materialize_private_copy(
                escaping_identity, temporary / "escaping-copy"
            ),
        )

        real_parent = temporary / "real-state-parent"
        real_parent.mkdir()
        alias_parent = temporary / "aliased-state-parent"
        alias_parent.symlink_to(real_parent, target_is_directory=True)
        assert_rejected(
            "state parent symlink",
            lambda: BOUNDARY.prepare_state_directory(alias_parent / "state"),
        )
        state = real_parent / "state"
        BOUNDARY.prepare_state_directory(state)
        lock_target = real_parent / "lock-target"
        lock_target.write_text("", encoding="ascii")
        (state / "lock").symlink_to(lock_target)
        assert_rejected(
            "state lock symlink",
            lambda: BOUNDARY.open_private_lock(state / "lock"),
        )


def refresh_inventory_tests() -> None:
    inventory = ENTRYPOINT.ALL_REFRESH_INVENTORY
    campaigns = [campaign for campaign, _outcome, _case in inventory]
    outcomes = [outcome for _campaign, outcome, _case in inventory]
    cases = [case for _campaign, _outcome, case in inventory]
    expected_outcomes: list[str] = []
    for case_path in (
        ROOT / "crates/core/chio-adversarial-suite/cases"
    ).glob("*/*.json"):
        case_body = json.loads(case_path.read_text(encoding="utf-8"))
        artifact = case_body.get("artifact")
        if not isinstance(artifact, dict):
            continue
        artifact_campaigns = artifact.get("campaigns")
        if not isinstance(artifact_campaigns, list):
            continue
        expected_outcomes.extend(
            campaign["outcomes"]["path"] for campaign in artifact_campaigns
        )
    expected_outcomes.sort()
    if (
        len(inventory) != 35
        or len(set(campaigns)) != 35
        or len(set(outcomes)) != 35
        or len(set(cases)) != 28
        or len(ENTRYPOINT.ALL_REFRESH_PATHS) != 64
        or sorted(outcomes) != expected_outcomes
        or tuple(campaigns) != ENTRYPOINT.ALL_CAMPAIGNS
    ):
        raise AssertionError("complete evidence refresh inventory is not exact")
    expected_paths = {
        "crates/core/chio-adversarial-suite/manifest.json",
        *outcomes,
        *cases,
    }
    if set(ENTRYPOINT.ALL_REFRESH_PATHS) != expected_paths:
        raise AssertionError("complete evidence refresh allowlist is not exact")


def pending_promotion_tests() -> None:
    def assert_entrypoint_rejected(label: str, callback) -> None:
        try:
            callback()
        except ENTRYPOINT.EntrypointError:
            return
        raise AssertionError(f"entrypoint accepted invalid pending promotion: {label}")

    with mock.patch.object(
        ENTRYPOINT,
        "run_trusted_bounded",
        return_value=b"broker_plaintext_custody\nsandbox_path_swap\n",
    ):
        if ENTRYPOINT.pending_campaigns(30) != frozenset(
            {"broker_plaintext_custody", "sandbox_path_swap"}
        ):
            raise AssertionError("pending campaign inventory was not preserved")
    for label, payload in (
        ("unsorted", b"sandbox_path_swap\nbroker_plaintext_custody\n"),
        ("duplicate", b"sandbox_path_swap\nsandbox_path_swap\n"),
        ("unknown", b"candidate_selected_campaign\n"),
        ("unterminated", b"sandbox_path_swap"),
        ("non-ASCII", b"sandbox_path_swap\xff\n"),
    ):
        with mock.patch.object(
            ENTRYPOINT, "run_trusted_bounded", return_value=payload
        ):
            assert_entrypoint_rejected(
                label, lambda: ENTRYPOINT.pending_campaigns(30)
            )

    pending_campaign = "broker_plaintext_custody"
    refreshed_campaign = "sandbox_path_swap"
    pending_outcome = ENTRYPOINT.OUTCOME_PATH_BY_CAMPAIGN[pending_campaign]
    campaigns = ENTRYPOINT.LINUX_CAMPAIGNS
    paths = ENTRYPOINT.REFRESH_PATHS
    tracked_names = "".join(
        f"{path}\0" for path in paths if path != pending_outcome
    ).encode("utf-8")
    tracked_patch = b"tracked evidence patch\n"
    new_patch = b"new Linux outcome patch\n"
    untracked = f"{pending_outcome}\0".encode("utf-8")
    publications: dict[str, bytes] = {}

    def trusted_refresh_command(
        command: list[str], _timeout_seconds: int, *, cwd=ENTRYPOINT.WORKSPACE
    ) -> bytes:
        del cwd
        if "--require-complete" in command:
            return b"complete\n"
        if "--name-only" in command:
            return tracked_names
        raise AssertionError(f"unexpected trusted refresh command: {command!r}")

    sequence = mock.Mock()
    exact_inventory = mock.Mock()
    with (
        mock.patch.object(
            ENTRYPOINT,
            "pending_campaigns",
            return_value=frozenset({pending_campaign}),
        ),
        mock.patch.object(ENTRYPOINT, "run_sequence", sequence),
        mock.patch.object(
            ENTRYPOINT,
            "run_trusted_bounded",
            side_effect=trusted_refresh_command,
        ),
        mock.patch.object(
            ENTRYPOINT,
            "repository_inventory",
            return_value=(tracked_patch, untracked, b""),
        ),
        mock.patch.object(
            ENTRYPOINT,
            "new_evidence_file_patch",
            return_value=new_patch,
        ) as new_file_patch,
        mock.patch.object(
            ENTRYPOINT,
            "candidate_environment",
            return_value={"SOURCE_SHA": "a" * 40},
        ),
        mock.patch.object(
            ENTRYPOINT, "require_exact_repository_inventory", exact_inventory
        ),
        mock.patch.object(
            ENTRYPOINT,
            "publish_regular",
            side_effect=lambda name, payload: publications.setdefault(name, payload),
        ),
    ):
        ENTRYPOINT.refresh_evidence(
            30,
            campaigns,
            paths,
            full_inventory=False,
        )
    commands = sequence.call_args.args[0]
    commands_by_campaign = dict(zip(campaigns, commands, strict=True))
    if (
        "--promote-pending-outcome" not in commands_by_campaign[pending_campaign]
        or pending_campaign not in commands_by_campaign[pending_campaign]
        or "--refresh-outcome" not in commands_by_campaign[refreshed_campaign]
        or refreshed_campaign not in commands_by_campaign[refreshed_campaign]
    ):
        raise AssertionError("pending and promoted campaigns used the wrong operations")
    if new_file_patch.call_args.args != (
        pending_outcome,
        30,
        ENTRYPOINT.LINUX_OUTCOME_PATHS,
    ):
        raise AssertionError("new Linux outcome did not use the exact patch path")
    exact_inventory.assert_called_once_with((tracked_patch, untracked, b""), 30)
    combined_patch = tracked_patch + new_patch
    combined_digest = hashlib.sha256(combined_patch).hexdigest()
    if (
        publications.get("linux-evidence.patch") != combined_patch
        or publications.get("linux-evidence.patch.sha256")
        != f"{combined_digest}  linux-evidence.patch\n".encode("ascii")
        or publications.get("source-sha.txt") != b"a" * 40 + b"\n"
    ):
        raise AssertionError("initial promotion publication was not source-bound")

    full_pending = frozenset({"broker_plaintext_custody", "grant_replay"})
    full_pending_paths = tuple(
        sorted(ENTRYPOINT.OUTCOME_PATH_BY_CAMPAIGN[name] for name in full_pending)
    )
    full_tracked_names = "".join(
        f"{path}\0"
        for path in ENTRYPOINT.ALL_REFRESH_PATHS
        if path not in full_pending_paths
    ).encode("utf-8")
    full_untracked = "".join(f"{path}\0" for path in full_pending_paths).encode(
        "utf-8"
    )
    full_tracked_patch = b"full tracked evidence patch\n"
    full_publications: dict[str, bytes] = {}

    def trusted_full_refresh_command(
        command: list[str], _timeout_seconds: int, *, cwd=ENTRYPOINT.WORKSPACE
    ) -> bytes:
        del cwd
        if "--require-complete" in command:
            return b"complete\n"
        if "--name-only" in command:
            return full_tracked_names
        raise AssertionError(f"unexpected full refresh command: {command!r}")

    def full_new_file_patch(
        path: str, timeout_seconds: int, allowed_paths: tuple[str, ...]
    ) -> bytes:
        if timeout_seconds != 30 or allowed_paths != ENTRYPOINT.ALL_OUTCOME_PATHS:
            raise AssertionError("full refresh did not use the complete outcome allowlist")
        return f"new full outcome: {path}\n".encode("utf-8")

    full_sequence = mock.Mock()
    full_exact_inventory = mock.Mock()
    with (
        mock.patch.object(
            ENTRYPOINT, "pending_campaigns", return_value=full_pending
        ),
        mock.patch.object(ENTRYPOINT, "run_sequence", full_sequence),
        mock.patch.object(
            ENTRYPOINT,
            "run_trusted_bounded",
            side_effect=trusted_full_refresh_command,
        ),
        mock.patch.object(
            ENTRYPOINT,
            "repository_inventory",
            return_value=(full_tracked_patch, full_untracked, b""),
        ),
        mock.patch.object(
            ENTRYPOINT,
            "new_evidence_file_patch",
            side_effect=full_new_file_patch,
        ) as full_file_patch,
        mock.patch.object(
            ENTRYPOINT,
            "candidate_environment",
            return_value={"SOURCE_SHA": "b" * 40},
        ),
        mock.patch.object(
            ENTRYPOINT,
            "execution_boundary_record",
            return_value=b'{"schema":"test-execution-boundary"}\n',
        ),
        mock.patch.object(
            ENTRYPOINT,
            "require_exact_repository_inventory",
            full_exact_inventory,
        ),
        mock.patch.object(
            ENTRYPOINT,
            "publish_regular",
            side_effect=lambda name, payload: full_publications.setdefault(
                name, payload
            ),
        ),
    ):
        ENTRYPOINT.refresh_evidence(
            30,
            ENTRYPOINT.ALL_CAMPAIGNS,
            ENTRYPOINT.ALL_REFRESH_PATHS,
            full_inventory=True,
        )
    full_commands = full_sequence.call_args.args[0]
    for campaign, command in zip(
        ENTRYPOINT.ALL_CAMPAIGNS, full_commands, strict=True
    ):
        operation = (
            "--promote-pending-outcome"
            if campaign in full_pending
            else "--refresh-outcome"
        )
        if operation not in command or campaign not in command:
            raise AssertionError("full refresh did not bootstrap the exact pending set")
    expected_full_patch_calls = [
        mock.call(path, 30, ENTRYPOINT.ALL_OUTCOME_PATHS)
        for path in full_pending_paths
    ]
    if full_file_patch.call_args_list != expected_full_patch_calls:
        raise AssertionError("full refresh new-file patch allowlist was not exact")
    full_exact_inventory.assert_called_once_with(
        (full_tracked_patch, full_untracked, b""), 30
    )
    full_inventory = json.loads(
        full_publications["all-evidence-inventory.json"].decode("utf-8")
    )
    if (
        full_inventory["campaigns"] != list(ENTRYPOINT.ALL_CAMPAIGNS)
        or full_inventory["paths"] != list(ENTRYPOINT.ALL_REFRESH_PATHS)
        or full_inventory["source_sha"] != "b" * 40
    ):
        raise AssertionError("full refresh publication inventory was not exact")

    with (
        mock.patch.object(
            ENTRYPOINT,
            "pending_campaigns",
            side_effect=AssertionError("invalid mode reached pending discovery"),
        ),
    ):
        assert_entrypoint_rejected(
            "arbitrary subset campaign",
            lambda: ENTRYPOINT.refresh_evidence(
                30,
                ("grant_replay",),
                (ENTRYPOINT.OUTCOME_PATH_BY_CAMPAIGN["grant_replay"],),
                full_inventory=False,
            ),
        )
        assert_entrypoint_rejected(
            "forged full inventory",
            lambda: ENTRYPOINT.refresh_evidence(
                30,
                ("grant_replay",),
                ENTRYPOINT.ALL_REFRESH_PATHS,
                full_inventory=True,
            ),
        )

    relative = ENTRYPOINT.LINUX_OUTCOME_PATHS[0]
    with tempfile.TemporaryDirectory(prefix="chio-new-linux-outcome-") as raw:
        workspace = Path(raw)
        outcome = workspace / relative
        outcome.parent.mkdir(parents=True)
        outcome.write_text("{}\n", encoding="utf-8")
        outcome.chmod(0o644)
        expected_patch = (
            f"diff --git a/{relative} b/{relative}\n"
            "new file mode 100644\n"
            "index 0000000..1234567\n"
            "--- /dev/null\n"
            f"+++ b/{relative}\n"
            "@@ -0,0 +1 @@\n"
            "+{}\n"
        ).encode("utf-8")
        trusted_diff = mock.Mock(return_value=expected_patch)
        with (
            mock.patch.object(ENTRYPOINT, "WORKSPACE", workspace),
            mock.patch.object(ENTRYPOINT, "VERIFIER_UID", os.getuid()),
            mock.patch.object(ENTRYPOINT, "VERIFIER_GID", os.getgid()),
            mock.patch.object(ENTRYPOINT, "run_trusted_bounded", trusted_diff),
        ):
            if (
                ENTRYPOINT.new_evidence_file_patch(
                    relative, 30, ENTRYPOINT.LINUX_OUTCOME_PATHS
                )
                != expected_patch
            ):
                raise AssertionError("new Linux outcome patch bytes changed")
            assert_entrypoint_rejected(
                "path outside fixed inventory",
                lambda: ENTRYPOINT.new_evidence_file_patch(
                    "candidate/path", 30, ENTRYPOINT.LINUX_OUTCOME_PATHS
                ),
            )
            assert_entrypoint_rejected(
                "caller-selected allowlist",
                lambda: ENTRYPOINT.new_evidence_file_patch(
                    relative, 30, (relative,)
                ),
            )
            renamed_outcome = outcome.with_name("outcome-real.json")
            outcome.rename(renamed_outcome)
            outcome.symlink_to(renamed_outcome)
            assert_entrypoint_rejected(
                "symlinked new outcome",
                lambda: ENTRYPOINT.new_evidence_file_patch(
                    relative, 30, ENTRYPOINT.LINUX_OUTCOME_PATHS
                ),
            )
            outcome.unlink()
            renamed_outcome.rename(outcome)
            hardlink = outcome.with_name("outcome-hardlink.json")
            os.link(outcome, hardlink)
            assert_entrypoint_rejected(
                "hard-linked new outcome",
                lambda: ENTRYPOINT.new_evidence_file_patch(
                    relative, 30, ENTRYPOINT.LINUX_OUTCOME_PATHS
                ),
            )
            hardlink.unlink()
            with mock.patch.object(ENTRYPOINT, "VERIFIER_UID", os.getuid() + 1):
                assert_entrypoint_rejected(
                    "wrong new outcome owner",
                    lambda: ENTRYPOINT.new_evidence_file_patch(
                        relative, 30, ENTRYPOINT.LINUX_OUTCOME_PATHS
                    ),
                )
            with mock.patch.object(ENTRYPOINT, "VERIFIER_GID", os.getgid() + 1):
                assert_entrypoint_rejected(
                    "wrong new outcome group",
                    lambda: ENTRYPOINT.new_evidence_file_patch(
                        relative, 30, ENTRYPOINT.LINUX_OUTCOME_PATHS
                    ),
                )
            full_relative = ENTRYPOINT.OUTCOME_PATH_BY_CAMPAIGN["grant_replay"]
            full_outcome = workspace / full_relative
            full_outcome.parent.mkdir(parents=True)
            full_outcome.write_text("{}\n", encoding="utf-8")
            full_outcome.chmod(0o644)
            expected_full_patch = (
                f"diff --git a/{full_relative} b/{full_relative}\n"
                "new file mode 100644\n"
                "index 0000000..7654321\n"
                "--- /dev/null\n"
                f"+++ b/{full_relative}\n"
                "@@ -0,0 +1 @@\n"
                "+{}\n"
            ).encode("utf-8")
            trusted_diff.return_value = expected_full_patch
            if (
                ENTRYPOINT.new_evidence_file_patch(
                    full_relative, 30, ENTRYPOINT.ALL_OUTCOME_PATHS
                )
                != expected_full_patch
            ):
                raise AssertionError("full refresh outcome patch bytes changed")
            outcome.chmod(0o600)
            assert_entrypoint_rejected(
                "noncanonical file mode",
                lambda: ENTRYPOINT.new_evidence_file_patch(
                    relative, 30, ENTRYPOINT.LINUX_OUTCOME_PATHS
                ),
            )
        diff_commands = [call.args[0] for call in trusted_diff.call_args_list]
        if len(diff_commands) != 2:
            raise AssertionError("new evidence patch command count changed")
        for diff_command, expected_relative in zip(
            diff_commands, (relative, full_relative), strict=True
        ):
            if (
                diff_command[:2] != ["/bin/bash", "-c"]
                or "--no-renames --no-index -- /dev/null \"$1\""
                not in diff_command[2]
                or diff_command[-1] != expected_relative
            ):
                raise AssertionError("new evidence outcome patch command is not fixed")


def trusted_refresh_state_tests() -> None:
    def assert_state_rejected(label: str, callback) -> None:
        try:
            callback()
        except ENTRYPOINT.EntrypointError:
            return
        raise AssertionError(f"entrypoint accepted invalid refresh state: {label}")

    with tempfile.TemporaryDirectory(prefix="chio-refresh-state-") as raw:
        private = Path(raw).resolve() / "private"
        private.mkdir(mode=0o755)
        workspace = private / "candidate"
        workspace.mkdir(mode=0o770)
        workspace_metadata = workspace.lstat()
        identity = {
            "canonical_path": os.fspath(workspace.resolve(strict=True)),
            "device": workspace_metadata.st_dev,
            "inode": workspace_metadata.st_ino,
        }
        digest = hashlib.sha256(
            (json.dumps(identity, indent=2, ensure_ascii=False) + "\n").encode(
                "utf-8"
            )
        ).hexdigest()
        state = private / f"{ENTRYPOINT.TRUSTED_STATE_DIRECTORY_PREFIX}{digest}"
        state.mkdir(mode=0o700)
        state.chmod(0o700)
        with (
            mock.patch.object(ENTRYPOINT, "WORKSPACE", workspace),
            mock.patch.object(ENTRYPOINT, "VERIFIER_UID", os.getuid()),
            mock.patch.object(ENTRYPOINT, "VERIFIER_GID", os.getgid()),
        ):
            if ENTRYPOINT.trusted_refresh_state_path() != state:
                raise AssertionError("trusted refresh state path binding changed")
            ENTRYPOINT.validate_trusted_refresh_state(state)
            assert_state_rejected(
                "adjacent path",
                lambda: ENTRYPOINT.validate_trusted_refresh_state(
                    state.with_name("candidate-selected-state")
                ),
            )
            with mock.patch.object(ENTRYPOINT, "VERIFIER_UID", os.getuid() + 1):
                assert_state_rejected(
                    "wrong owner",
                    lambda: ENTRYPOINT.validate_trusted_refresh_state(state),
                )
            with mock.patch.object(ENTRYPOINT, "VERIFIER_GID", os.getgid() + 1):
                assert_state_rejected(
                    "wrong group",
                    lambda: ENTRYPOINT.validate_trusted_refresh_state(state),
                )
            state.chmod(0o750)
            assert_state_rejected(
                "wrong mode", lambda: ENTRYPOINT.validate_trusted_refresh_state(state)
            )
            state.chmod(0o700)
            child = state / "unexpected-child"
            child.mkdir()
            assert_state_rejected(
                "unexpected link count",
                lambda: ENTRYPOINT.validate_trusted_refresh_state(state),
            )
            child.rmdir()
            real_state = state.with_name(f"{state.name}.real")
            state.rename(real_state)
            state.symlink_to(real_state, target_is_directory=True)
            assert_state_rejected(
                "symlink replacement",
                lambda: ENTRYPOINT.validate_trusted_refresh_state(state),
            )
            state.unlink()
            real_state.rename(state)
            private.chmod(0o555)
            with (
                mock.patch.object(ENTRYPOINT, "CANDIDATE_UID", os.getuid()),
                mock.patch.object(ENTRYPOINT, "CANDIDATE_GID", os.getgid()),
            ):
                ENTRYPOINT.require_candidate_cannot_replace_trusted_state(state)

        checker_program = r'''
import importlib.util
import sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("state_checker", Path(sys.argv[1]))
assert spec is not None and spec.loader is not None
checker = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = checker
spec.loader.exec_module(checker)
with checker.refresh_lock(Path(sys.argv[2])):
    pass
'''
        for _invocation in range(2):
            completed = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    checker_program,
                    os.fspath(ROOT / "scripts/check-security-adversarial-evidence.py"),
                    os.fspath(workspace),
                ],
                cwd=ROOT,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=30,
            )
            if completed.returncode != 0:
                raise AssertionError(
                    "precreated refresh state did not survive checker invocations: "
                    + completed.stdout
                )
        if not state.is_dir() or state.lstat().st_nlink != 2:
            raise AssertionError("checker invocation did not preserve trusted state")
        private.chmod(0o755)


def immutable_workspace_tests() -> None:
    def assert_workspace_rejected(label: str, callback) -> None:
        try:
            callback()
        except ENTRYPOINT.EntrypointError:
            return
        raise AssertionError(f"entrypoint accepted mutable workspace: {label}")

    def populate(workspace: Path) -> tuple[Path, Path, Path]:
        workspace.mkdir(mode=0o700)
        data = workspace / "data"
        data.mkdir()
        regular = data / "input.txt"
        regular.write_text("immutable input\n", encoding="utf-8")
        executable = workspace / "tool.sh"
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o755)
        links = workspace / "links"
        links.mkdir()
        symlink = links / "fixture"
        symlink.symlink_to("../data/input.txt")
        return regular, executable, symlink

    def identity_boundary(workspace: Path) -> contextlib.ExitStack:
        stack = contextlib.ExitStack()
        stack.enter_context(mock.patch.object(ENTRYPOINT, "WORKSPACE", workspace))
        stack.enter_context(
            mock.patch.object(ENTRYPOINT, "CANDIDATE_UID", os.getuid())
        )
        stack.enter_context(
            mock.patch.object(ENTRYPOINT, "CANDIDATE_GID", os.getgid())
        )
        stack.enter_context(
            mock.patch.object(ENTRYPOINT, "VERIFIER_UID", os.getuid())
        )
        stack.enter_context(
            mock.patch.object(ENTRYPOINT, "VERIFIER_GID", os.getgid())
        )
        stack.enter_context(
            mock.patch.object(
                ENTRYPOINT,
                "effective_identity",
                side_effect=lambda _uid, _gid: contextlib.nullcontext(),
            )
        )
        return stack

    with tempfile.TemporaryDirectory(prefix="chio-immutable-workspace-") as raw:
        temporary = Path(raw).resolve()
        workspace = temporary / "candidate"
        regular, executable, symlink = populate(workspace)
        with identity_boundary(workspace):
            snapshot = ENTRYPOINT.freeze_candidate_workspace()
            ENTRYPOINT.validate_frozen_candidate_workspace(snapshot)
            if (
                stat.S_IMODE(workspace.lstat().st_mode) != 0o755
                or stat.S_IMODE(regular.lstat().st_mode) != 0o644
                or stat.S_IMODE(executable.lstat().st_mode) != 0o755
                or os.readlink(symlink) != "../data/input.txt"
            ):
                raise AssertionError("workspace freeze modes or symlink changed")

            regular.chmod(0o600)
            assert_workspace_rejected(
                "post-freeze writable mode",
                lambda: ENTRYPOINT.validate_frozen_candidate_workspace(snapshot),
            )
            regular.chmod(0o644)
            with mock.patch.object(ENTRYPOINT, "VERIFIER_UID", os.getuid() + 1):
                assert_workspace_rejected(
                    "post-freeze wrong owner",
                    lambda: ENTRYPOINT.validate_frozen_candidate_workspace(snapshot),
                )
            with mock.patch.object(ENTRYPOINT, "VERIFIER_GID", os.getgid() + 1):
                assert_workspace_rejected(
                    "post-freeze wrong group",
                    lambda: ENTRYPOINT.validate_frozen_candidate_workspace(snapshot),
                )
            tampered_device = tuple(
                (
                    relative,
                    kind,
                    device + (1 if relative == "data/input.txt" else 0),
                    inode,
                    mode,
                    target,
                )
                for relative, kind, device, inode, mode, target in snapshot
            )
            assert_workspace_rejected(
                "post-freeze device replacement",
                lambda: ENTRYPOINT.validate_frozen_candidate_workspace(
                    tampered_device
                ),
            )
            data = workspace / "data"
            data.chmod(0o777)
            assert_workspace_rejected(
                "post-freeze writable directory",
                lambda: ENTRYPOINT.validate_frozen_candidate_workspace(snapshot),
            )
            data.chmod(0o755)
            unexpected = workspace / "candidate-added"
            unexpected.write_text("unexpected\n", encoding="utf-8")
            assert_workspace_rejected(
                "post-freeze added path",
                lambda: ENTRYPOINT.validate_frozen_candidate_workspace(snapshot),
            )
            unexpected.unlink()
            original = regular.read_bytes()
            regular.unlink()
            regular.write_bytes(original)
            regular.chmod(0o644)
            assert_workspace_rejected(
                "post-freeze inode replacement",
                lambda: ENTRYPOINT.validate_frozen_candidate_workspace(snapshot),
            )

        escaping_workspace = temporary / "escaping"
        escaping_workspace.mkdir()
        (escaping_workspace / "outside-link").symlink_to(temporary / "outside")
        with identity_boundary(escaping_workspace):
            assert_workspace_rejected(
                "escaping symbolic link", ENTRYPOINT.candidate_workspace_inventory
            )

        reentry_workspace = temporary / "reentry"
        reentry_workspace.mkdir()
        reentry_data = reentry_workspace / "data"
        reentry_data.mkdir()
        (reentry_data / "input").write_text("inside\n", encoding="utf-8")
        external = temporary / "external"
        external.mkdir()
        (external / "back-inside").symlink_to(reentry_data / "input")
        (reentry_workspace / "escape-and-reenter").symlink_to(
            "../external/back-inside"
        )
        with identity_boundary(reentry_workspace):
            assert_workspace_rejected(
                "lexical symbolic-link escape and reentry",
                ENTRYPOINT.candidate_workspace_inventory,
            )

        hardlink_workspace = temporary / "hardlink"
        hardlink_workspace.mkdir()
        source = hardlink_workspace / "source"
        source.write_text("one inode\n", encoding="utf-8")
        os.link(source, hardlink_workspace / "alias")
        with identity_boundary(hardlink_workspace):
            assert_workspace_rejected(
                "hard-linked regular file", ENTRYPOINT.candidate_workspace_inventory
            )

        wrong_identity_workspace = temporary / "wrong-identity"
        wrong_identity_workspace.mkdir()
        with (
            mock.patch.object(ENTRYPOINT, "WORKSPACE", wrong_identity_workspace),
            mock.patch.object(ENTRYPOINT, "CANDIDATE_UID", os.getuid() + 1),
            mock.patch.object(ENTRYPOINT, "CANDIDATE_GID", os.getgid()),
            mock.patch.object(ENTRYPOINT, "VERIFIER_GID", os.getgid()),
        ):
            assert_workspace_rejected(
                "wrong initial owner", ENTRYPOINT.candidate_workspace_inventory
            )

        special_workspace = temporary / "special"
        special_workspace.mkdir()
        os.mkfifo(special_workspace / "candidate-fifo")
        with identity_boundary(special_workspace):
            assert_workspace_rejected(
                "special file", ENTRYPOINT.candidate_workspace_inventory
            )

        retarget_workspace = temporary / "retarget"
        _regular, _executable, retargeted = populate(retarget_workspace)
        other = retarget_workspace / "data/other.txt"
        other.write_text("other\n", encoding="utf-8")
        with identity_boundary(retarget_workspace):
            retarget_snapshot = ENTRYPOINT.freeze_candidate_workspace()
            retargeted.unlink()
            retargeted.symlink_to("../data/other.txt")
            assert_workspace_rejected(
                "post-freeze symbolic-link retarget",
                lambda: ENTRYPOINT.validate_frozen_candidate_workspace(
                    retarget_snapshot
                ),
            )

    trusted_ancestors = mock.Mock()
    trusted_executable = mock.Mock()
    with (
        mock.patch.object(
            ENTRYPOINT, "validate_trusted_directory", trusted_ancestors
        ),
        mock.patch.object(
            ENTRYPOINT, "validate_trusted_regular_file", trusted_executable
        ),
    ):
        ENTRYPOINT.validate_trusted_cargo_mutants()
    expected_ancestors = [
        mock.call(
            Path(path),
            expected_mode=0o755,
            description=f"trusted cargo-mutants ancestor {path}",
        )
        for path in ("/", "/usr", "/usr/local", "/usr/local/cargo", "/usr/local/cargo/bin")
    ]
    if trusted_ancestors.call_args_list != expected_ancestors:
        raise AssertionError("cargo-mutants ancestor authentication changed")
    trusted_executable.assert_called_once_with(
        ENTRYPOINT.TRUSTED_CARGO_MUTANTS,
        expected_mode=0o555,
        description="trusted cargo-mutants executable",
    )


def entrypoint_repository_inventory_tests() -> None:
    def assert_entrypoint_rejected(label: str, callback) -> None:
        try:
            callback()
        except ENTRYPOINT.EntrypointError:
            return
        raise AssertionError(f"entrypoint accepted candidate-tree mutation: {label}")

    for label, inventory in (
        ("tracked mutation", (b"diff", b"", b"")),
        ("untracked mutation", (b"", b"new-path\0", b"")),
        ("ignored mutation", (b"", b"", b"ignored-path\0")),
    ):
        with mock.patch.object(
            ENTRYPOINT, "repository_inventory", return_value=inventory
        ):
            assert_entrypoint_rejected(
                label, lambda: ENTRYPOINT.require_clean_repository(30)
            )

    clippy_completed = False

    def hostile_run_candidate(
        command: list[str], _timeout_seconds: int, *, cwd=ENTRYPOINT.WORKSPACE
    ) -> bytes:
        del cwd
        nonlocal clippy_completed
        if "clippy" in command:
            clippy_completed = True
        return b""

    def hostile_run_trusted(
        command: list[str], _timeout_seconds: int, *, cwd=ENTRYPOINT.WORKSPACE
    ) -> bytes:
        del cwd
        if "--ignored" in command and clippy_completed:
            return b"ignored-build-script-output\0"
        return b""

    with (
        mock.patch.object(
            ENTRYPOINT, "run_candidate_bounded", side_effect=hostile_run_candidate
        ),
        mock.patch.object(
            ENTRYPOINT, "run_trusted_bounded", side_effect=hostile_run_trusted
        ),
        mock.patch.object(ENTRYPOINT, "execution_boundary_record", return_value=b""),
        mock.patch.object(
            ENTRYPOINT,
            "publish_regular",
            side_effect=AssertionError("publication preceded final inventory check"),
        ),
    ):
        assert_entrypoint_rejected(
            "post-clippy ignored build-script mutation",
            lambda: ENTRYPOINT.linux_enforcement(30),
        )


class FakeDocker:
    def __init__(self, image: str) -> None:
        self.image = image
        self.containers: dict[str, dict[str, object]] = {}
        self.next_identifier = 1
        self.fail_start = False
        self.fail_remove = False
        self.removed: list[str] = []
        self.inspect_mutator = None

    def inspection(self, identifier: str) -> dict[str, object]:
        state = self.containers[identifier]
        create = state["create"]
        assert isinstance(create, list)

        def values(flag: str) -> list[str]:
            return [
                create[index + 1] for index, value in enumerate(create) if value == flag
            ]

        name = values("--name")[0]
        labels = dict(value.split("=", 1) for value in values("--label"))
        env = values("--env")
        image_index = create.index(self.image)
        command = create[image_index + 1 :]
        source_mount, output_mount = values("--mount")

        def mount_record(value: str) -> dict[str, object]:
            fields = value.split(",")
            source = next(
                field.removeprefix("src=")
                for field in fields
                if field.startswith("src=")
            )
            destination = next(
                field.removeprefix("dst=")
                for field in fields
                if field.startswith("dst=")
            )
            return {
                "Type": "bind",
                "Source": source,
                "Destination": destination,
                "Mode": "",
                "RW": "readonly" not in fields,
                "Propagation": "rprivate",
            }

        seccomp = json.dumps(BOUNDARY.expected_seccomp_profile(), separators=(",", ":"))
        document: dict[str, object] = {
            "Id": identifier,
            "Name": f"/{name}",
            "Image": self.image,
            "Path": "/usr/bin/python3",
            "Args": ["-I", "/opt/chio-security/entrypoint.py", *command],
            "Config": {
                "Image": self.image,
                "Cmd": command,
                "Entrypoint": [
                    "/usr/bin/python3",
                    "-I",
                    "/opt/chio-security/entrypoint.py",
                ],
                "WorkingDir": "/private/candidate",
                "User": "",
                "Labels": labels,
                "Env": env,
                "OpenStdin": False,
                "StdinOnce": False,
                "Tty": False,
            },
            "HostConfig": {
                "AutoRemove": False,
                "Binds": None,
                "CapAdd": ["CAP_CHOWN", "CAP_SETGID", "CAP_SETUID"],
                "CapDrop": ["ALL"],
                "CgroupnsMode": "private",
                "DeviceRequests": None,
                "Devices": [],
                "Dns": [],
                "DnsOptions": [],
                "DnsSearch": [],
                "ExtraHosts": None,
                "Init": True,
                "IpcMode": "private",
                "Links": None,
                "LogConfig": {"Type": "none", "Config": {}},
                "Memory": 12884901888,
                "MemoryReservation": 0,
                "MemorySwap": 12884901888,
                "MemorySwappiness": None,
                "NanoCpus": 4000000000,
                "NetworkMode": "none",
                "OomKillDisable": False,
                "OomScoreAdj": 0,
                "PidMode": "",
                "PidsLimit": 512,
                "PortBindings": {},
                "Privileged": False,
                "PublishAllPorts": False,
                "ReadonlyRootfs": True,
                "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
                "Runtime": "runc",
                "SecurityOpt": ["no-new-privileges", f"seccomp={seccomp}"],
                "ShmSize": 67108864,
                "Tmpfs": BOUNDARY.EXPECTED_TMPFS,
                "UTSMode": "",
                "Ulimits": [
                    {"Name": name, "Soft": soft, "Hard": hard}
                    for name, soft, hard in BOUNDARY.EXPECTED_ULIMITS
                ],
                "UsernsMode": "",
                "VolumesFrom": None,
            },
            "Mounts": [mount_record(source_mount), mount_record(output_mount)],
        }
        if self.inspect_mutator is not None:
            self.inspect_mutator(document)
        return document

    def output(
        self,
        _docker: str,
        arguments: list[str],
        _environment: dict[str, str],
        timeout: int = 60,
    ) -> str:
        del timeout
        if arguments[:2] == ["image", "inspect"]:
            return f"{self.image}|linux|amd64"
        if arguments[0] == "ps":
            if any(value.startswith("id=") for value in arguments):
                requested = next(
                    value.removeprefix("id=")
                    for value in arguments
                    if value.startswith("id=")
                )
                return (
                    requested
                    if self.containers.get(requested, {}).get("exists")
                    else ""
                )
            return "\n".join(
                identifier
                for identifier, state in self.containers.items()
                if state.get("exists")
            )
        if arguments[0] == "create":
            identifier = f"{self.next_identifier:064x}"
            self.next_identifier += 1
            cidfile = Path(arguments[arguments.index("--cidfile") + 1])
            cidfile.write_text(identifier + "\n", encoding="ascii")
            output_mount = next(
                arguments[index + 1]
                for index, value in enumerate(arguments)
                if value == "--mount" and "dst=/output" in arguments[index + 1]
            )
            output = Path(
                next(
                    field.removeprefix("src=")
                    for field in output_mount.split(",")
                    if field.startswith("src=")
                )
            )
            state_label = next(
                value.split("=", 1)[1]
                for value in arguments
                if value.startswith(f"{BOUNDARY.STATE_LABEL}=")
            )
            self.containers[identifier] = {
                "create": list(arguments),
                "exists": True,
                "output": output,
                "state": "created",
                "state_label": state_label,
            }
            return ""
        if len(arguments) == 2 and arguments[0] == "inspect":
            return json.dumps([self.inspection(arguments[-1])])
        identifier = arguments[-1]
        state = self.containers[identifier]
        if arguments[0] == "start":
            if self.fail_start:
                raise BOUNDARY.BoundaryError("synthetic Docker start failure")
            state["state"] = "running"
            output = state["output"]
            assert isinstance(output, Path)
            (output / "probe.log").write_bytes(b"fake isolated output\n")
            return identifier
        if arguments[0] == "wait":
            state["state"] = "exited"
            return "0"
        if arguments[0] == "inspect":
            template = arguments[2]
            if ".State.Running" in template:
                return "true" if state["state"] == "running" else "false"
            if ".State.Status" in template:
                return str(state["state"])
            if ".Config.Labels" in template:
                return f"true|{state['state_label']}"
        raise AssertionError(f"unexpected fake Docker output call: {arguments!r}")

    def run_checked(
        self,
        command: list[str],
        *,
        environment: dict[str, str],
        timeout: int = 60,
        input_bytes: bytes | None = None,
    ) -> bytes:
        if command[0] != "/fake/docker":
            return ORIGINAL_RUN_CHECKED(
                command,
                environment=environment,
                timeout=timeout,
                input_bytes=input_bytes,
            )
        identifier = command[-1]
        if command[1] == "kill":
            self.containers[identifier]["state"] = "exited"
            return b""
        if command[1] == "rm":
            if self.fail_remove:
                raise BOUNDARY.BoundaryError("synthetic Docker removal failure")
            self.containers[identifier]["exists"] = False
            self.removed.append(identifier)
            return b""
        raise AssertionError(f"unexpected fake Docker command: {command!r}")


ORIGINAL_RUN_CHECKED = BOUNDARY.run_checked


def fake_docker_main_tests() -> None:
    image = "sha256:" + "b" * 64
    with tempfile.TemporaryDirectory(prefix="chio-boundary-main-") as raw:
        temporary = Path(raw).resolve()
        candidate = temporary / "candidate"
        head = initialize_repository(candidate, {"probe.py": "print('safe')\n"})
        state = temporary / "state"

        def invoke(
            fake: FakeDocker,
            output: Path,
            *,
            authorized_sha: str,
            revalidate=None,
        ) -> None:
            argv = runner_command(
                candidate=candidate,
                head=head,
                image=image,
                operation="hostile-probe",
                output=output,
                state=state,
                authorized_sha=authorized_sha,
            )[1:]
            patches = (
                mock.patch.object(
                    BOUNDARY, "validate_trusted_runner", return_value=ROOT
                ),
                mock.patch.object(BOUNDARY, "docker_path", return_value="/fake/docker"),
                mock.patch.object(BOUNDARY, "validate_docker_host", return_value=None),
                mock.patch.object(BOUNDARY, "docker_output", side_effect=fake.output),
                mock.patch.object(
                    BOUNDARY, "run_checked", side_effect=fake.run_checked
                ),
                mock.patch.object(sys, "argv", argv),
            )
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5]:
                if revalidate is None:
                    BOUNDARY.main()
                else:
                    with mock.patch.object(
                        BOUNDARY, "revalidate_repository", side_effect=revalidate
                    ):
                        BOUNDARY.main()

        successful = FakeDocker(image)
        first_output = temporary / "first-output"
        invoke(successful, first_output, authorized_sha="a" * 40)
        if (first_output / "probe.log").read_bytes() != b"fake isolated output\n":
            raise AssertionError(
                "real runner main path did not import fake Docker output"
            )

        def mutate_network(document: dict[str, object]) -> None:
            document["HostConfig"]["NetworkMode"] = "host"

        def add_mount(document: dict[str, object]) -> None:
            document["Mounts"].append(
                {
                    "Type": "bind",
                    "Source": "/",
                    "Destination": "/host",
                    "Mode": "",
                    "RW": False,
                    "Propagation": "rprivate",
                }
            )

        def relax_pids(document: dict[str, object]) -> None:
            document["HostConfig"]["PidsLimit"] = 0

        def relax_memory(document: dict[str, object]) -> None:
            document["HostConfig"]["Memory"] = 0

        def relax_cpu(document: dict[str, object]) -> None:
            document["HostConfig"]["NanoCpus"] = 0

        def remove_read_only(document: dict[str, object]) -> None:
            document["HostConfig"]["ReadonlyRootfs"] = False

        for label, mutator in (
            ("post-create network override", mutate_network),
            ("post-create extra mount", add_mount),
            ("post-create relaxed pids", relax_pids),
            ("post-create relaxed memory", relax_memory),
            ("post-create relaxed CPU", relax_cpu),
            ("post-create writable root", remove_read_only),
        ):
            mutant = FakeDocker(image)
            mutant.inspect_mutator = mutator
            mutant_output = temporary / label.replace(" ", "-")
            assert_rejected(
                label,
                lambda mutant=mutant, mutant_output=mutant_output: invoke(
                    mutant,
                    mutant_output,
                    authorized_sha="a" * 40,
                ),
            )
            if mutant_output.exists() or any(
                item["exists"] for item in mutant.containers.values()
            ):
                raise AssertionError(
                    f"post-create contract mutant escaped cleanup: {label}"
                )

        start_failure = FakeDocker(image)
        start_failure.fail_start = True
        assert_rejected(
            "Docker start failure",
            lambda: invoke(
                start_failure,
                temporary / "start-failure-output",
                authorized_sha="a" * 40,
            ),
        )
        if any(state["exists"] for state in start_failure.containers.values()):
            raise AssertionError("created container survived a start failure")

        stale = FakeDocker(image)
        stale.fail_remove = True
        assert_rejected(
            "mandatory cleanup failure",
            lambda: invoke(
                stale,
                temporary / "cleanup-failure-output",
                authorized_sha="a" * 40,
            ),
        )
        if not (state / "runs").exists() or not any(
            item["exists"] for item in stale.containers.values()
        ):
            raise AssertionError(
                "cleanup failure did not preserve recoverable run state"
            )
        stale.fail_remove = False
        recovered_output = temporary / "recovered-output"
        invoke(stale, recovered_output, authorized_sha="c" * 40)
        if not stale.removed or not (recovered_output / "probe.log").is_file():
            raise AssertionError(
                "C2-to-C3 stale state was not recovered before execution"
            )

        publication = FakeDocker(image)
        calls = 0
        original_revalidate = BOUNDARY.revalidate_repository

        def source_race(identity) -> None:
            nonlocal calls
            calls += 1
            if calls == 4:
                raise BOUNDARY.BoundaryError("synthetic post-publication source race")
            original_revalidate(identity)

        rejected_output = temporary / "rejected-output"
        assert_rejected(
            "post-publication source race",
            lambda: invoke(
                publication,
                rejected_output,
                authorized_sha="d" * 40,
                revalidate=source_race,
            ),
        )
        if rejected_output.exists():
            raise AssertionError("source-race rejection left a consumable artifact")


def runner_command(
    *,
    candidate: Path,
    head: str,
    image: str,
    operation: str,
    output: Path,
    state: Path,
    authorized_sha: str,
    timeout_seconds: int = 120,
    docker_host: str | None = None,
) -> list[str]:
    command = [
        sys.executable,
        os.fspath(RUNNER_PATH),
        "--authorized-source-sha",
        authorized_sha,
        "--candidate",
        os.fspath(candidate),
        "--expected-sha",
        head,
        "--image",
        image,
        "--operation",
        operation,
        "--output-dir",
        os.fspath(output),
        "--state-dir",
        os.fspath(state),
        "--timeout-seconds",
        str(timeout_seconds),
    ]
    if docker_host is not None:
        command.extend(["--docker-host", docker_host])
    return command


def local_docker_host(docker: str) -> str | None:
    if sys.platform == "linux":
        if docker != "/usr/bin/docker":
            raise AssertionError("Linux Docker boundary did not select /usr/bin/docker")
        return None
    if sys.platform != "darwin":
        raise AssertionError("Docker hostile probes require Linux or macOS")
    result = subprocess.run(
        [docker, "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
    )
    host = result.stdout.strip()
    if result.returncode != 0 or not host.startswith("unix://"):
        raise AssertionError("macOS Docker hostile probes require a Unix context")
    return host


def docker_hostile_tests(image: str) -> None:
    docker = BOUNDARY.docker_path()
    docker_host = local_docker_host(docker)
    authorized_sha = run(["git", "rev-parse", "HEAD"], cwd=ROOT).strip()
    with tempfile.TemporaryDirectory(prefix="chio-boundary-docker-") as raw:
        temporary = Path(raw).resolve()
        sanitized_environment = BOUNDARY.docker_environment(
            temporary / "docker-config-probe", docker_host
        )
        platform = BOUNDARY.docker_output(
            docker,
            ["version", "--format", "{{.Server.Os}}/{{.Server.Arch}}"],
            sanitized_environment,
        )
        if platform not in ("linux/amd64", "linux/arm64"):
            raise AssertionError(
                "sanitized Docker context did not reach a Linux daemon"
            )
        authority = temporary / "authority"
        authority.mkdir()
        sentinel_name = f"chio-boundary-host-{os.urandom(12).hex()}"
        sentinel = Path("/tmp") / sentinel_name
        checker_sentinel = Path("/tmp") / f"{sentinel_name}-candidate-checker"
        background_sentinel = Path("/tmp") / f"{sentinel_name}-background"
        candidate = temporary / "candidate"
        probe = f'''
import ctypes
import errno
import json
import os
import signal
import subprocess
import sys
import textwrap
from pathlib import Path

authority = Path({os.fspath(sentinel)!r})
authority.write_text("container-only", encoding="utf-8")
workspace_stat = Path(__file__).stat()
contract_write_denials = []
for label, protected in (
    ("source", Path(__file__)),
    ("manifest", Path("crates/core/chio-adversarial-suite/manifest.json")),
    (
        "later-case",
        Path("crates/core/chio-adversarial-suite/cases/label_downgrade/label-downgrade-001.json"),
    ),
    (
        "later-outcome",
        Path("audits/evidence/mutants/security/grant_replay/mutants.out/outcomes.json"),
    ),
    ("threat", Path("audits/evidence/threats/README.md")),
):
    try:
        with protected.open("ab"):
            pass
    except PermissionError:
        contract_write_denials.append(label)
    else:
        raise SystemExit(f"candidate can rewrite frozen contract: {{label}}")
contract_create_denials = []
for label, protected in (
    ("workspace", Path(".")),
    ("cases", Path("crates/core/chio-adversarial-suite/cases")),
    ("mutants", Path("audits/evidence/mutants/security")),
    ("threats", Path("audits/evidence/threats")),
):
    try:
        (protected / ".candidate-cross-campaign-probe").write_text(
            "forged", encoding="utf-8"
        )
    except PermissionError:
        contract_create_denials.append(label)
    else:
        raise SystemExit(f"candidate can add frozen contract: {{label}}")
contract_rename_denials = []
for label, protected in (
    ("workspace", Path("/private/candidate")),
    ("manifest", Path("crates/core/chio-adversarial-suite/manifest.json")),
    ("cases", Path("crates/core/chio-adversarial-suite/cases")),
    ("mutants", Path("audits/evidence/mutants/security")),
    (
        "later-case",
        Path("crates/core/chio-adversarial-suite/cases/label_downgrade/label-downgrade-001.json"),
    ),
):
    replacement = protected.with_name(f"{{protected.name}}.candidate-renamed")
    try:
        protected.rename(replacement)
    except PermissionError:
        contract_rename_denials.append(label)
    else:
        raise SystemExit(f"candidate can rename frozen contract: {{label}}")
later_case = Path(
    "crates/core/chio-adversarial-suite/cases/label_downgrade/label-downgrade-001.json"
)
try:
    later_case.unlink()
except PermissionError:
    contract_unlink_denied = True
else:
    raise SystemExit("candidate can unlink a later campaign contract")
try:
    Path("crates/core/chio-adversarial-suite/cases").rmdir()
except PermissionError:
    contract_rmdir_denied = True
else:
    raise SystemExit("candidate can remove the campaign contract tree")
parent = os.getppid()
try:
    os.kill(parent, 0)
except PermissionError:
    parent_signal_denied = True
else:
    raise SystemExit("candidate can signal the trusted supervisor")
libc = ctypes.CDLL(None, use_errno=True)
if libc.ptrace(16, parent, None, None) != -1 or ctypes.get_errno() != errno.EPERM:
    raise SystemExit("candidate can ptrace the trusted supervisor")
if libc.unshare(0x10000000) != -1 or ctypes.get_errno() != errno.EPERM:
    raise SystemExit("candidate can create a user namespace")
baseline_denials = []
for protected in (Path("/baseline/git/HEAD"), Path("/baseline/git/index")):
    try:
        protected.write_text("forged", encoding="utf-8")
    except PermissionError:
        baseline_denials.append(protected.name)
    else:
        raise SystemExit("candidate can replace root-owned Git baseline metadata")
broker_token_argv = []
for process in Path("/proc").iterdir():
    if not process.name.isdigit():
        continue
    try:
        command_line = (process / "cmdline").read_bytes()
    except OSError:
        continue
    if b"--broker-token" in command_line:
        broker_token_argv.append(process.name)
poisoned_paths = []
for target in (
    Path(os.environ["HOME"]) / ".local/lib/python3.12/site-packages/sitecustomize.py",
    Path(os.environ["TMPDIR"]) / "trusted-verifier.log",
    Path(os.environ["CARGO_HOME"]) / "config.toml",
    Path(os.environ["CARGO_TARGET_DIR"]) / "debug/cargo",
    Path("/tmp/sitecustomize.py"),
):
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("print('CANDIDATE_POISON_RAN')\n", encoding="utf-8")
    poisoned_paths.append(str(target))
daemon = textwrap.dedent("""
    import os
    import time
    from pathlib import Path
    if os.fork() != 0:
        raise SystemExit(0)
    os.setsid()
    if os.fork() != 0:
        raise SystemExit(0)
    for descriptor in (0, 1, 2):
        try:
            os.close(descriptor)
        except OSError:
            pass
    while True:
        Path('/tmp/detached-candidate-poison').write_text(
            'DETACHED CANDIDATE SURVIVED', encoding='utf-8'
        )
        time.sleep(0.1)
""")
subprocess.Popen(
    [sys.executable, "-c", daemon],
    stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    start_new_session=True,
)
print(json.dumps({{
    "baseline_denials": sorted(baseline_denials),
    "broker_token_argv": broker_token_argv,
    "contract_create_denials": sorted(contract_create_denials),
    "contract_rename_denials": sorted(contract_rename_denials),
    "contract_rmdir_denied": contract_rmdir_denied,
    "contract_unlink_denied": contract_unlink_denied,
    "contract_write_denials": sorted(contract_write_denials),
    "environment": sorted(os.environ),
    "inode": workspace_stat.st_ino,
    "device": workspace_stat.st_dev,
    "parent_signal_denied": parent_signal_denied,
    "poisoned_paths": sorted(poisoned_paths),
    "uid": os.getuid(),
}}))
'''.lstrip()
        malicious_checker = (
            "#!/bin/sh\n" "printf 'CANDIDATE_EXECUTION_AUTHORITY_RAN\\n'\n"
        )
        head = initialize_repository(
            candidate,
            {
                "probe.py": probe,
                "scripts/check-security-adversarial-evidence.py": malicious_checker,
                "scripts/check-linux-enforcement-stack.py": malicious_checker,
                "scripts/check-keyring-transparency.sh": malicious_checker,
                "scripts/check-secret-broker-boundary.sh": malicious_checker,
                "scripts/check-cage-enforcement.sh": malicious_checker,
                "crates/core/chio-adversarial-suite/manifest.json": "{}\n",
                "crates/core/chio-adversarial-suite/cases/label_downgrade/label-downgrade-001.json": "{}\n",
                "audits/evidence/mutants/security/grant_replay/mutants.out/outcomes.json": "{}\n",
                "audits/evidence/threats/README.md": "immutable threat contract\n",
            },
            executable=(
                "scripts/check-security-adversarial-evidence.py",
                "scripts/check-linux-enforcement-stack.py",
                "scripts/check-keyring-transparency.sh",
                "scripts/check-secret-broker-boundary.sh",
                "scripts/check-cage-enforcement.sh",
            ),
        )
        original_probe = (candidate / "probe.py").read_bytes()
        original_identity = (candidate / "probe.py").stat()
        output = temporary / "probe-output"
        state = temporary / "state"
        environment = os.environ.copy()
        environment.update(
            {
                "GITHUB_TOKEN": "must-not-cross-boundary",
                "GH_TOKEN": "must-not-cross-boundary",
                "SSH_AUTH_SOCK": "/tmp/must-not-cross-boundary",
            }
        )
        command = runner_command(
            candidate=candidate,
            head=head,
            image=image,
            operation="hostile-probe",
            output=output,
            state=state,
            authorized_sha=authorized_sha,
            docker_host=docker_host,
        )
        result = subprocess.run(
            command,
            cwd=ROOT,
            env=environment,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=180,
        )
        if result.returncode != 0:
            raise AssertionError(f"Docker hostile probe failed: {result.stderr}")
        if (
            sentinel.exists()
            or checker_sentinel.exists()
            or background_sentinel.exists()
        ):
            raise AssertionError("candidate process reached host authority")
        if (candidate / "probe.py").read_bytes() != original_probe:
            raise AssertionError("candidate process changed the authoritative source")
        log = (output / "probe.log").read_text(encoding="utf-8")
        record = next(
            json.loads(line)
            for line in log.splitlines()
            if line.startswith("{") and '"baseline_denials"' in line
        )
        if "detached candidate quiescence verified" not in log:
            raise AssertionError("detached candidate quiescence was not verified")
        if "CANDIDATE_EXECUTION_AUTHORITY_RAN" in log:
            raise AssertionError("candidate checker or gate became execution authority")
        if "CANDIDATE_POISON_RAN" in log:
            raise AssertionError("candidate Python, temp, Cargo, or target poison ran")
        if (
            record["uid"] != 65532
            or record["baseline_denials"] != ["HEAD", "index"]
            or record["broker_token_argv"] != []
            or record["contract_create_denials"]
            != ["cases", "mutants", "threats", "workspace"]
            or record["contract_rename_denials"]
            != ["cases", "later-case", "manifest", "mutants", "workspace"]
            or record["contract_rmdir_denied"] is not True
            or record["contract_unlink_denied"] is not True
            or record["contract_write_denials"]
            != ["later-case", "later-outcome", "manifest", "source", "threat"]
            or record["parent_signal_denied"] is not True
            or len(record["poisoned_paths"]) != 5
        ):
            raise AssertionError("candidate privilege separation is not effective")
        forbidden_env = {"GITHUB_TOKEN", "GH_TOKEN", "SSH_AUTH_SOCK"}
        if forbidden_env.intersection(record["environment"]):
            raise AssertionError("host capability environment crossed the boundary")
        if (record["device"], record["inode"]) == (
            original_identity.st_dev,
            original_identity.st_ino,
        ):
            raise AssertionError("container workspace aliases host authority")

        output_attack = temporary / "output-attack"
        attack_body = "from pathlib import Path\nPath('/output/extra').write_text('hostile')\nprint('done')\n"
        (candidate / "probe.py").write_text(attack_body, encoding="utf-8")
        run(["git", "add", "probe.py"], cwd=candidate)
        run(["git", "commit", "--quiet", "-m", "output attack"], cwd=candidate)
        attack_head = run(["git", "rev-parse", "HEAD"], cwd=candidate).strip()
        attack = subprocess.run(
            runner_command(
                candidate=candidate,
                head=attack_head,
                image=image,
                operation="hostile-probe",
                output=output_attack,
                state=state,
                authorized_sha=authorized_sha,
                docker_host=docker_host,
            ),
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=180,
        )
        if attack.returncode == 0 or output_attack.exists():
            raise AssertionError("runner imported an extra candidate output path")

        build_sentinel = authority / "build-script"
        wrapper_sentinel = authority / "rustc-wrapper"
        cargo_candidate = temporary / "cargo-candidate"
        cargo_head = initialize_repository(
            cargo_candidate,
            {
                "Cargo.toml": '[package]\nname = "hostile-boundary"\nversion = "0.1.0"\nedition = "2021"\nbuild = "build.rs"\n',
                "Cargo.lock": 'version = 3\n\n[[package]]\nname = "hostile-boundary"\nversion = "0.1.0"\n',
                "build.rs": f'use std::fs; fn main() {{ fs::create_dir_all({json.dumps(str(build_sentinel.parent))}).unwrap(); fs::write({json.dumps(str(build_sentinel))}, b"hostile").unwrap(); }}\n',
                "src/lib.rs": "pub fn value() -> u8 { 7 }\n#[test]\nfn works() { assert_eq!(value(), 7); }\n",
                ".cargo/config.toml": '[build]\nrustc-wrapper = "/private/candidate/wrapper.sh"\n',
                "crates/core/chio-adversarial-suite/manifest.json": "{}\n",
                "crates/core/chio-adversarial-suite/cases/label_downgrade/label-downgrade-001.json": "{}\n",
                "audits/evidence/mutants/security/grant_replay/mutants.out/outcomes.json": "{}\n",
                "audits/evidence/threats/README.md": "immutable threat contract\n",
                "wrapper.sh": f'''#!/bin/sh
mkdir -p {wrapper_sentinel.parent!s}
printf hostile > {wrapper_sentinel!s}
mkdir -p "$HOME/.local/lib/python3.12/site-packages" "$CARGO_TARGET_DIR/debug"
printf "print('CANDIDATE_POISON_RAN')\\n" > "$HOME/.local/lib/python3.12/site-packages/sitecustomize.py"
printf "print('CANDIDATE_POISON_RAN')\\n" > /tmp/sitecustomize.py
printf CANDIDATE_POISON_RAN > "$TMPDIR/trusted-verifier.log"
printf '[build]\\nrustc-wrapper = "/private/candidate/wrapper.sh"\\n' > "$CARGO_HOME/config.toml"
printf '#!/bin/sh\\nprintf CANDIDATE_POISON_RAN\\n' > "$CARGO_TARGET_DIR/debug/cargo"
chmod 755 "$CARGO_TARGET_DIR/debug/cargo"
	(while :; do printf CANDIDATE_POISON_RAN > /tmp/detached-candidate-poison; sleep 0.1; done) </dev/null >/dev/null 2>&1 &
real="$1"
shift
exec "$real" "$@"
''',
            },
            executable=("wrapper.sh",),
        )
        cargo_output = temporary / "cargo-output"
        cargo_result = subprocess.run(
            runner_command(
                candidate=cargo_candidate,
                head=cargo_head,
                image=image,
                operation="hostile-cargo-probe",
                output=cargo_output,
                state=state,
                authorized_sha=authorized_sha,
                docker_host=docker_host,
            ),
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=180,
        )
        if cargo_result.returncode != 0:
            raise AssertionError(
                f"hostile Cargo isolation probe failed: {cargo_result.stderr}"
            )
        if build_sentinel.exists() or wrapper_sentinel.exists():
            raise AssertionError("build.rs or rustc-wrapper reached host authority")
        cargo_log = (cargo_output / "probe.log").read_text(encoding="utf-8")
        if "CANDIDATE_POISON_RAN" in cargo_log:
            raise AssertionError(
                "candidate Cargo, target, temp, Python, or detached poison ran"
            )
        if "cargo 1.93.0" not in cargo_log:
            raise AssertionError("fresh disposable Cargo verification did not run")
        if "detached candidate quiescence verified" not in cargo_log:
            raise AssertionError("detached Cargo process quiescence was not verified")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--docker", action="store_true")
    parser.add_argument("--image")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    static_contract_tests()
    copy_and_output_tests()
    refresh_inventory_tests()
    pending_promotion_tests()
    trusted_refresh_state_tests()
    immutable_workspace_tests()
    entrypoint_repository_inventory_tests()
    fake_docker_main_tests()
    if args.docker:
        image = args.image or os.environ.get("CHIO_SECURITY_EXECUTION_IMAGE", "")
        if not BOUNDARY.IMAGE_PATTERN.fullmatch(image):
            raise AssertionError(
                "Docker hostile probes require a digest-addressed image"
            )
        docker_hostile_tests(image)
    print("security execution container tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
