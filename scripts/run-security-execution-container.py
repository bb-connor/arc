#!/usr/bin/env python3
"""Run candidate security evidence in a disposable, bounded Docker boundary."""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import fcntl
import hashlib
import json
import os
import posixpath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path, PurePosixPath


class BoundaryError(RuntimeError):
    pass


SHA_PATTERN = re.compile(r"[0-9a-f]{40}")
IMAGE_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
CONTAINER_ID_PATTERN = re.compile(r"[0-9a-f]{12,64}")
MANAGED_LABEL = "org.chio.security-execution.managed=true"
AUTHORITY_LABEL = "org.chio.security-execution.authority"
STATE_LABEL = "org.chio.security-execution.state"
MAX_SOURCE_BYTES = 2 * 1024 * 1024 * 1024
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_OUTPUT_BYTES = 128 * 1024 * 1024
SECCOMP_DENIED_SYSCALLS = (
    "_sysctl",
    "acct",
    "add_key",
    "bpf",
    "clone3",
    "delete_module",
    "finit_module",
    "fsconfig",
    "fsmount",
    "fsopen",
    "fspick",
    "init_module",
    "ioperm",
    "iopl",
    "kcmp",
    "kexec_file_load",
    "kexec_load",
    "keyctl",
    "lookup_dcookie",
    "mount",
    "move_mount",
    "open_by_handle_at",
    "open_tree",
    "perf_event_open",
    "pivot_root",
    "process_vm_readv",
    "process_vm_writev",
    "quotactl",
    "reboot",
    "request_key",
    "setns",
    "settimeofday",
    "stime",
    "swapoff",
    "swapon",
    "syslog",
    "umount",
    "umount2",
    "unshare",
    "userfaultfd",
)
SECCOMP_CLONE_DENIED_MASKS = (
    128,
    131072,
    33554432,
    67108864,
    134217728,
    268435456,
    536870912,
    1073741824,
)
EXPECTED_TMPFS = {
    "/baseline": "rw,nosuid,nodev,noexec,size=268435456,mode=0755",
    "/cargo-home": (
        "rw,nosuid,nodev,noexec,size=2147483648,uid=65532,gid=65532,mode=0700"
    ),
    "/private": "rw,nosuid,nodev,size=2147483648,uid=0,gid=0,mode=0755",
    "/target": "rw,nosuid,nodev,size=8589934592,uid=65532,gid=65532,mode=0700",
    "/tmp": "rw,nosuid,nodev,size=536870912,mode=1777",
}
EXPECTED_ULIMITS = (
    ("core", 0, 0),
    ("fsize", 1073741824, 1073741824),
    ("nofile", 1024, 1024),
)
TRUSTED_BOUNDARY_FILE_KEYS = frozenset(
    {
        "cargo-mutants",
        "check-cage-all-target-inventory.py",
        "check-cage-enforcement.sh",
        "check-cage-linux-enforcement.sh",
        "check-exact-cargo-test-inventory.py",
        "check-keyring-transparency.sh",
        "check-linux-enforcement-stack.py",
        "check-secret-broker-boundary.sh",
        "check-security-adversarial-evidence.py",
        "command-client.py",
        "entrypoint.py",
        "security-evidence-seccomp.json",
        "verifier-bin/cargo",
        "verifier-bin/cc",
        "verifier-bin/ldd",
    }
)


@dataclasses.dataclass(frozen=True)
class OutputSpec:
    names: tuple[str, ...]
    nonempty: tuple[str, ...]


OUTPUT_SPECS = {
    "adversarial-release": OutputSpec(
        names=("adversarial-evidence.log",),
        nonempty=("adversarial-evidence.log",),
    ),
    "linux-enforcement": OutputSpec(
        names=(
            "broker-boundary.log",
            "cage-enforcement.log",
            "committed-adversarial-evidence.log",
            "key-log-transparency.log",
            "linux-adversarial-controls.log",
            "migration-state-store.log",
            "runner-contract.log",
        ),
        nonempty=(
            "broker-boundary.log",
            "cage-enforcement.log",
            "committed-adversarial-evidence.log",
            "key-log-transparency.log",
            "linux-adversarial-controls.log",
            "migration-state-store.log",
            "runner-contract.log",
        ),
    ),
    "refresh-linux-evidence": OutputSpec(
        names=("linux-evidence.patch", "linux-evidence.patch.sha256", "source-sha.txt"),
        nonempty=(
            "linux-evidence.patch",
            "linux-evidence.patch.sha256",
            "source-sha.txt",
        ),
    ),
    "refresh-all-evidence": OutputSpec(
        names=(
            "all-evidence-inventory.json",
            "all-evidence.patch",
            "all-evidence.patch.sha256",
            "source-sha.txt",
        ),
        nonempty=(
            "all-evidence-inventory.json",
            "all-evidence.patch",
            "all-evidence.patch.sha256",
            "source-sha.txt",
        ),
    ),
    "hostile-probe": OutputSpec(
        names=("probe.log",),
        nonempty=("probe.log",),
    ),
    "hostile-cargo-probe": OutputSpec(
        names=("probe.log",),
        nonempty=("probe.log",),
    ),
}


@dataclasses.dataclass(frozen=True)
class RepositoryIdentity:
    root: Path
    device: int
    inode: int
    mode: int
    head: str
    tree: str


@dataclasses.dataclass(frozen=True)
class DirectoryChainIdentity:
    path: Path
    components: tuple[tuple[Path, int, int, int, int], ...]


def expected_seccomp_profile() -> dict[str, object]:
    errno_rule = {
        "names": list(SECCOMP_DENIED_SYSCALLS),
        "action": "SCMP_ACT_ERRNO",
        "errnoRet": 1,
    }
    clone_rules = [
        {
            "names": ["clone"],
            "action": "SCMP_ACT_ERRNO",
            "errnoRet": 1,
            "args": [
                {
                    "index": 0,
                    "value": mask,
                    "valueTwo": mask,
                    "op": "SCMP_CMP_MASKED_EQ",
                }
            ],
        }
        for mask in SECCOMP_CLONE_DENIED_MASKS
    ]
    return {
        "defaultAction": "SCMP_ACT_ALLOW",
        "defaultErrnoRet": 1,
        "archMap": [
            {
                "architecture": "SCMP_ARCH_X86_64",
                "subArchitectures": ["SCMP_ARCH_X86", "SCMP_ARCH_X32"],
            }
        ],
        "syscalls": [errno_rule, *clone_rules],
    }


def validate_seccomp_profile(path: Path) -> tuple[dict[str, object], str]:
    try:
        raw = path.read_bytes()
        profile = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BoundaryError("trusted seccomp profile is not valid JSON") from error
    if profile != expected_seccomp_profile():
        raise BoundaryError("trusted seccomp profile contract changed")
    return profile, hashlib.sha256(raw).hexdigest()


def clean_host_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    environment = {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    if extra:
        environment.update(extra)
    return environment


def run_checked(
    command: list[str],
    *,
    environment: dict[str, str],
    timeout: int = 60,
    input_bytes: bytes | None = None,
) -> bytes:
    try:
        result = subprocess.run(
            command,
            check=False,
            env=environment,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise BoundaryError(f"command failed to complete: {command[0]}") from error
    if result.returncode != 0:
        detail = result.stderr[:4096].decode("utf-8", "replace").strip()
        raise BoundaryError(
            f"command failed ({result.returncode}): {command[0]}: {detail}"
        )
    return result.stdout


def git_command(root: Path, arguments: list[str], timeout: int = 60) -> bytes:
    command = [
        "/usr/bin/git",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "diff.external=",
        "-C",
        os.fspath(root),
        *arguments,
    ]
    return run_checked(command, environment=clean_host_env(), timeout=timeout)


def repository_identity(
    root: Path, expected_head: str, expected_tree: str | None
) -> RepositoryIdentity:
    if not SHA_PATTERN.fullmatch(expected_head):
        raise BoundaryError("expected source commit must be a lowercase 40-byte SHA")
    raw_root = root.absolute()
    try:
        root_lstat = raw_root.lstat()
    except OSError as error:
        raise BoundaryError("candidate root is unavailable") from error
    if stat.S_ISLNK(root_lstat.st_mode) or not stat.S_ISDIR(root_lstat.st_mode):
        raise BoundaryError("candidate root must be a real directory")
    resolved = raw_root.resolve(strict=True)
    resolved_stat = resolved.stat()
    if (root_lstat.st_dev, root_lstat.st_ino) != (
        resolved_stat.st_dev,
        resolved_stat.st_ino,
    ):
        raise BoundaryError("candidate root identity changed during resolution")
    head = git_command(resolved, ["rev-parse", "HEAD"]).decode("ascii").strip()
    tree = git_command(resolved, ["rev-parse", "HEAD^{tree}"]).decode("ascii").strip()
    if head != expected_head:
        raise BoundaryError("candidate checkout does not match the expected commit")
    if expected_tree is not None:
        if not SHA_PATTERN.fullmatch(expected_tree) or tree != expected_tree:
            raise BoundaryError("candidate checkout does not match the expected tree")
    status_output = git_command(
        resolved,
        [
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ],
        timeout=120,
    )
    if status_output:
        raise BoundaryError("candidate checkout must be clean before isolation")
    return RepositoryIdentity(
        root=resolved,
        device=resolved_stat.st_dev,
        inode=resolved_stat.st_ino,
        mode=stat.S_IMODE(resolved_stat.st_mode),
        head=head,
        tree=tree,
    )


def revalidate_repository(identity: RepositoryIdentity) -> None:
    observed = repository_identity(identity.root, identity.head, identity.tree)
    if (
        observed.device,
        observed.inode,
        observed.mode,
    ) != (identity.device, identity.inode, identity.mode):
        raise BoundaryError("candidate root identity changed during isolated execution")


def validate_trusted_runner(authorized_source_sha: str) -> Path:
    trusted_root = Path(__file__).resolve().parents[1]
    identity = repository_identity(trusted_root, authorized_source_sha, None)
    runner = Path(__file__).resolve()
    runner_stat = runner.lstat()
    if (
        not stat.S_ISREG(runner_stat.st_mode)
        or stat.S_ISLNK(runner_stat.st_mode)
        or runner_stat.st_nlink != 1
        or not runner.is_relative_to(identity.root)
    ):
        raise BoundaryError(
            "trusted runner is not a unique regular file in authorized source"
        )
    return identity.root


def parse_tree(root: Path, head: str) -> list[tuple[int, str, str]]:
    raw = git_command(root, ["ls-tree", "-rz", "--full-tree", head], timeout=120)
    entries: list[tuple[int, str, str]] = []
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            raw_mode, object_type, raw_object = metadata.split(b" ", 2)
            path = raw_path.decode("utf-8")
            mode = int(raw_mode, 8)
            object_id = raw_object.decode("ascii")
        except (UnicodeDecodeError, ValueError) as error:
            raise BoundaryError(
                "candidate tree contains an unsupported entry"
            ) from error
        pure = PurePosixPath(path)
        if (
            not path
            or pure.is_absolute()
            or ".." in pure.parts
            or ".git" in pure.parts
            or object_type != b"blob"
            or mode not in (0o100644, 0o100755, 0o120000)
            or not SHA_PATTERN.fullmatch(object_id)
        ):
            raise BoundaryError(f"candidate tree entry is unsafe: {path!r}")
        entries.append((mode, object_id, path))
    if not entries:
        raise BoundaryError("candidate tree is empty")
    return entries


def read_git_blobs(
    root: Path, entries: list[tuple[int, str, str]]
) -> list[tuple[int, str, bytes]]:
    command = [
        "/usr/bin/git",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-C",
        os.fspath(root),
        "cat-file",
        "--batch",
    ]
    try:
        process = subprocess.Popen(
            command,
            env=clean_host_env(),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except OSError as error:
        raise BoundaryError("unable to read candidate Git objects") from error
    if process.stdin is None or process.stdout is None:
        process.kill()
        raise BoundaryError("Git object reader did not expose bounded pipes")
    blobs: list[tuple[int, str, bytes]] = []
    total = 0
    try:
        for mode, object_id, path in entries:
            process.stdin.write(object_id.encode("ascii") + b"\n")
            process.stdin.flush()
            header = process.stdout.readline(MAX_FILE_BYTES + 1)
            fields = header.rstrip(b"\n").split(b" ")
            if (
                len(fields) != 3
                or fields[0] != object_id.encode("ascii")
                or fields[1] != b"blob"
            ):
                raise BoundaryError("Git returned an unexpected candidate object")
            try:
                size = int(fields[2])
            except ValueError as error:
                raise BoundaryError(
                    "Git returned an invalid candidate object size"
                ) from error
            if size < 0 or size > MAX_FILE_BYTES or total + size > MAX_SOURCE_BYTES:
                raise BoundaryError("candidate source exceeds the isolation copy bound")
            data = process.stdout.read(size)
            trailer = process.stdout.read(1)
            if len(data) != size or trailer != b"\n":
                raise BoundaryError("Git candidate object was truncated")
            total += size
            blobs.append((mode, path, data))
        process.stdin.close()
        if process.wait(timeout=30) != 0:
            raise BoundaryError("Git candidate object reader failed")
    except BaseException:
        with contextlib.suppress(OSError):
            process.kill()
        with contextlib.suppress(OSError, subprocess.TimeoutExpired):
            process.wait(timeout=5)
        raise
    return blobs


def safe_parent(root: Path, relative: PurePosixPath) -> Path:
    current = root
    for part in relative.parts[:-1]:
        current = current / part
        try:
            current.mkdir(mode=0o755)
        except FileExistsError:
            current_stat = current.lstat()
            if not stat.S_ISDIR(current_stat.st_mode) or stat.S_ISLNK(
                current_stat.st_mode
            ):
                raise BoundaryError(
                    "candidate copy has a non-directory parent collision"
                )
    return current


def materialize_private_copy(identity: RepositoryIdentity, destination: Path) -> None:
    destination.mkdir(mode=0o700)
    entries = parse_tree(identity.root, identity.head)
    blobs = read_git_blobs(identity.root, entries)
    for mode, path, data in blobs:
        relative = PurePosixPath(path)
        parent = safe_parent(destination, relative)
        target = parent / relative.name
        if mode == 0o120000:
            try:
                link_target = data.decode("utf-8")
            except UnicodeDecodeError as error:
                raise BoundaryError(
                    "candidate source contains a non-UTF-8 symlink"
                ) from error
            normalized_target = posixpath.normpath(
                posixpath.join(posixpath.dirname(path), link_target)
            )
            if (
                not link_target
                or "\0" in link_target
                or posixpath.isabs(link_target)
                or normalized_target == ".."
                or normalized_target.startswith("../")
            ):
                raise BoundaryError("candidate source contains an invalid symlink")
            os.symlink(link_target, target)
            continue
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(target, flags, 0o755 if mode == 0o100755 else 0o644)
        try:
            view = memoryview(data)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise BoundaryError("candidate copy write did not make progress")
                view = view[written:]
        finally:
            os.close(descriptor)


def ensure_private_directory(path: Path) -> None:
    try:
        path.mkdir(mode=0o700, parents=True)
    except FileExistsError:
        pass
    observed = path.lstat()
    if (
        not stat.S_ISDIR(observed.st_mode)
        or stat.S_ISLNK(observed.st_mode)
        or observed.st_uid != os.getuid()
        or stat.S_IMODE(observed.st_mode) & 0o077
    ):
        raise BoundaryError(f"runner state is not private: {path}")


def directory_chain_identity(path: Path) -> DirectoryChainIdentity:
    normalized = Path(os.path.abspath(os.fspath(path)))
    if not normalized.is_absolute():
        raise BoundaryError("runner state path is not absolute")
    current = Path(normalized.anchor)
    components: list[tuple[Path, int, int, int, int]] = []
    for part in normalized.parts[1:]:
        current /= part
        try:
            observed = current.lstat()
        except OSError as error:
            raise BoundaryError(
                f"runner state parent is unavailable: {current}"
            ) from error
        if stat.S_ISLNK(observed.st_mode) or not stat.S_ISDIR(observed.st_mode):
            raise BoundaryError(
                f"runner state parent is not a real directory: {current}"
            )
        components.append(
            (
                current,
                observed.st_dev,
                observed.st_ino,
                stat.S_IMODE(observed.st_mode),
                observed.st_uid,
            )
        )
    resolved = normalized.resolve(strict=True)
    if resolved != normalized:
        raise BoundaryError("runner state path resolves through an alias")
    return DirectoryChainIdentity(path=normalized, components=tuple(components))


def revalidate_directory_chain(identity: DirectoryChainIdentity) -> None:
    observed = directory_chain_identity(identity.path)
    if observed.components != identity.components:
        raise BoundaryError("runner state directory identity changed")


def prepare_state_directory(raw_path: Path) -> DirectoryChainIdentity:
    normalized = Path(os.path.abspath(os.fspath(raw_path)))
    parent_identity = directory_chain_identity(normalized.parent)
    revalidate_directory_chain(parent_identity)
    try:
        normalized.mkdir(mode=0o700)
    except FileExistsError:
        pass
    ensure_private_directory(normalized)
    identity = directory_chain_identity(normalized)
    revalidate_directory_chain(parent_identity)
    return identity


def open_private_lock(path: Path) -> int:
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise BoundaryError("runner lock is unavailable or aliased") from error
    try:
        opened = os.fstat(descriptor)
        observed = path.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or stat.S_ISLNK(observed.st_mode)
            or opened.st_nlink != 1
            or opened.st_uid != os.getuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
            or (opened.st_dev, opened.st_ino, opened.st_mode)
            != (observed.st_dev, observed.st_ino, observed.st_mode)
        ):
            raise BoundaryError("runner lock is not a private unique regular file")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def docker_environment(docker_config: Path, docker_host: str | None) -> dict[str, str]:
    ensure_private_directory(docker_config)
    extra = {"DOCKER_CONFIG": os.fspath(docker_config)}
    if docker_host is not None:
        extra["DOCKER_HOST"] = docker_host
    return clean_host_env(extra)


def validate_docker_host(
    raw_host: str | None, candidate: Path, state_dir: Path
) -> str | None:
    if sys.platform != "darwin":
        if raw_host is not None:
            raise BoundaryError("an explicit Docker host is restricted to macOS")
        return None
    if raw_host is None or not raw_host.startswith("unix://"):
        raise BoundaryError(
            "macOS security execution requires an explicit Unix Docker host"
        )
    socket_path = Path(raw_host.removeprefix("unix://"))
    if not socket_path.is_absolute():
        raise BoundaryError("Docker host socket must be absolute")
    try:
        observed = socket_path.lstat()
        resolved = socket_path.resolve(strict=True)
        resolved_stat = resolved.stat()
    except OSError as error:
        raise BoundaryError("Docker host socket is unavailable") from error
    if (
        stat.S_ISLNK(observed.st_mode)
        or not stat.S_ISSOCK(observed.st_mode)
        or observed.st_uid != os.getuid()
        or (observed.st_dev, observed.st_ino)
        != (resolved_stat.st_dev, resolved_stat.st_ino)
        or resolved == candidate
        or resolved.is_relative_to(candidate)
        or resolved == state_dir
        or resolved.is_relative_to(state_dir)
    ):
        raise BoundaryError("Docker host socket is not caller-owned and isolated")
    return f"unix://{resolved}"


def docker_path() -> str:
    if sys.platform == "linux":
        docker = shutil.which("docker", path="/usr/bin:/bin")
        if docker != "/usr/bin/docker":
            raise BoundaryError("Linux security execution requires /usr/bin/docker")
        return docker
    if sys.platform == "darwin":
        docker = shutil.which(
            "docker", path="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"
        )
        if docker not in ("/opt/homebrew/bin/docker", "/usr/local/bin/docker"):
            raise BoundaryError(
                "macOS security execution requires a system package Docker CLI"
            )
        return docker
    raise BoundaryError("security execution requires a Linux or macOS Docker host")


def docker_output(
    docker: str,
    arguments: list[str],
    environment: dict[str, str],
    timeout: int = 60,
) -> str:
    return (
        run_checked([docker, *arguments], environment=environment, timeout=timeout)
        .decode("utf-8", "strict")
        .strip()
    )


def container_ids_for_state(
    docker: str, environment: dict[str, str], state_identity: str
) -> set[str]:
    output = docker_output(
        docker,
        [
            "ps",
            "--all",
            "--quiet",
            "--no-trunc",
            "--filter",
            f"label={MANAGED_LABEL}",
            "--filter",
            f"label={STATE_LABEL}={state_identity}",
        ],
        environment,
    )
    identifiers = {line for line in output.splitlines() if line}
    if any(
        not CONTAINER_ID_PATTERN.fullmatch(identifier) for identifier in identifiers
    ):
        raise BoundaryError("Docker returned an invalid managed container identifier")
    return identifiers


def stop_and_remove_container(
    docker: str, environment: dict[str, str], identifier: str
) -> None:
    if not CONTAINER_ID_PATTERN.fullmatch(identifier):
        raise BoundaryError("refusing to manage an invalid container identifier")
    status = docker_output(
        docker,
        ["inspect", "--format", "{{.State.Status}}", identifier],
        environment,
    )
    if status not in ("created", "running", "paused", "restarting", "exited", "dead"):
        raise BoundaryError("Docker returned an invalid container state")
    if status in ("running", "paused", "restarting"):
        run_checked(
            [docker, "kill", "--signal", "KILL", identifier],
            environment=environment,
            timeout=30,
        )
    if status != "created":
        wait_status = docker_output(
            docker, ["wait", identifier], environment, timeout=60
        )
        if not wait_status.isdigit():
            raise BoundaryError("Docker returned an invalid container wait status")
        status_after = docker_output(
            docker,
            ["inspect", "--format", "{{.State.Status}}", identifier],
            environment,
        )
        if status_after not in ("exited", "dead"):
            raise BoundaryError("managed container did not reach a stopped state")
    run_checked(
        [docker, "rm", "--force", "--volumes", identifier],
        environment=environment,
        timeout=60,
    )


def clean_stale_state(
    docker: str,
    environment: dict[str, str],
    state_identity: str,
    state_dir: Path,
    directory_identity: DirectoryChainIdentity,
) -> None:
    revalidate_directory_chain(directory_identity)
    identifiers = container_ids_for_state(docker, environment, state_identity)
    runs = state_dir / "runs"
    if runs.exists():
        for cidfile in runs.glob("*/container.cid"):
            try:
                identifier = cidfile.read_text(encoding="ascii").strip()
            except OSError as error:
                raise BoundaryError(
                    "unable to read stale container identity"
                ) from error
            if identifier:
                if not CONTAINER_ID_PATTERN.fullmatch(identifier):
                    raise BoundaryError("stale container identity is invalid")
                if identifier not in identifiers:
                    present = docker_output(
                        docker,
                        [
                            "ps",
                            "--all",
                            "--quiet",
                            "--no-trunc",
                            "--filter",
                            f"id={identifier}",
                        ],
                        environment,
                    )
                    if present:
                        if present != identifier:
                            raise BoundaryError(
                                "stale container identity resolved ambiguously"
                            )
                        labels = docker_output(
                            docker,
                            [
                                "inspect",
                                "--format",
                                '{{index .Config.Labels "org.chio.security-execution.managed"}}|{{index .Config.Labels "org.chio.security-execution.state"}}',
                                identifier,
                            ],
                            environment,
                        )
                        if labels != f"true|{state_identity}":
                            raise BoundaryError(
                                "stale container is not owned by this runner state"
                            )
                        identifiers.add(identifier)
    for identifier in sorted(identifiers):
        stop_and_remove_container(docker, environment, identifier)
    if container_ids_for_state(docker, environment, state_identity):
        raise BoundaryError("managed containers remain after stale cleanup")
    if runs.exists():
        revalidate_directory_chain(directory_identity)
        observed = runs.lstat()
        if not stat.S_ISDIR(observed.st_mode) or stat.S_ISLNK(observed.st_mode):
            raise BoundaryError("runner run-state root is unsafe")
        shutil.rmtree(runs)
    runs.mkdir(mode=0o700)
    revalidate_directory_chain(directory_identity)


def container_create_arguments(
    *,
    name: str,
    cidfile: Path,
    authority_scope: str,
    state_identity: str,
    image: str,
    operation: str,
    source: Path,
    output: Path,
    seccomp_profile: Path,
    source_sha: str,
    timeout_seconds: int,
) -> list[str]:
    uid = os.getuid()
    gid = os.getgid()
    arguments = [
        "create",
        "--platform",
        "linux/amd64",
        "--name",
        name,
        "--cidfile",
        os.fspath(cidfile),
        "--label",
        MANAGED_LABEL,
        "--label",
        f"{AUTHORITY_LABEL}={authority_scope}",
        "--label",
        f"{STATE_LABEL}={state_identity}",
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
        f"seccomp={seccomp_profile}",
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
        f"type=bind,src={source},dst=/source,readonly",
        "--mount",
        f"type=bind,src={output},dst=/output",
    ]
    container_env = {
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
        "CHIO_SECURITY_IMAGE_ID": image,
        "CHIO_SECCOMP_PROFILE_SHA256": hashlib.sha256(
            seccomp_profile.read_bytes()
        ).hexdigest(),
        "HOME": "/tmp/home",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "RUSTUP_HOME": "/usr/local/rustup",
        "SOURCE_SHA": source_sha,
    }
    for key, value in sorted(container_env.items()):
        arguments.extend(["--env", f"{key}={value}"])
    arguments.extend([image, operation, "--timeout-seconds", str(timeout_seconds)])
    return arguments


def validate_container_create_arguments(arguments: list[str]) -> None:
    if not arguments or arguments[0] != "create":
        raise BoundaryError("Docker create command contract changed")
    image_indexes = [
        index for index, value in enumerate(arguments) if IMAGE_PATTERN.fullmatch(value)
    ]
    if len(image_indexes) != 1:
        raise BoundaryError("Docker create image contract changed")
    image_index = image_indexes[0]
    suffix = arguments[image_index:]
    if (
        len(suffix) != 4
        or suffix[2] != "--timeout-seconds"
        or suffix[1] not in OUTPUT_SPECS
        or not suffix[3].isdigit()
    ):
        raise BoundaryError("Docker create operation contract changed")

    value_flags = {
        "--cap-add": 3,
        "--cap-drop": 1,
        "--cidfile": 1,
        "--cpus": 1,
        "--env": 19,
        "--label": 3,
        "--log-driver": 1,
        "--memory": 1,
        "--memory-swap": 1,
        "--mount": 2,
        "--name": 1,
        "--network": 1,
        "--pids-limit": 1,
        "--platform": 1,
        "--security-opt": 2,
        "--tmpfs": 5,
        "--ulimit": 3,
    }
    boolean_flags = {"--init", "--read-only"}
    observed: dict[str, list[str]] = {flag: [] for flag in value_flags}
    observed_boolean: set[str] = set()
    cursor = 1
    while cursor < image_index:
        flag = arguments[cursor]
        if flag in boolean_flags:
            if flag in observed_boolean:
                raise BoundaryError("Docker create contains a duplicate boolean flag")
            observed_boolean.add(flag)
            cursor += 1
            continue
        if flag not in value_flags or cursor + 1 >= image_index:
            raise BoundaryError("Docker create contains an unauthorized option")
        observed[flag].append(arguments[cursor + 1])
        cursor += 2
    if observed_boolean != boolean_flags or any(
        len(observed[flag]) != count for flag, count in value_flags.items()
    ):
        raise BoundaryError("Docker create option inventory changed")

    exact_values = {
        "--cap-add": ["CHOWN", "SETGID", "SETUID"],
        "--cap-drop": ["ALL"],
        "--cpus": ["4"],
        "--log-driver": ["none"],
        "--memory": ["12g"],
        "--memory-swap": ["12g"],
        "--network": ["none"],
        "--pids-limit": ["512"],
        "--platform": ["linux/amd64"],
        "--tmpfs": [
            f"{path}:{EXPECTED_TMPFS[path]}"
            for path in ("/tmp", "/private", "/baseline", "/target", "/cargo-home")
        ],
        "--ulimit": [
            "core=0:0",
            "fsize=1073741824:1073741824",
            "nofile=1024:1024",
        ],
    }
    if any(observed[flag] != values for flag, values in exact_values.items()):
        raise BoundaryError("Docker create resource or isolation values changed")
    security_options = observed["--security-opt"]
    if security_options[0] != "no-new-privileges" or not security_options[1].startswith(
        "seccomp=/"
    ):
        raise BoundaryError("Docker create security options changed")
    labels = observed["--label"]
    if (
        labels[0] != MANAGED_LABEL
        or not labels[1].startswith(f"{AUTHORITY_LABEL}=")
        or not labels[2].startswith(f"{STATE_LABEL}=")
        or len(labels[1].split("=", 1)[1]) != 24
        or len(labels[2].split("=", 1)[1]) != 24
    ):
        raise BoundaryError("Docker create label contract changed")
    mounts = observed["--mount"]
    if not re.fullmatch(
        r"type=bind,src=[^,]+,dst=/source,readonly", mounts[0]
    ) or not re.fullmatch(r"type=bind,src=[^,]+,dst=/output", mounts[1]):
        raise BoundaryError("Docker create mount contract changed")
    environment_entries = observed["--env"]
    if any("=" not in entry for entry in environment_entries):
        raise BoundaryError("Docker create environment contract changed")
    environment = dict(entry.split("=", 1) for entry in environment_entries)
    expected_environment_keys = {
        "CARGO_BUILD_JOBS",
        "CARGO_HOME",
        "CARGO_INCREMENTAL",
        "CARGO_NET_OFFLINE",
        "CARGO_PROFILE_DEV_DEBUG",
        "CARGO_PROFILE_TEST_DEBUG",
        "CARGO_TARGET_DIR",
        "CARGO_TERM_COLOR",
        "CHIO_ENTERPRISE_SECURITY_RUNNER",
        "CHIO_HOST_GID",
        "CHIO_HOST_UID",
        "CHIO_SECURITY_IMAGE_ID",
        "CHIO_SECCOMP_PROFILE_SHA256",
        "HOME",
        "LANG",
        "LC_ALL",
        "PATH",
        "RUSTUP_HOME",
        "SOURCE_SHA",
    }
    if (
        len(environment) != len(environment_entries)
        or set(environment) != expected_environment_keys
    ):
        raise BoundaryError("Docker create environment inventory changed")


def validate_created_container(
    docker: str,
    environment: dict[str, str],
    identifier: str,
    *,
    name: str,
    authority_scope: str,
    state_identity: str,
    image: str,
    operation: str,
    source: Path,
    output: Path,
    timeout_seconds: int,
    seccomp_profile: dict[str, object],
) -> None:
    raw = docker_output(docker, ["inspect", identifier], environment, timeout=60)
    try:
        documents = json.loads(raw)
    except json.JSONDecodeError as error:
        raise BoundaryError(
            "Docker returned an invalid container inspection"
        ) from error
    if (
        not isinstance(documents, list)
        or len(documents) != 1
        or not isinstance(documents[0], dict)
    ):
        raise BoundaryError("Docker returned an ambiguous container inspection")
    document = documents[0]
    config = document.get("Config")
    host = document.get("HostConfig")
    mounts = document.get("Mounts")
    if not isinstance(config, dict) or not isinstance(host, dict):
        raise BoundaryError("Docker omitted the created container contract")
    expected_labels = {
        MANAGED_LABEL.split("=", 1)[0]: "true",
        AUTHORITY_LABEL: authority_scope,
        STATE_LABEL: state_identity,
    }
    expected_config = {
        "Image": image,
        "Cmd": [operation, "--timeout-seconds", str(timeout_seconds)],
        "Entrypoint": [
            "/usr/bin/python3",
            "-I",
            "/opt/chio-security/entrypoint.py",
        ],
        "WorkingDir": "/private/candidate",
        "User": "",
        "Labels": expected_labels,
        "OpenStdin": False,
        "StdinOnce": False,
        "Tty": False,
    }
    if any(config.get(key) != value for key, value in expected_config.items()):
        raise BoundaryError("Docker changed the created container configuration")
    if (
        document.get("Id") != identifier
        or document.get("Name") != f"/{name}"
        or document.get("Image") != image
        or document.get("Path") != "/usr/bin/python3"
        or document.get("Args")
        != [
            "-I",
            "/opt/chio-security/entrypoint.py",
            operation,
            "--timeout-seconds",
            str(timeout_seconds),
        ]
    ):
        raise BoundaryError("Docker changed the created container identity")

    security_options = host.get("SecurityOpt")
    if (
        not isinstance(security_options, list)
        or len(security_options) != 2
        or security_options[0] != "no-new-privileges"
        or not isinstance(security_options[1], str)
        or not security_options[1].startswith("seccomp=")
    ):
        raise BoundaryError("Docker changed the created container security options")
    try:
        observed_seccomp = json.loads(security_options[1].removeprefix("seccomp="))
    except json.JSONDecodeError as error:
        raise BoundaryError(
            "Docker returned an invalid applied seccomp profile"
        ) from error
    if observed_seccomp != seccomp_profile:
        raise BoundaryError("Docker changed the applied seccomp profile")

    expected_host = {
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
        "ShmSize": 67108864,
        "Tmpfs": EXPECTED_TMPFS,
        "UTSMode": "",
        "UsernsMode": "",
        "VolumesFrom": None,
    }
    if any(host.get(key) != value for key, value in expected_host.items()):
        raise BoundaryError("Docker changed the created container host boundary")
    observed_ulimits = host.get("Ulimits")
    if not isinstance(observed_ulimits, list) or any(
        not isinstance(item, dict) for item in observed_ulimits
    ):
        raise BoundaryError("Docker omitted the created container ulimit contract")
    normalized_ulimits = tuple(
        (item.get("Name"), item.get("Soft"), item.get("Hard"))
        for item in observed_ulimits
    )
    if normalized_ulimits != EXPECTED_ULIMITS:
        raise BoundaryError("Docker changed the created container ulimit contract")

    expected_mounts = (
        {
            "Type": "bind",
            "Source": os.fspath(source),
            "Destination": "/source",
            "Mode": "",
            "RW": False,
            "Propagation": "rprivate",
        },
        {
            "Type": "bind",
            "Source": os.fspath(output),
            "Destination": "/output",
            "Mode": "",
            "RW": True,
            "Propagation": "rprivate",
        },
    )
    if not isinstance(mounts, list) or tuple(mounts) != expected_mounts:
        raise BoundaryError("Docker changed the created container mount inventory")


def read_regular_file_once(path: Path, maximum: int, nonempty: bool) -> bytes:
    before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_nlink != 1
        or before.st_size > maximum
        or (nonempty and before.st_size == 0)
    ):
        raise BoundaryError(
            f"container output is not an admissible regular file: {path.name}"
        )
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_nlink,
            opened.st_size,
        ) != (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_size,
        ):
            raise BoundaryError("container output identity changed before import")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if len(data) > maximum or len(data) != before.st_size:
        raise BoundaryError("container output exceeded its one-read bound")
    if (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_nlink,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ) != (
        opened.st_dev,
        opened.st_ino,
        opened.st_mode,
        opened.st_nlink,
        opened.st_size,
        opened.st_mtime_ns,
        opened.st_ctime_ns,
    ):
        raise BoundaryError("container output changed during its one-read import")
    return data


def collect_outputs(
    stage: Path,
    operation: str,
    expected_source_sha: str,
    expected_image: str,
    expected_seccomp_digest: str,
) -> dict[str, bytes]:
    spec = OUTPUT_SPECS[operation]
    observed = set()
    for entry in os.scandir(stage):
        if entry.name in (".", ".."):
            continue
        observed.add(entry.name)
    expected = set(spec.names)
    if observed != expected:
        raise BoundaryError(
            "container output inventory changed: "
            f"expected {sorted(expected)}, observed {sorted(observed)}"
        )
    payloads: dict[str, bytes] = {}
    total = 0
    for name in spec.names:
        payload = read_regular_file_once(
            stage / name, MAX_FILE_BYTES, name in spec.nonempty
        )
        total += len(payload)
        if total > MAX_TOTAL_OUTPUT_BYTES:
            raise BoundaryError("container output exceeds the aggregate import bound")
        payloads[name] = payload
    if operation in ("refresh-linux-evidence", "refresh-all-evidence"):
        source = payloads["source-sha.txt"].decode("ascii", "strict").strip()
        if source != expected_source_sha:
            raise BoundaryError(
                "refreshed evidence output is bound to the wrong source"
            )
        patch_name = (
            "all-evidence.patch"
            if operation == "refresh-all-evidence"
            else "linux-evidence.patch"
        )
        checksum_line = (
            payloads[f"{patch_name}.sha256"].decode("ascii", "strict").strip()
        )
        expected_checksum = hashlib.sha256(payloads[patch_name]).hexdigest()
        if checksum_line != f"{expected_checksum}  {patch_name}":
            raise BoundaryError("refreshed evidence patch checksum is invalid")
        if operation == "refresh-all-evidence":
            try:
                inventory = json.loads(
                    payloads["all-evidence-inventory.json"].decode("utf-8")
                )
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise BoundaryError(
                    "full evidence inventory is invalid JSON"
                ) from error
            canonical_inventory = (
                json.dumps(inventory, sort_keys=True, separators=(",", ":")) + "\n"
            ).encode("utf-8")
            if not isinstance(inventory, dict):
                raise BoundaryError("full evidence inventory is not an object")
            execution_boundary = inventory.get("execution_boundary", {})
            trusted_file_hashes = (
                execution_boundary.get("trusted_file_sha256")
                if isinstance(execution_boundary, dict)
                else None
            )
            if (
                canonical_inventory != payloads["all-evidence-inventory.json"]
                or inventory.get("schema") != "chio.security-evidence-refresh.v1"
                or inventory.get("source_sha") != expected_source_sha
                or inventory.get("patch_sha256") != expected_checksum
                or inventory.get("campaign_count") != 35
                or inventory.get("outcome_count") != 35
                or inventory.get("case_count") != 28
                or not isinstance(inventory.get("campaigns"), list)
                or len(set(inventory["campaigns"])) != 35
                or not isinstance(inventory.get("paths"), list)
                or len(set(inventory["paths"])) != 64
                or not isinstance(execution_boundary, dict)
                or set(execution_boundary)
                != {
                    "image_id",
                    "platform",
                    "schema",
                    "seccomp_profile_sha256",
                    "trusted_file_sha256",
                }
                or execution_boundary.get("schema")
                != "chio.security-execution-boundary.v1"
                or execution_boundary.get("image_id") != expected_image
                or execution_boundary.get("platform") != "linux/amd64"
                or execution_boundary.get("seccomp_profile_sha256")
                != expected_seccomp_digest
                or not isinstance(trusted_file_hashes, dict)
                or set(trusted_file_hashes) != TRUSTED_BOUNDARY_FILE_KEYS
                or any(
                    not isinstance(digest, str)
                    or len(digest) != 64
                    or any(
                        character not in "0123456789abcdef" for character in digest
                    )
                    for digest in trusted_file_hashes.values()
                )
            ):
                raise BoundaryError("full evidence inventory contract is invalid")
    return payloads


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def publish_outputs(output_dir: Path, payloads: dict[str, bytes]) -> None:
    parent = output_dir.parent.resolve(strict=True)
    if output_dir.exists() or output_dir.is_symlink():
        raise BoundaryError("final output directory already exists")
    temporary = Path(
        tempfile.mkdtemp(prefix=f".{output_dir.name}.partial-", dir=parent)
    )
    os.chmod(temporary, 0o700)
    try:
        for name, payload in payloads.items():
            target = temporary / name
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                view = memoryview(payload)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise BoundaryError(
                            "output publication write did not make progress"
                        )
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        fsync_directory(temporary)
        os.replace(temporary, output_dir)
        fsync_directory(parent)
    except BaseException:
        if temporary.exists():
            shutil.rmtree(temporary)
        raise


def reject_published_outputs(output_dir: Path, expected_names: set[str]) -> None:
    parent = output_dir.parent.resolve(strict=True)
    parent_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    parent_descriptor = os.open(parent, parent_flags)
    quarantine_name = f".{output_dir.name}.rejected-{os.urandom(12).hex()}"
    directory_descriptor = -1
    try:
        observed = os.stat(
            output_dir.name, dir_fd=parent_descriptor, follow_symlinks=False
        )
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        directory_descriptor = os.open(output_dir.name, flags, dir_fd=parent_descriptor)
        opened = os.fstat(directory_descriptor)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or (opened.st_dev, opened.st_ino, opened.st_mode)
            != (observed.st_dev, observed.st_ino, observed.st_mode)
            or opened.st_uid != os.getuid()
            or stat.S_IMODE(opened.st_mode) != 0o700
        ):
            raise BoundaryError("rejected output directory identity changed")
        names = set(os.listdir(directory_descriptor))
        if names != expected_names:
            raise BoundaryError("rejected output inventory changed before removal")
        os.rename(
            output_dir.name,
            quarantine_name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        for name in sorted(names):
            item = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
            if (
                not stat.S_ISREG(item.st_mode)
                or item.st_nlink != 1
                or item.st_uid != os.getuid()
                or stat.S_IMODE(item.st_mode) != 0o600
            ):
                raise BoundaryError("rejected output file identity changed")
            os.unlink(name, dir_fd=directory_descriptor)
        os.fsync(directory_descriptor)
        os.rmdir(quarantine_name, dir_fd=parent_descriptor)
        os.fsync(parent_descriptor)
    finally:
        if directory_descriptor >= 0:
            os.close(directory_descriptor)
        os.close(parent_descriptor)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--authorized-source-sha", required=True)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--docker-host")
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--expected-tree")
    parser.add_argument("--image", required=True)
    parser.add_argument("--operation", required=True, choices=sorted(OUTPUT_SPECS))
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--state-dir", type=Path)
    parser.add_argument("--timeout-seconds", type=int, default=7200)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not SHA_PATTERN.fullmatch(args.authorized_source_sha):
        raise BoundaryError("authorized source must be a lowercase 40-byte SHA")
    if not SHA_PATTERN.fullmatch(args.expected_sha):
        raise BoundaryError("candidate source must be a lowercase 40-byte SHA")
    if not IMAGE_PATTERN.fullmatch(args.image):
        raise BoundaryError(
            "security execution image must be addressed by sha256 digest"
        )
    if not 10 <= args.timeout_seconds <= 21600:
        raise BoundaryError("container timeout must be between 10 seconds and 6 hours")
    trusted_root = validate_trusted_runner(args.authorized_source_sha)
    seccomp_profile = trusted_root / "deploy/docker/security-evidence-seccomp.json"
    profile_stat = seccomp_profile.lstat()
    if (
        not stat.S_ISREG(profile_stat.st_mode)
        or stat.S_ISLNK(profile_stat.st_mode)
        or profile_stat.st_nlink != 1
    ):
        raise BoundaryError("trusted seccomp profile is not a unique regular file")
    parsed_seccomp_profile, seccomp_digest = validate_seccomp_profile(seccomp_profile)
    candidate = repository_identity(
        args.candidate, args.expected_sha, args.expected_tree
    )
    output_dir = args.output_dir.absolute()
    output_parent = output_dir.parent.resolve(strict=True)
    if output_dir == candidate.root or output_parent.is_relative_to(candidate.root):
        raise BoundaryError(
            "container output must be outside the authoritative candidate root"
        )
    scope = hashlib.sha256(args.authorized_source_sha.encode("ascii")).hexdigest()[:24]
    raw_state_dir = (
        args.state_dir
        if args.state_dir is not None
        else output_parent / ".chio-security-execution-state"
    )
    state_parent = directory_chain_identity(
        Path(os.path.abspath(os.fspath(raw_state_dir))).parent
    )
    state_dir = state_parent.path / Path(raw_state_dir).name
    if state_dir == candidate.root or state_dir.is_relative_to(candidate.root):
        raise BoundaryError(
            "runner state must be outside the authoritative candidate root"
        )
    state_directory_identity = prepare_state_directory(state_dir)
    state_component = state_directory_identity.components[-1]
    state_identity = hashlib.sha256(
        f"{state_dir}\0{state_component[1]}\0{state_component[2]}".encode("utf-8")
    ).hexdigest()[:24]
    docker_host = validate_docker_host(args.docker_host, candidate.root, state_dir)
    lock_path = state_dir / "lock"
    lock_descriptor = open_private_lock(lock_path)
    try:
        docker = docker_path()
    except BoundaryError:
        os.close(lock_descriptor)
        raise
    try:
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
        docker_config = state_dir / "docker-config"
        environment = docker_environment(docker_config, docker_host)
        image_identity = docker_output(
            docker,
            [
                "image",
                "inspect",
                "--format",
                "{{.Id}}|{{.Os}}|{{.Architecture}}",
                args.image,
            ],
            environment,
        )
        if image_identity != f"{args.image}|linux|amd64":
            raise BoundaryError("security execution image identity or platform changed")
        clean_stale_state(
            docker,
            environment,
            state_identity,
            state_dir,
            state_directory_identity,
        )
        run_id = f"{int(time.time())}-{os.getpid()}-{os.urandom(8).hex()}"
        run_root = state_dir / "runs" / run_id
        run_root.mkdir(mode=0o700)
        source_root = run_root / "source"
        source_root.mkdir(mode=0o700)
        work = source_root / "candidate"
        stage = run_root / "output"
        materialize_private_copy(candidate, work)
        os.chmod(work, 0o755)
        stage.mkdir(mode=0o700)
        cidfile = run_root / "container.cid"
        name = f"chio-security-{scope}-{os.urandom(6).hex()}"
        create_arguments = container_create_arguments(
            name=name,
            cidfile=cidfile,
            authority_scope=scope,
            state_identity=state_identity,
            image=args.image,
            operation=args.operation,
            source=work,
            output=stage,
            seccomp_profile=seccomp_profile,
            source_sha=args.expected_sha,
            timeout_seconds=args.timeout_seconds,
        )
        validate_container_create_arguments(create_arguments)
        identifier = ""
        payloads: dict[str, bytes] | None = None
        execution_error: BaseException | None = None
        try:
            docker_output(docker, create_arguments, environment, timeout=120)
            identifier = cidfile.read_text(encoding="ascii").strip()
            if not CONTAINER_ID_PATTERN.fullmatch(identifier):
                raise BoundaryError("Docker did not persist a valid container identity")
            validate_created_container(
                docker,
                environment,
                identifier,
                name=name,
                authority_scope=scope,
                state_identity=state_identity,
                image=args.image,
                operation=args.operation,
                source=work,
                output=stage,
                timeout_seconds=args.timeout_seconds,
                seccomp_profile=parsed_seccomp_profile,
            )
            docker_output(docker, ["start", identifier], environment, timeout=60)
            try:
                status = docker_output(
                    docker,
                    ["wait", identifier],
                    environment,
                    timeout=args.timeout_seconds + 30,
                )
            except BoundaryError:
                raise BoundaryError("candidate container exceeded its execution bound")
            if not status.isdigit() or int(status) != 0:
                raise BoundaryError(
                    f"candidate container failed with status {status!r}"
                )
            running = docker_output(
                docker,
                ["inspect", "--format", "{{.State.Running}}", identifier],
                environment,
            )
            if running != "false":
                raise BoundaryError(
                    "candidate container is still running before import"
                )
            revalidate_repository(candidate)
            payloads = collect_outputs(
                stage,
                args.operation,
                args.expected_sha,
                args.image,
                seccomp_digest,
            )
            revalidate_repository(candidate)
        except BaseException as error:
            execution_error = error

        cleanup_errors: list[BoundaryError] = []
        managed_identifiers: set[str] = set()
        if identifier:
            managed_identifiers.add(identifier)
        try:
            managed_identifiers.update(
                container_ids_for_state(docker, environment, state_identity)
            )
        except BoundaryError as error:
            cleanup_errors.append(error)
        for managed_identifier in sorted(managed_identifiers):
            try:
                stop_and_remove_container(docker, environment, managed_identifier)
            except BoundaryError as error:
                cleanup_errors.append(error)
        try:
            remaining = container_ids_for_state(docker, environment, state_identity)
        except BoundaryError as error:
            cleanup_errors.append(error)
            remaining = managed_identifiers
        if remaining:
            cleanup_errors.append(
                BoundaryError(
                    "managed container remains after mandatory kill and wait: "
                    + ", ".join(sorted(remaining))
                )
            )
        if cleanup_errors:
            raise BoundaryError(
                "candidate container cleanup failed; runner state was preserved"
            ) from cleanup_errors[0]
        if run_root.exists():
            shutil.rmtree(run_root)
        if execution_error is not None:
            raise execution_error
        if payloads is None:
            raise BoundaryError("candidate execution produced no importable output")
        revalidate_repository(candidate)
        publish_outputs(output_dir, payloads)
        try:
            revalidate_repository(candidate)
        except BaseException:
            reject_published_outputs(output_dir, set(payloads))
            raise
    finally:
        fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
        os.close(lock_descriptor)
    print(f"isolated security execution complete: {args.operation}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BoundaryError as error:
        print(f"security execution boundary failed: {error}", file=sys.stderr)
        raise SystemExit(1)
