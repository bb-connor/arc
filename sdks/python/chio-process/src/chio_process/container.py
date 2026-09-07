"""Bounded Python workers on a local Linux Docker engine.

The operator retains Docker authority. Workers receive only their authenticated
Chio socket, a private descriptor, read-only program bytes and temporary scratch
space. Docker and the shared Linux kernel remain part of the isolation boundary.
"""

import json
import os
import platform
import re
import selectors
import stat
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

MAX_PROGRAM_BYTES = 1024 * 1024
MAX_OUTPUT_BYTES = 8 * 1024 * 1024
DOCKER = ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock"]


class ContainerWorkerError(RuntimeError):
    """A launch, output-bound or lifecycle failure, with no automatic retry."""


@dataclass(frozen=True)
class ContainerResult:
    exit_code: int
    output: bytes
    container_id: str
    profile: dict


def _docker(*arguments, check=True):
    try:
        return subprocess.run(
            [*DOCKER, *arguments],
            capture_output=True,
            check=check,
            timeout=30,
            env={key: value for key, value in os.environ.items() if key != "DOCKER_CONTEXT"},
        )
    except subprocess.CalledProcessError:
        raise ContainerWorkerError(f"Docker {arguments[0]} failed") from None
    except subprocess.TimeoutExpired:
        raise ContainerWorkerError(f"Docker {arguments[0]} exceeded its time limit") from None


def _private_socket(value: str) -> Path:
    if not isinstance(value, str) or any(char in value for char in ",\n\r\0"):
        raise ValueError("Worker socket path cannot contain mount-option delimiters")
    path = Path(value)
    if not path.is_absolute():
        raise ValueError("Worker socket must have an absolute path")
    info = path.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("Worker socket must be private and owned by the operator")
    _protected_directories(path.parent)
    return path


def _protected_directories(directory):
    for parent in (directory, *directory.parents):
        info = parent.lstat()
        sticky_root = info.st_uid == 0 and info.st_mode & stat.S_ISVTX
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid not in (0, os.getuid())
            or (info.st_mode & 0o022 and not sticky_root)
        ):
            raise ValueError("Worker input ancestry is not protected")


def _collect(process, timeout, maximum):
    output = bytearray()
    deadline = time.monotonic() + timeout
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                raise ContainerWorkerError("Worker exceeded its wall-clock limit")
            chunk = os.read(process.stdout.fileno(), 8192)
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > maximum:
                raise ContainerWorkerError("Worker exceeded its output limit")
    try:
        process.wait(timeout=max(0.01, deadline - time.monotonic()))
    except subprocess.TimeoutExpired:
        raise ContainerWorkerError("Worker exceeded its wall-clock limit") from None
    return bytes(output)


def _remove_owned(name, nonce):
    inspected = _docker("inspect", name, check=False)
    if inspected.returncode:
        # A daemon error is not proof that a possibly created worker is gone.
        if (
            b"No such object" not in inspected.stderr
            and b"No such container" not in inspected.stderr
        ):
            raise ContainerWorkerError(f"Could not confirm worker cleanup: {name}")
        return
    record = json.loads(inspected.stdout)[0]
    if record["Config"]["Labels"].get("chio.worker.owner") != nonce:
        raise ContainerWorkerError("Refusing cleanup of a container with another owner")
    _docker("rm", "--force", "--volumes", record["Id"])


def run_container_worker(
    *,
    image: str,
    connection: dict,
    program: bytes,
    arguments: list[str] | None = None,
    timeout: int = 120,
    max_output_bytes: int = 2 * 1024 * 1024,
) -> ContainerResult:
    """Run one attempt and remove its container on success, failure or timeout.

    The image must be an installed immutable sha256 image id with Python at
    /usr/local/bin/python. The caller selects program bytes and arguments; they
    are not model-selected Docker options. No host output directory is mounted.
    A nonzero exit is returned for the application to reconcile through Chio.
    """
    if platform.system() != "Linux" or os.getuid() == 0:
        raise ValueError("This profile requires a non-root operator on Linux")
    if not isinstance(image, str) or re.fullmatch(r"sha256:[a-f0-9]{64}", image) is None:
        raise ValueError("Worker image must be an immutable local image id")
    if not isinstance(program, bytes) or not 0 < len(program) <= MAX_PROGRAM_BYTES:
        raise ValueError("Worker program must contain bounded bytes")
    if type(timeout) is not int or not 1 <= timeout <= 3600:
        raise ValueError("Worker timeout must be between 1 and 3600 seconds")
    if type(max_output_bytes) is not int or not 1 <= max_output_bytes <= MAX_OUTPUT_BYTES:
        raise ValueError("Worker output limit is out of range")
    if arguments is not None and (
        not isinstance(arguments, list)
        or len(arguments) > 64
        or any(not isinstance(arg, str) or "\0" in arg or len(arg) > 4096 for arg in arguments)
    ):
        raise ValueError("Invalid worker arguments")
    socket_path = _private_socket(connection["socket_path"])
    credential = connection.get("credential")
    if not isinstance(credential, str) or not credential or len(credential) > 8192:
        raise ValueError("A private process credential is required")
    security = json.loads(_docker("info", "--format", "{{json .SecurityOptions}}").stdout)
    if "name=seccomp,profile=builtin" not in security or any(
        option in security for option in ("name=rootless", "name=userns")
    ):
        raise ValueError("Worker requires the qualified local engine with built-in seccomp")
    image_record = json.loads(_docker("image", "inspect", image).stdout)[0]
    if image_record["Id"] != image or image_record["Config"].get("Volumes"):
        raise ValueError("Worker image must not declare additional writable volumes")
    nonce = uuid.uuid4().hex
    name = f"chio-worker-{nonce}"
    # A caller-controlled TMPDIR must not expose staged credentials through an
    # unprotected ancestor. This Linux profile uses the protected system tmp.
    _protected_directories(Path("/tmp"))
    with tempfile.TemporaryDirectory(prefix="chio-container-", dir="/tmp") as temporary:
        root = Path(temporary)
        descriptor = root / "connection.json"
        descriptor.write_text(
            json.dumps(
                {
                    "socket_path": "/run/chio/process.sock",
                    "credential": credential,
                }
            )
        )
        descriptor.chmod(0o600)
        source = root / "worker.py"
        source.write_bytes(program)
        source.chmod(0o400)
        uid, gid = os.getuid(), os.getgid()
        arguments = arguments or []
        create = [
            "create",
            "--pull=never",
            "--name",
            name,
            "--label",
            f"chio.worker.owner={nonce}",
            "--network",
            "none",
            "--ipc",
            "private",
            "--cgroupns",
            "private",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--user",
            f"{uid}:{gid}",
            "--memory",
            "512m",
            "--memory-swap",
            "512m",
            "--cpus",
            "1",
            "--pids-limit",
            "64",
            "--shm-size",
            "8m",
            "--init",
            "--restart",
            "no",
            "--log-driver",
            "none",
            "--no-healthcheck",
            "--ulimit",
            "core=0:0",
            "--ulimit",
            "nofile=128:128",
            "--ulimit",
            "fsize=16777216:16777216",
            "--tmpfs",
            f"/work:rw,noexec,nosuid,nodev,size=64m,mode=700,uid={uid},gid={gid}",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777",
            "--workdir",
            "/work",
            "--env",
            "HOME=/work",
            "--env",
            "MSWEA_GLOBAL_CONFIG_DIR=/work/mini-config",
            "--env",
            "MSWEA_SILENT_STARTUP=1",
            "--env",
            "PYTHONDONTWRITEBYTECODE=1",
            "--mount",
            f"type=bind,src={socket_path},dst=/run/chio/process.sock,readonly",
            "--mount",
            f"type=bind,src={descriptor},dst=/run/chio/connection.json,readonly",
            "--mount",
            f"type=bind,src={source},dst=/app/worker.py,readonly",
        ]
        for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"):
            for spelling in (key, key.lower()):
                create.extend(["--env", f"{spelling}="])
        create.extend(
            ["--entrypoint", "/usr/local/bin/python", image, "-u", "/app/worker.py", *arguments]
        )
        attached = None
        try:
            container_id = _docker(*create).stdout.decode().strip()
            if re.fullmatch(r"[a-f0-9]{64}", container_id) is None:
                raise ContainerWorkerError("Docker returned an invalid container identity")
            attached = subprocess.Popen(
                [*DOCKER, "start", "--attach", container_id],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env={key: value for key, value in os.environ.items() if key != "DOCKER_CONTEXT"},
            )
            output = _collect(attached, timeout, max_output_bytes)
            record = json.loads(_docker("inspect", container_id).stdout)[0]
            if record["State"]["Running"]:
                raise ContainerWorkerError("Worker attach ended while its container was running")
            return ContainerResult(
                record["State"]["ExitCode"],
                output,
                container_id,
                {
                    "image": record["Image"],
                    "user": record["Config"]["User"],
                    "network": record["HostConfig"]["NetworkMode"],
                    "readonly_rootfs": record["HostConfig"]["ReadonlyRootfs"],
                    "cap_drop": record["HostConfig"]["CapDrop"],
                    "security_opt": record["HostConfig"]["SecurityOpt"],
                    "memory_bytes": record["HostConfig"]["Memory"],
                    "pids_limit": record["HostConfig"]["PidsLimit"],
                    "mounts": [
                        {
                            "type": mount["Type"],
                            "destination": mount["Destination"],
                            "writable": mount["RW"],
                        }
                        for mount in record["Mounts"]
                    ],
                },
            )
        finally:
            try:
                if attached is not None:
                    # Stop the attachment first: an unread full output pipe can
                    # otherwise keep Docker's container removal waiting on I/O.
                    if attached.poll() is None:
                        attached.kill()
                    attached.wait(timeout=10)
            finally:
                if attached is not None:
                    attached.stdout.close()
                # Killing the client never substitutes for killing the worker.
                _remove_owned(name, nonce)
