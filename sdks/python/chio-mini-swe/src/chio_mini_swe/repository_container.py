"""Owned local containers and a bounded temporary volume for one repository command."""

import json
import os
import re
from datetime import UTC, datetime

from chio_mini_swe.repository_archive import MAX_ARCHIVE
from chio_mini_swe.repository_transport import DOCKER, docker, run

LABEL = "chio.repository.lease"
VOLUME_OPTIONS = {
    "type": "tmpfs",
    "device": "tmpfs",
    "o": "size=67108864,uid=65534,gid=65534,mode=0700,nosuid,nodev",
}


def engine():
    value = json.loads(docker("info", "--format", "{{json .}}"))
    security = value.get("SecurityOptions", [])
    if (
        os.getuid() == 0
        or value.get("OSType") != "linux"
        or value.get("CgroupVersion") != "2"
        or not value.get("ID")
        or not all(
            value.get(key) for key in ("MemoryLimit", "SwapLimit", "CpuCfsQuota", "PidsLimit")
        )
        or "name=seccomp,profile=builtin" not in security
        or any(option in security for option in ("name=rootless", "name=userns"))
    ):
        raise ValueError(
            "Repository execution requires a non-root operator and local Docker "
            "with cgroup v2 and built-in seccomp"
        )
    return value["ID"]


def qualify_image(identifier):
    if not isinstance(identifier, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", identifier) is None:
        raise ValueError("Repository images must be immutable local image IDs")
    image = json.loads(docker("image", "inspect", "--format", "{{json .}}", identifier))
    if image["Id"] != identifier or image["Config"].get("Volumes"):
        raise ValueError("Repository image has changed or declares additional writable volumes")


def execution_timestamp(value):
    if not isinstance(value, str):
        return None
    try:
        timestamp = datetime.fromisoformat(value)
    except ValueError:
        return None
    if timestamp.tzinfo is None or timestamp <= datetime(1970, 1, 1, tzinfo=UTC):
        return None
    return timestamp


class Containers:
    def __init__(self, config, lease, identifiers, remember):
        self.config, self.lease = config, lease
        self.identifiers, self.remember = identifiers, remember
        self.volume = "chio-repository-" + lease

    def check_engine(self):
        if engine() != self.config["engine"]:
            raise ValueError("Repository Docker engine changed; preserve the state for recovery")

    def volume_record(self):
        names = (
            docker("volume", "ls", "--filter", "name=" + self.volume, "--format", "{{.Name}}")
            .decode()
            .splitlines()
        )
        if self.volume not in names:
            return None
        value = json.loads(docker("volume", "inspect", self.volume))[0]
        if (
            value["Name"] != self.volume
            or value.get("Labels", {}).get(LABEL) != self.lease
            or value["Driver"] != "local"
            or value.get("Options") != VOLUME_OPTIONS
        ):
            raise ValueError("Repository volume ownership or configuration changed")
        return value

    def record(self, role):
        identifier = self.identifiers.get(role)
        selector = "id=" + identifier if identifier else "name=^/" + self.volume + "-" + role + "$"
        matches = (
            docker("ps", "--all", "--quiet", "--no-trunc", "--filter", selector)
            .decode()
            .splitlines()
        )
        if not matches:
            return None
        if len(matches) != 1:
            raise ValueError("Repository container ownership is ambiguous")
        value = json.loads(docker("inspect", matches[0]))[0]
        if (
            re.fullmatch(r"[0-9a-f]{64}", value["Id"]) is None
            or (identifier is not None and value["Id"] != identifier)
            or value["Name"] != "/" + self.volume + "-" + role
            or value["Config"].get("Labels", {}).get(LABEL) != self.lease
        ):
            raise ValueError("Repository container identity changed")
        return value

    def create(self, role, image, arguments):
        identifier = (
            docker(
                "create",
                "--pull=never",
                "--name",
                self.volume + "-" + role,
                "--label",
                LABEL + "=" + self.lease,
                "--network=none",
                "--ipc=private",
                "--cgroupns=private",
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges:true",
                "--user=65534:65534",
                "--memory=512m",
                "--memory-swap=512m",
                "--cpus=1",
                "--pids-limit=64",
                "--shm-size=8m",
                "--init",
                "--restart=no",
                "--log-driver=none",
                "--no-healthcheck",
                "--ulimit=core=0",
                "--ulimit=nofile=128:128",
                "--ulimit=fsize=16777216:16777216",
                "--workdir=/workspace",
                "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777",
                "--env=HOME=/workspace",
                "--env=TMPDIR=/tmp",
                "--env=PYTHONDONTWRITEBYTECODE=1",
                "--mount",
                "type=volume,src=" + self.volume + ",dst=/workspace,volume-nocopy",
                "--entrypoint",
                arguments[0],
                image,
                *arguments[1:],
            )
            .decode()
            .strip()
        )
        if re.fullmatch(r"[0-9a-f]{64}", identifier) is None:
            raise ValueError("Docker create did not return an exact repository container ID")
        self.remember(role, identifier)
        self.identifiers[role] = identifier
        record = self.record(role)
        if record is None or record["State"]["Running"] or record["Image"] != image:
            raise ValueError("New repository container differs from its recorded intent")
        return identifier

    def remove(self, role):
        record = self.record(role)
        if record is not None:
            docker("rm", "--force", "--volumes", record["Id"])
        if self.record(role) is not None:
            raise RuntimeError("Repository container removal remains unresolved")

    def cleanup(self):
        self.check_engine()
        self.remove("worker")
        self.remove("holder")
        if self.volume_record() is not None:
            docker("volume", "rm", self.volume)
        if self.volume_record() is not None:
            raise RuntimeError("Repository volume removal remains unresolved")

    def execute(self, snapshot, command):
        self.check_engine()
        for image in {self.config["image"], self.config["helper_image"]}:
            qualify_image(image)
        options = [
            item for key, value in VOLUME_OPTIONS.items() for item in ("--opt", key + "=" + value)
        ]
        docker(
            "volume",
            "create",
            "--driver=local",
            "--label",
            LABEL + "=" + self.lease,
            *options,
            self.volume,
        )
        self.volume_record()
        holder = self.create(
            "holder",
            self.config["helper_image"],
            ["/bin/sleep", str(self.config["timeout_seconds"] + 120)],
        )
        docker("start", holder)
        docker(
            "exec",
            "-i",
            holder,
            "/bin/tar",
            "--extract",
            "--no-same-owner",
            "--file=-",
            "--directory=/workspace",
            data=snapshot,
        )
        worker = self.create(
            "worker",
            self.config["image"],
            [
                "/usr/bin/timeout",
                "--signal=KILL",
                str(self.config["timeout_seconds"]),
                "/bin/bash",
                "--noprofile",
                "--norc",
                "-c",
                command,
            ],
        )
        attached_status, output, errors = run(
            [*DOCKER, "start", "--attach", worker],
            timeout=self.config["timeout_seconds"] + 5,
            limit=512 * 1024,
            allow_failure=True,
            merge_output=True,
        )
        record = self.record("worker")
        state = record["State"] if record is not None else {}
        started = execution_timestamp(state.get("StartedAt"))
        finished = execution_timestamp(state.get("FinishedAt"))
        if (
            state.get("Status") != "exited"
            or state.get("Running") is not False
            or state.get("OOMKilled") is not False
            or state.get("Error") != ""
            or started is None
            or finished is None
            or finished < started
        ):
            raise RuntimeError("Repository command did not reach a known terminal state")
        returncode = state["ExitCode"]
        if type(returncode) is not int or not 0 <= returncode <= 255 or returncode in {124, 137}:
            raise ValueError("Invalid repository command exit status")
        if attached_status != returncode:
            raise RuntimeError("Repository attachment did not complete with the command")
        # Removing the whole container also removes forked/background processes.
        # The separate helper is the sole remaining mount user during export.
        self.remove("worker")
        archive = docker(
            "exec",
            holder,
            "/bin/tar",
            "--create",
            "--format=posix",
            "--hard-dereference",
            "--file=-",
            "--directory=/workspace",
            ".",
            limit=MAX_ARCHIVE,
        )
        if len(output) + len(errors) > 512 * 1024:
            raise ValueError("Combined repository command output exceeds its limit")
        return archive, {
            "output": (output + errors).decode("utf-8", errors="replace"),
            "returncode": returncode,
            "exception_info": "",
        }
