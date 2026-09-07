"""Bounded cleanup of an interrupted comparison's exact recorded worker and container."""

import json
import os
import re
import signal
import time
from pathlib import Path

from chio_mini_swe.repository_transport import docker
from chio_mini_swe.session_security import read_document

LABEL = "chio.comparison.owner"


def process_identity(pid):
    root = Path("/proc") / str(pid)
    try:
        fields = (root / "stat").read_text().rsplit(")", 1)[1].split()
        return {
            "uid": root.stat().st_uid,
            "start_ticks": int(fields[19]),
            "pgid": int(fields[2]),
            "state": fields[0],
            "argv": (root / "cmdline").read_bytes().split(b"\0")[:-1],
        }
    except FileNotFoundError:
        return None


def terminate_attempt(control, config_path, config, expected_argv):
    record = read_document(control, private=True, maximum=65536)
    if (
        record.get("config_path") != str(config_path)
        or record.get("output") != config["output"]
        or record.get("owner") != config["owner"]
        or record.get("image") != config["image"]
        or record.get("uid") != os.getuid()
        or type(record.get("pid")) is not int
        or record["pid"] <= 1
        or type(record.get("start_ticks")) is not int
    ):
        raise ValueError("Unexpected comparison worker ownership record")
    pid = record["pid"]
    if record.get("state") == "reaped":
        return {"pid": pid, "running": False}
    if record.get("state") != "running":
        raise ValueError("Invalid comparison worker control state")
    try:
        descriptor = os.pidfd_open(pid)
    except ProcessLookupError:
        return {"pid": pid, "running": False}
    try:
        observed = process_identity(pid)
        if observed is None or observed["state"] == "Z":
            return {"pid": pid, "running": False}
        if (
            observed["uid"] != record["uid"]
            or observed["start_ticks"] != record["start_ticks"]
            or observed["argv"] != [os.fsencode(argument) for argument in expected_argv]
        ):
            raise ValueError("Comparison worker identity changed; preserve the process")
        # Signal the pinned process, never a numeric PID/group that could be
        # reused after inspection. Owned container cleanup terminates any
        # outstanding repository command and closes its Docker attachment.
        try:
            signal.pidfd_send_signal(descriptor, signal.SIGKILL)
        except ProcessLookupError:
            return {"pid": pid, "running": False}
    finally:
        os.close(descriptor)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        current = process_identity(pid)
        if current is None or current["state"] == "Z":
            return {"pid": pid, "running": False}
        if current["start_ticks"] != record["start_ticks"]:
            return {"pid": pid, "running": False, "pid_reused_after_termination": True}
        time.sleep(0.02)
    raise RuntimeError("Comparison worker termination remains unresolved")


def cleanup(config_path, expected_argv):
    config_path = Path(config_path)
    config = read_document(config_path, private=True, maximum=65536)
    output = Path(config["output"])
    owner, image = config["owner"], config["image"]
    if (
        re.fullmatch(r"[0-9a-f]{32}", owner) is None
        or re.fullmatch(r"sha256:[0-9a-f]{64}", image) is None
    ):
        raise ValueError("Invalid comparison ownership identity")
    attempts = []
    for number in (1, 2):
        control = output / f"attempt-{number}" / "control.json"
        if os.path.lexists(control):
            attempts.append(terminate_attempt(control, config_path, config, expected_argv))
    identifiers = set(
        docker("ps", "--all", "--quiet", "--no-trunc", "--filter", "label=" + LABEL + "=" + owner)
        .decode()
        .splitlines()
    )
    original = output / "container-control.json"
    if os.path.lexists(original):
        record = read_document(original, private=True, maximum=65536)
        if (
            record.get("owner") != owner
            or record.get("image") != image
            or record.get("config_path") != str(config_path)
            or record.get("output") != str(output)
            or re.fullmatch(r"[0-9a-f]{64}", record.get("id", "")) is None
        ):
            raise ValueError("Unexpected comparison container ownership record")
        identifiers.update(
            docker("ps", "--all", "--quiet", "--no-trunc", "--filter", "id=" + record["id"])
            .decode()
            .splitlines()
        )
    if len(identifiers) > 4:
        raise ValueError("Ambiguous comparison container inventory")
    # Validate every candidate before removing any container. A changed label
    # or image is an unresolved ownership failure, never cleanup permission.
    for identifier in identifiers:
        if re.fullmatch(r"[0-9a-f]{64}", identifier) is None:
            raise ValueError("Invalid comparison container identifier")
        value = json.loads(docker("inspect", identifier))[0]
        if (
            value["Id"] != identifier
            or value["Image"] != image
            or value["Config"].get("Labels", {}).get(LABEL) != owner
        ):
            raise ValueError("Comparison container ownership changed; preserve it")
    for identifier in identifiers:
        docker("rm", "--force", "--volumes", identifier)
        if docker("ps", "--all", "--quiet", "--no-trunc", "--filter", "id=" + identifier).strip():
            raise RuntimeError("Comparison container removal remains unresolved")
    return {"attempts": attempts, "removed_container_ids": sorted(identifiers), "verified": True}
