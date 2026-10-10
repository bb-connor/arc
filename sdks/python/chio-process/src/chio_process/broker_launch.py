"""Operator provisioning for a static MCP tool using the prepared broker stream."""

import os
import shutil
import subprocess
from pathlib import Path

from chio_process.launch import _native_cage_authority_arguments


def provision_brokered_demo(
    chio: str | Path,
    server_id: str,
    command: list[str],
    output_dir: str | Path,
    working_directory: str | Path,
    *,
    tools_fixture: str | Path,
    broker_binding: str | Path,
) -> dict:
    """Bind reviewed tools and the authenticated broker peer into an enforced cage.

    The CLI validates the static executable, bounded tools fixture, socket owner,
    peer identity and authentication digest. This API adds no discovery, filesystem
    grants or environment inheritance. Calls still require original signed broker
    requests and the process host's durable admission. Provisioning grants no
    Docker or provider access by itself.
    """
    if not command or not command[0] or not server_id:
        raise ValueError("A broker MCP command and server identity are required")
    output = Path(output_dir).absolute()
    if os.path.lexists(output):
        raise FileExistsError("Broker MCP policy output already exists")
    authority = _native_cage_authority_arguments()
    target = shutil.which(command[0])
    if target is None:
        raise ValueError("Broker MCP executable was not found")
    bound = [str(Path(target).resolve(strict=True)), *command[1:]]
    groups = sorted(set(os.getgroups()) - {os.getgid()})
    if os.getuid() == 0 or os.getgid() == 0 or 0 in groups or len(groups) > 64:
        raise ValueError("Broker MCP execution requires a non-root bounded identity")
    arguments = [
        str(Path(chio).resolve(strict=True)),
        "security",
        "provision-reference-runtime",
        *authority,
        "--output-dir",
        str(output),
        "--tools-fixture",
        str(Path(tools_fixture).resolve(strict=True)),
        "--broker-binding",
        str(Path(broker_binding).resolve(strict=True)),
        "--target",
        bound[0],
        "--working-directory",
        str(Path(working_directory).resolve(strict=True)),
        "--execution-uid",
        str(os.getuid()),
        "--execution-gid",
        str(os.getgid()),
        "--server-id",
        server_id,
        "--server-name",
        server_id,
        "--server-version",
        "1",
    ]
    for group in groups:
        arguments.extend(["--execution-supplementary-gid", str(group)])
    for argument in bound[1:]:
        arguments.extend(["--target-arg", argument])
    subprocess.run(
        arguments,
        check=True,
        capture_output=True,
        text=True,
        timeout=90,
        env={"PATH": "/usr/bin:/bin"},
    )
    return {
        "id": server_id,
        "command": bound,
        "launch_policy": str(output / "cage-launch-policy.json"),
        "launch_policy_signer": (output / "cage-policy-signer").read_text().strip(),
    }
