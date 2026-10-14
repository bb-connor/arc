"""Explicit operator provisioning for local native MCP demos.

The signed policy uses migration stage Disabled. It authorizes the exact command
and discovered manifest, but provides no OS containment. Production operators
must supply their own signed launch policy and publisher trust configuration.
"""

import os
import shutil
import stat
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path


class NativeDemoProvisionError(RuntimeError):
    """A provisioning failure whose public diagnostic contains no target output."""

    def __init__(self, returncode: int, stderr: str | None):
        self.returncode = returncode
        self.diagnostic = _safe_diagnostic(stderr)
        super().__init__(
            f"Native MCP demo provisioning failed with exit status {returncode}: {self.diagnostic}"
        )


def _safe_diagnostic(stderr: str | None) -> str:
    # A tool's diagnostic can contain database URLs, credentials or file data.
    # Copy only known failure phrases, never arbitrary target text or stdout.
    allowed = (
        "native MCP tool discovery failed",
        "discovery failed",
        "privileged discovery requires an Enforced cage",
        "CHIO_JOB_DATABASE_URL is required",
        "CHIO_JOB_DATABASE_CA is required",
        "the target closed its output before answering tools/list",
        "the target closed its input before the MCP handshake",
        "the target did not answer tools/list",
        "MCP response exceeds the size limit",
        "out-of-order MCP discovery response",
        "failed to launch MCP discovery",
        "native MCP target advertised an invalid tools/list result",
    )
    bounded = (stderr or "")[:4096]
    diagnostic = "; ".join(phrase for phrase in allowed if phrase in bounded)
    if not diagnostic:
        diagnostic = "unrecognized provisioner stderr withheld"
    if len(stderr or "") > len(bounded):
        diagnostic += "; stderr truncated"
    return diagnostic


def demo_python() -> str:
    """Find a Python executable for stdlib-only demo tools that others cannot write.

    A system interpreter may replace a writable development interpreter. Tools
    needing installed dependencies must select and protect their own executable.
    """
    for candidate in (sys.executable, "/usr/bin/python3", "/usr/local/bin/python3"):
        path = Path(candidate).resolve()
        if path.is_file() and os.access(path, os.X_OK):
            mode = path.stat().st_mode
            if stat.S_ISREG(mode) and not mode & (stat.S_IWGRP | stat.S_IWOTH):
                return str(path)
    raise RuntimeError("No Python demo executable protected from other users' writes")


def provision_native_demo(
    chio: str | Path,
    server_id: str,
    command: list[str],
    output_dir: str | Path,
    working_directory: str | Path,
    *,
    environment: Mapping[str, str] | None = None,
    tools_fixture: str | Path | None = None,
) -> dict:
    """Provision a fresh policy and return one process-host server configuration.

    Provisioning discovers metadata or uses an explicitly reviewed tools fixture.
    It does not invoke tools. Existing output is refused; rebuilding Chio requires a
    fresh policy because the authorization binds that executable's digest.
    An explicit environment replaces inheritance for the provisioner. Native
    discovery retains the CLI's cleared environment. A tool requiring secrets
    for metadata must be reviewed separately and supplied as a tools fixture;
    operators separately supply its environment when starting the process host.
    """
    if not command or not command[0]:
        raise ValueError("A native MCP command is required")
    target = shutil.which(command[0])
    if target is None:
        raise ValueError("Native MCP executable was not found")
    bound_command = [str(Path(target).resolve(strict=True)), *command[1:]]
    output = Path(output_dir).resolve()
    if os.path.lexists(output_dir):
        raise FileExistsError("Native MCP demo policy output already exists")
    arguments = [
        str(Path(chio).resolve(strict=True)),
        "security",
        "provision-native-mcp-demo",
        "--output-dir",
        str(output),
        "--target",
        bound_command[0],
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
    if tools_fixture is None:
        arguments.append("--discover-tools")
    else:
        arguments.extend(["--tools-fixture", str(Path(tools_fixture).resolve(strict=True))])
    for argument in bound_command[1:]:
        arguments.extend(["--target-arg", argument])
    try:
        subprocess.run(
            arguments,
            check=True,
            capture_output=True,
            text=True,
            timeout=90,
            env=environment,
        )
    except subprocess.CalledProcessError as error:
        raise NativeDemoProvisionError(error.returncode, error.stderr) from None
    return {
        "id": server_id,
        "command": bound_command,
        "launch_policy": str(output / "cage-launch-policy.json"),
        "launch_policy_signer": (output / "cage-policy-signer").read_text().strip(),
    }
