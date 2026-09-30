"""Explicit operator provisioning for local native MCP demos.

The signed policy uses migration stage Enforced. Discovery requires a qualified
Linux host, a cage helper, an independent receipt anchor and reviewed read grants.
Production operators retain ownership of publisher trust and signed policy.
"""

import os
import shutil
import stat
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path


def demo_python() -> str:
    """Find a Python executable for stdlib-only demo tools that others cannot write.

    A system interpreter may replace a writable development interpreter. Tools
    needing installed dependencies must select and protect their own executable.
    """
    selected = os.environ.get("CHIO_DEMO_PYTHON")
    candidates = (
        (selected,) if selected else (sys.executable, "/usr/bin/python3", "/usr/local/bin/python3")
    )
    for candidate in candidates:
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
    read_paths: Sequence[str | Path] = (),
    write_paths: Sequence[str | Path] = (),
) -> dict:
    """Provision a fresh policy and return one process-host server configuration.

    Provisioning starts the command inside an enforced cage for discovery. It
    does not invoke its tools. Existing output is refused; rebuilding Chio requires a
    fresh policy because the authorization binds that executable's digest.
    An explicit environment replaces subprocess inheritance during discovery;
    operators must separately supply it when starting the process host.
    Enforcement inputs come from the operator's CHIO_CAGE_INIT,
    CHIO_RECEIPT_ANCHOR_ROOT and CHIO_CAGE_READ_PATHS_FILE environment settings.
    Dynamic targets also require CHIO_CAGE_RUNTIME_FILES_FILE to declare their
    exact loader and shared objects, each included in the reviewed read grants.
    """
    if not command or not command[0]:
        raise ValueError("A native MCP command is required")
    output = Path(output_dir).resolve()
    cage_arguments = _native_cage_arguments(output)
    target = shutil.which(command[0])
    if target is None:
        raise ValueError("Native MCP executable was not found")
    bound_command = [str(Path(target).resolve(strict=True)), *command[1:]]
    if os.path.lexists(output_dir):
        raise FileExistsError("Native MCP demo policy output already exists")
    arguments = [
        str(Path(chio).resolve(strict=True)),
        "security",
        "provision-reference-runtime",
        *cage_arguments,
        "--output-dir",
        str(output),
        "--discover-tools",
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
    groups = sorted(set(os.getgroups()) - {os.getgid()})
    if len(groups) > 64:
        raise ValueError("native supplementary groups exceed the bound")
    for group in groups:
        if group == 0:
            raise ValueError("native execution cannot retain root supplementary group")
        arguments.extend(["--execution-supplementary-gid", str(group)])
    anchor = Path(os.environ["CHIO_RECEIPT_ANCHOR_ROOT"]).resolve()
    for flag, paths in (("--read-path", read_paths), ("--write-path", write_paths)):
        for path in paths:
            grant = Path(path).resolve(strict=True)
            if grant == Path("/") or any(
                protected == grant or grant in protected.parents or protected in grant.parents
                for protected in (output, anchor)
            ):
                raise ValueError("tool grants cannot include launch authority or receipt anchors")
            arguments.extend([flag, str(grant)])
    for argument in bound_command[1:]:
        arguments.extend(["--target-arg", argument])
    subprocess.run(
        arguments,
        check=True,
        capture_output=True,
        text=True,
        timeout=90,
        env=environment,
    )
    return {
        "id": server_id,
        "command": bound_command,
        "launch_policy": str(output / "cage-launch-policy.json"),
        "launch_policy_signer": (output / "cage-policy-signer").read_text().strip(),
    }


def _native_cage_authority_arguments() -> list[str]:
    arguments = ["--stage", "enforced", "--max-artifact-bytes", str(64 * 1024 * 1024)]
    for variable, flag in (
        ("CHIO_CAGE_INIT", "--cage-init"),
        ("CHIO_RECEIPT_ANCHOR_ROOT", "--receipt-rollback-anchor-root"),
    ):
        path = os.environ.get(variable, "")
        if not os.path.isabs(path):
            raise ValueError(f"{variable} must name an absolute path on the enforcing host")
        arguments.extend([flag, path])
    return arguments


def _native_cage_arguments(output: Path) -> list[str]:
    arguments = _native_cage_authority_arguments()
    profile = os.environ.get("CHIO_CAGE_SYSCALL_PROFILE")
    if profile is not None:
        if profile not in {"native-minimal-v1", "native-standard-v1"}:
            raise ValueError("CHIO_CAGE_SYSCALL_PROFILE must select a reviewed native profile")
        arguments.extend(["--syscall-profile", profile])
    grants = os.environ.get("CHIO_CAGE_READ_PATHS_FILE", "")
    if not os.path.isabs(grants):
        raise ValueError("CHIO_CAGE_READ_PATHS_FILE must name the reviewed read-grants file")
    arguments.extend(_native_path_arguments(grants, "--read-path", output))
    runtime = os.environ.get("CHIO_CAGE_RUNTIME_FILES_FILE")
    if runtime is not None:
        if not os.path.isabs(runtime):
            raise ValueError("CHIO_CAGE_RUNTIME_FILES_FILE must name an absolute path")
        arguments.extend(_native_path_arguments(runtime, "--runtime-file", output))
    return arguments


def _native_path_arguments(source: str, flag: str, output: Path) -> list[str]:
    arguments = []
    with open(source, encoding="utf-8") as handle:
        text = handle.read(64 * 1024 + 1)
        if len(text.encode("utf-8")) > 64 * 1024:
            raise ValueError("native read grants exceed 64 KiB")
        for path in text.splitlines():
            if not path:
                continue
            if not os.path.isabs(path):
                raise ValueError("read grants must be absolute paths")
            grant = Path(path).resolve()
            anchor = Path(os.environ["CHIO_RECEIPT_ANCHOR_ROOT"]).resolve()
            if grant == Path("/") or any(
                protected == grant or grant in protected.parents or protected in grant.parents
                for protected in (output, anchor)
            ):
                raise ValueError("read grants cannot include launch authority or receipt anchors")
            arguments.extend([flag, str(grant)])
    return arguments
