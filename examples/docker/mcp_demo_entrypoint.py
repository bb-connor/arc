#!/usr/bin/env python3

import json
import os
import re
import stat
import urllib.parse
from pathlib import Path


MAX_KEY_BYTES = 128
MAX_COMMAND_BYTES = 64 * 1024
MAX_ARTIFACT_BYTES = 4 * 1024 * 1024
MAX_CA_BYTES = 1024 * 1024
PUBLIC_KEY = re.compile(r"[0-9a-f]{64}")
BEARER_TOKEN = re.compile(r"[A-Za-z0-9\-._~+/]+=*")


def read_regular(path: Path, limit: int, expected_mode: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise SystemExit(
            f"cannot open required security input {path}: {error}"
        ) from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise SystemExit(f"required security input is not a regular file: {path}")
        if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != expected_mode:
            raise SystemExit(
                f"required security input has invalid ownership or mode: {path}"
            )
        if metadata.st_size <= 0 or metadata.st_size > limit:
            raise SystemExit(f"required security input has an invalid size: {path}")
        chunks = []
        total = 0
        while chunk := os.read(descriptor, min(64 * 1024, limit + 1 - total)):
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                raise SystemExit(f"required security input exceeds its bound: {path}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def read_public_key(path: Path) -> str:
    try:
        value = read_regular(path, MAX_KEY_BYTES, 0o444).decode("ascii")
    except UnicodeDecodeError as error:
        raise SystemExit(f"public key is not ASCII: {path}") from error
    if PUBLIC_KEY.fullmatch(value) is None:
        raise SystemExit(f"public key is not exact lowercase Ed25519 hex: {path}")
    return value


def load_target_command(path: Path) -> list[str]:
    try:
        value = json.loads(read_regular(path, MAX_COMMAND_BYTES, 0o444))
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise SystemExit(f"target command is not valid JSON: {path}") from error
    if (
        not isinstance(value, list)
        or not value
        or len(value) > 257
        or any(not isinstance(argument, str) or not argument for argument in value)
        or any(len(argument.encode("utf-8")) > 16 * 1024 for argument in value)
    ):
        raise SystemExit("target command must be a bounded nonempty JSON string array")
    if not Path(value[0]).is_absolute():
        raise SystemExit("target command executable must be absolute")
    return value


def require_https_control_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise SystemExit("CHIO_CONTROL_URL must be a final HTTPS origin")
    return value.rstrip("/")


def main() -> None:
    auth_token = os.environ.get("CHIO_AUTH_TOKEN", "")
    admin_token = os.environ.get("CHIO_ADMIN_TOKEN", "")
    control_token = os.environ.get("CHIO_CONTROL_TOKEN", "")
    for variable, value in (
        ("CHIO_AUTH_TOKEN", auth_token),
        ("CHIO_ADMIN_TOKEN", admin_token),
        ("CHIO_CONTROL_TOKEN", control_token),
    ):
        if BEARER_TOKEN.fullmatch(value) is None:
            raise SystemExit(f"{variable} must be an explicit bearer token")
    if len({auth_token, admin_token, control_token}) != 3:
        raise SystemExit("edge, admin, and control bearer tokens must be distinct")

    public_security_directory = Path(
        os.environ.get("CHIO_PUBLIC_SECURITY_DIR", "/run/chio-public")
    )
    private_security_directory = Path(
        os.environ.get("CHIO_PRIVATE_SECURITY_DIR", "/var/lib/chio/security")
    )
    for directory, expected_mode in (
        (public_security_directory, 0o555),
        (private_security_directory, 0o700),
    ):
        directory_metadata = directory.lstat()
        if (
            not stat.S_ISDIR(directory_metadata.st_mode)
            or directory.is_symlink()
            or directory_metadata.st_uid != 0
            or stat.S_IMODE(directory_metadata.st_mode) != expected_mode
        ):
            raise SystemExit(
                f"security directory has invalid ownership or mode: {directory}"
            )

    signed_manifest = public_security_directory / "signed-manifest.json"
    cage_policy = public_security_directory / "cage-launch-policy.json"
    authority_seed = private_security_directory / "control-authority.seed"
    session_database = private_security_directory / "mcp-sessions.sqlite3"
    for path in (signed_manifest, cage_policy):
        read_regular(path, MAX_ARTIFACT_BYTES, 0o444)
    read_regular(authority_seed, 256, 0o600)
    control_ca = Path(
        os.environ.get(
            "CHIO_CONTROL_TLS_ROOT_CA_FILE",
            "/var/lib/chio-tls-public/demo-ca.pem",
        )
    )
    read_regular(control_ca, MAX_CA_BYTES, 0o444)

    target_command = load_target_command(public_security_directory / "target-command")
    manifest_public_key = read_public_key(
        public_security_directory / "manifest-public-key"
    )
    cage_policy_signer = read_public_key(
        public_security_directory / "cage-policy-signer"
    )
    control_authority = read_public_key(
        public_security_directory / "control-authority-public-key"
    )
    control_url = require_https_control_url(
        os.environ.get("CHIO_CONTROL_URL", "https://chio-trust-tls:8940")
    )

    executable = "/usr/local/bin/chio"
    arguments = [
        executable,
        "--authority-seed-file",
        str(authority_seed),
        "--session-db",
        str(session_database),
        "--control-url",
        control_url,
        "--control-authority-public-key",
        control_authority,
        "mcp",
        "serve-http",
        "--policy",
        os.environ.get("CHIO_DEMO_POLICY", "/opt/chio/examples/policy.yaml"),
        "--server-id",
        os.environ.get("CHIO_DEMO_SERVER_ID", "docker-demo"),
        "--server-name",
        os.environ.get("CHIO_DEMO_SERVER_NAME", "Docker demo MCP"),
        "--server-version",
        os.environ.get("CHIO_DEMO_SERVER_VERSION", "1"),
        "--signed-manifest",
        str(signed_manifest),
        "--manifest-public-key",
        manifest_public_key,
        "--cage-policy",
        str(cage_policy),
        "--cage-policy-signer",
        cage_policy_signer,
        "--listen",
        os.environ.get("CHIO_DEMO_LISTEN", "0.0.0.0:8931"),
        "--",
        *target_command,
    ]
    environment = {
        "CHIO_AUTH_TOKEN": auth_token,
        "CHIO_ADMIN_TOKEN": admin_token,
        "CHIO_CONTROL_TOKEN": control_token,
        "CHIO_CONTROL_TLS_ROOT_CA_FILE": str(control_ca),
        "HOME": "/root",
        "LANG": "C.UTF-8",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "RUST_LOG": os.environ.get("RUST_LOG", "info"),
    }
    os.execve(executable, arguments, environment)


if __name__ == "__main__":
    main()
