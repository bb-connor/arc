#!/usr/bin/env python3
"""Launch the demo hosted edge with distinct bearer credentials.

The edge presents the control token to the trust service, clients present the
auth token to the edge, the admin routes accept only the admin token, and the
trust service accepts the workload token only for capability issuance. The
credentials reach the edge through its environment, never through argv.

Before the launch, the entrypoint provisions the signed manifest and the
signed native-launch policy that bind the exact wrapped command, with
demo-only signers at migration stage Disabled, into a private directory that
lives only as long as the container, and pins the trust service's current
capability authority key.
"""

import base64
import json
import os
import re
import shutil
import subprocess
import urllib.request

BEARER_TOKEN = re.compile(r"[A-Za-z0-9\-._~+/]+=*")
PUBLIC_KEY = re.compile(r"[0-9a-f]{64}")
EXECUTABLE = "/usr/local/bin/chio"
MOCK_SERVER = "/opt/chio/examples/mock_mcp_server.py"
WORKING_DIRECTORY = "/opt/chio"
PROVISION_ROOTS = ("/run/chio-provision", "/tmp/chio-provision")
CREDENTIAL_VARIABLES = (
    "CHIO_AUTH_TOKEN",
    "CHIO_ADMIN_TOKEN",
    "CHIO_CONTROL_TOKEN",
    "CHIO_REMOTE_AUTHORITY_WORKLOAD_TOKEN",
)
AUTHORITY_TIMEOUT_SECONDS = 10


def provision_root() -> str:
    configured = os.environ.get("CHIO_PROVISION_DIR")
    candidates = (configured,) if configured else PROVISION_ROOTS
    for candidate in candidates:
        if os.path.isdir(candidate) and os.access(candidate, os.W_OK):
            return candidate
    fallback = candidates[-1]
    os.makedirs(fallback, mode=0o700, exist_ok=True)
    return fallback


def require_public_key(value: str, origin: str) -> str:
    if not isinstance(value, str) or PUBLIC_KEY.fullmatch(value) is None:
        raise SystemExit(f"{origin} is not a lowercase Ed25519 public key")
    return value


def read_public_key(path: str) -> str:
    with open(path, encoding="ascii") as handle:
        return require_public_key(handle.read().strip(), path)


def control_authority_public_key(control_url: str, control_token: str) -> str:
    """Ask the trust service for the capability authority key the edge must pin."""
    request = urllib.request.Request(
        f"{control_url.rstrip('/')}/v1/authority",
        headers={"Authorization": f"Bearer {control_token}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=AUTHORITY_TIMEOUT_SECONDS) as response:
            authority = json.load(response)
    except (OSError, ValueError) as error:
        raise SystemExit(f"could not read the trust service's authority key: {error}") from error
    return require_public_key(authority.get("publicKey"), "the trust service's authority key")


def write_resume_hmac_keyring(path: str) -> str:
    """Write a fresh private resume keyring for this container's sessions."""
    key = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("ascii")
    keyring = {
        "schema": "chio.remote-mcp.resume-hmac-keyring.v1",
        "current": {"keyId": "demo-" + os.urandom(4).hex(), "version": 1, "keyBase64": key},
        "previous": [],
    }
    if os.path.lexists(path):
        os.remove(path)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(keyring, handle)
    return path


def provision_launch(server_id: str, server_name: str, server_version: str) -> dict:
    """Provision the launch material for the mock server and return the edge flags."""
    target = os.path.realpath("/usr/bin/python3")
    output_dir = os.path.join(provision_root(), "security")
    if os.path.isdir(output_dir):
        shutil.rmtree(output_dir)
    environment = {
        name: value
        for name, value in os.environ.items()
        if name not in CREDENTIAL_VARIABLES
    }
    with open(f"{output_dir}.provision-report.json", "w", encoding="utf-8") as report:
        subprocess.run(
            [
                EXECUTABLE,
                "security",
                "provision-native-mcp-demo",
                "--output-dir",
                output_dir,
                "--discover-tools",
                "--target",
                target,
                "--target-arg",
                MOCK_SERVER,
                "--working-directory",
                WORKING_DIRECTORY,
                "--execution-uid",
                str(os.getuid()),
                "--execution-gid",
                str(os.getgid()),
                "--server-id",
                server_id,
                "--server-name",
                server_name,
                "--server-version",
                server_version,
            ],
            check=True,
            stdout=report,
            env=environment,
        )
    root = os.path.dirname(output_dir)
    return {
        "session_db": os.path.join(root, "mcp-sessions.sqlite3"),
        "resume_hmac_keyring": write_resume_hmac_keyring(os.path.join(root, "resume-hmac-keyring.json")),
        "signed_manifest": os.path.join(output_dir, "signed-manifest.json"),
        "manifest_public_key": read_public_key(os.path.join(output_dir, "manifest-public-key")),
        "cage_policy": os.path.join(output_dir, "cage-launch-policy.json"),
        "cage_policy_signer": read_public_key(os.path.join(output_dir, "cage-policy-signer")),
        "target": target,
    }


def main() -> None:
    auth_token = os.environ.get("CHIO_AUTH_TOKEN", "")
    admin_token = os.environ.get("CHIO_ADMIN_TOKEN", "")
    control_token = os.environ.get("CHIO_CONTROL_TOKEN", "")
    workload_token = os.environ.get("CHIO_REMOTE_AUTHORITY_WORKLOAD_TOKEN", "")
    for variable, value in (
        ("CHIO_AUTH_TOKEN", auth_token),
        ("CHIO_ADMIN_TOKEN", admin_token),
        ("CHIO_CONTROL_TOKEN", control_token),
        ("CHIO_REMOTE_AUTHORITY_WORKLOAD_TOKEN", workload_token),
    ):
        if BEARER_TOKEN.fullmatch(value) is None:
            raise SystemExit(f"{variable} must be an explicit bearer token")
    if len({auth_token, admin_token, control_token}) != 3:
        raise SystemExit("edge, admin, and control bearer tokens must be distinct")
    if workload_token in {auth_token, admin_token, control_token}:
        raise SystemExit("the workload token must differ from the edge, admin, and control tokens")
    if os.getuid() == 0:
        raise SystemExit("the demo edge must not run as root")

    control_url = os.environ.get("CHIO_CONTROL_URL", "http://chio-trust-demo:8940")
    server_id = os.environ.get("CHIO_DEMO_SERVER_ID", "wrapped-http-mock")
    server_name = os.environ.get("CHIO_DEMO_SERVER_NAME", "Wrapped HTTP Mock")
    server_version = os.environ.get("CHIO_DEMO_SERVER_VERSION", "1")
    try:
        launch = provision_launch(server_id, server_name, server_version)
    except subprocess.CalledProcessError as error:
        raise SystemExit(f"provisioning the demo launch failed with status {error.returncode}") from error
    authority_key = control_authority_public_key(control_url, control_token)

    arguments = [
        "tini",
        "--",
        EXECUTABLE,
        "--control-url",
        control_url,
        "--control-authority-public-key",
        authority_key,
        "mcp",
        "serve-http",
        "--policy",
        os.environ.get("CHIO_DEMO_POLICY", "/opt/chio/examples/policy.yaml"),
        "--server-id",
        server_id,
        "--server-name",
        server_name,
        "--server-version",
        server_version,
        "--listen",
        os.environ.get("CHIO_DEMO_LISTEN", "0.0.0.0:8931"),
        "--session-db",
        launch["session_db"],
        "--resume-hmac-keyring",
        launch["resume_hmac_keyring"],
        "--signed-manifest",
        launch["signed_manifest"],
        "--manifest-public-key",
        launch["manifest_public_key"],
        "--cage-policy",
        launch["cage_policy"],
        "--cage-policy-signer",
        launch["cage_policy_signer"],
        "--",
        launch["target"],
        MOCK_SERVER,
    ]
    environment = {
        "CHIO_AUTH_TOKEN": auth_token,
        "CHIO_ADMIN_TOKEN": admin_token,
        "CHIO_CONTROL_TOKEN": control_token,
        "CHIO_REMOTE_AUTHORITY_WORKLOAD_TOKEN": workload_token,
        "HOME": os.environ.get("HOME", "/home/chio"),
        "LANG": "C.UTF-8",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "RUST_LOG": os.environ.get("RUST_LOG", "info"),
    }
    os.execve("/sbin/tini", arguments, environment)


if __name__ == "__main__":
    main()
