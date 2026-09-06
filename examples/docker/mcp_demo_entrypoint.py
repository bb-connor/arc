#!/usr/bin/env python3
"""Launch the demo hosted edge with three distinct bearer credentials.

The edge presents the control token to the trust service, clients present the
auth token to the edge, and the admin routes accept only the admin token. The
credentials reach the edge through its environment, never through argv.
"""

import os
import re

BEARER_TOKEN = re.compile(r"[A-Za-z0-9\-._~+/]+=*")
EXECUTABLE = "/usr/local/bin/chio"


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

    arguments = [
        "tini",
        "--",
        EXECUTABLE,
        "--control-url",
        os.environ.get("CHIO_CONTROL_URL", "http://chio-trust-demo:8940"),
        "mcp",
        "serve-http",
        "--policy",
        os.environ.get("CHIO_DEMO_POLICY", "/opt/chio/examples/policy.yaml"),
        "--server-id",
        os.environ.get("CHIO_DEMO_SERVER_ID", "wrapped-http-mock"),
        "--server-name",
        os.environ.get("CHIO_DEMO_SERVER_NAME", "Wrapped HTTP Mock"),
        "--listen",
        os.environ.get("CHIO_DEMO_LISTEN", "0.0.0.0:8931"),
        "--",
        "python3",
        "/opt/chio/examples/mock_mcp_server.py",
    ]
    environment = {
        "CHIO_AUTH_TOKEN": auth_token,
        "CHIO_ADMIN_TOKEN": admin_token,
        "CHIO_CONTROL_TOKEN": control_token,
        "HOME": os.environ.get("HOME", "/home/chio"),
        "LANG": "C.UTF-8",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "RUST_LOG": os.environ.get("RUST_LOG", "info"),
    }
    os.execve("/sbin/tini", arguments, environment)


if __name__ == "__main__":
    main()
