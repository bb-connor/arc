"""Own trusted database adapters and prepared brokers across kernel restarts.

The service helper provisions the existing production transports with fixture
keys. Only the static, credential-free MCP proxy executes inside the native cage.
"""

import contextlib
import json
import os
import secrets
import select
import socket
import subprocess
import time

from host import MAX_CALLS, ROLES, command, host_environment, route, stop, write

HOST = "boundary-upstream.test"


def certificate(directory):
    command(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            directory / "key.pem",
            "-out",
            directory / "cert.pem",
            "-days",
            "1",
            "-subj",
            f"/CN={HOST}",
            "-addext",
            f"subjectAltName=DNS:{HOST}",
            "-addext",
            "basicConstraints=critical,CA:FALSE",
            "-addext",
            "extendedKeyUsage=serverAuth",
        ],
        directory,
        env=host_environment(),
    )
    command(
        [
            "openssl",
            "x509",
            "-in",
            directory / "cert.pem",
            "-outform",
            "DER",
            "-out",
            directory / "cert.der",
        ],
        directory,
        env=host_environment(),
    )
    command(
        [
            "openssl",
            "pkcs8",
            "-topk8",
            "-nocrypt",
            "-in",
            directory / "key.pem",
            "-outform",
            "DER",
            "-out",
            directory / "key.der",
        ],
        directory,
        env=host_environment(),
    )
    for name in ("key.pem", "cert.pem", "key.der", "cert.der"):
        (directory / name).chmod(0o600)


def wait(child, marker, timeout=180):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not select.select([child.stdout], [], [], 0.2)[0]:
            continue
        line = child.stdout.readline()
        if not line:
            raise RuntimeError(
                "trusted service exited before readiness; inspect private logs"
            )
        if line.strip() == marker.encode():
            return
    raise TimeoutError("trusted service readiness timed out")


class Services(contextlib.AbstractContextManager):
    def __init__(self, chio, gateway, tenant, directory, environment, *, fault=None):
        self.stack = contextlib.ExitStack()
        self.directory = directory
        self.started = False
        try:
            self._prepare(chio, gateway, tenant, environment, fault)
        except BaseException:
            self.stack.close()
            raise

    def __exit__(self, *exc):
        return self.stack.__exit__(*exc)

    def spawn(self, arguments, name, environment, *, stdin=None):
        log = self.stack.enter_context((self.directory / (name + ".stderr")).open("xb"))
        child = subprocess.Popen(
            [str(value) for value in arguments],
            env=environment,
            stdin=stdin,
            stdout=subprocess.PIPE,
            stderr=log,
            bufsize=0,
        )
        self.stack.callback(child.stdout.close)
        # Reap the child before closing its output or private log.
        self.stack.callback(stop, child)
        return child

    def _prepare(self, chio, gateway, tenant, environment, fault):
        root = self.directory / "adapters"
        root.mkdir(mode=0o700)
        certificate(root)
        cert = list((root / "cert.der").read_bytes())
        routes = []
        for role, tools in (
            ("worker", ("task", "complete", "renew")),
            ("operator", ("assign", "release", "inspect")),
        ):
            credential = root / (role + ".credential")
            credential.write_text(secrets.token_hex(32))
            credential.chmod(0o600)
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            config = root / (role + ".json")
            write(
                config,
                {
                    "schema": "chio.postgres-job-https-adapter.v1",
                    "endpoint": {
                        "bind": f"127.0.0.1:{port}",
                        "certificate_der": cert,
                        "private_key_file": str(root / "key.der"),
                        "bearer_file": str(credential),
                    },
                    "tenant": tenant,
                    "role": role,
                    "qualification_fault_directory": str(fault)
                    if fault and role == "operator"
                    else None,
                },
            )
            child = self.spawn(
                [gateway, "serve", config], role + "-adapter", environment
            )
            wait(child, "CHIO_POSTGRES_ADAPTER_READY", 30)
            for tool in tools:
                routes.append(
                    {
                        "server": route(tool, operator=role == "operator"),
                        "tool": tool,
                        "request_timeout_seconds": 60,
                        "timeout_ms": 45000,
                        "response_limit_bytes": 131072,
                        "path": "/execute",
                        "payload": {"kind": "kernel_mcp_tool_call"},
                        "credential_file": str(credential),
                        "adapter": {
                            "serverName": HOST,
                            "address": "127.0.0.1",
                            "port": port,
                            "certificateDer": cert,
                        },
                    }
                )
        campaign = root / "campaign.json"
        write(
            campaign,
            {
                "directory": str(root),
                "authority_state_directory": str(self.directory / "host"),
                "working_directory": str(self.directory),
                "binary": str(chio),
                "routes": routes,
                "broker_tool": os.environ["CHIO_BROKER_MCP_TOOL"],
                "cage_init": os.environ["CHIO_CAGE_INIT"],
                "anchor": os.environ["CHIO_RECEIPT_ANCHOR_ROOT"],
            },
        )
        self.helper = self.spawn(
            [
                os.environ["CHIO_BROKER_TEST_BINARY"],
                "process_boundary_tests::consumer_services::native_consumer_services_helper_process",
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "--format=terse",
            ],
            "broker-services",
            dict(
                host_environment(),
                CHIO_BOUNDARY_ROLE="consumer-services",
                CHIO_BOUNDARY_CONFIG=str(campaign),
            ),
            stdin=subprocess.PIPE,
        )
        self.stack.callback(self.close_helper)
        wait(self.helper, "CHIO_CONSUMER_READY")
        self.config_path = root / "config.json"
        config = json.loads(self.config_path.read_text())
        config["limits"].update(max_calls=MAX_CALLS, max_processes=3)
        config["children"] = [
            {
                "id": name,
                "parent": "root",
                "budget_share_bps": 4000,
                "tools": [
                    {"server_id": route(tool), "tool_name": tool}
                    for tool in ("task", "complete", "renew")
                ],
            }
            for name in ROLES
        ]
        self.config_path.write_text(json.dumps(config))

    def start(self):
        if self.started:
            if self.helper.poll() is not None:
                raise RuntimeError("broker services exited during qualification")
            return
        self.helper.stdin.write(b"\x01")
        self.helper.stdin.flush()
        wait(self.helper, "CHIO_BROKERS_READY")
        self.started = True

    def close_helper(self):
        self.helper.stdin.close()
        try:
            self.helper.wait(timeout=10)
        except subprocess.TimeoutExpired:
            stop(self.helper)
