"""Native qualification services using the existing production broker runtime.

The broker test executable supplies explicit isolated qualification identities
and migration fixtures. It does not establish production deployment approval.
The PostgreSQL adapter and every serving broker use their production boundaries.
"""

import contextlib
import hashlib
import json
import os
import secrets
import select
import signal
import socket
import subprocess
import time
from pathlib import Path

import host

OPERATIONS = ("task", "complete", "renew", "assign", "release", "inspect")
WORKER_OPERATIONS = OPERATIONS[:3]
SERVER_NAME = "postgres-jobs.chio.invalid"


def server(tool):
    if tool not in OPERATIONS:
        raise ValueError("unknown PostgreSQL operation")
    return "jobs-" + tool


def wait_line(process, expected, *, timeout=180):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not select.select([process.stdout], [], [], 1)[0]:
            if process.poll() is not None:
                raise RuntimeError("resource service exited; inspect private service log")
            continue
        line = process.stdout.readline(65537)
        if not line or len(line) > 65536:
            raise RuntimeError("resource service readiness refused")
        if expected in line:
            return
    raise TimeoutError("resource service readiness expired")


class ResourceGateway:
    def __init__(self, gateway, tenant, directory, environment, *, fault=None):
        self.gateway = gateway
        self.tenant, self.directory = tenant, directory
        self.environment, self.fault = environment, fault
        self.stack = contextlib.ExitStack()
        self.started = False

    def __enter__(self):
        try:
            self._prepare()
            return self
        except BaseException:
            self.stack.close()
            raise

    def __exit__(self, *_):
        self.stack.close()

    def _spawn(self, command, name, *, environment, graceful_stdin=False):
        log = self.stack.enter_context((self.root / (name + ".log")).open("ab"))
        process = subprocess.Popen(
            [str(value) for value in command],
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=log,
            start_new_session=True,
        )
        self.stack.callback(process.stdin.close)
        self.stack.callback(process.stdout.close)
        def stop():
            if graceful_stdin:
                process.stdin.close()
            elif process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                # This process group was created exclusively for this service.
                # Include its owned broker children if graceful cleanup stalled.
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=10)
        self.stack.callback(stop)
        return process

    def _prepare(self):
        self.root = self.directory / "resources"
        self.root.mkdir(mode=0o700)
        # Operator-generated private credentials never enter a native target.
        host.command(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", self.root / "key.pem", "-out", self.root / "cert.pem",
             "-days", "1", "-subj", "/CN=" + SERVER_NAME,
             "-addext", "subjectAltName=DNS:" + SERVER_NAME,
             "-addext", "basicConstraints=critical,CA:FALSE",
             "-addext", "extendedKeyUsage=serverAuth"], self.directory,
        )
        host.command(
            ["openssl", "x509", "-in", self.root / "cert.pem", "-outform", "DER",
             "-out", self.root / "cert.der"], self.directory,
        )
        host.command(
            ["openssl", "pkcs8", "-topk8", "-nocrypt", "-in", self.root / "key.pem",
             "-outform", "DER", "-out", self.root / "key.der"], self.directory,
        )
        certificate = list((self.root / "cert.der").read_bytes())
        endpoints, routes = [], []
        for operation in OPERATIONS:
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                port = listener.getsockname()[1]
            credential = self.root / (operation + ".credential")
            with credential.open("x") as stream:
                stream.write(secrets.token_hex(32))
            endpoints.append({
                "operation": operation, "bind": f"127.0.0.1:{port}",
                "certificate_der": certificate,
                "private_key_file": str(self.root / "key.der"),
                "bearer_file": str(credential),
            })
            routes.append({
                "server": server(operation), "tool": operation,
                "request_timeout_seconds": 40, "timeout_ms": 20000,
                "response_limit_bytes": 131072, "path": "/execute",
                "credential_file": str(credential),
                "credential_id": self.tenant + "-" + operation,
                "adapter": {"serverName": SERVER_NAME, "address": "127.0.0.1",
                            "port": port, "certificateDer": certificate},
                "payload": {"kind": "caller_bound_resource", "route": {
                    "resource": "postgres-jobs", "tenant": self.tenant,
                    "operation": operation}},
            })
        config = {"schema": "chio.postgres-job-resource.v1", "tenant": self.tenant,
                  "timeout_ms": 20000, "endpoints": endpoints}
        if self.fault is not None:
            config["claim_response_loss_directory"] = str(self.fault)
        host.write(self.root / "adapter.json", config)
        self.adapter = self._spawn(
            [self.gateway, "serve", self.root / "adapter.json"], "postgres-adapter",
            environment=self.environment,
        )
        wait_line(self.adapter, b'"ready":true', timeout=30)
        self.routes = routes


class QualificationResources(ResourceGateway):
    def __init__(self, chio, gateway, tenant, directory, environment, *, fault=None):
        super().__init__(gateway, tenant, directory, environment, fault=fault)
        self.chio = chio

    def _prepare(self):
        super()._prepare()
        provision = self.root / "provision"
        provision.mkdir(mode=0o700)
        native_work = self.directory / "native-work"
        native_work.mkdir(mode=0o700)
        host.write(self.root / "campaign.json", {
            "directory": str(provision),
            "authority_state_directory": str(self.directory / "host"),
            "working_directory": str(native_work), "binary": str(self.chio),
            "routes": self.routes, "broker_tool": os.environ["CHIO_BROKER_MCP_TOOL"],
            "cage_init": os.environ["CHIO_CAGE_INIT"],
            "anchor": os.environ["CHIO_RECEIPT_ANCHOR_ROOT"],
        })
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith("CHIO_JOB_DATABASE_")}
        environment.update(CHIO_BOUNDARY_ROLE="consumer-services",
                           CHIO_BOUNDARY_CONFIG=str(self.root / "campaign.json"))
        self.brokers = self._spawn([
            os.environ["CHIO_BROKER_TEST_BINARY"],
            "process_boundary_tests::consumer_services::native_consumer_services_helper_process",
            "--exact", "--nocapture", "--test-threads=1",
        ], "broker-services", environment=environment, graceful_stdin=True)
        wait_line(self.brokers, b"CHIO_CONSUMER_READY")
        self.config = json.loads((provision / "config.json").read_text())

    def start(self, key):
        if self.started:
            raise RuntimeError("broker services already started")
        with host.serve(self.chio, self.directory, key, self.environment):
            self.brokers.stdin.write(b"\x01")
            self.brokers.stdin.flush()
            wait_line(self.brokers, b"CHIO_BROKERS_READY")
        self.started = True

    def evidence(self):
        return {
            "adapter_sha256": hashlib.sha256(self.gateway.read_bytes()).hexdigest(),
            "target_sha256": hashlib.sha256(
                Path(os.environ["CHIO_BROKER_MCP_TOOL"]).read_bytes()
            ).hexdigest(),
            "fixed_operations": list(OPERATIONS),
            "database_credentials_in_native_target": False,
            "qualification_fixture_identities": True,
        }
