"""Native qualification fixture with production Rust brokers and host adapters.

Only the saved HTTPS model is simulated. Docker commands, admission, TLS,
credential custody, native cages and receipts use their production owners.
"""

import hashlib
import http.server
import json
import os
import secrets
import select
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

from worker import decisions

DOCKER = ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock"]
HOST = "boundary-upstream.test"
POLICY = {
    "max_output_tokens": 1024,
    "input_usd_per_million": 10000,
    "output_usd_per_million": 0,
}


def provider_endpoint():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return f"https://{HOST}:{listener.getsockname()[1]}/v1"


def canonical(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()


def write(path, value):
    path.write_bytes(value if isinstance(value, bytes) else canonical(value))
    path.chmod(0o600)


def docker(*args):
    return subprocess.check_output([*DOCKER, *args], text=True, timeout=30).strip()


def certificate(root):
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(root / "key.pem"),
            "-out",
            str(root / "cert.pem"),
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
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        [
            "openssl",
            "x509",
            "-in",
            str(root / "cert.pem"),
            "-outform",
            "DER",
            "-out",
            str(root / "cert.der"),
        ],
        check=True,
    )
    subprocess.run(
        [
            "openssl",
            "pkcs8",
            "-topk8",
            "-nocrypt",
            "-in",
            str(root / "key.pem"),
            "-outform",
            "DER",
            "-out",
            str(root / "key.der"),
        ],
        check=True,
    )
    for name in ("key.pem", "cert.pem", "cert.der", "key.der"):
        (root / name).chmod(0o600)


class BrokerCampaign:
    def __init__(
        self,
        binary,
        directory,
        container,
        profile,
        *,
        session=False,
        host_state=None,
        provider=None,
        workspace=None,
        slow_command=False,
        repository_only=False,
        response_limit_bytes=16384,
    ):
        self.directory = directory
        self.session = session
        self.provisioning_directory = directory / "adapters" if session else directory
        self.config_path = self.provisioning_directory / "config.json"
        self.host_state = host_state or (directory / "run/host" if session else directory / "host")
        self.provider_config = provider
        self.workspace = directory / "repository" if session else workspace
        self.slow_command = slow_command
        self.repository_only = repository_only
        self.response_limit_bytes = response_limit_bytes
        self.failed = threading.Event()
        self.children = []
        self.logs = []
        self.provider = None
        self.release_provider = threading.Event()
        self.services = None
        try:
            self._prepare(binary, container, profile)
        except BaseException:
            self.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def _prepare(self, binary, container, profile):
        from minisweagent.models.utils.actions_toolcall import BASH_TOOL

        from chio_mini_swe.provider_config import identity

        provider = (
            json.loads((self.directory / "provider.json").read_text())
            if self.session
            else self.provider_config
        )
        model = provider["model"] if provider else "saved-native-model"
        model_id = identity(provider) if provider else "saved-native-decisions-v1"
        selected = (
            json.loads((self.directory / "configuration.json").read_text()).get("source_paths")
            if self.session
            else None
        )

        root = self.directory / "adapters"
        root.mkdir(mode=0o700)
        certificate(root)
        token = secrets.token_hex(32)
        write(root / "credential", token.encode())
        record = self.directory / "queries.jsonl"
        record.touch(mode=0o600)
        release = self.release_provider
        failed = self.failed
        slow_command = self.slow_command

        class Provider(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_):
                pass

            def do_POST(self):
                assert self.path == "/v1/chat/completions"
                assert self.headers["Authorization"] == "Bearer " + token
                size = int(self.headers["Content-Length"])
                assert 0 < size <= 131072
                body = self.rfile.read(size)
                data = json.loads(body)
                assert data["model"] == model
                assert data["stream"] is False and data["max_completion_tokens"] == 1024
                assert data["tools"] == [BASH_TOOL]
                assert token.encode() not in body
                turn = sum(message["role"] == "assistant" for message in data["messages"])
                with record.open("a") as stream:
                    stream.write(
                        json.dumps(
                            {
                                "turn": turn,
                                "request_sha256": hashlib.sha256(body).hexdigest(),
                                "prompt": data["messages"][:2],
                                "actions": [
                                    json.loads(call["function"]["arguments"])["command"]
                                    for call in decisions()[turn]["tool_calls"]
                                ],
                            }
                        )
                        + "\n"
                    )
                    stream.flush()
                    os.fsync(stream.fileno())
                if profile == "unknown":
                    release.wait(90)
                    self.close_connection = True
                    return
                if profile == "session-slow" and turn == 0:
                    time.sleep(65)
                message = decisions()[turn]
                if selected:
                    assert selected == ["package"]
                    assert any(
                        "Selected paths:" in m.get("content", "") and "package" in m["content"]
                        for m in data["messages"]
                        if m["role"] == "user"
                    )
                    for call in message["tool_calls"]:
                        action = json.loads(call["function"]["arguments"])
                        action["command"] = (
                            "test ! -e unselected.txt && cd package && " + action["command"]
                        )
                        call["function"]["arguments"] = json.dumps(action)
                message.pop("extra")
                if slow_command and turn == 0:
                    call = message["tool_calls"][0]["function"]
                    action = json.loads(call["arguments"])
                    action["command"] = "sleep 65; " + action["command"]
                    call["arguments"] = json.dumps(action)
                result = {
                    "id": f"chatcmpl-{turn}",
                    "object": "chat.completion",
                    "created": 1,
                    "model": model,
                    "choices": [{"index": 0, "finish_reason": "tool_calls", "message": message}],
                    "usage": {
                        "prompt_tokens": 100,
                        "completion_tokens": 20,
                        "total_tokens": 120,
                    },
                }
                encoded = canonical(result)
                self.send_response(500 if failed.is_set() else 200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(encoded)
                self.wfile.flush()
                self.close_connection = True

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(root / "cert.pem", root / "key.pem")
        context.set_alpn_protocols(["http/1.1"])
        provider_port = urlsplit(provider["endpoint"]).port if provider else 0
        self.provider = http.server.ThreadingHTTPServer(("127.0.0.1", provider_port), Provider)
        self.provider.socket = context.wrap_socket(self.provider.socket, server_side=True)
        threading.Thread(target=self.provider.serve_forever, daemon=True).start()
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            docker_port = listener.getsockname()[1]
        cert = list((root / "cert.der").read_bytes())
        endpoint = {
            "bind": f"127.0.0.1:{docker_port}",
            "certificate_der": cert,
            "private_key_file": str(root / "key.der"),
            "bearer_file": str(root / "credential"),
        }
        if self.workspace is not None:
            from chio_mini_swe.repository_store import configuration_digest

            workspace_config = json.loads((self.workspace / "workspace.json").read_text())
            executable = Path(sys.executable).parent / "chio-mini-swe-repository"
            config = dict(
                endpoint,
                schema="chio.repository-https-adapter.v1",
                repository={
                    "executable": str(executable),
                    "executable_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
                    "state": str(self.workspace),
                    "configuration_sha256": configuration_digest(workspace_config),
                    "timeout_ms": 120000,
                },
            )
            adapter = os.environ["CHIO_REPOSITORY_ADAPTER"]
        else:
            with socket.socket(socket.AF_UNIX) as sock:
                sock.connect("/var/run/docker.sock")
                pid, uid, gid = struct.unpack(
                    "3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
                )
            info = json.loads(docker("info", "--format", "{{json .}}"))
            spec = json.loads(docker("inspect", container))[0]
            config = dict(
                endpoint,
                schema="chio.docker-https-adapter.v1",
                docker={
                    "socket_path": "/var/run/docker.sock",
                    "peer": {"processId": pid, "userId": uid, "groupId": gid},
                    "api_version": "v" + docker("version", "--format", "{{.Server.APIVersion}}"),
                    "daemon_id": info["ID"],
                    "container_id": container,
                    "container_configuration_sha256": hashlib.sha256(
                        canonical(
                            {key: spec[key] for key in ("Config", "HostConfig", "Mounts", "Image")}
                        )
                    ).hexdigest(),
                    "container_started_at": spec["State"]["StartedAt"],
                    "timeout_ms": 15000,
                    "maximum_output_bytes": 4096,
                },
            )
            adapter = os.environ["CHIO_DOCKER_ADAPTER"]
        write(root / "adapter.json", config)
        self._spawn([adapter, "--config", str(root / "adapter.json")], "command-adapter")
        deadline = time.monotonic() + 10
        while True:
            if self.children[-1].poll() is not None:
                raise RuntimeError("Command adapter exited before readiness")
            try:
                with socket.create_connection(("127.0.0.1", docker_port), timeout=0.2):
                    break
            except OSError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.02)
        routes = []
        for server, tool, port, path, payload in [
            ("sandbox", "execute", docker_port, "/execute", {"kind": "json"}),
            (
                "model",
                "model_infer",
                self.provider.server_port,
                "/v1/chat/completions",
                {
                    "kind": "mini_swe_chat",
                    "model_id": model_id,
                    "model": model,
                    "tools": [BASH_TOOL],
                    "max_completion_tokens": 1024,
                    "temperature": provider.get("temperature") if provider else None,
                },
            ),
        ]:
            if self.repository_only and server != "sandbox":
                continue
            routes.append(
                {
                    "server": server,
                    "request_timeout_seconds": (
                        provider["timeout_seconds"] + 30 if provider else 30
                    )
                    if server == "model"
                    else (
                        workspace_config["timeout_seconds"] + 120
                        if self.workspace is not None
                        else 30
                    ),
                    "timeout_ms": (
                        (provider["timeout_seconds"] * 1000 if provider else 20000)
                        if server == "model"
                        else (120000 if self.workspace is not None else 20000)
                    ),
                    "response_limit_bytes": self.response_limit_bytes,
                    "tool": tool,
                    "path": path,
                    "payload": payload,
                    "credential_file": str(root / "credential"),
                    "adapter": {
                        "serverName": HOST,
                        "address": "127.0.0.1",
                        "port": port,
                        "certificateDer": cert,
                    },
                }
            )
        write(
            root / "campaign.json",
            {
                "directory": str(self.provisioning_directory),
                "authority_state_directory": str(self.host_state),
                "working_directory": str(self.directory),
                "binary": str(binary),
                "routes": routes,
                "broker_tool": os.environ["CHIO_BROKER_MCP_TOOL"],
                "cage_init": os.environ["CHIO_CAGE_INIT"],
                "anchor": os.environ["CHIO_RECEIPT_ANCHOR_ROOT"],
            },
        )
        environment = dict(
            os.environ,
            CHIO_BOUNDARY_ROLE="consumer-services",
            CHIO_BOUNDARY_CONFIG=str(root / "campaign.json"),
        )
        self.services = self._spawn(
            [
                os.environ["CHIO_BROKER_TEST_BINARY"],
                "process_boundary_tests::consumer_services::native_consumer_services_helper_process",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ],
            "broker-services",
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        self._wait("CHIO_CONSUMER_READY")

    def _spawn(self, command, name, **kwargs):
        log = (self.directory / (name + ".stderr")).open("wb")
        self.logs.append(log)
        child = subprocess.Popen(command, stderr=log, bufsize=0, **kwargs)
        self.children.append(child)
        return child

    def _wait(self, marker):
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            if not select.select([self.services.stdout], [], [], 1)[0]:
                continue
            line = self.services.stdout.readline()
            if not line:
                raise RuntimeError("Native fixture exited; inspect broker-services.stderr")
            if marker.encode() in line:
                return
        raise TimeoutError("Native broker fixture readiness expired")

    def start(self, binary):
        from qualify import serving

        with serving(binary, self.host_state.parent):
            self.services.stdin.write(b"\x01")
            self.services.stdin.flush()
            self._wait("CHIO_BROKERS_READY")

    def release_repository(self):
        if self.workspace is None:
            raise ValueError("Campaign has no repository child")
        child = self.children[0]
        if child.poll() is None:
            child.terminate()
            child.wait(timeout=10)

    def stop_provider(self):
        self.release_provider.set()

    def close(self):
        self.release_provider.set()
        if self.services is not None and self.services.poll() is None:
            self.services.stdin.close()
            try:
                self.services.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.services.terminate()
        for child in reversed(self.children):
            if child.poll() is None:
                child.terminate()
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        if self.provider is not None:
            self.provider.shutdown()
            self.provider.server_close()
        for log in self.logs:
            log.close()
