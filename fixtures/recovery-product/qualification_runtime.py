"""Explicit fixture validation and credential-free native process inputs."""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import importlib
import importlib.metadata
import importlib.util
import ipaddress
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from urllib.parse import urlsplit


NATIVE_ENVIRONMENT = frozenset({
    "PATH", "HOME", "CARGO_HOME", "RUSTUP_HOME", "RUSTUP_TOOLCHAIN", "TMPDIR",
    "LANG", "LC_ALL", "CARGO_TARGET_DIR", "CARGO_BUILD_JOBS", "CARGO_INCREMENTAL",
    "CARGO_PROFILE_DEV_DEBUG", "CARGO_PROFILE_TEST_DEBUG",
})


def require(condition: bool, reason: str) -> None:
    """Acceptance stays effective under Python optimization."""
    if not condition:
        raise ValueError("qualification." + reason)


def disable_telemetry() -> None:
    os.environ["OTEL_SDK_DISABLED"] = "true"
    os.environ["CREWAI_DISABLE_TELEMETRY"] = "true"
    os.environ["CREWAI_TELEMETRY_DISABLED"] = "true"
    os.environ["LITELLM_LOCAL_MODEL_COST_MAP"] = "True"


def installed_module(distribution: str, name: str):
    """An ignored local module cannot impersonate a declared wheel installation."""
    package = importlib.metadata.distribution(distribution)
    prefix = Path(sys.prefix).resolve(strict=True)
    package_root = Path(package.locate_file("")).resolve(strict=True)
    require(package_root.is_relative_to(prefix) and package_root.name == "site-packages",
            "provider_module_origin")
    relative = Path(*name.split("."))
    expected = Path(package.locate_file(relative / "__init__.py")).resolve(strict=True)
    require(expected.is_relative_to(package_root), "provider_module_origin")
    spec = importlib.util.find_spec(name)
    require(spec is not None and spec.origin is not None
            and Path(spec.origin).resolve(strict=True) == expected, "provider_module_origin")
    module = importlib.import_module(name)
    require(Path(module.__file__).resolve(strict=True) == expected, "provider_module_origin")
    observation = {"distribution":distribution, "module":name, "version":package.version,
                   "installation_path":str(expected.relative_to(prefix)),
                   "sha256":hashlib.sha256(expected.read_bytes()).hexdigest()}
    return module, observation


def native_environment(exchange_name: str, exchange: Path) -> dict[str, str]:
    require(exchange_name in {"CHIO_RECOVERY_CAMPAIGN_EXCHANGE", "CHIO_RECOVERY_HOST_EXCHANGE"},
            "native_exchange_name")
    environment = {name: value for name, value in os.environ.items() if name in NATIVE_ENVIRONMENT}
    environment.update({exchange_name: str(exchange.resolve()), "CARGO_NET_OFFLINE":"true"})
    return environment


def wait_endpoint(path: Path, process: subprocess.Popen, timeout: float, *, fixed_port: int | None = None) -> str:
    """A created but incomplete ready file is not a published endpoint."""
    require(fixed_port is None or type(fixed_port) is int and 0 < fixed_port <= 65535,
            "native_ready_port")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            framed = path.read_text(encoding="utf-8")
            endpoint = framed[:-1] if framed.endswith("\n") and framed.count("\n") == 1 else ""
        except FileNotFoundError:
            endpoint = ""
        if fixed_port is not None and endpoint == str(fixed_port):
            endpoint = f"http://127.0.0.1:{fixed_port}"
        if endpoint:
            try:
                parsed = urlsplit(endpoint)
                host = ipaddress.ip_address(parsed.hostname or "")
                valid = parsed.scheme == "http" and host.is_loopback and parsed.port is not None \
                    and parsed.username is None and parsed.password is None \
                    and parsed.path in {"", "/"} and not parsed.query and not parsed.fragment
                if fixed_port is not None:
                    valid = valid and parsed.port == fixed_port
            except ValueError:
                valid = False
            if valid:
                return endpoint
        if process.poll() is not None:
            raise RuntimeError("campaign.native_preparation_failed")
        time.sleep(0.05)
    raise TimeoutError("campaign.native_preparation_failed")


@contextmanager
def model_free_network_guard():
    """Permit native loopback I/O, count and refuse every remote socket attempt."""
    attempts = []
    connect = socket.socket.connect
    connect_ex = socket.socket.connect_ex
    resolve = socket.getaddrinfo

    def allowed(host):
        if host == "localhost":
            return True
        try:
            return ipaddress.ip_address(host).is_loopback
        except ValueError:
            return False

    def check(host, operation):
        if not allowed(host):
            attempts.append({"operation":operation, "destination":"non_loopback"})
            raise RuntimeError("qualification.model_free_remote_io")

    def guarded_connect(sock, address):
        if sock.family in {socket.AF_INET, socket.AF_INET6}:
            check(address[0], "connect")
        return connect(sock, address)

    def guarded_connect_ex(sock, address):
        if sock.family in {socket.AF_INET, socket.AF_INET6}:
            check(address[0], "connect_ex")
        return connect_ex(sock, address)

    def guarded_resolve(host, *arguments, **options):
        check(host, "resolve")
        answers = resolve(host, *arguments, **options)
        for answer in answers:
            check(answer[4][0], "resolved_address")
        return answers

    socket.socket.connect = guarded_connect
    socket.socket.connect_ex = guarded_connect_ex
    socket.getaddrinfo = guarded_resolve
    try:
        yield attempts
    finally:
        socket.socket.connect = connect
        socket.socket.connect_ex = connect_ex
        socket.getaddrinfo = resolve
