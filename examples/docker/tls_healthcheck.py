#!/usr/bin/env python3

import os
import socket
import stat
import ssl
import threading
import time
import urllib.parse
import urllib.request


HEALTH_URL = os.environ.get("CHIO_TLS_HEALTH_URL", "https://localhost:8940/health")
CA_FILE = os.environ.get("CHIO_TLS_CA_FILE", "/var/lib/chio-tls-public/demo-ca.pem")
MAX_CA_BYTES = 1024 * 1024
MAX_HEALTH_BODY_BYTES = 64 * 1024
HEALTH_BODY_TIMEOUT_SECONDS = 2.0
READ_CHUNK_BYTES = 16 * 1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, _request, _file_pointer, _code, _message, _headers, _url
    ):
        return None


class HealthResponseDeadline:
    def __init__(self, response) -> None:
        self.expires_at = time.monotonic() + HEALTH_BODY_TIMEOUT_SECONDS
        file_pointer = getattr(response, "fp", None)
        raw = getattr(file_pointer, "raw", None)
        self.connection = getattr(raw, "_sock", None)
        self.lock = threading.Lock()
        self.active = False
        self.timer = threading.Timer(HEALTH_BODY_TIMEOUT_SECONDS, self._expire)
        self.timer.daemon = True

    def _expire(self) -> None:
        with self.lock:
            if not self.active:
                return
            self.active = False
        if self.connection is not None:
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def __enter__(self):
        with self.lock:
            self.active = True
        self.timer.start()
        return self

    def __exit__(self, _exception_type, _exception, _traceback) -> None:
        with self.lock:
            self.active = False
        self.timer.cancel()

    def remaining(self) -> float:
        remaining = self.expires_at - time.monotonic()
        if remaining <= 0.0:
            raise SystemExit("trust-control health response deadline expired")
        return remaining


def validate_health_url(url: str) -> str:
    if (
        not url
        or not url.isascii()
        or "\\" in url
        or any(ord(character) <= 0x20 or ord(character) == 0x7F for character in url)
    ):
        raise SystemExit("health URL contains invalid characters")
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise SystemExit("health URL is invalid") from exc
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or "%" in parsed.netloc
        or parsed.path != "/health"
        or parsed.query
        or parsed.fragment
    ):
        raise SystemExit("health URL must be an exact HTTPS /health URL")
    if port is not None and not 1 <= port <= 65535:
        raise SystemExit("health URL port is invalid")
    return url


def read_ca_pem(path: str) -> str:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SystemExit("health CA must be a readable non-symlink file") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise SystemExit("health CA must be a regular file")
        if metadata.st_size <= 0 or metadata.st_size > MAX_CA_BYTES:
            raise SystemExit("health CA is empty or exceeds 1 MiB")
        chunks = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, MAX_CA_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_CA_BYTES:
                raise SystemExit("health CA exceeds 1 MiB")
        if total != metadata.st_size:
            raise SystemExit("health CA changed while it was read")
        try:
            return b"".join(chunks).decode("ascii")
        except UnicodeDecodeError as exc:
            raise SystemExit("health CA must be ASCII PEM") from exc
    finally:
        os.close(descriptor)


def read_health_body(response) -> bytes:
    declared_length = getattr(response, "length", None)
    if declared_length is not None and declared_length > MAX_HEALTH_BODY_BYTES:
        raise SystemExit("trust-control health response exceeds 64 KiB")
    payload = bytearray()
    reader = getattr(response, "read1", None)
    if not callable(reader):
        raise SystemExit("trust-control health response transport is not bounded")
    with HealthResponseDeadline(response) as deadline:
        while len(payload) <= MAX_HEALTH_BODY_BYTES:
            if deadline.connection is not None:
                deadline.connection.settimeout(deadline.remaining())
            try:
                chunk = reader(
                    min(
                        READ_CHUNK_BYTES,
                        MAX_HEALTH_BODY_BYTES + 1 - len(payload),
                    )
                )
            except (OSError, TimeoutError) as exc:
                raise SystemExit(
                    "trust-control health response deadline expired"
                ) from exc
            deadline.remaining()
            if not chunk:
                break
            payload.extend(chunk)
    if len(payload) > MAX_HEALTH_BODY_BYTES:
        raise SystemExit("trust-control health response exceeds 64 KiB")
    return bytes(payload)


def main() -> None:
    expected_url = validate_health_url(HEALTH_URL)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cadata=read_ca_pem(CA_FILE))
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        NoRedirect(),
        urllib.request.HTTPSHandler(context=context),
    )
    request = urllib.request.Request(expected_url, method="GET")
    with opener.open(request, timeout=3) as response:
        if response.geturl() != expected_url:
            raise SystemExit("health response origin or target changed")
        if response.status != 200:
            raise SystemExit(
                f"unexpected trust-control health status: {response.status}"
            )
        read_health_body(response)


if __name__ == "__main__":
    main()
