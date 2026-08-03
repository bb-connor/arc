#!/usr/bin/env python3

import http.client
import io
import os
import re
import select
import socket
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


LISTEN_HOST = os.environ.get("CHIO_TLS_LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("CHIO_TLS_LISTEN_PORT", "8940"))
UPSTREAM_HOST = os.environ.get("CHIO_TLS_UPSTREAM_HOST", "chio-trust-demo")
UPSTREAM_PORT = int(os.environ.get("CHIO_TLS_UPSTREAM_PORT", "8940"))
CERT_FILE = os.environ.get(
    "CHIO_TLS_CERT_FILE", "/var/lib/chio-tls-private/demo-server.pem"
)
KEY_FILE = os.environ.get(
    "CHIO_TLS_KEY_FILE", "/var/lib/chio-tls-private/demo-server-key.pem"
)
MAX_REQUEST_BYTES = 16 * 1024 * 1024
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_CONCURRENT_REQUESTS = 32
TLS_HANDSHAKE_TIMEOUT_SECONDS = 5.0
HEADER_TIMEOUT_SECONDS = 5.0
BODY_TIMEOUT_SECONDS = 10.0
UPSTREAM_TIMEOUT_SECONDS = 10.0
CLIENT_WRITE_TIMEOUT_SECONDS = 5.0
READ_CHUNK_BYTES = 64 * 1024
CONTENT_LENGTH = re.compile(r"[0-9]+")
HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


class RequestRejected(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


class ResponseTooLarge(Exception):
    pass


class ResolvedEndpoint:
    def __init__(self, family: int, socket_type: int, protocol: int, address) -> None:
        self.family = family
        self.socket_type = socket_type
        self.protocol = protocol
        self.address = address


class ResolvedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host, port, *, endpoint: ResolvedEndpoint, timeout: float):
        super().__init__(host, port, timeout=timeout)
        self.endpoint = endpoint

    def connect(self) -> None:
        connection = socket.socket(
            self.endpoint.family,
            self.endpoint.socket_type,
            self.endpoint.protocol,
        )
        try:
            connection.settimeout(self.timeout)
            if self.source_address is not None:
                connection.bind(self.source_address)
            connection.connect(self.endpoint.address)
            try:
                connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass
            self.sock = connection
        except BaseException:
            connection.close()
            raise


class ReadDeadline:
    def __init__(self) -> None:
        self.expires_at = 0.0

    def start(self, seconds: float) -> None:
        self.expires_at = time.monotonic() + seconds

    def clear(self) -> None:
        self.expires_at = 0.0

    def remaining(self) -> float:
        if self.expires_at == 0.0:
            raise TimeoutError("socket read attempted without an active deadline")
        remaining = self.expires_at - time.monotonic()
        if remaining <= 0.0:
            raise TimeoutError("socket read deadline expired")
        return remaining


class DeadlineReader(io.RawIOBase):
    def __init__(self, connection: socket.socket, deadline: ReadDeadline) -> None:
        super().__init__()
        self.connection = connection
        self.deadline = deadline

    def readable(self) -> bool:
        return True

    def readinto(self, buffer) -> int:
        self.connection.settimeout(self.deadline.remaining())
        return self.connection.recv_into(buffer)


class SocketWriter(io.BufferedIOBase):
    def __init__(self, connection: socket.socket) -> None:
        super().__init__()
        self.connection = connection

    def writable(self) -> bool:
        return True

    def write(self, buffer) -> int:
        self.connection.sendall(buffer)
        return len(buffer)


class SocketShutdownDeadline:
    def __init__(self, connection: socket.socket, seconds: float) -> None:
        self.connection = connection
        self.seconds = seconds
        self.lock = threading.Lock()
        self.active = False
        self.expired = False
        self.timer = threading.Timer(seconds, self._expire)
        self.timer.daemon = True

    def _expire(self) -> None:
        with self.lock:
            if not self.active:
                return
            self.active = False
            self.expired = True
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


def connection_tokens(header_values) -> set[str]:
    tokens = set()
    for value in header_values or ():
        for token in value.split(","):
            normalized = token.strip().lower()
            if normalized:
                tokens.add(normalized)
    return tokens


def resolve_upstream(host: str, port: int) -> ResolvedEndpoint:
    addresses = socket.getaddrinfo(
        host,
        port,
        family=socket.AF_UNSPEC,
        type=socket.SOCK_STREAM,
        proto=socket.IPPROTO_TCP,
    )
    for family, socket_type, protocol, _canonical_name, address in addresses:
        if family in {socket.AF_INET, socket.AF_INET6}:
            return ResolvedEndpoint(family, socket_type, protocol, address)
    raise RuntimeError("trust-control upstream did not resolve to an IP endpoint")


def parse_content_length(header_values) -> int:
    if not header_values:
        return 0
    values = []
    for field_value in header_values:
        candidates = field_value.split(",")
        if not candidates or any(
            CONTENT_LENGTH.fullmatch(value) is None for value in candidates
        ):
            raise RequestRejected(400, "invalid content length")
        values.extend(candidates)
    if len(set(values)) != 1:
        raise RequestRejected(400, "inconsistent content lengths")
    value = values[0]
    if len(value) > len(str(MAX_REQUEST_BYTES)):
        raise RequestRejected(413, "request body exceeds the demo proxy limit")
    content_length = int(value)
    if content_length > MAX_REQUEST_BYTES:
        raise RequestRejected(413, "request body exceeds the demo proxy limit")
    return content_length


def perform_tls_handshake(connection: ssl.SSLSocket, timeout: float) -> None:
    expires_at = time.monotonic() + timeout
    connection.setblocking(False)
    try:
        while True:
            try:
                connection.do_handshake()
                return
            except ssl.SSLWantReadError:
                readers, writers = [connection], []
            except ssl.SSLWantWriteError:
                readers, writers = [], [connection]
            remaining = expires_at - time.monotonic()
            if remaining <= 0.0:
                raise TimeoutError("TLS handshake deadline expired")
            readable, writable, _ = select.select(readers, writers, [], remaining)
            if not readable and not writable:
                raise TimeoutError("TLS handshake deadline expired")
    finally:
        connection.setblocking(True)


class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "ChioDemoTLSProxy/1"

    def setup(self) -> None:
        self.connection = self.request
        self.read_deadline = ReadDeadline()
        self.rfile = io.BufferedReader(
            DeadlineReader(self.connection, self.read_deadline),
            buffer_size=io.DEFAULT_BUFFER_SIZE,
        )
        self.wfile = SocketWriter(self.connection)

    def log_message(self, _format, *_args) -> None:
        return

    def handle_one_request(self) -> None:
        self.read_deadline.start(HEADER_TIMEOUT_SECONDS)
        try:
            super().handle_one_request()
        except TimeoutError:
            self.close_connection = True
        finally:
            self.read_deadline.clear()

    def _reject(self, status: int, message: str) -> None:
        self.close_connection = True
        self.connection.settimeout(CLIENT_WRITE_TIMEOUT_SECONDS)
        self.send_error(status, message)

    def _read_request_body(self, content_length: int) -> bytes:
        self.read_deadline.start(BODY_TIMEOUT_SECONDS)
        try:
            body = self.rfile.read(content_length) if content_length else b""
        except TimeoutError as exc:
            raise RequestRejected(408, "request body deadline expired") from exc
        finally:
            self.read_deadline.clear()
        if len(body) != content_length:
            raise RequestRejected(400, "request body ended before content length")
        return body

    def _request_headers(self, body_length: int) -> dict[str, str]:
        excluded = HOP_BY_HOP | connection_tokens(self.headers.get_all("Connection"))
        excluded |= {"host", "accept-encoding", "content-length"}
        headers = {
            name: value
            for name, value in self.headers.items()
            if name.lower() not in excluded
        }
        headers["Host"] = f"{UPSTREAM_HOST}:{UPSTREAM_PORT}"
        headers["Accept-Encoding"] = "identity"
        headers["Content-Length"] = str(body_length)
        return headers

    def _read_response_body(self, response: http.client.HTTPResponse) -> bytes:
        if self.command == "HEAD":
            return b""
        expected_length = response.length
        if expected_length is not None and expected_length > MAX_RESPONSE_BYTES:
            raise ResponseTooLarge
        body = bytearray()
        while len(body) <= MAX_RESPONSE_BYTES:
            remaining = MAX_RESPONSE_BYTES + 1 - len(body)
            chunk = response.read1(min(READ_CHUNK_BYTES, remaining))
            if not chunk:
                break
            body.extend(chunk)
        if len(body) > MAX_RESPONSE_BYTES:
            raise ResponseTooLarge
        if expected_length is not None and len(body) != expected_length:
            raise http.client.IncompleteRead(bytes(body), expected_length - len(body))
        return bytes(body)

    def _send_response(self, response: http.client.HTTPResponse, body: bytes) -> None:
        excluded = HOP_BY_HOP | connection_tokens(
            [
                value
                for name, value in response.getheaders()
                if name.lower() == "connection"
            ]
        )
        excluded.add("content-length")
        self.connection.settimeout(CLIENT_WRITE_TIMEOUT_SECONDS)
        self.send_response(response.status, response.reason)
        for name, value in response.getheaders():
            if name.lower() not in excluded:
                self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _proxy(self) -> None:
        try:
            if self.headers.get_all("Transfer-Encoding"):
                raise RequestRejected(400, "transfer encoding is not accepted")
            if not self.path.startswith("/") or self.path.startswith("//"):
                raise RequestRejected(400, "request target must use origin form")
            content_length = parse_content_length(
                self.headers.get_all("Content-Length")
            )
            body = self._read_request_body(content_length)
        except RequestRejected as exc:
            self._reject(exc.status, exc.message)
            return

        connection = ResolvedHTTPConnection(
            UPSTREAM_HOST,
            UPSTREAM_PORT,
            endpoint=self.server.upstream_endpoint,
            timeout=UPSTREAM_TIMEOUT_SECONDS,
        )
        try:
            connection.connect()
            upstream_socket = connection.sock
            if upstream_socket is None:
                raise ConnectionError("upstream connection did not open a socket")
            response_deadline = SocketShutdownDeadline(
                upstream_socket, UPSTREAM_TIMEOUT_SECONDS
            )
            with response_deadline:
                connection.request(
                    self.command,
                    self.path,
                    body=body,
                    headers=self._request_headers(len(body)),
                )
                response = connection.getresponse()
                response_body = self._read_response_body(response)
            if response_deadline.expired:
                raise TimeoutError("trust-control upstream deadline expired")
            self._send_response(response, response_body)
        except ResponseTooLarge:
            self._reject(502, "trust-control response exceeds the proxy limit")
        except (ConnectionError, OSError, TimeoutError, http.client.HTTPException):
            self._reject(502, "trust-control upstream is unavailable")
        finally:
            connection.close()

    do_GET = _proxy
    do_HEAD = _proxy
    do_POST = _proxy
    do_PUT = _proxy
    do_PATCH = _proxy
    do_DELETE = _proxy
    do_OPTIONS = _proxy


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64

    def __init__(
        self,
        address,
        handler,
        tls_context: ssl.SSLContext,
        upstream_endpoint: ResolvedEndpoint,
    ):
        self.tls_context = tls_context
        self.upstream_endpoint = upstream_endpoint
        self.request_slots = threading.BoundedSemaphore(MAX_CONCURRENT_REQUESTS)
        super().__init__(address, handler)

    def process_request(self, request, client_address) -> None:
        if not self.request_slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.request_slots.release()
            request.close()
            raise

    def process_request_thread(self, request, client_address) -> None:
        tls_request = None
        try:
            tls_request = self.tls_context.wrap_socket(
                request,
                server_side=True,
                do_handshake_on_connect=False,
            )
            perform_tls_handshake(tls_request, TLS_HANDSHAKE_TIMEOUT_SECONDS)
            super().process_request_thread(tls_request, client_address)
        except (OSError, TimeoutError, ssl.SSLError):
            pass
        except Exception:
            self.handle_error(request, client_address)
        finally:
            target = tls_request if tls_request is not None else request
            target.close()
            self.request_slots.release()


def main() -> None:
    upstream_endpoint = resolve_upstream(UPSTREAM_HOST, UPSTREAM_PORT)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(CERT_FILE, KEY_FILE)
    server = BoundedThreadingHTTPServer(
        (LISTEN_HOST, LISTEN_PORT), ProxyHandler, context, upstream_endpoint
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
