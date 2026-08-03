#!/usr/bin/env python3

import http.client
import http.cookiejar
import ipaddress
import json
import os
import re
import socket
import stat
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from pathlib import Path


BASE_URL = os.environ.get("CHIO_BASE_URL", "http://127.0.0.1:8931")
CONTROL_URL = os.environ.get("CHIO_CONTROL_URL", "https://127.0.0.1:8940")
PROTOCOL_VERSION = "2025-11-25"
MAX_CA_BYTES = 1024 * 1024
MAX_HEALTH_BYTES = 64 * 1024
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_SSE_BYTES = 2 * 1024 * 1024
MAX_SSE_LINE_BYTES = 256 * 1024
RESPONSE_READ_CHUNK_BYTES = 16 * 1024
REQUEST_TIMEOUT_SECONDS = 5
EDGE_READY_TIMEOUT_SECONDS = 60.0
EDGE_READY_RETRY_SECONDS = 0.25
BEARER_TOKEN = re.compile(r"[A-Za-z0-9\-._~+/]+=*")
EXPECTED_TOOL_SERVER = "docker-demo"
EXPECTED_TOOL_NAME = "echo_text"
EXPECTED_ECHO_MESSAGE = "hello from docker"
DASHBOARD_SESSION_PATH = "/v1/dashboard/session"
DASHBOARD_SESSION_COOKIE = "__Host-chio_dashboard"
DASHBOARD_SESSION_COOKIE_PATTERN = re.compile(
    r"^__Host-chio_dashboard=([0-9a-f]{64}); Path=/; Max-Age=900; Secure; HttpOnly; SameSite=Strict$"
)
DASHBOARD_SESSION_CLEAR_COOKIE = (
    "__Host-chio_dashboard=; Path=/; Max-Age=0; "
    "Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; HttpOnly; SameSite=Strict"
)
EXPECTED_TOOL = {
    "name": EXPECTED_TOOL_NAME,
    "description": "Echo Text\n\nReturn the provided message",
    "inputSchema": {
        "type": "object",
        "properties": {
            "message": {
                "type": "string",
                "minLength": 1,
                "maxLength": 4096,
            }
        },
        "required": ["message"],
        "additionalProperties": False,
    },
    "annotations": {
        "readOnlyHint": True,
        "destructiveHint": False,
    },
    "execution": {"taskSupport": "optional"},
}
EXPECTED_TOOL_RESULT = {
    "content": [
        {
            "type": "text",
            "text": f"echo: {EXPECTED_ECHO_MESSAGE}",
        }
    ],
    "structuredContent": {"echo": EXPECTED_ECHO_MESSAGE},
    "isError": False,
}


def require_token(name: str) -> str:
    value = os.environ.get(name, "")
    if BEARER_TOKEN.fullmatch(value) is None:
        raise SystemExit(f"{name} must be set to an explicit bearer token")
    return value


EDGE_TOKEN = require_token("CHIO_EDGE_TOKEN")
ADMIN_TOKEN = require_token("CHIO_ADMIN_TOKEN")
DASHBOARD_READ_TOKEN = require_token("CHIO_DASHBOARD_READ_TOKEN")
SERVICE_TOKEN = require_token("CHIO_SERVICE_TOKEN")
if len({EDGE_TOKEN, ADMIN_TOKEN, DASHBOARD_READ_TOKEN, SERVICE_TOKEN}) != 4:
    raise SystemExit(
        "edge, admin, dashboard read, and service bearer tokens must be distinct"
    )


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, _request, _file_pointer, _code, _message, _headers, _url
    ):
        return None


class EdgeNotReady(RuntimeError):
    pass


class DeadlineHTTPResponse(http.client.HTTPResponse):
    def __init__(self, connection, *args, **kwargs) -> None:
        super().__init__(connection, *args, **kwargs)
        configured_timeout = connection.gettimeout()
        seconds = (
            configured_timeout
            if configured_timeout is not None and configured_timeout > 0.0
            else REQUEST_TIMEOUT_SECONDS
        )
        self.deadline_connection = connection
        self.deadline_lock = threading.Lock()
        self.deadline_active = True
        self.deadline_timer = threading.Timer(seconds, self._expire_deadline)
        self.deadline_timer.daemon = True
        self.deadline_timer.start()

    def _expire_deadline(self) -> None:
        with self.deadline_lock:
            if not self.deadline_active:
                return
            self.deadline_active = False
        try:
            self.deadline_connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def close(self) -> None:
        with self.deadline_lock:
            self.deadline_active = False
        self.deadline_timer.cancel()
        super().close()


class DeadlineHTTPConnection(http.client.HTTPConnection):
    response_class = DeadlineHTTPResponse


class DeadlineHTTPSConnection(http.client.HTTPSConnection):
    response_class = DeadlineHTTPResponse


class DeadlineHTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, request):
        return self.do_open(DeadlineHTTPConnection, request)


class DeadlineHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, request):
        return self.do_open(DeadlineHTTPSConnection, request, context=self._context)


class ResponseDeadline:
    def __init__(self, response, seconds: float, *, name: str) -> None:
        self.expires_at = time.monotonic() + seconds
        self.name = name
        self.connection = self._socket(response)
        self.lock = threading.Lock()
        self.active = False
        self.timer = threading.Timer(seconds, self._expire)
        self.timer.daemon = True

    def _remaining(self) -> float:
        remaining = self.expires_at - time.monotonic()
        if remaining <= 0.0:
            raise SystemExit(f"{self.name} response deadline expired")
        return remaining

    @staticmethod
    def _socket(response):
        file_pointer = getattr(response, "fp", None)
        raw = getattr(file_pointer, "raw", None)
        return getattr(raw, "_sock", None)

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

    def read1(self, response, limit: int) -> bytes:
        if self.connection is not None:
            self.connection.settimeout(self._remaining())
        reader = getattr(response, "read1", None)
        if not callable(reader):
            raise SystemExit(f"{self.name} response transport is not bounded")
        try:
            chunk = reader(limit)
        except (OSError, TimeoutError) as exc:
            raise SystemExit(f"{self.name} response deadline expired") from exc
        self._remaining()
        return chunk


def parsed_origin(url: str, *, name: str, allow_loopback_http: bool):
    if (
        not url
        or not url.isascii()
        or "\\" in url
        or any(ord(character) <= 0x20 or ord(character) == 0x7F for character in url)
    ):
        raise SystemExit(f"{name} URL contains invalid characters")
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise SystemExit(f"{name} URL is invalid") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or "%" in parsed.netloc
    ):
        raise SystemExit(f"{name} URL must have an HTTP(S) origin without userinfo")
    if port is not None and not 1 <= port <= 65535:
        raise SystemExit(f"{name} URL port is invalid")
    if parsed.scheme == "http":
        if not allow_loopback_http:
            raise SystemExit(f"{name} URL must use HTTPS")
        try:
            address = ipaddress.ip_address(parsed.hostname)
        except ValueError as exc:
            raise SystemExit(
                f"{name} cleartext URL must use a numeric loopback address"
            ) from exc
        if not address.is_loopback:
            raise SystemExit(
                f"{name} cleartext URL must use a numeric loopback address"
            )
    effective_port = (
        port if port is not None else (443 if parsed.scheme == "https" else 80)
    )
    return parsed, (parsed.scheme, parsed.hostname.lower(), effective_port)


def validate_origin(url: str, *, name: str, allow_loopback_http: bool) -> str:
    parsed, _ = parsed_origin(url, name=name, allow_loopback_http=allow_loopback_http)
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise SystemExit(f"{name} URL must contain only an origin")
    return url[:-1] if url.endswith("/") else url


def validate_token(token: str, *, name: str) -> str:
    if BEARER_TOKEN.fullmatch(token) is None:
        raise SystemExit(f"{name} token does not use bearer-token grammar")
    return token


def assert_final_url(
    response, expected_url: str, *, name: str, allow_loopback_http: bool
):
    final_url = response.geturl()
    _, expected_origin = parsed_origin(
        expected_url, name=name, allow_loopback_http=allow_loopback_http
    )
    _, final_origin = parsed_origin(
        final_url, name=f"final {name}", allow_loopback_http=allow_loopback_http
    )
    if final_origin != expected_origin or final_url != expected_url:
        raise SystemExit(f"{name} response changed origin or target")


def read_ca_pem(path) -> str:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        descriptor = os.open(os.fspath(path), flags)
    except OSError as exc:
        raise SystemExit("control CA must be a readable non-symlink file") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise SystemExit("control CA must be a regular file")
        if metadata.st_size <= 0 or metadata.st_size > MAX_CA_BYTES:
            raise SystemExit("control CA is empty or exceeds 1 MiB")
        chunks = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, MAX_CA_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_CA_BYTES:
                raise SystemExit("control CA exceeds 1 MiB")
        if total != metadata.st_size:
            raise SystemExit("control CA changed while it was read")
        try:
            return b"".join(chunks).decode("ascii")
        except UnicodeDecodeError as exc:
            raise SystemExit("control CA must be ASCII PEM") from exc
    finally:
        os.close(descriptor)


@contextmanager
def control_ca_file():
    configured = os.environ.get("CHIO_CONTROL_CA_FILE")
    if configured:
        yield Path(configured)
        return

    compose = Path(__file__).with_name("compose.yaml")
    with tempfile.TemporaryDirectory(prefix="chio-docker-ca-") as directory:
        destination = Path(directory) / "demo-ca.pem"
        subprocess.run(
            [
                "docker",
                "compose",
                "-f",
                str(compose),
                "cp",
                "chio-trust-tls:/var/lib/chio-tls-public/demo-ca.pem",
                str(destination),
            ],
            check=True,
        )
        yield destination


def build_tls_opener(
    ca_pem: str | None = None,
    cookie_jar: http.cookiejar.CookieJar | None = None,
):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if ca_pem is None:
        context.load_default_certs()
    else:
        context.load_verify_locations(cadata=ca_pem)
    handlers = [urllib.request.ProxyHandler({}), NoRedirect()]
    if cookie_jar is not None:
        handlers.append(urllib.request.HTTPCookieProcessor(cookie_jar))
    handlers.append(DeadlineHTTPSHandler(context=context))
    return urllib.request.build_opener(*handlers)


def build_edge_opener(edge_origin: str):
    parsed, _ = parsed_origin(edge_origin, name="edge", allow_loopback_http=True)
    if parsed.scheme == "https":
        configured_ca = os.environ.get("CHIO_EDGE_CA_FILE")
        return build_tls_opener(
            None if configured_ca is None else read_ca_pem(configured_ca)
        )
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}), NoRedirect(), DeadlineHTTPHandler()
    )


def build_control_opener(ca_file, cookie_jar):
    return build_tls_opener(read_ca_pem(ca_file), cookie_jar=cookie_jar)


def read_bounded(
    response,
    limit: int,
    *,
    name: str,
    timeout_seconds: float = REQUEST_TIMEOUT_SECONDS,
) -> bytes:
    declared_length = getattr(response, "length", None)
    if declared_length is not None and declared_length > limit:
        raise SystemExit(f"{name} response exceeds {limit} bytes")
    payload = bytearray()
    with ResponseDeadline(response, timeout_seconds, name=name) as deadline:
        while len(payload) <= limit:
            remaining = limit + 1 - len(payload)
            chunk = deadline.read1(response, min(RESPONSE_READ_CHUNK_BYTES, remaining))
            if not chunk:
                break
            payload.extend(chunk)
    if len(payload) > limit:
        raise SystemExit(f"{name} response exceeds {limit} bytes")
    return bytes(payload)


def iter_bounded_lines(response, *, name: str):
    pending = bytearray()
    total = 0
    with ResponseDeadline(response, REQUEST_TIMEOUT_SECONDS, name=name) as deadline:
        while True:
            chunk = deadline.read1(
                response,
                min(RESPONSE_READ_CHUNK_BYTES, MAX_SSE_BYTES + 1 - total),
            )
            if not chunk:
                if pending:
                    yield bytes(pending)
                return
            total += len(chunk)
            if total > MAX_SSE_BYTES:
                raise SystemExit("SSE response exceeds 2 MiB")
            pending.extend(chunk)
            while True:
                newline = pending.find(b"\n")
                if newline < 0:
                    break
                line_length = newline + 1
                if line_length > MAX_SSE_LINE_BYTES:
                    raise SystemExit("SSE line exceeds 256 KiB")
                yield bytes(pending[:line_length])
                del pending[:line_length]
            if len(pending) > MAX_SSE_LINE_BYTES:
                raise SystemExit("SSE line exceeds 256 KiB")


def request_json(
    url,
    *,
    expected_origin,
    name,
    allow_loopback_http,
    method="GET",
    payload=None,
    headers=None,
    opener,
):
    _, actual_origin = parsed_origin(
        url, name=name, allow_loopback_http=allow_loopback_http
    )
    _, required_origin = parsed_origin(
        expected_origin, name=name, allow_loopback_http=allow_loopback_http
    )
    if actual_origin != required_origin:
        raise SystemExit(f"{name} request target changed origin")
    request = urllib.request.Request(
        url,
        data=None if payload is None else json.dumps(payload).encode("utf-8"),
        method=method,
        headers=headers or {},
    )
    try:
        with opener.open(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            assert_final_url(
                response,
                url,
                name=name,
                allow_loopback_http=allow_loopback_http,
            )
            raw = read_bounded(response, MAX_JSON_BYTES, name=name)
    except urllib.error.HTTPError as exc:
        status = exc.code
        exc.close()
        if 300 <= status < 400:
            raise SystemExit(f"{name} redirect rejected") from exc
        raise SystemExit(f"{name} request failed with status {status}") from exc
    except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
        raise SystemExit(f"{name} request failed") from exc
    try:
        decoded = json.loads(raw.decode("utf-8")) if raw else {}
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"{name} response is not valid UTF-8 JSON") from exc
    if not isinstance(decoded, dict):
        raise SystemExit(f"{name} response must be a JSON object")
    return decoded


def validate_edge_health(payload) -> dict:
    if not isinstance(payload, dict):
        raise SystemExit("edge readiness response must be a JSON object")
    server = payload.get("server")
    auth = payload.get("auth")
    control = payload.get("controlPlane")
    if (
        payload.get("ok") is not True
        or not isinstance(server, dict)
        or server.get("serverId") != EXPECTED_TOOL_SERVER
        or not isinstance(auth, dict)
        or auth.get("adminTokenConfigured") is not True
        or not isinstance(control, dict)
        or control.get("proxied") is not True
        or control.get("controlTokenConfigured") is not True
    ):
        raise SystemExit("edge readiness response does not match the Docker demo")
    return payload


def probe_edge_health(
    *, edge_origin, admin_token, edge_opener, timeout_seconds: float
):
    url = f"{edge_origin}/admin/health"
    request = urllib.request.Request(
        url,
        method="GET",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    try:
        with edge_opener.open(request, timeout=timeout_seconds) as response:
            assert_final_url(
                response,
                url,
                name="edge readiness",
                allow_loopback_http=True,
            )
            raw = read_bounded(
                response,
                MAX_HEALTH_BYTES,
                name="edge readiness",
                timeout_seconds=timeout_seconds,
            )
    except urllib.error.HTTPError as exc:
        status = exc.code
        exc.close()
        if status >= 500:
            raise EdgeNotReady(f"edge readiness returned status {status}") from exc
        raise SystemExit(f"edge readiness failed with status {status}") from exc
    except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
        raise EdgeNotReady("edge readiness request failed") from exc
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit("edge readiness response is not valid UTF-8 JSON") from exc
    return validate_edge_health(payload)


def wait_for_edge_ready(*, edge_origin, admin_token, edge_opener) -> None:
    deadline = time.monotonic() + EDGE_READY_TIMEOUT_SECONDS
    last_error = None
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0.0:
            raise SystemExit("edge readiness deadline expired") from last_error
        try:
            probe_edge_health(
                edge_origin=edge_origin,
                admin_token=admin_token,
                edge_opener=edge_opener,
                timeout_seconds=min(REQUEST_TIMEOUT_SECONDS, remaining),
            )
            return
        except EdgeNotReady as exc:
            last_error = exc
        remaining = deadline - time.monotonic()
        if remaining <= 0.0:
            raise SystemExit("edge readiness deadline expired") from last_error
        time.sleep(min(EDGE_READY_RETRY_SECONDS, remaining))


def post_mcp(payload, *, edge_origin, edge_token, edge_opener, session_id=None):
    url = f"{edge_origin}/mcp"
    headers = {
        "Authorization": f"Bearer {edge_token}",
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "MCP-Protocol-Version": PROTOCOL_VERSION,
    }
    if session_id:
        headers["MCP-Session-Id"] = session_id
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers=headers,
    )
    try:
        response = edge_opener.open(request, timeout=REQUEST_TIMEOUT_SECONDS)
        try:
            assert_final_url(
                response,
                url,
                name="edge MCP",
                allow_loopback_http=True,
            )
        except BaseException:
            response.close()
            raise
        return response
    except urllib.error.HTTPError as exc:
        status = exc.code
        exc.close()
        if 300 <= status < 400:
            raise SystemExit("edge MCP redirect rejected") from exc
        raise SystemExit(f"edge MCP request failed with status {status}") from exc
    except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
        raise SystemExit("edge MCP request failed") from exc


def read_sse_json(response):
    data_lines = []
    lines = iter_bounded_lines(response, name="edge SSE")
    try:
        for raw_line in lines:
            try:
                line = raw_line.decode("utf-8").rstrip("\r\n")
            except UnicodeDecodeError as exc:
                raise SystemExit("SSE response is not valid UTF-8") from exc
            if not line:
                if data_lines:
                    try:
                        payload = json.loads("\n".join(data_lines))
                    except json.JSONDecodeError as exc:
                        raise SystemExit("SSE data is not valid JSON") from exc
                    if not isinstance(payload, dict):
                        raise SystemExit("SSE JSON-RPC payload must be an object")
                    return payload
                continue
            if line.startswith("data:"):
                data_lines.append(line.split(":", 1)[1].lstrip())
    finally:
        lines.close()
    raise SystemExit("no JSON-RPC payload received from SSE response")


def require_jsonrpc_result(payload, request_id: int, *, name: str) -> dict:
    response_id = payload.get("id") if isinstance(payload, dict) else None
    if (
        not isinstance(payload, dict)
        or payload.get("jsonrpc") != "2.0"
        or not isinstance(response_id, int)
        or isinstance(response_id, bool)
        or response_id != request_id
        or "error" in payload
        or not isinstance(payload.get("result"), dict)
    ):
        raise SystemExit(f"{name} did not return the expected JSON-RPC result")
    return payload["result"]


def validate_initialize_response(payload) -> dict:
    result = require_jsonrpc_result(payload, 1, name="initialize")
    if (
        result.get("protocolVersion") != PROTOCOL_VERSION
        or not isinstance(result.get("capabilities"), dict)
        or result.get("serverInfo")
        != {"name": "Docker demo MCP", "version": "1"}
    ):
        raise SystemExit("initialize result does not match the Docker demo")
    return result


def validate_tools_response(payload) -> dict:
    result = require_jsonrpc_result(payload, 2, name="tools/list")
    if result != {"tools": [EXPECTED_TOOL], "nextCursor": None}:
        raise SystemExit("tools/list result does not match the signed Docker tool")
    return result


def validate_tool_call_response(payload) -> dict:
    result = require_jsonrpc_result(payload, 3, name="tools/call")
    if result != EXPECTED_TOOL_RESULT:
        raise SystemExit("tools/call result does not match the governed Docker echo")
    return result


def validate_receipt(receipt, capability_id: str) -> dict:
    decision = receipt.get("decision") if isinstance(receipt, dict) else None
    if (
        not isinstance(receipt, dict)
        or receipt.get("capability_id") != capability_id
        or receipt.get("tool_server") != EXPECTED_TOOL_SERVER
        or receipt.get("tool_name") != EXPECTED_TOOL_NAME
        or not isinstance(decision, dict)
        or decision.get("verdict") != "allow"
        or not isinstance(receipt.get("id"), str)
        or not receipt["id"]
    ):
        raise SystemExit("receipt does not bind the allowed Docker echo call")
    return receipt


def session_capability_id(session_id, *, edge_origin, admin_token, edge_opener):
    encoded_session_id = urllib.parse.quote(session_id, safe="")
    trust = request_json(
        f"{edge_origin}/admin/sessions/{encoded_session_id}/trust",
        expected_origin=edge_origin,
        name="edge session trust",
        allow_loopback_http=True,
        headers={"Authorization": f"Bearer {admin_token}"},
        opener=edge_opener,
    )
    capabilities = trust.get("capabilities")
    if (
        not isinstance(capabilities, list)
        or not capabilities
        or not isinstance(capabilities[0], dict)
    ):
        raise SystemExit("session trust endpoint did not return capabilities")
    capability_id = capabilities[0].get("capabilityId")
    if not isinstance(capability_id, str) or not capability_id:
        raise SystemExit("session trust endpoint did not return a capability id")
    return capability_id


def validate_dashboard_session(payload, *, expected_expires_at=None) -> dict:
    expires_at = payload.get("expiresAt") if isinstance(payload, dict) else None
    if (
        not isinstance(payload, dict)
        or set(payload) != {"authenticated", "expiresAt", "relayReports"}
        or payload.get("authenticated") is not True
        or not isinstance(expires_at, int)
        or isinstance(expires_at, bool)
        or expires_at <= 0
        or not isinstance(payload.get("relayReports"), dict)
        or (
            expected_expires_at is not None
            and expires_at != expected_expires_at
        )
    ):
        raise SystemExit("dashboard session status is invalid")
    return payload


def create_dashboard_session(
    *, control_origin, dashboard_read_token, control_opener, cookie_jar
):
    url = f"{control_origin}{DASHBOARD_SESSION_PATH}"
    request = urllib.request.Request(
        url,
        data=json.dumps(
            {"token": dashboard_read_token}, separators=(",", ":")
        ).encode("utf-8"),
        method="POST",
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
    )
    try:
        with control_opener.open(
            request, timeout=REQUEST_TIMEOUT_SECONDS
        ) as response:
            assert_final_url(
                response,
                url,
                name="dashboard session creation",
                allow_loopback_http=False,
            )
            if response.status != 200:
                raise SystemExit("dashboard session creation did not return status 200")
            set_cookies = response.headers.get_all("Set-Cookie", [])
            if len(set_cookies) != 1:
                raise SystemExit("dashboard session creation did not set exactly one cookie")
            match = DASHBOARD_SESSION_COOKIE_PATTERN.fullmatch(set_cookies[0])
            if match is None:
                raise SystemExit("dashboard session cookie attributes are invalid")
            if response.headers.get("Cache-Control") != "no-store":
                raise SystemExit("dashboard session creation is cacheable")
            raw = read_bounded(
                response, MAX_JSON_BYTES, name="dashboard session creation"
            )
    except urllib.error.HTTPError as exc:
        status = exc.code
        exc.close()
        if 300 <= status < 400:
            raise SystemExit("dashboard session creation redirect rejected") from exc
        raise SystemExit(
            f"dashboard session creation failed with status {status}"
        ) from exc
    except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
        raise SystemExit("dashboard session creation failed") from exc
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit(
            "dashboard session creation response is not valid UTF-8 JSON"
        ) from exc
    session = validate_dashboard_session(payload)
    session_id = match.group(1)
    if dashboard_read_token.encode("utf-8") in raw or session_id.encode("ascii") in raw:
        raise SystemExit("dashboard session creation reflected credential material")
    matching_cookies = [
        cookie
        for cookie in cookie_jar
        if cookie.name == DASHBOARD_SESSION_COOKIE
    ]
    if (
        len(matching_cookies) != 1
        or matching_cookies[0].value != session_id
        or not matching_cookies[0].secure
        or matching_cookies[0].path != "/"
        or matching_cookies[0].domain_specified
    ):
        raise SystemExit("dashboard session cookie jar state is invalid")
    status = request_json(
        url,
        expected_origin=control_origin,
        name="dashboard session status",
        allow_loopback_http=False,
        opener=control_opener,
    )
    validate_dashboard_session(
        status, expected_expires_at=session["expiresAt"]
    )
    return f"{DASHBOARD_SESSION_COOKIE}={session_id}"


def delete_dashboard_session(
    *, control_origin, stale_cookie, control_opener, cookie_jar
) -> None:
    url = f"{control_origin}{DASHBOARD_SESSION_PATH}"
    request = urllib.request.Request(url, method="DELETE")
    try:
        with control_opener.open(
            request, timeout=REQUEST_TIMEOUT_SECONDS
        ) as response:
            assert_final_url(
                response,
                url,
                name="dashboard session logout",
                allow_loopback_http=False,
            )
            if response.status != 204:
                raise SystemExit("dashboard session logout did not return status 204")
            if response.headers.get_all("Set-Cookie", []) != [
                DASHBOARD_SESSION_CLEAR_COOKIE
            ]:
                raise SystemExit("dashboard session logout did not clear its cookie")
            if response.headers.get("Cache-Control") != "no-store":
                raise SystemExit("dashboard session logout is cacheable")
            if read_bounded(
                response, MAX_JSON_BYTES, name="dashboard session logout"
            ):
                raise SystemExit("dashboard session logout returned an unexpected body")
    except urllib.error.HTTPError as exc:
        status = exc.code
        exc.close()
        if 300 <= status < 400:
            raise SystemExit("dashboard session logout redirect rejected") from exc
        raise SystemExit(
            f"dashboard session logout failed with status {status}"
        ) from exc
    except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
        raise SystemExit("dashboard session logout failed") from exc
    if any(cookie.name == DASHBOARD_SESSION_COOKIE for cookie in cookie_jar):
        raise SystemExit("dashboard session cookie remained after logout")

    stale_request = urllib.request.Request(
        url,
        method="GET",
        headers={"Cookie": stale_cookie},
    )
    try:
        response = control_opener.open(
            stale_request, timeout=REQUEST_TIMEOUT_SECONDS
        )
    except urllib.error.HTTPError as exc:
        try:
            assert_final_url(
                exc,
                url,
                name="dashboard session invalidation",
                allow_loopback_http=False,
            )
            if exc.code != 401 or exc.headers.get("Cache-Control") != "no-store":
                raise SystemExit("dashboard session logout did not invalidate the session")
        finally:
            exc.close()
    except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
        raise SystemExit("dashboard session invalidation check failed") from exc
    else:
        response.close()
        raise SystemExit("dashboard session remained valid after logout")


def query_receipts(capability_id, *, control_origin, control_opener):
    query = urllib.parse.urlencode(
        {
            "capabilityId": capability_id,
            "toolServer": EXPECTED_TOOL_SERVER,
            "toolName": EXPECTED_TOOL_NAME,
            "limit": 10,
        }
    )
    payload = request_json(
        f"{control_origin}/v1/receipts/query?{query}",
        expected_origin=control_origin,
        name="control receipt query",
        allow_loopback_http=False,
        opener=control_opener,
    )
    receipts = payload.get("receipts", [])
    if not isinstance(receipts, list) or len(receipts) != 1:
        raise SystemExit("receipt query did not return exactly one Docker echo receipt")
    return validate_receipt(receipts[0], capability_id)


def run_smoke(
    control_opener,
    *,
    edge_origin,
    control_origin,
    edge_token,
    admin_token,
    dashboard_read_token,
    control_cookie_jar,
    edge_opener,
):
    with post_mcp(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {
                    "name": "docker-smoke-client",
                    "version": "1.0.0",
                },
            },
        },
        edge_origin=edge_origin,
        edge_token=edge_token,
        edge_opener=edge_opener,
    ) as response:
        session_id = response.headers.get("MCP-Session-Id")
        if not session_id:
            raise SystemExit("initialize response omitted MCP-Session-Id")
        initialize = validate_initialize_response(read_sse_json(response))

    with post_mcp(
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        session_id=session_id,
        edge_origin=edge_origin,
        edge_token=edge_token,
        edge_opener=edge_opener,
    ):
        pass

    with post_mcp(
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        session_id=session_id,
        edge_origin=edge_origin,
        edge_token=edge_token,
        edge_opener=edge_opener,
    ) as response:
        tools = validate_tools_response(read_sse_json(response))

    with post_mcp(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": EXPECTED_TOOL_NAME,
                "arguments": {"message": EXPECTED_ECHO_MESSAGE},
            },
        },
        session_id=session_id,
        edge_origin=edge_origin,
        edge_token=edge_token,
        edge_opener=edge_opener,
    ) as response:
        tool_call = validate_tool_call_response(read_sse_json(response))

    capability_id = session_capability_id(
        session_id,
        edge_origin=edge_origin,
        admin_token=admin_token,
        edge_opener=edge_opener,
    )
    dashboard_cookie = create_dashboard_session(
        control_origin=control_origin,
        dashboard_read_token=dashboard_read_token,
        control_opener=control_opener,
        cookie_jar=control_cookie_jar,
    )
    try:
        receipt = query_receipts(
            capability_id,
            control_origin=control_origin,
            control_opener=control_opener,
        )
    finally:
        delete_dashboard_session(
            control_origin=control_origin,
            stale_cookie=dashboard_cookie,
            control_opener=control_opener,
            cookie_jar=control_cookie_jar,
        )
    print(
        json.dumps(
            {
                "sessionId": session_id,
                "capabilityId": capability_id,
                "initialize": initialize,
                "tools": tools["tools"],
                "toolResult": tool_call,
                "receiptId": receipt["id"],
                "controlOrigin": control_origin,
            },
            indent=2,
        )
    )


def main() -> None:
    edge_origin = validate_origin(BASE_URL, name="edge", allow_loopback_http=True)
    control_origin = validate_origin(
        CONTROL_URL, name="control", allow_loopback_http=False
    )
    edge_token = validate_token(EDGE_TOKEN, name="edge")
    admin_token = validate_token(ADMIN_TOKEN, name="admin")
    dashboard_read_token = validate_token(
        DASHBOARD_READ_TOKEN, name="dashboard read"
    )
    edge_opener = build_edge_opener(edge_origin)
    wait_for_edge_ready(
        edge_origin=edge_origin,
        admin_token=admin_token,
        edge_opener=edge_opener,
    )
    with control_ca_file() as ca_file:
        control_cookie_jar = http.cookiejar.CookieJar()
        run_smoke(
            build_control_opener(ca_file, control_cookie_jar),
            edge_origin=edge_origin,
            control_origin=control_origin,
            edge_token=edge_token,
            admin_token=admin_token,
            dashboard_read_token=dashboard_read_token,
            control_cookie_jar=control_cookie_jar,
            edge_opener=edge_opener,
        )


if __name__ == "__main__":
    main()
