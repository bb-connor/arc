#!/usr/bin/env python3

import copy
import http.cookiejar
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock


HERE = Path(__file__).resolve().parent


def load_module(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {filename}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


proxy = load_module("docker_tls_reverse_proxy", "tls_reverse_proxy.py")
health = load_module("docker_tls_healthcheck", "tls_healthcheck.py")
edge_health = load_module("docker_mcp_edge_healthcheck", "mcp_edge_healthcheck.py")
with mock.patch.dict(
    os.environ,
    {
        "CHIO_EDGE_TOKEN": "edge-test-token",
        "CHIO_ADMIN_TOKEN": "admin-test-token",
        "CHIO_DASHBOARD_READ_TOKEN": "dashboard-read-test-token",
        "CHIO_SERVICE_TOKEN": "service-test-token",
    },
):
    smoke = load_module("docker_smoke_client", "smoke_client.py")


class SmokeCredentialTests(unittest.TestCase):
    def run_smoke(self, additions):
        environment = os.environ.copy()
        environment.pop("CHIO_EDGE_TOKEN", None)
        environment.pop("CHIO_ADMIN_TOKEN", None)
        environment.pop("CHIO_DASHBOARD_READ_TOKEN", None)
        environment.pop("CHIO_SERVICE_TOKEN", None)
        environment.update(additions)
        return subprocess.run(
            [sys.executable, str(HERE / "smoke_client.py")],
            env=environment,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )

    def test_smoke_requires_explicit_edge_admin_dashboard_read_and_service_tokens(self):
        completed = self.run_smoke({})
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("CHIO_EDGE_TOKEN must be set", completed.stderr)

    def test_smoke_rejects_every_equal_token_pair(self):
        cases = (
            (
                "same-test-token",
                "same-test-token",
                "dashboard-read-test-token",
                "service-test-token",
            ),
            (
                "same-test-token",
                "admin-test-token",
                "same-test-token",
                "service-test-token",
            ),
            (
                "same-test-token",
                "admin-test-token",
                "dashboard-read-test-token",
                "same-test-token",
            ),
            (
                "edge-test-token",
                "same-test-token",
                "same-test-token",
                "service-test-token",
            ),
            (
                "edge-test-token",
                "same-test-token",
                "dashboard-read-test-token",
                "same-test-token",
            ),
            (
                "edge-test-token",
                "admin-test-token",
                "same-test-token",
                "same-test-token",
            ),
        )
        for edge_token, admin_token, dashboard_read_token, service_token in cases:
            with self.subTest(
                edge_token=edge_token,
                admin_token=admin_token,
                dashboard_read_token=dashboard_read_token,
                service_token=service_token,
            ):
                completed = self.run_smoke(
                    {
                        "CHIO_EDGE_TOKEN": edge_token,
                        "CHIO_ADMIN_TOKEN": admin_token,
                        "CHIO_DASHBOARD_READ_TOKEN": dashboard_read_token,
                        "CHIO_SERVICE_TOKEN": service_token,
                    }
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn("must be distinct", completed.stderr)


class FakeConnection:
    def __init__(self, incoming=b""):
        self.incoming = incoming
        self.timeout = None
        self.closed = False

    def settimeout(self, timeout):
        self.timeout = timeout

    def recv_into(self, buffer):
        count = min(len(buffer), len(self.incoming))
        buffer[:count] = self.incoming[:count]
        self.incoming = self.incoming[count:]
        return count

    def sendall(self, _buffer):
        return None

    def close(self):
        self.closed = True


class FakeDeadline:
    def __init__(self):
        self.started = []
        self.cleared = 0

    def start(self, seconds):
        self.started.append(seconds)

    def clear(self):
        self.cleared += 1


class FakeResponse:
    def __init__(self, url, payload=b"{}", status=200, headers=None):
        self.url = url
        self.payload = io.BytesIO(payload)
        self.status = status
        self.headers = headers or Message()
        self.closed = False

    def geturl(self):
        return self.url

    def read(self, limit=-1):
        return self.payload.read(limit)

    def read1(self, limit=-1):
        return self.payload.read(limit)

    def readline(self, limit=-1):
        return self.payload.readline(limit)

    def __enter__(self):
        return self

    def __exit__(self, _exception_type, _exception, _traceback):
        return None

    def close(self):
        self.closed = True


class CapturingOpener:
    def __init__(self, response):
        self.response = response
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        return self.response


class SequenceOpener:
    def __init__(self, events):
        self.events = list(events)
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        if not self.events:
            raise AssertionError("sequence opener exhausted")
        event = self.events.pop(0)
        if isinstance(event, BaseException):
            raise event
        return event


def dashboard_cookie(value: str) -> http.cookiejar.Cookie:
    return http.cookiejar.Cookie(
        version=0,
        name=smoke.DASHBOARD_SESSION_COOKIE,
        value=value,
        port=None,
        port_specified=False,
        domain="control.example",
        domain_specified=False,
        domain_initial_dot=False,
        path="/",
        path_specified=True,
        secure=True,
        expires=int(time.time()) + 900,
        discard=False,
        comment=None,
        comment_url=None,
        rest={"HttpOnly": None, "SameSite": "Strict"},
        rfc2109=False,
    )


def ready_edge_health_payload():
    return {
        "ok": True,
        "server": {"serverId": "docker-demo"},
        "auth": {"adminTokenConfigured": True},
        "controlPlane": {
            "proxied": True,
            "controlTokenConfigured": True,
        },
    }


class EdgeHealthcheckTests(unittest.TestCase):
    def test_container_healthcheck_uses_admin_auth_and_exact_runtime_contract(self):
        response = FakeResponse(
            edge_health.HEALTH_URL,
            payload=json.dumps(ready_edge_health_payload()).encode(),
        )
        opener = CapturingOpener(response)
        self.assertTrue(edge_health.probe_health(opener, "admin-secret")["ok"])
        request = opener.requests[0][0]
        self.assertEqual(
            request.get_header("Authorization"), "Bearer admin-secret"
        )

    def test_container_healthcheck_rejects_runtime_contract_drift(self):
        mutations = (
            ("ok", False),
            ("server", {"serverId": "other"}),
            ("auth", {"adminTokenConfigured": False}),
            (
                "controlPlane",
                {"proxied": False, "controlTokenConfigured": True},
            ),
        )
        for key, value in mutations:
            with self.subTest(key=key):
                payload = ready_edge_health_payload()
                payload[key] = value
                opener = CapturingOpener(
                    FakeResponse(
                        edge_health.HEALTH_URL,
                        payload=json.dumps(payload).encode(),
                    )
                )
                with self.assertRaises(SystemExit):
                    edge_health.probe_health(opener, "admin-secret")

    def test_smoke_readiness_retries_connection_failure_then_succeeds(self):
        response = FakeResponse(
            "http://127.0.0.1:8931/admin/health",
            payload=json.dumps(ready_edge_health_payload()).encode(),
        )
        opener = SequenceOpener([urllib.error.URLError("not ready"), response])
        with mock.patch.object(smoke, "EDGE_READY_RETRY_SECONDS", 0.0):
            smoke.wait_for_edge_ready(
                edge_origin="http://127.0.0.1:8931",
                admin_token="admin-secret",
                edge_opener=opener,
            )
        self.assertEqual(len(opener.requests), 2)
        self.assertEqual(
            opener.requests[-1][0].get_header("Authorization"),
            "Bearer admin-secret",
        )

    def test_smoke_readiness_deadline_is_fail_closed(self):
        opener = SequenceOpener([urllib.error.URLError("not ready")])
        with mock.patch.object(
            smoke.time, "monotonic", side_effect=[0.0, 0.0, 61.0]
        ):
            with self.assertRaisesRegex(SystemExit, "readiness deadline expired"):
                smoke.wait_for_edge_ready(
                    edge_origin="http://127.0.0.1:8931",
                    admin_token="admin-secret",
                    edge_opener=opener,
                )


class SmokeSemanticBindingTests(unittest.TestCase):
    @staticmethod
    def jsonrpc(request_id, result):
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    @staticmethod
    def receipt(capability_id="cap-1"):
        return {
            "id": "receipt-1",
            "capability_id": capability_id,
            "tool_server": smoke.EXPECTED_TOOL_SERVER,
            "tool_name": smoke.EXPECTED_TOOL_NAME,
            "decision": {"verdict": "allow"},
        }

    def test_initialize_requires_exact_protocol_and_server_identity(self):
        result = {
            "protocolVersion": smoke.PROTOCOL_VERSION,
            "capabilities": {},
            "serverInfo": {"name": "Docker demo MCP", "version": "1"},
        }
        self.assertEqual(
            smoke.validate_initialize_response(self.jsonrpc(1, result)), result
        )
        for key, value in (
            ("protocolVersion", "wrong"),
            ("serverInfo", {"name": "other", "version": "1"}),
        ):
            with self.subTest(key=key):
                changed = copy.deepcopy(result)
                changed[key] = value
                with self.assertRaises(SystemExit):
                    smoke.validate_initialize_response(self.jsonrpc(1, changed))

    def test_tools_list_requires_the_exact_signed_inventory(self):
        result = {"tools": [copy.deepcopy(smoke.EXPECTED_TOOL)], "nextCursor": None}
        self.assertEqual(smoke.validate_tools_response(self.jsonrpc(2, result)), result)
        changed = copy.deepcopy(result)
        changed["tools"][0]["name"] = "wrong_tool"
        with self.assertRaises(SystemExit):
            smoke.validate_tools_response(self.jsonrpc(2, changed))

    def test_tool_call_requires_exact_echo_and_non_error_result(self):
        result = copy.deepcopy(smoke.EXPECTED_TOOL_RESULT)
        self.assertEqual(
            smoke.validate_tool_call_response(self.jsonrpc(3, result)), result
        )
        wrong_echo = copy.deepcopy(result)
        wrong_echo["structuredContent"]["echo"] = "wrong"
        wrong_error = copy.deepcopy(result)
        wrong_error["isError"] = True
        for changed in (wrong_echo, wrong_error):
            with self.subTest(changed=changed):
                with self.assertRaises(SystemExit):
                    smoke.validate_tool_call_response(self.jsonrpc(3, changed))

    def test_receipt_requires_exact_capability_tool_and_allow_bindings(self):
        receipt = self.receipt()
        self.assertEqual(smoke.validate_receipt(receipt, "cap-1"), receipt)
        mutations = (
            ("capability_id", "cap-other"),
            ("tool_server", "other-server"),
            ("tool_name", "other-tool"),
            ("decision", {"verdict": "deny"}),
            ("id", ""),
        )
        for key, value in mutations:
            with self.subTest(key=key):
                changed = copy.deepcopy(receipt)
                changed[key] = value
                with self.assertRaises(SystemExit):
                    smoke.validate_receipt(changed, "cap-1")


class ProxyFramingTests(unittest.TestCase):
    def test_content_length_accepts_exact_consistent_decimal(self):
        self.assertEqual(proxy.parse_content_length(None), 0)
        self.assertEqual(proxy.parse_content_length(["12"]), 12)
        self.assertEqual(proxy.parse_content_length(["12", "12"]), 12)
        self.assertEqual(proxy.parse_content_length(["12,12"]), 12)

    def test_content_length_rejects_ambiguous_or_non_decimal_grammar(self):
        bad_values = [
            ["+1"],
            ["-1"],
            [" 1"],
            ["1 "],
            ["1, 1"],
            ["1", "01"],
            ["1", "2"],
            ["1_0"],
            ["\N{ARABIC-INDIC DIGIT ONE}"],
            [""],
        ]
        for values in bad_values:
            with self.subTest(values=values), self.assertRaises(proxy.RequestRejected):
                proxy.parse_content_length(values)

    def test_content_length_rejects_oversize_without_large_integer_conversion(self):
        with self.assertRaises(proxy.RequestRejected) as caught:
            proxy.parse_content_length(["9" * 10000])
        self.assertEqual(caught.exception.status, 413)

    def test_short_request_body_is_rejected_exactly(self):
        handler = object.__new__(proxy.ProxyHandler)
        handler.rfile = io.BytesIO(b"ab")
        handler.read_deadline = FakeDeadline()
        with self.assertRaises(proxy.RequestRejected) as caught:
            handler._read_request_body(3)
        self.assertEqual(caught.exception.status, 400)
        self.assertEqual(handler.read_deadline.cleared, 1)

    def test_any_transfer_encoding_header_is_rejected(self):
        handler = object.__new__(proxy.ProxyHandler)
        handler.headers = Message()
        handler.headers.add_header("Transfer-Encoding", "")
        handler.path = "/health"
        handler._reject = mock.Mock()
        handler._proxy()
        handler._reject.assert_called_once_with(
            400, "transfer encoding is not accepted"
        )

    def test_request_hop_headers_and_connection_tokens_are_stripped(self):
        handler = object.__new__(proxy.ProxyHandler)
        handler.headers = Message()
        handler.headers.add_header("Connection", "X-Remove, keep-alive")
        handler.headers.add_header("X-Remove", "secret")
        handler.headers.add_header("Proxy-Connection", "close")
        handler.headers.add_header("Transfer-Encoding", "chunked")
        handler.headers.add_header("Content-Length", "999")
        handler.headers.add_header("Accept-Encoding", "gzip")
        handler.headers.add_header("X-Preserve", "yes")
        headers = handler._request_headers(7)
        self.assertEqual(headers["Content-Length"], "7")
        self.assertEqual(headers["Accept-Encoding"], "identity")
        self.assertEqual(headers["X-Preserve"], "yes")
        for name in ("Connection", "X-Remove", "Proxy-Connection", "Transfer-Encoding"):
            self.assertNotIn(name, headers)

    def test_response_hop_headers_and_connection_tokens_are_stripped(self):
        class UpstreamResponse:
            status = 200
            reason = "OK"

            @staticmethod
            def getheaders():
                return [
                    ("Connection", "X-Remove"),
                    ("X-Remove", "secret"),
                    ("Proxy-Connection", "close"),
                    ("Transfer-Encoding", "chunked"),
                    ("Content-Length", "999"),
                    ("X-Preserve", "yes"),
                ]

        handler = object.__new__(proxy.ProxyHandler)
        handler.connection = FakeConnection()
        handler.command = "GET"
        handler.wfile = io.BytesIO()
        handler.send_response = mock.Mock()
        handler.send_header = mock.Mock()
        handler.end_headers = mock.Mock()
        handler._send_response(UpstreamResponse(), b"body")
        sent = handler.send_header.call_args_list
        self.assertIn(mock.call("X-Preserve", "yes"), sent)
        self.assertIn(mock.call("Content-Length", "4"), sent)
        for forbidden in (
            "Connection",
            "X-Remove",
            "Proxy-Connection",
            "Transfer-Encoding",
        ):
            self.assertFalse(any(call.args[0] == forbidden for call in sent))

    def test_response_body_is_bounded_when_length_is_unknown(self):
        class UpstreamResponse:
            length = None

            def read1(self, _limit):
                return b"12345"

        handler = object.__new__(proxy.ProxyHandler)
        handler.command = "GET"
        with mock.patch.object(proxy, "MAX_RESPONSE_BYTES", 4):
            with self.assertRaises(proxy.ResponseTooLarge):
                handler._read_response_body(UpstreamResponse())

    def test_declared_oversize_response_is_rejected_before_body_read(self):
        class UpstreamResponse:
            length = 5
            read1 = mock.Mock(side_effect=AssertionError("body must not be read"))

        handler = object.__new__(proxy.ProxyHandler)
        handler.command = "GET"
        with mock.patch.object(proxy, "MAX_RESPONSE_BYTES", 4):
            with self.assertRaises(proxy.ResponseTooLarge):
                handler._read_response_body(UpstreamResponse())
        UpstreamResponse.read1.assert_not_called()

    def test_deadline_reader_applies_remaining_absolute_time(self):
        connection = FakeConnection(b"abc")
        deadline = mock.Mock()
        deadline.remaining.return_value = 0.25
        reader = proxy.DeadlineReader(connection, deadline)
        buffer = bytearray(3)
        self.assertEqual(reader.readinto(buffer), 3)
        self.assertEqual(bytes(buffer), b"abc")
        self.assertEqual(connection.timeout, 0.25)


class ProxyWorkerTests(unittest.TestCase):
    def test_resolved_http_connection_never_enters_dns(self):
        endpoint = proxy.ResolvedEndpoint(
            proxy.socket.AF_INET,
            proxy.socket.SOCK_STREAM,
            proxy.socket.IPPROTO_TCP,
            ("127.0.0.1", 8940),
        )
        connection = proxy.ResolvedHTTPConnection(
            "chio-trust-demo",
            8940,
            endpoint=endpoint,
            timeout=1.0,
        )
        transport = mock.Mock()
        with mock.patch.object(proxy.socket, "getaddrinfo") as resolver:
            with mock.patch.object(proxy.socket, "socket", return_value=transport):
                connection.connect()
        resolver.assert_not_called()
        transport.settimeout.assert_called_once_with(1.0)
        transport.connect.assert_called_once_with(("127.0.0.1", 8940))

    def test_thread_creation_failure_releases_slot_and_closes_socket(self):
        server = object.__new__(proxy.BoundedThreadingHTTPServer)
        server.request_slots = threading.BoundedSemaphore(1)
        request = FakeConnection()
        with mock.patch.object(
            ThreadingHTTPServer,
            "process_request",
            side_effect=RuntimeError("thread creation failed"),
        ):
            with self.assertRaises(RuntimeError):
                server.process_request(request, ("127.0.0.1", 1))
        self.assertTrue(request.closed)
        self.assertTrue(server.request_slots.acquire(blocking=False))

    def test_tls_wrap_and_handshake_run_in_worker_and_release_slot(self):
        raw_request = FakeConnection()
        tls_request = FakeConnection()
        context = mock.Mock()
        context.wrap_socket.return_value = tls_request
        server = object.__new__(proxy.BoundedThreadingHTTPServer)
        server.tls_context = context
        server.request_slots = threading.BoundedSemaphore(1)
        self.assertTrue(server.request_slots.acquire(blocking=False))
        with mock.patch.object(proxy, "perform_tls_handshake") as handshake:
            with mock.patch.object(
                ThreadingHTTPServer, "process_request_thread"
            ) as worker:
                server.process_request_thread(raw_request, ("127.0.0.1", 1))
        context.wrap_socket.assert_called_once_with(
            raw_request, server_side=True, do_handshake_on_connect=False
        )
        handshake.assert_called_once_with(
            tls_request, proxy.TLS_HANDSHAKE_TIMEOUT_SECONDS
        )
        worker.assert_called_once_with(tls_request, ("127.0.0.1", 1))
        self.assertTrue(tls_request.closed)
        self.assertTrue(server.request_slots.acquire(blocking=False))

    def test_unexpected_worker_failure_closes_socket_and_releases_slot(self):
        raw_request = FakeConnection()
        tls_request = FakeConnection()
        context = mock.Mock()
        context.wrap_socket.return_value = tls_request
        server = object.__new__(proxy.BoundedThreadingHTTPServer)
        server.tls_context = context
        server.request_slots = threading.BoundedSemaphore(1)
        server.handle_error = mock.Mock()
        self.assertTrue(server.request_slots.acquire(blocking=False))
        with mock.patch.object(proxy, "perform_tls_handshake"):
            with mock.patch.object(
                ThreadingHTTPServer,
                "process_request_thread",
                side_effect=RuntimeError("worker failed"),
            ):
                server.process_request_thread(raw_request, ("127.0.0.1", 1))
        server.handle_error.assert_called_once_with(raw_request, ("127.0.0.1", 1))
        self.assertTrue(tls_request.closed)
        self.assertTrue(server.request_slots.acquire(blocking=False))


class HealthClientTests(unittest.TestCase):
    def test_health_url_is_exact_https_target(self):
        self.assertEqual(
            health.validate_health_url("https://localhost:8940/health"),
            "https://localhost:8940/health",
        )
        invalid = [
            "http://127.0.0.1:8940/health",
            "https://user@localhost:8940/health",
            "https://localhost:8940/other",
            "https://localhost:8940/health?next=x",
            "https://localhost:8940/health#fragment",
            "https://localhost:8940\\@elsewhere.example/health",
            "https://localhost:8940/health\n",
            "https://local%68ost:8940/health",
        ]
        for url in invalid:
            with self.subTest(url=url), self.assertRaises(SystemExit):
                health.validate_health_url(url)

    def test_health_redirect_handler_refuses_redirect(self):
        handler = health.NoRedirect()
        self.assertIsNone(handler.redirect_request(None, None, 302, "Found", {}, "/x"))

    def test_health_rejects_changed_final_url(self):
        context = mock.Mock()
        response = FakeResponse("https://localhost:8940/other")
        opener = CapturingOpener(response)
        with mock.patch.object(health, "read_ca_pem", return_value="PEM"):
            with mock.patch.object(health.ssl, "SSLContext", return_value=context):
                with mock.patch.object(
                    health.urllib.request, "build_opener", return_value=opener
                ):
                    with self.assertRaises(SystemExit):
                        health.main()
        context.load_verify_locations.assert_called_once_with(cadata="PEM")

    def test_health_body_has_absolute_deadline(self):
        class DripResponse:
            length = None
            fp = None

            @staticmethod
            def read1(_limit):
                time.sleep(0.06)
                return b"x"

        with mock.patch.object(health, "HEALTH_BODY_TIMEOUT_SECONDS", 0.1):
            with self.assertRaises(SystemExit):
                health.read_health_body(DripResponse())


class SmokeOriginTests(unittest.TestCase):
    def test_control_requires_https_and_origin_only(self):
        self.assertEqual(
            smoke.validate_origin(
                "https://control.example:9443/",
                name="control",
                allow_loopback_http=False,
            ),
            "https://control.example:9443",
        )
        invalid = [
            "http://127.0.0.1:8940",
            "https://user@control.example",
            "https://control.example/path",
            "https://control.example?query=x",
            "https://control.example\\elsewhere",
            "https://control.example\n.evil",
            "https://control%2eexample",
        ]
        for url in invalid:
            with self.subTest(url=url), self.assertRaises(SystemExit):
                smoke.validate_origin(url, name="control", allow_loopback_http=False)

    def test_edge_cleartext_requires_numeric_loopback(self):
        accepted = [
            "http://127.0.0.1:8931",
            "http://127.255.0.1:8931",
            "http://[::1]:8931",
            "https://edge.example:8931",
        ]
        for url in accepted:
            with self.subTest(url=url):
                self.assertEqual(
                    smoke.validate_origin(url, name="edge", allow_loopback_http=True),
                    url,
                )
        rejected = [
            "http://localhost:8931",
            "http://0.0.0.0:8931",
            "http://192.168.1.2:8931",
            "http://edge.example:8931",
        ]
        for url in rejected:
            with self.subTest(url=url), self.assertRaises(SystemExit):
                smoke.validate_origin(url, name="edge", allow_loopback_http=True)

    def test_origin_mismatch_is_rejected_before_network_request(self):
        opener = mock.Mock()
        with self.assertRaises(SystemExit):
            smoke.request_json(
                "https://other.example/v1/receipts/query",
                expected_origin="https://control.example",
                name="control",
                allow_loopback_http=False,
                opener=opener,
            )
        opener.open.assert_not_called()

    def test_changed_final_target_is_rejected(self):
        response = FakeResponse("https://control.example/other")
        with self.assertRaises(SystemExit):
            smoke.assert_final_url(
                response,
                "https://control.example/health",
                name="control",
                allow_loopback_http=False,
            )

    def test_bearer_token_grammar_rejects_header_ambiguity(self):
        self.assertEqual(
            smoke.validate_token("abc-DEF_123.~+/==", name="edge"),
            "abc-DEF_123.~+/==",
        )
        for token in (
            "",
            "two words",
            "line\nbreak",
            "colon:value",
            "caf\N{LATIN SMALL LETTER E WITH ACUTE}",
        ):
            with self.subTest(token=token), self.assertRaises(SystemExit):
                smoke.validate_token(token, name="edge")


class SmokeTransportTests(unittest.TestCase):
    def test_json_and_sse_reads_have_absolute_deadlines(self):
        class DripServer(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, _format, *_args):
                return

            def do_GET(self):
                if self.path == "/headers":
                    response = (
                        b"HTTP/1.1 200 OK\r\n"
                        b"Content-Length: 2\r\n"
                        b"Connection: close\r\n\r\n{}"
                    )
                    try:
                        for byte in response:
                            self.connection.sendall(bytes([byte]))
                            time.sleep(0.08)
                    except (BrokenPipeError, ConnectionResetError):
                        pass
                    return
                payload = (
                    b'{"value":1}'
                    if self.path == "/json"
                    else b'data: {"jsonrpc":"2.0"}\n\n'
                )
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                try:
                    for byte in payload:
                        self.wfile.write(bytes([byte]))
                        self.wfile.flush()
                        time.sleep(0.08)
                except (BrokenPipeError, ConnectionResetError):
                    pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), DripServer)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        origin = f"http://127.0.0.1:{server.server_port}"
        opener = smoke.build_edge_opener(origin)
        started = time.monotonic()
        try:
            with mock.patch.object(smoke, "REQUEST_TIMEOUT_SECONDS", 0.15):
                with self.assertRaises(SystemExit):
                    smoke.request_json(
                        f"{origin}/headers",
                        expected_origin=origin,
                        name="drip headers",
                        allow_loopback_http=True,
                        opener=opener,
                    )
                with self.assertRaises(SystemExit):
                    smoke.request_json(
                        f"{origin}/json",
                        expected_origin=origin,
                        name="drip JSON",
                        allow_loopback_http=True,
                        opener=opener,
                    )
                request = urllib.request.Request(f"{origin}/sse")
                with opener.open(request, timeout=0.15) as response:
                    with self.assertRaises(SystemExit):
                        smoke.read_sse_json(response)
            self.assertLess(time.monotonic() - started, 1.5)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_edge_opener_ignores_ambient_proxy_credentials_route(self):
        capture = {"proxy": 0, "target": 0, "authorization": None}

        class MaliciousProxy(BaseHTTPRequestHandler):
            def log_message(self, _format, *_args):
                return

            def do_GET(self):
                capture["proxy"] += 1
                capture["authorization"] = self.headers.get("Authorization")
                self.send_response(502)
                self.send_header("Content-Length", "0")
                self.end_headers()

        class TargetServer(BaseHTTPRequestHandler):
            def log_message(self, _format, *_args):
                return

            def do_GET(self):
                capture["target"] += 1
                capture["authorization"] = self.headers.get("Authorization")
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

        proxy_server = ThreadingHTTPServer(("127.0.0.1", 0), MaliciousProxy)
        target_server = ThreadingHTTPServer(("127.0.0.1", 0), TargetServer)
        threads = [
            threading.Thread(target=proxy_server.serve_forever, daemon=True),
            threading.Thread(target=target_server.serve_forever, daemon=True),
        ]
        for thread in threads:
            thread.start()
        try:
            proxy_origin = f"http://127.0.0.1:{proxy_server.server_port}"
            target_origin = f"http://127.0.0.1:{target_server.server_port}"
            proxy_environment = {
                "http_proxy": proxy_origin,
                "HTTP_PROXY": proxy_origin,
                "all_proxy": proxy_origin,
                "ALL_PROXY": proxy_origin,
                "no_proxy": "",
                "NO_PROXY": "",
            }
            with mock.patch.dict(os.environ, proxy_environment, clear=False):
                opener = smoke.build_edge_opener(target_origin)
                request = urllib.request.Request(
                    f"{target_origin}/probe",
                    headers={"Authorization": "Bearer edge-secret"},
                )
                with opener.open(request, timeout=2) as response:
                    self.assertEqual(response.status, 200)
            self.assertEqual(capture["proxy"], 0)
            self.assertEqual(capture["target"], 1)
            self.assertEqual(capture["authorization"], "Bearer edge-secret")
        finally:
            for server in (proxy_server, target_server):
                server.shutdown()
                server.server_close()
            for thread in threads:
                thread.join(timeout=2)

    def test_edge_opener_does_not_follow_or_forward_auth_on_redirect(self):
        capture = {"requests": 0, "authorization": None}

        class RedirectServer(BaseHTTPRequestHandler):
            def log_message(self, _format, *_args):
                return

            def do_GET(self):
                if self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", "/capture")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                capture["requests"] += 1
                capture["authorization"] = self.headers.get("Authorization")
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

        server = ThreadingHTTPServer(("127.0.0.1", 0), RedirectServer)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            origin = f"http://127.0.0.1:{server.server_port}"
            opener = smoke.build_edge_opener(origin)
            request = urllib.request.Request(
                f"{origin}/redirect",
                headers={"Authorization": "Bearer edge-secret"},
            )
            with self.assertRaises(urllib.error.HTTPError) as caught:
                opener.open(request, timeout=2)
            self.assertEqual(caught.exception.code, 302)
            caught.exception.close()
            self.assertEqual(capture["requests"], 0)
            self.assertIsNone(capture["authorization"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_edge_and_dashboard_session_requests_use_separate_credentials(self):
        edge_response = FakeResponse("http://127.0.0.1:8931/mcp")
        edge_opener = CapturingOpener(edge_response)
        response = smoke.post_mcp(
            {"jsonrpc": "2.0"},
            edge_origin="http://127.0.0.1:8931",
            edge_token="edge-secret",
            edge_opener=edge_opener,
        )
        response.close()
        edge_request = edge_opener.requests[0][0]
        self.assertEqual(edge_request.get_header("Authorization"), "Bearer edge-secret")

        control_payload = json.dumps(
            {
                "receipts": [
                    {
                        "id": "receipt-1",
                        "capability_id": "cap-1",
                        "tool_server": smoke.EXPECTED_TOOL_SERVER,
                        "tool_name": smoke.EXPECTED_TOOL_NAME,
                        "decision": {"verdict": "allow"},
                    }
                ]
            }
        ).encode()
        control_response = FakeResponse(
            "https://control.example/v1/receipts/query?"
            "capabilityId=cap-1&toolServer=docker-demo&toolName=echo_text&limit=10",
            payload=control_payload,
        )
        control_opener = CapturingOpener(control_response)
        smoke.query_receipts(
            "cap-1",
            control_origin="https://control.example",
            control_opener=control_opener,
        )
        control_request = control_opener.requests[0][0]
        self.assertIsNone(control_request.get_header("Authorization"))

    def test_dashboard_session_exchange_is_strict_and_cookie_backed(self):
        session_id = "ab" * 32
        set_cookie = (
            f"{smoke.DASHBOARD_SESSION_COOKIE}={session_id}; Path=/; "
            "Max-Age=900; Secure; HttpOnly; SameSite=Strict"
        )
        headers = Message()
        headers.add_header("Set-Cookie", set_cookie)
        headers.add_header("Cache-Control", "no-store")
        payload = {
            "authenticated": True,
            "expiresAt": int(time.time()) + 900,
            "relayReports": {"observability": False},
        }
        login = FakeResponse(
            "https://control.example/v1/dashboard/session",
            payload=json.dumps(payload).encode(),
            headers=headers,
        )
        status = FakeResponse(
            "https://control.example/v1/dashboard/session",
            payload=json.dumps(payload).encode(),
        )
        opener = SequenceOpener([login, status])
        jar = http.cookiejar.CookieJar()
        jar.set_cookie(dashboard_cookie(session_id))

        stale_cookie = smoke.create_dashboard_session(
            control_origin="https://control.example",
            dashboard_read_token="dashboard-read-secret",
            control_opener=opener,
            cookie_jar=jar,
        )

        self.assertEqual(
            stale_cookie, f"{smoke.DASHBOARD_SESSION_COOKIE}={session_id}"
        )
        login_request = opener.requests[0][0]
        self.assertEqual(login_request.get_method(), "POST")
        self.assertEqual(login_request.data, b'{"token":"dashboard-read-secret"}')
        self.assertEqual(login_request.get_header("Content-type"), "application/json")
        self.assertIsNone(login_request.get_header("Authorization"))
        status_request = opener.requests[1][0]
        self.assertEqual(status_request.get_method(), "GET")
        self.assertIsNone(status_request.get_header("Authorization"))

    def test_dashboard_logout_clears_cookie_and_rejects_stale_replay(self):
        session_id = "cd" * 32
        stale_cookie = f"{smoke.DASHBOARD_SESSION_COOKIE}={session_id}"
        jar = http.cookiejar.CookieJar()
        jar.set_cookie(dashboard_cookie(session_id))
        logout_headers = Message()
        logout_headers.add_header("Set-Cookie", smoke.DASHBOARD_SESSION_CLEAR_COOKIE)
        logout_headers.add_header("Cache-Control", "no-store")
        unauthorized_headers = Message()
        unauthorized_headers.add_header("Cache-Control", "no-store")

        class LogoutOpener:
            def __init__(self):
                self.requests = []

            def open(self, request, timeout):
                self.requests.append((request, timeout))
                if len(self.requests) == 1:
                    jar.clear()
                    return FakeResponse(
                        "https://control.example/v1/dashboard/session",
                        payload=b"",
                        status=204,
                        headers=logout_headers,
                    )
                raise urllib.error.HTTPError(
                    request.full_url,
                    401,
                    "Unauthorized",
                    unauthorized_headers,
                    io.BytesIO(b'{}'),
                )

        opener = LogoutOpener()
        smoke.delete_dashboard_session(
            control_origin="https://control.example",
            stale_cookie=stale_cookie,
            control_opener=opener,
            cookie_jar=jar,
        )

        self.assertEqual(opener.requests[0][0].get_method(), "DELETE")
        self.assertIsNone(opener.requests[0][0].get_header("Authorization"))
        self.assertEqual(opener.requests[1][0].get_method(), "GET")
        self.assertEqual(opener.requests[1][0].get_header("Cookie"), stale_cookie)
        self.assertIsNone(opener.requests[1][0].get_header("Authorization"))

    def test_post_mcp_closes_response_when_final_target_changes(self):
        response = FakeResponse("http://127.0.0.1:8931/changed")
        opener = CapturingOpener(response)
        with self.assertRaises(SystemExit):
            smoke.post_mcp(
                {"jsonrpc": "2.0"},
                edge_origin="http://127.0.0.1:8931",
                edge_token="edge-secret",
                edge_opener=opener,
            )
        self.assertTrue(response.closed)

    def test_tls_context_receives_bounded_ca_as_cadata(self):
        context = mock.Mock()
        with mock.patch.object(smoke.ssl, "SSLContext", return_value=context):
            with mock.patch.object(smoke.urllib.request, "build_opener"):
                smoke.build_tls_opener("PEM")
        context.load_verify_locations.assert_called_once_with(cadata="PEM")


class CaFileTests(unittest.TestCase):
    def test_clients_read_regular_ascii_ca(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ca.pem"
            path.write_bytes(b"PEM\n")
            self.assertEqual(smoke.read_ca_pem(path), "PEM\n")
            self.assertEqual(health.read_ca_pem(str(path)), "PEM\n")

    def test_clients_reject_symlink_ca(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target.pem"
            target.write_bytes(b"PEM\n")
            link = Path(directory) / "link.pem"
            link.symlink_to(target)
            with self.assertRaises(SystemExit):
                smoke.read_ca_pem(link)
            with self.assertRaises(SystemExit):
                health.read_ca_pem(str(link))

    def test_clients_reject_non_regular_ca_without_blocking(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ca.pipe"
            os.mkfifo(path)
            with self.assertRaises(SystemExit):
                smoke.read_ca_pem(path)
            with self.assertRaises(SystemExit):
                health.read_ca_pem(str(path))

    def test_clients_bound_ca_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ca.pem"
            path.write_bytes(b"12345")
            with mock.patch.object(smoke, "MAX_CA_BYTES", 4):
                with self.assertRaises(SystemExit):
                    smoke.read_ca_pem(path)
            with mock.patch.object(health, "MAX_CA_BYTES", 4):
                with self.assertRaises(SystemExit):
                    health.read_ca_pem(str(path))


class ToolSchemaTests(unittest.TestCase):
    def test_echo_input_schema_is_closed_and_bounded(self):
        document = json.loads((HERE / "tools.json").read_text(encoding="utf-8"))
        schema = document["tools"][0]["inputSchema"]
        message = schema["properties"]["message"]
        self.assertIs(schema["additionalProperties"], False)
        self.assertEqual(message["minLength"], 1)
        self.assertEqual(message["maxLength"], 4096)


if __name__ == "__main__":
    unittest.main()
