from __future__ import annotations

import time
import unittest
import urllib.error
from concurrent.futures import CancelledError
from email.utils import formatdate
from io import BytesIO
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import httpx
from chio import ChioQueryError, ChioTransportError, ReceiptQueryClient

FAKE_RECEIPT = {
    "id": "receipt-001",
    "timestamp": 1700000000,
    "capability_id": "cap-001",
    "tool_server": "wrapped-http-mock",
    "tool_name": "echo_text",
    "action": {"parameters": {}, "parameter_hash": "abc123"},
    "decision": {"verdict": "allow"},
    "content_hash": "deadbeef",
    "policy_hash": "cafebabe",
    "kernel_key": "aa" * 32,
    "signature": "bb" * 64,
}

SNAPSHOT = {
    "id": "version:42",
    "throughEntrySeq": 120345,
    "checkpointSeq": None,
    "observedAt": 1760000000123,
    "recertifiedAt": 1759996400456,
}
RETRY_CODE = "receipt_query_snapshot_building"


class ReceiptSnapshotRetryTests(unittest.TestCase):
    def setUp(self):
        self.elapsed = 0.0
        self.delays = []
        self.requests = []
        self.mono = patch("time.monotonic", side_effect=lambda: self.elapsed)
        self.wall = patch("time.time", side_effect=lambda: 1791504000 + self.elapsed)
        self.sleep = patch("time.sleep", side_effect=self.advance)
        for mocked in (self.mono, self.wall, self.sleep):
            mocked.start()
            self.addCleanup(mocked.stop)

    def advance(self, seconds):
        self.delays.append(seconds)
        self.elapsed += seconds

    def client(self, responses, **options):
        def handler(request):
            self.requests.append(request)
            return responses.pop(0)

        return ReceiptQueryClient(
            "http://localhost",
            "tok",
            client=httpx.Client(transport=httpx.MockTransport(handler)),
            **options,
        )

    def error(self, status=503, code=RETRY_CODE, retry_after=None):
        return httpx.Response(
            status,
            json={"error": "snapshot pending", "code": code},
            headers={} if retry_after is None else {"Retry-After": retry_after},
        )

    def test_known_503_codes_retry_then_preserve_exact_snapshot_metadata(self):
        for code in (RETRY_CODE, "receipt_query_snapshot_stale", "receipt_query_busy"):
            with self.subTest(code=code):
                client = self.client(
                    [
                        self.error(code=code, retry_after="2"),
                        httpx.Response(
                            200,
                            json={
                                "totalCount": 0,
                                "receipts": [],
                                "snapshot": SNAPSHOT,
                            },
                        ),
                    ]
                )
                result = client.query()
                self.assertEqual(result["snapshot"], SNAPSHOT)
        self.assertEqual(self.delays, [2.0, 2.0, 2.0])
        self.assertEqual(len(self.requests), 6)

    def test_terminal_status_unknown_and_unavailable_codes_never_retry(self):
        for status, code in (
            (422, "receipt_query_work_budget_exhausted"),
            (500, "receipt_query_snapshot_invalid"),
            (503, "receipt_query_snapshot_unavailable"),
            (503, "unknown"),
            (500, RETRY_CODE),
        ):
            with self.subTest(status=status, code=code):
                with self.assertRaises(ChioQueryError) as caught:
                    self.client([self.error(status, code)]).query()
                self.assertEqual(caught.exception.status, status)
                self.assertEqual(caught.exception.server_code, code)
        self.assertEqual(len(self.requests), 5)
        self.assertEqual(self.delays, [])

    def test_attempt_limit_and_opt_out_preserve_typed_last_error(self):
        for options, count in (
            ({"max_attempts": 3}, 3),
            ({"max_attempts": 1}, 1),
            ({"retry_budget_seconds": 0}, 1),
        ):
            with self.subTest(options=options):
                start = len(self.requests)
                with self.assertRaises(ChioQueryError) as caught:
                    self.client(
                        [self.error(retry_after="0") for _ in range(3)], **options
                    ).query()
                self.assertEqual(caught.exception.server_code, RETRY_CODE)
                self.assertEqual(len(self.requests) - start, count)

    def test_http_date_delay_and_excessive_delay_seconds_date_or_overflow(self):
        date = formatdate(time.time() + 2, usegmt=True)
        result = self.client(
            [
                self.error(retry_after=date),
                httpx.Response(200, json={"totalCount": 0, "receipts": []}),
            ]
        ).query()
        self.assertEqual(result["totalCount"], 0)
        self.assertEqual(self.delays, [2.0])
        for header in ("31", "9" * 5000, formatdate(time.time() + 60, usegmt=True)):
            with self.subTest(header=header):
                start = len(self.requests)
                with self.assertRaises(ChioQueryError) as caught:
                    self.client([self.error(retry_after=header)]).query()
                self.assertEqual(caught.exception.server_code, RETRY_CODE)
                self.assertEqual(len(self.requests) - start, 1)
        self.assertEqual(self.delays, [2.0])

    def test_missing_invalid_header_fallback_stops_at_total_budget(self):
        with self.assertRaises(ChioQueryError) as caught:
            self.client(
                [self.error(), self.error(retry_after="invalid")],
                retry_budget_seconds=1.5,
            ).query()
        self.assertEqual(caught.exception.server_code, RETRY_CODE)
        self.assertEqual(self.delays, [1.0])
        self.assertEqual(len(self.requests), 2)

    def test_malformed_or_oversized_error_keeps_status_without_retries(self):
        for content in (
            b"{broken",
            b'{"code":"receipt_query_busy"}',
            b'{"error":"' + b"x" * 17000 + b'","code":"receipt_query_busy"}',
        ):
            with self.subTest(size=len(content)):
                with self.assertRaises(ChioQueryError) as caught:
                    self.client([httpx.Response(503, content=content)]).query()
                self.assertEqual(caught.exception.status, 503)
                self.assertIsNone(caught.exception.server_code)
        self.assertEqual(len(self.requests), 3)
        self.assertEqual(self.delays, [])

    def test_transport_and_caller_cancellation_are_not_retried(self):
        class Transport:
            def get(self, *_args, **_kwargs):
                raise KeyboardInterrupt("caller stopped")

        with self.assertRaises(KeyboardInterrupt):
            ReceiptQueryClient("http://localhost", "tok", client=Transport()).query()
        self.assertEqual(self.delays, [])

    def test_remaining_budget_caps_injected_transport_timeout(self):
        test_case = self

        class Transport:
            def get(self, _url, *, headers, timeout):
                test_case.assertLessEqual(timeout, 0.5)
                return httpx.Response(
                    503,
                    json={"error": "busy", "code": "receipt_query_busy"},
                    headers={"Retry-After": "1"},
                )

        with self.assertRaises(ChioQueryError):
            ReceiptQueryClient(
                "http://localhost", "tok", client=Transport(), retry_budget_seconds=0.5
            ).query()

    def test_empty_short_pages_with_cursors_and_legacy_servers_continue(self):
        client = self.client(
            [
                httpx.Response(200, json=body)
                for body in (
                    {"totalCount": 2, "nextCursor": 1, "receipts": []},
                    {"totalCount": 2, "nextCursor": 2, "receipts": [FAKE_RECEIPT]},
                    {"totalCount": 2, "nextCursor": None, "receipts": [FAKE_RECEIPT]},
                )
            ]
        )
        self.assertEqual(len(list(client.paginate({"limit": 100}))), 2)
        self.assertEqual(len(self.requests), 3)

    def test_invalid_attempt_counts_and_budgets_are_rejected(self):
        for value in (0, -1, 1.5, float("inf"), float("nan"), True, "3"):
            with self.subTest(attempts=value), self.assertRaises(ValueError):
                ReceiptQueryClient("http://localhost", "tok", max_attempts=value)
        for value in (-1, float("inf"), float("nan"), True, "30", 10**400):
            with self.subTest(budget=value), self.assertRaises((TypeError, ValueError)):
                ReceiptQueryClient(
                    "http://localhost", "tok", retry_budget_seconds=value
                )

    def test_cancellation_while_reading_error_body_is_not_swallowed(self):
        class Response:
            status_code = 503
            closed = False

            @property
            def content(self):
                raise CancelledError("caller stopped")

            def close(self):
                self.closed = True

        response = Response()

        class Transport:
            def get(self, *_args, **_kwargs):
                return response

        with self.assertRaises(CancelledError):
            ReceiptQueryClient("http://localhost", "tok", client=Transport()).query()
        self.assertTrue(response.closed)

    def test_urllib_error_body_read_is_bounded_and_closed_before_retry(self):
        body = BytesIO(b'{"error":"pending","code":"receipt_query_busy"}')
        failure = urllib.error.HTTPError(
            "http://localhost", 503, "busy", {"Retry-After": "0"}, body
        )
        success = BytesIO(b'{"totalCount":0,"receipts":[]}')
        with patch("urllib.request.urlopen", side_effect=[failure, success]) as opened:
            result = ReceiptQueryClient("http://localhost", "tok").query()
        self.assertEqual(result["totalCount"], 0)
        self.assertTrue(body.closed)
        self.assertTrue(success.closed)
        self.assertEqual(opened.call_count, 2)

    def test_urllib_oversized_error_body_has_a_bounded_read(self):
        class TrackedBody(BytesIO):
            consumed = 0

            def read(self, size=-1):
                result = super().read(size)
                self.consumed += len(result)
                return result

        body = TrackedBody(
            b'{"error":"' + b"x" * 20000 + b'","code":"receipt_query_busy"}'
        )
        failure = urllib.error.HTTPError("http://localhost", 503, "busy", {}, body)
        with (
            patch("urllib.request.urlopen", side_effect=failure),
            self.assertRaises(ChioQueryError) as caught,
        ):
            ReceiptQueryClient("http://localhost", "tok").query()
        self.assertEqual(caught.exception.status, 503)
        self.assertIsNone(caught.exception.server_code)
        self.assertLessEqual(body.consumed, 16385)
        self.assertTrue(body.closed)

    def test_transport_failure_after_snapshot_retry_is_not_retried(self):
        calls = []

        def handler(_request):
            calls.append(1)
            if len(calls) == 1:
                return self.error(retry_after="0")
            raise httpx.ConnectError("connection lost")

        client = ReceiptQueryClient(
            "http://localhost",
            "tok",
            client=httpx.Client(transport=httpx.MockTransport(handler)),
        )
        with self.assertRaises(ChioTransportError):
            client.query()
        self.assertEqual(len(calls), 2)


class ReceiptQueryClientTests(unittest.TestCase):
    def test_query_uses_receipt_query_endpoint_and_bearer_auth(self) -> None:
        requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            return httpx.Response(200, json={"totalCount": 0, "receipts": []})

        client = ReceiptQueryClient(
            "http://localhost:8080",
            "tok-123",
            client=httpx.Client(transport=httpx.MockTransport(handler)),
        )

        result = client.query()

        self.assertEqual(result["totalCount"], 0)
        self.assertEqual(
            str(requests[0].url), "http://localhost:8080/v1/receipts/query"
        )
        self.assertEqual(requests[0].headers["Authorization"], "Bearer tok-123")

    def test_query_encodes_filters_as_camel_case_query_parameters(self) -> None:
        requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            return httpx.Response(200, json={"totalCount": 0, "receipts": []})

        client = ReceiptQueryClient(
            "http://localhost:8080/",
            "tok",
            client=httpx.Client(transport=httpx.MockTransport(handler)),
        )

        client.query(
            {
                "capabilityId": "cap-001",
                "toolServer": "wrapped-http-mock",
                "toolName": "echo_text",
                "limit": 10,
                "cursor": 5,
            }
        )

        parsed = urlparse(str(requests[0].url))
        params = parse_qs(parsed.query)
        self.assertEqual(params["capabilityId"], ["cap-001"])
        self.assertEqual(params["toolServer"], ["wrapped-http-mock"])
        self.assertEqual(params["toolName"], ["echo_text"])
        self.assertEqual(params["limit"], ["10"])
        self.assertEqual(params["cursor"], ["5"])

    def test_query_preserves_u64_cost_bounds_and_currency(self) -> None:
        requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            return httpx.Response(200, json={"totalCount": 0, "receipts": []})

        client = ReceiptQueryClient(
            "http://localhost:8080",
            "tok",
            client=httpx.Client(transport=httpx.MockTransport(handler)),
        )

        client.query(
            {
                "minCost": 18446744073709551615,
                "maxCost": 18446744073709551615,
                "costCurrency": "USD",
            }
        )

        params = parse_qs(urlparse(str(requests[0].url)).query)
        self.assertEqual(params["minCost"], ["18446744073709551615"])
        self.assertEqual(params["maxCost"], ["18446744073709551615"])
        self.assertEqual(params["costCurrency"], ["USD"])

    def test_query_returns_typed_response(self) -> None:
        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={"totalCount": 1, "nextCursor": 42, "receipts": [FAKE_RECEIPT]},
            )

        client = ReceiptQueryClient(
            "http://localhost:8080",
            "tok",
            client=httpx.Client(transport=httpx.MockTransport(handler)),
        )

        result = client.query()

        self.assertEqual(result["totalCount"], 1)
        self.assertEqual(result["nextCursor"], 42)
        self.assertEqual(result["receipts"][0]["id"], "receipt-001")

    def test_query_raises_chio_query_error_for_non_success_status(self) -> None:
        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(404, json={"error": "not found"})

        client = ReceiptQueryClient(
            "http://localhost:8080",
            "tok",
            client=httpx.Client(transport=httpx.MockTransport(handler)),
        )

        with self.assertRaises(ChioQueryError) as exc:
            client.query()
        self.assertEqual(exc.exception.status, 404)

    def test_query_raises_chio_transport_error_for_network_failures(self) -> None:
        def handler(_request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("ECONNREFUSED")

        client = ReceiptQueryClient(
            "http://localhost:8080",
            "tok",
            client=httpx.Client(transport=httpx.MockTransport(handler)),
        )

        with self.assertRaises(ChioTransportError):
            client.query()

    def test_paginate_yields_non_empty_pages_until_next_cursor_is_absent(self) -> None:
        pages = iter(
            [
                {
                    "totalCount": 3,
                    "nextCursor": 2,
                    "receipts": [{**FAKE_RECEIPT, "id": "r1"}],
                },
                {
                    "totalCount": 3,
                    "nextCursor": 3,
                    "receipts": [{**FAKE_RECEIPT, "id": "r2"}],
                },
                {"totalCount": 3, "receipts": [{**FAKE_RECEIPT, "id": "r3"}]},
            ]
        )

        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=next(pages))

        client = ReceiptQueryClient(
            "http://localhost:8080",
            "tok",
            client=httpx.Client(transport=httpx.MockTransport(handler)),
        )

        collected = [[receipt["id"] for receipt in page] for page in client.paginate()]

        self.assertEqual(collected, [["r1"], ["r2"], ["r3"]])

    def test_paginate_rejects_repeated_next_cursor(self) -> None:
        pages = iter(
            [
                {
                    "totalCount": 2,
                    "nextCursor": 2,
                    "receipts": [{**FAKE_RECEIPT, "id": "r1"}],
                },
                {
                    "totalCount": 2,
                    "nextCursor": 2,
                    "receipts": [{**FAKE_RECEIPT, "id": "r2"}],
                },
            ]
        )

        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=next(pages))

        client = ReceiptQueryClient(
            "http://localhost:8080",
            "tok",
            client=httpx.Client(transport=httpx.MockTransport(handler)),
        )

        iterator = client.paginate()
        self.assertEqual([receipt["id"] for receipt in next(iterator)], ["r1"])
        with self.assertRaises(ChioQueryError):
            next(iterator)

    def test_paginate_rejects_regressing_next_cursor_before_yield(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            params = parse_qs(urlparse(str(request.url)).query)
            self.assertEqual(params["cursor"], ["5"])
            return httpx.Response(
                200,
                json={
                    "totalCount": 2,
                    "nextCursor": 4,
                    "receipts": [{**FAKE_RECEIPT, "id": "r1"}],
                },
            )

        client = ReceiptQueryClient(
            "http://localhost:8080",
            "tok",
            client=httpx.Client(transport=httpx.MockTransport(handler)),
        )

        iterator = client.paginate({"cursor": 5})
        with self.assertRaises(ChioQueryError):
            next(iterator)


if __name__ == "__main__":
    unittest.main()
