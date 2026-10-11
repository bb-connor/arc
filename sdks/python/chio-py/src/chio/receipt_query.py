from __future__ import annotations

import math
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator
from concurrent.futures import CancelledError
from datetime import timezone
from email.utils import parsedate_to_datetime
from typing import Any, TypedDict, cast

from .errors import (
    ChioInvariantError,
    ChioQueryError,
    ChioTransportError,
    parse_json_text,
    parse_json_text_unique_keys,
)


class ReceiptQueryParams(TypedDict, total=False):
    capabilityId: str
    toolServer: str
    toolName: str
    outcome: str
    since: int
    until: int
    minCost: int
    maxCost: int
    costCurrency: str
    agentSubject: str
    cursor: int
    limit: int


class ReceiptQuerySnapshot(TypedDict):
    id: str
    throughEntrySeq: int
    checkpointSeq: int | None
    observedAt: int
    recertifiedAt: int


class ReceiptQueryResponse(TypedDict, total=False):
    totalCount: int
    nextCursor: int | None
    receipts: list[dict[str, Any]]
    snapshot: ReceiptQuerySnapshot


_MAX_ERROR_BYTES = 16 * 1024
_RETRY_CODES = {
    "receipt_query_snapshot_building",
    "receipt_query_snapshot_stale",
    "receipt_query_busy",
}


def _retry_delay(header: str | None) -> float:
    if header is not None:
        value = header.strip()
        if value.isascii() and value.isdigit():
            value = value.lstrip("0") or "0"
            # An overflowing valid delay is excessive, never a fallback delay.
            if len(value) > 300:
                return math.inf
            return float(int(value))
        try:
            date = parsedate_to_datetime(value)
            if date.tzinfo is None:
                date = date.replace(tzinfo=timezone.utc)
            return max(0.0, date.timestamp() - time.time())
        except (ValueError, TypeError, OverflowError):
            pass
    return 1.0


def _http_error(status: int, body: bytes | str | None) -> ChioQueryError:
    code = None
    if isinstance(body, (bytes, str)) and len(body) <= _MAX_ERROR_BYTES:
        try:
            raw = body.encode("utf-8") if isinstance(body, str) else body
            if len(raw) <= _MAX_ERROR_BYTES:
                payload = parse_json_text_unique_keys(raw.decode("utf-8"))
                if (
                    isinstance(payload, dict)
                    and isinstance(payload.get("error"), str)
                    and isinstance(payload.get("code"), str)
                ):
                    code = payload["code"]
        except (UnicodeError, ChioInvariantError, ValueError):
            pass
    return ChioQueryError(
        f"receipt query failed with status {status}", status=status, server_code=code
    )


class ReceiptQueryClient:
    def __init__(
        self,
        base_url: str,
        auth_token: str,
        *,
        client: Any | None = None,
        max_attempts: int = 5,
        retry_budget_seconds: float = 30.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.auth_token = auth_token
        self._client = client
        if (
            isinstance(max_attempts, bool)
            or not isinstance(max_attempts, int)
            or max_attempts < 1
        ):
            raise ValueError("receipt query attempt count must be a positive integer")
        if isinstance(retry_budget_seconds, bool) or not isinstance(
            retry_budget_seconds, (int, float)
        ):
            raise TypeError("receipt query retry budget must be a number")
        try:
            retry_budget_seconds = float(retry_budget_seconds)
        except OverflowError as error:
            raise ValueError(
                "receipt query retry budget must be finite and nonnegative"
            ) from error
        if not math.isfinite(retry_budget_seconds) or retry_budget_seconds < 0:
            raise ValueError(
                "receipt query retry budget must be finite and nonnegative"
            )
        self.max_attempts = max_attempts
        self.retry_budget_seconds = retry_budget_seconds

    def query(self, params: ReceiptQueryParams | None = None) -> ReceiptQueryResponse:
        """Retry transient snapshot outcomes with a monotonic admission budget.

        A positive per-query/page budget bounds retry admission and delays.
        Blocking reads can outlive it: default urllib uses socket inactivity
        timeouts, and injected transports retain their timeout and buffering
        semantics. Late responses are refused when blocking I/O returns, and
        an expired budget admits no further retry. A zero budget permits one
        initial request without retries.
        """
        deadline = time.monotonic() + self.retry_budget_seconds
        last_error = None
        for attempt in range(1, self.max_attempts + 1):
            remaining = deadline - time.monotonic()
            if attempt > 1 and remaining <= 0:
                raise cast(ChioQueryError, last_error)
            timeout = (
                min(5.0, max(0.0, remaining)) if self.retry_budget_seconds else 5.0
            )
            result, retry_after = self._query_once(params, timeout)
            if not isinstance(result, ChioQueryError):
                if self.retry_budget_seconds and time.monotonic() >= deadline:
                    raise ChioTransportError("receipt query deadline expired")
                return result
            last_error = result
            delay = _retry_delay(retry_after)
            if (
                result.status != 503
                or result.server_code not in _RETRY_CODES
                or attempt == self.max_attempts
                or not self.retry_budget_seconds
                or delay >= deadline - time.monotonic()
            ):
                raise result
            time.sleep(delay)
        raise cast(ChioQueryError, last_error)

    def _query_once(
        self, params: ReceiptQueryParams | None, timeout: float
    ) -> tuple[ReceiptQueryResponse | ChioQueryError, str | None]:
        url = self._build_url(params or {})
        headers = {"Authorization": f"Bearer {self.auth_token}"}

        if self._client is not None:
            try:
                response = self._client.get(url, headers=headers, timeout=timeout)
            except CancelledError:
                raise
            except Exception as exc:
                raise ChioTransportError("failed to fetch receipts") from exc
            if response.status_code < 200 or response.status_code >= 300:
                try:
                    body = getattr(response, "content", None)
                    if body is None:
                        body = getattr(response, "text", None)
                    error = _http_error(response.status_code, body)
                    retry_after = (getattr(response, "headers", None) or {}).get(
                        "Retry-After"
                    )
                except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
                    error = _http_error(response.status_code, None)
                    retry_after = None
                finally:
                    close = getattr(response, "close", None)
                    if close is not None:
                        close()
                return error, retry_after
            return self._parse_payload(response.text), None

        request = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return self._parse_payload(response.read().decode("utf-8")), None
        except urllib.error.HTTPError as exc:
            try:
                try:
                    body = exc.read(_MAX_ERROR_BYTES + 1)
                except OSError:
                    body = None
                return _http_error(exc.code, body), exc.headers.get(
                    "Retry-After"
                ) if exc.headers else None
            finally:
                exc.close()
        except OSError as exc:
            raise ChioTransportError("failed to fetch receipts") from exc

    def paginate(
        self, params: ReceiptQueryParams | None = None
    ) -> Iterator[list[dict[str, Any]]]:
        query_params = dict(params or {})
        cursor = cast(int | None, query_params.get("cursor"))
        seen_cursors: set[int] = set()
        while True:
            if cursor is not None:
                if cursor in seen_cursors:
                    raise ChioQueryError(
                        "receipt query pagination stalled: repeated cursor"
                    )
                seen_cursors.add(cursor)
                query_params["cursor"] = cursor
            response = self.query(cast(ReceiptQueryParams, query_params))
            next_cursor = response.get("nextCursor")
            if next_cursor is not None and cursor is not None and next_cursor <= cursor:
                raise ChioQueryError(
                    "receipt query pagination stalled: regressing nextCursor"
                )
            if next_cursor is not None and next_cursor in seen_cursors:
                raise ChioQueryError(
                    "receipt query pagination stalled: repeated nextCursor"
                )
            receipts = response.get("receipts", [])
            if receipts:
                yield receipts
            if next_cursor is None:
                break
            cursor = next_cursor

    def _build_url(self, params: ReceiptQueryParams) -> str:
        query = urllib.parse.urlencode(
            {key: str(value) for key, value in params.items() if value is not None}
        )
        base = f"{self.base_url}/v1/receipts/query"
        return f"{base}?{query}" if query else base

    def _parse_payload(self, payload: str) -> ReceiptQueryResponse:
        parsed = parse_json_text(payload)
        if not isinstance(parsed, dict):
            raise ChioTransportError("receipt query response was not a JSON object")
        return cast(ReceiptQueryResponse, parsed)
