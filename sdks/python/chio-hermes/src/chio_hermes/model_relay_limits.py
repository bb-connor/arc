"""Per-relay connection, inbound deadline and faithful evidence budgets."""

from __future__ import annotations

import io
import json
import math
import socket
import threading
from dataclasses import dataclass
from http.server import ThreadingHTTPServer
from time import monotonic
from typing import Any


@dataclass(frozen=True)
class RelayLimits:
    """Defaults are hard ceilings; fixtures/operators may only narrow them."""

    connections: int = 4
    request_seconds: float = 10.0
    events: int = 1024
    event_bytes: int = 1024 * 1024
    record_bytes: int = 4096

    def __post_init__(self) -> None:
        for name, maximum, minimum in [
            ("connections", 4, 1),
            ("events", 1024, 2),
            ("event_bytes", 1024 * 1024, 1),
            ("record_bytes", 4096, 256),
        ]:
            value = getattr(self, name)
            if type(value) is not int or not minimum <= value <= maximum:
                raise ValueError("relay resource limits may only be narrowed")
        if (
            type(self.request_seconds) not in (int, float)
            or not math.isfinite(self.request_seconds)
            or not 0 < self.request_seconds <= 10
        ):
            raise ValueError("relay inbound deadline may only be narrowed")


class RequestDeadline:
    """One monotonic deadline from accept through validated body completion."""

    def __init__(self, seconds: float) -> None:
        self.seconds = seconds
        self.expires = monotonic() + seconds
        self.finished = False

    def remaining(self) -> float:
        if self.finished:
            return self.seconds
        remaining = self.expires - monotonic()
        if remaining <= 0:
            raise TimeoutError("model request headers/body deadline exhausted")
        return remaining

    def finish(self) -> None:
        # Buffered bytes must not bypass the final deadline check. This edge
        # precedes delivery validation, paid admission and upstream forwarding.
        self.remaining()
        self.finished = True


class DeadlineReader(io.RawIOBase):
    def __init__(self, connection: socket.socket, deadline: RequestDeadline) -> None:
        self.connection = connection
        self.deadline = deadline

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int:
        # Each underlying recv gets the remaining absolute time, not a fresh
        # inactivity allowance. Trickle input cannot extend the read phase.
        self.connection.settimeout(self.deadline.remaining())
        return self.connection.recv_into(buffer)


CAPACITY_BODY = b'{"error":{"message":"Model relay capacity exhausted"}}'
REFUSAL = (
    b"HTTP/1.0 503 Service Unavailable\r\nConnection: close\r\n"
    + f"Content-Length: {len(CAPACITY_BODY)}\r\n".encode("ascii")
    + b"Content-Type: application/json\r\n\r\n"
    + CAPACITY_BODY
)


class BoundedRelayServer(ThreadingHTTPServer):
    """Nonqueued admission owns its permit until the entire handler finishes."""

    def __init__(self, address: Any, handler: Any, limits: RelayLimits) -> None:
        self.limits = limits
        self._permits = threading.BoundedSemaphore(limits.connections)
        self._lock = threading.Condition()
        self._accepting = True
        self._deadlines: dict[socket.socket, RequestDeadline] = {}
        super().__init__(address, handler)

    def get_request(self) -> Any:
        connection, address = super().get_request()
        with self._lock:
            self._deadlines[connection] = RequestDeadline(self.limits.request_seconds)
        return connection, address

    def deadline(self, connection: socket.socket) -> RequestDeadline:
        with self._lock:
            return self._deadlines[connection]

    def _release(self, connection: socket.socket) -> None:
        with self._lock:
            self._deadlines.pop(connection, None)
            self._permits.release()
            self._lock.notify_all()

    def process_request(self, request: socket.socket, address: Any) -> None:
        with self._lock:
            admitted = self._accepting and self._permits.acquire(blocking=False)
        if not admitted:
            with self._lock:
                self._deadlines.pop(request, None)
                self._lock.notify_all()
            try:
                request.settimeout(min(self.limits.request_seconds, 0.1))
                request.sendall(REFUSAL)
            except OSError:
                pass
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self._release(request)
            raise

    def process_request_thread(self, request: socket.socket, address: Any) -> None:
        try:
            super().process_request_thread(request, address)
        finally:
            self._release(request)

    def stop_readers(self) -> None:
        with self._lock:
            self._accepting = False
            readers = [
                connection
                for connection, deadline in self._deadlines.items()
                if not deadline.finished
            ]
        for connection in readers:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def drain(self, seconds: float) -> bool:
        with self._lock:
            return self._lock.wait_for(lambda: not self._deadlines, timeout=seconds)


class EvidenceLog:
    """Reserve terminal capacity and worst-case live-record bytes before work.

    The byte budget counts compact ASCII JSON for every field plus list commas
    and brackets. Record count bounds the fixed Python/pretty-print overhead.
    A failed faithful update leaves the prior record and an explicit incomplete
    marker, never a silently shortened reason or silently missing success.
    """

    TERMINAL = {
        "event": "evidence_capacity_exhausted",
        "forwarded": False,
        "reason": "retained model relay evidence is incomplete",
    }
    INCOMPLETE = {
        "event": "capture_incomplete",
        "forwarded": False,
        "reason": "active handlers remained at finalization",
    }

    def __init__(self, limits: RelayLimits, lock: Any) -> None:
        self.limits, self._lock = limits, lock
        self._events: list[dict[str, Any]] = []
        self._pending: set[int] = set()
        self.exhausted = False
        self._used = 2 + self.size(self.TERMINAL)
        if self._used + limits.record_bytes > limits.event_bytes:
            raise ValueError("relay evidence budget cannot reserve a complete record and terminal")

    @staticmethod
    def size(event: dict[str, Any]) -> int:
        return (
            len(
                json.dumps(event, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode(
                    "ascii"
                )
            )
            + 1
        )

    def _exhaust(self, terminal: dict[str, Any] | None = None) -> None:
        if not self.exhausted:
            self.exhausted = True
            self._events.append(dict(self.TERMINAL if terminal is None else terminal))

    def mark_incomplete(self) -> None:
        with self._lock:
            self._exhaust(self.INCOMPLETE)

    def begin(self, event: dict[str, Any]) -> int | None:
        with self._lock:
            if self.exhausted:
                return None
            if (
                len(self._events) >= self.limits.events - 1
                or self._used + self.limits.record_bytes > self.limits.event_bytes
                or self.size(event) > self.limits.record_bytes
            ):
                self._exhaust()
                return None
            index = len(self._events)
            self._events.append(dict(event))
            self._pending.add(index)
            self._used += self.limits.record_bytes
            return index

    def update(self, index: int, **fields: Any) -> bool:
        with self._lock:
            if index not in self._pending:
                raise ValueError("relay evidence record is already terminal")
            event = {**self._events[index], **fields}
            if self.size(event) > self.limits.record_bytes:
                self._exhaust()
                return False
            self._events[index] = event
            return True

    def finish(self, index: int) -> None:
        with self._lock:
            if index in self._pending:
                self._pending.remove(index)
                self._used -= self.limits.record_bytes - self.size(self._events[index])

    @property
    def complete(self) -> bool:
        with self._lock:
            return not self.exhausted and not self._pending

    def snapshot(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(event) for event in self._events]
