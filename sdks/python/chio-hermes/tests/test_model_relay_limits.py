"""Small local controls for the relay's pre-admission resource boundaries."""

import http.client
import io
import json
import socket
import threading
import urllib.request
from contextlib import ExitStack
from http.server import ThreadingHTTPServer

import pytest

from chio_hermes.model_relay import ModelRelay

MODEL = "fixture-model"
TOOLS = {"fixture-tool"}


def post(relay, path, *, body=b"{}", length=None):
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{relay.server.server_port}\r\n"
        f"Authorization: Bearer {relay.token}\r\n"
        f"Content-Length: {len(body) if length is None else length}\r\n"
        "Connection: close\r\n\r\n"
    ).encode() + body


def peer(relay, stack):
    connection = socket.create_connection(("127.0.0.1", relay.server.server_port), timeout=2)
    stack.callback(connection.close)
    return connection


def prohibit_provider(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("refused local input reached the provider")

    monkeypatch.setattr(urllib.request, "build_opener", forbidden)


def exchange(relay, path, body=b"{}", *, token=None, timeout=2):
    client = http.client.HTTPConnection("127.0.0.1", relay.server.server_port, timeout=timeout)
    try:
        client.request(
            "POST",
            path,
            body,
            headers={
                "Authorization": "Bearer " + (relay.token if token is None else token),
            },
        )
        reply = client.getresponse()
        return reply.status, reply.read()
    finally:
        client.close()


def valid_body():
    return json.dumps({"model": MODEL, "messages": [{"role": "user", "content": "text"}]}).encode()


def observe_release(relay, monkeypatch):
    released = threading.Event()
    original = relay.server._release

    def release(connection):
        original(connection)
        released.set()

    monkeypatch.setattr(relay.server, "_release", release)
    return released


def test_connection_capacity_refuses_before_a_fifth_handler_starts(monkeypatch):
    prohibit_provider(monkeypatch)
    entered, condition = [], threading.Condition()
    original = ThreadingHTTPServer.process_request_thread

    def observe(server, request, address):
        with condition:
            entered.append(address)
            condition.notify_all()
        return original(server, request, address)

    monkeypatch.setattr(ThreadingHTTPServer, "process_request_thread", observe)
    with ModelRelay("fixture-secret", MODEL, TOOLS, 1) as relay, ExitStack() as stack:
        for count in range(1, 5):
            peer(relay, stack).sendall(b"POST /v1/chat/completions HTTP/1.1\r\n")
            with condition:
                assert condition.wait_for(lambda count=count: len(entered) >= count, timeout=2)
        rejected = peer(relay, stack)
        rejected.sendall(post(relay, "/refused"))
        response = rejected.recv(4096)
        assert int(response.split()[1]) == 503, (response, len(entered))
        assert len(entered) == 4
        assert relay._remaining == 1


def test_long_refused_metadata_latches_explicit_capture_refusal(monkeypatch):
    prohibit_provider(monkeypatch)
    with ModelRelay("fixture-secret", MODEL, TOOLS, 1) as relay, ExitStack() as stack:
        request = peer(relay, stack)
        request.sendall(post(relay, "/" + "x" * 5120))
        response = request.recv(4096)
        assert int(response.split()[1]) == 503
        assert relay.events[-1]["event"] == "evidence_capacity_exhausted"
        assert relay.events[-1]["forwarded"] is False
        assert relay.evidence_complete is False
        following = peer(relay, stack)
        following.sendall(post(relay, "/v1/chat/completions"))
        assert int(following.recv(4096).split()[1]) == 503
        assert relay._remaining == 1
        assert "fixture-secret" not in json.dumps(relay.events)


def test_partial_body_deadline_refuses_before_delivery_or_paid_admission(monkeypatch):
    prohibit_provider(monkeypatch)
    observations = []
    with (
        ModelRelay("fixture-secret", MODEL, TOOLS, 1, observations.append) as relay,
        ExitStack() as stack,
    ):
        request = peer(relay, stack)
        request.settimeout(11)
        request.sendall(post(relay, "/v1/chat/completions", body=b"{", length=4096))
        response = request.recv(4096)
        assert int(response.split()[1]) == 403
        assert relay.events[-1]["error_type"] == "TimeoutError"
        assert relay.events[-1]["forwarded"] is False
        assert observations == []
        assert relay._remaining == 1


def test_absolute_deadline_resists_drip_and_buffered_completion(monkeypatch):
    from chio_hermes import model_relay_limits as limits

    clock = [0.0]
    monkeypatch.setattr(limits, "monotonic", lambda: clock[0])
    deadline = limits.RequestDeadline(1)

    class Drip:
        timeouts = []
        reads = 0

        def settimeout(self, value):
            self.timeouts.append(value)

        def recv_into(self, buffer):
            self.reads += 1
            buffer[0] = ord("x")
            clock[0] += 0.6
            return 1

    socket = Drip()
    reader = limits.DeadlineReader(socket, deadline)
    assert reader.readinto(bytearray(1)) == 1
    assert reader.readinto(bytearray(1)) == 1
    with pytest.raises(TimeoutError, match="headers/body deadline exhausted"):
        reader.readinto(bytearray(1))
    assert socket.reads == 2
    assert socket.timeouts == pytest.approx([1, 0.4])
    with pytest.raises(TimeoutError, match="headers/body deadline exhausted"):
        deadline.finish()
    assert deadline.finished is False


def test_buffered_request_expiry_stops_actual_callback_paid_and_provider_path(monkeypatch):
    from chio_hermes.model_relay_limits import RequestDeadline

    prohibit_provider(monkeypatch)
    finish = RequestDeadline.finish

    def expired(deadline):
        deadline.expires = 0
        finish(deadline)

    monkeypatch.setattr(RequestDeadline, "finish", expired)
    observations = []
    with ModelRelay("fixture-secret", MODEL, TOOLS, 1, observations.append) as relay:
        status, _ = exchange(relay, "/v1/chat/completions", valid_body())
        assert status == 403
        assert observations == []
        assert relay._remaining == 1
        assert relay.events[-1]["error_type"] == "TimeoutError"
        assert relay.events[-1]["forwarded"] is False


def test_refused_posts_exhaust_record_count_and_stop_further_paid_work(monkeypatch):
    from chio_hermes.model_relay_limits import RelayLimits

    prohibit_provider(monkeypatch)
    with ModelRelay("fixture-secret", MODEL, TOOLS, 1, limits=RelayLimits(events=3)) as relay:
        assert exchange(relay, "/refused")[0] == 403
        assert exchange(relay, "/refused")[0] == 403
        assert exchange(relay, "/refused")[0] == 503
        captured = relay.events
        assert len(captured) == 3
        assert captured[-1]["event"] == "evidence_capacity_exhausted"
        assert (
            captured[:2]
            == [
                {
                    "method": "POST",
                    "path": "/refused",
                    "forwarded": False,
                    "error_type": "ValueError",
                    "reason": "route or authentication refused",
                }
            ]
            * 2
        )
        assert exchange(relay, "/v1/chat/completions", valid_body())[0] == 503
        assert relay.events == captured
        assert relay.evidence_complete is False
        assert relay._remaining == 1


def test_concurrent_active_record_reservations_include_terminal_and_all_updates():
    from chio_hermes.model_relay_limits import EvidenceLog, RelayLimits

    lock = threading.RLock()
    terminal = EvidenceLog.size(EvidenceLog.TERMINAL) + 2
    limits = RelayLimits(events=10, record_bytes=256, event_bytes=terminal + 512)
    log = EvidenceLog(limits, lock)
    ready, release = threading.Barrier(3, timeout=2), threading.Event()
    failures = []

    def record(path):
        try:
            index = log.begin({"method": "POST", "path": path, "forwarded": False})
            assert index is not None
            ready.wait()
            assert release.wait(2)
            assert log.update(index, error_type="ValueError", reason="r" * 100)
            log.finish(index)
        except BaseException as error:
            failures.append(error)

    threads = [threading.Thread(target=record, args=(path,)) for path in ["/first", "/second"]]
    try:
        for thread in threads:
            thread.start()
        ready.wait()
        assert log.complete is False
        assert log.begin({"method": "POST", "path": "/third", "forwarded": False}) is None
    finally:
        release.set()
        for thread in threads:
            thread.join(timeout=3)
    assert not failures, failures
    assert not any(thread.is_alive() for thread in threads)
    captured = log.snapshot()
    assert len(captured) == 3
    assert captured[-1] == EvidenceLog.TERMINAL
    assert sorted(row["path"] for row in captured[:-1]) == ["/first", "/second"]
    assert all(row["reason"] == "r" * 100 for row in captured[:-1])
    assert sum(EvidenceLog.size(row) for row in captured) + 2 <= limits.event_bytes
    assert log.complete is False


def test_oversized_error_update_is_explicitly_incomplete_before_provider(monkeypatch):
    prohibit_provider(monkeypatch)

    def too_large(_observations):
        raise ValueError("r" * 5120)

    with ModelRelay("fixture-secret", MODEL, TOOLS, 1, too_large) as relay:
        assert exchange(relay, "/v1/chat/completions", valid_body())[0] == 503
        assert relay.events[0] == {
            "method": "POST",
            "path": "/v1/chat/completions",
            "forwarded": False,
        }
        assert relay.events[-1]["event"] == "evidence_capacity_exhausted"
        assert relay.evidence_complete is False
        assert relay._remaining == 1


@pytest.mark.parametrize("failure", ["authentication", "malformed", "callback", "upstream"])
def test_connection_permit_releases_after_refusal_or_handler_exception(monkeypatch, failure):
    from chio_hermes.model_relay_limits import RelayLimits

    forwarded = []
    faulty = [failure]

    class Reply(io.BytesIO):
        status = 200
        headers = {"Content-Type": "application/json"}

    class Opener:
        def open(self, request, timeout):
            assert timeout == 60
            forwarded.append(request)
            if faulty[0] == "upstream":
                raise OSError("fixture provider failure")
            return Reply(b'{"ok":true}')

    def callback(_messages):
        if faulty[0] == "callback":
            raise RuntimeError("fixture handler exception")

    monkeypatch.setattr(urllib.request, "build_opener", lambda *_: Opener())
    with ModelRelay(
        "fixture-secret", MODEL, TOOLS, 2, callback, limits=RelayLimits(connections=1)
    ) as relay:
        released = observe_release(relay, monkeypatch)
        body = b"{" if failure == "malformed" else valid_body()
        token = "incorrect" if failure == "authentication" else None
        status, _ = exchange(relay, "/v1/chat/completions", body, token=token)
        assert (
            status
            == {"authentication": 403, "malformed": 403, "callback": 500, "upstream": 502}[failure]
        )
        assert released.wait(2)
        assert relay._remaining == (1 if failure == "upstream" else 2)
        faulty[0] = None
        status, body = exchange(relay, "/v1/chat/completions", valid_body())
        assert status == 200
        assert json.loads(body) == {"ok": True}
        assert len(forwarded) == (2 if failure == "upstream" else 1)
        assert relay._remaining == (0 if failure == "upstream" else 1)


def test_header_deadline_releases_capacity_for_a_later_request(monkeypatch):
    from chio_hermes.model_relay_limits import RelayLimits

    prohibit_provider(monkeypatch)
    with (
        ModelRelay(
            "fixture-secret",
            MODEL,
            TOOLS,
            1,
            limits=RelayLimits(connections=1, request_seconds=0.1),
        ) as relay,
        ExitStack() as stack,
    ):
        released = observe_release(relay, monkeypatch)
        request = peer(relay, stack)
        request.sendall(b"POST /v1/chat/completions HTTP/1.1\r\nHost:")
        assert request.recv(4096) == b""
        assert released.wait(2)
        assert exchange(relay, "/refused")[0] == 403
        assert relay._remaining == 1


def test_client_disconnect_keeps_permit_until_started_upstream_finishes(monkeypatch):
    from chio_hermes.model_relay_limits import RelayLimits

    started, finish = threading.Event(), threading.Event()
    calls = []

    class Reply(io.BytesIO):
        status = 200
        headers = {"Content-Type": "application/json"}

        def read1(self, size):
            started.set()
            assert finish.wait(5)
            return super().read1(size)

    class Opener:
        def open(self, request, timeout):
            calls.append(request)
            return Reply(b'{"ok":true}')

    monkeypatch.setattr(urllib.request, "build_opener", lambda *_: Opener())
    with (
        ModelRelay("fixture-secret", MODEL, TOOLS, 2, limits=RelayLimits(connections=1)) as relay,
        ExitStack() as stack,
    ):
        released = observe_release(relay, monkeypatch)
        request = peer(relay, stack)
        request.sendall(post(relay, "/v1/chat/completions", body=valid_body()))
        try:
            assert started.wait(2)
            request.shutdown(socket.SHUT_RDWR)
            request.close()
            assert exchange(relay, "/refused")[0] == 503
            assert not released.is_set()
            assert relay._remaining == 1
            assert len(calls) == 1
        finally:
            finish.set()
        assert released.wait(2)
        assert exchange(relay, "/refused")[0] == 403
        assert relay._remaining == 1


def test_healthy_finalization_is_idempotent_and_does_not_charge_refused_input(monkeypatch):
    prohibit_provider(monkeypatch)
    with ModelRelay("fixture-secret", MODEL, TOOLS, 1) as relay:
        assert exchange(relay, "/refused")[0] == 403
        assert relay.finalize_capture() is True
        captured = relay.events
        assert relay.finalize_capture() is True
        assert relay.events == captured
        assert relay._remaining == 1
        with pytest.raises(OSError):
            socket.create_connection(("127.0.0.1", relay.server.server_port), timeout=0.2)


@pytest.mark.parametrize("phase", ["delivery", "preparation", "started"])
def test_finalization_stops_new_work_and_retains_started_reconciliation(monkeypatch, phase):
    entered, finish = threading.Event(), threading.Event()
    calls, outcomes = [], []

    class Reply(io.BytesIO):
        status = 200
        headers = {"Content-Type": "application/json"}

        def read1(self, size):
            entered.set()
            assert finish.wait(5)
            return super().read1(size)

    class Opener:
        def __init__(self):
            if phase == "preparation":
                entered.set()
                assert finish.wait(5)

        def open(self, request, timeout):
            calls.append(request)
            return Reply(b'{"ok":true}')

    def callback(_observations):
        if phase == "delivery":
            entered.set()
            assert finish.wait(5)

    monkeypatch.setattr(urllib.request, "build_opener", lambda *_: Opener())
    with ModelRelay("fixture-secret", MODEL, TOOLS, 1, callback) as relay:
        released = observe_release(relay, monkeypatch)

        def request():
            try:
                outcomes.append(exchange(relay, "/v1/chat/completions", valid_body(), timeout=5))
            except BaseException as error:
                outcomes.append(error)

        worker = threading.Thread(target=request)
        worker.start()
        try:
            assert entered.wait(2)
            assert relay.finalize_capture() is False
            assert relay.evidence_complete is False
            assert relay.events[-1]["event"] == "capture_incomplete"
            assert not released.is_set()
            assert len(calls) == (1 if phase == "started" else 0)
            assert relay._remaining == (1 if phase == "delivery" else 0)
        finally:
            finish.set()
            worker.join(timeout=3)
        assert not worker.is_alive()
        assert released.wait(2)
        assert len(outcomes) == 1
        assert not isinstance(outcomes[0], BaseException), outcomes
        assert outcomes[0][0] == (200 if phase == "started" else 503)
        assert len(calls) == (1 if phase == "started" else 0)
        assert relay._remaining == (1 if phase == "delivery" else 0)
        assert relay.finalize_capture() is False
        assert relay.evidence_complete is False


@pytest.mark.parametrize(
    "field,value",
    [
        ("connections", 5),
        ("request_seconds", 11),
        ("request_seconds", float("nan")),
        ("events", 1025),
        ("event_bytes", 1024 * 1024 + 1),
        ("record_bytes", 4097),
    ],
)
def test_resource_ceiling_cannot_be_widened(field, value):
    from chio_hermes.model_relay_limits import RelayLimits

    with pytest.raises(ValueError):
        RelayLimits(**{field: value})
