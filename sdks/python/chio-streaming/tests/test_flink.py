"""Unit tests for :mod:`chio_streaming.flink`.

These tests exercise the operator classes at their public API surface
with PyFlink mocked out. The whole file is skipped when PyFlink is
not installed, so the chio-streaming test suite stays green on
machines without the Flink extra. Real PyFlink-mini-cluster tests
live outside the unit suite (gated behind ``FLINK_INTEGRATION=1``).
"""

from __future__ import annotations

import asyncio
import importlib
import json
import sys
import types
from typing import Any

import pytest
from chio_sdk.errors import ChioConnectionError
from chio_sdk.testing import allow_all, deny_all

from chio_streaming.core import SYNTHETIC_RECEIPT_MARKER
from chio_streaming.dlq import DLQRouter
from chio_streaming.errors import ChioStreamingConfigError, ChioStreamingError
from chio_streaming.receipt import build_envelope

# ---------------------------------------------------------------------------
# PyFlink surrogate
# ---------------------------------------------------------------------------
#
# chio_streaming.flink tries to import the real PyFlink at module
# import time. When PyFlink is not installed, the module falls back to
# its own placeholder base classes that raise at __init__ time. For
# unit tests we want the operator classes to be fully instantiable, so
# we inject a tiny surrogate ``pyflink`` package before importing
# chio_streaming.flink and then reload it.
#
# NOTE: the surrogate models only the PyFlink 2.2+ shape (async_invoke
# returning a list, OutputTag(name, type_info)). Pre-2.2 ResultFuture
# behaviour would not be caught here.


_SURROGATE_MODULE_NAMES = (
    "pyflink",
    "pyflink.datastream",
    "pyflink.common",
    "pyflink.common.typeinfo",
)


def _install_pyflink_surrogate() -> bool:
    """Install a surrogate ``pyflink`` package unless one is already present.

    Returns ``True`` if this call installed the surrogate (so teardown
    can remove it), ``False`` if a real PyFlink or a prior surrogate
    was already loaded.
    """
    if "pyflink" in sys.modules and not hasattr(
        sys.modules["pyflink"], "_chio_surrogate"
    ):
        # Real PyFlink is installed; do not shadow it.
        return False
    if "pyflink" in sys.modules and hasattr(sys.modules["pyflink"], "_chio_surrogate"):
        return False

    pyflink = types.ModuleType("pyflink")
    pyflink._chio_surrogate = True  # type: ignore[attr-defined]
    datastream = types.ModuleType("pyflink.datastream")
    common = types.ModuleType("pyflink.common")
    typeinfo = types.ModuleType("pyflink.common.typeinfo")

    class _AsyncFunction:
        def open(self, ctx: Any) -> None:
            pass

        def close(self) -> None:
            pass

        async def async_invoke(self, value: Any) -> list[Any]:
            return []

    class _ProcessFunction:
        def open(self, ctx: Any) -> None:
            pass

        def close(self) -> None:
            pass

        def process_element(self, value: Any, ctx: Any) -> Any:
            return ()

    class _OutputTag:
        def __init__(self, name: str, type_info: Any) -> None:
            self.name = name
            self.type_info = type_info

        def __repr__(self) -> str:  # pragma: no cover - debug aid
            return f"OutputTag({self.name!r})"

        def __eq__(self, other: Any) -> bool:
            return isinstance(other, _OutputTag) and self.name == other.name

        def __hash__(self) -> int:
            return hash(self.name)

    class _Types:
        @staticmethod
        def PICKLED_BYTE_ARRAY() -> str:
            return "pickled-bytes"

        @staticmethod
        def BYTES() -> str:
            return "bytes"

    class _RuntimeContext:  # pragma: no cover - stub
        pass

    class _StreamExecutionEnvironment:  # pragma: no cover - stub
        pass

    datastream.AsyncFunction = _AsyncFunction  # type: ignore[attr-defined]
    datastream.ProcessFunction = _ProcessFunction  # type: ignore[attr-defined]
    datastream.OutputTag = _OutputTag  # type: ignore[attr-defined]
    datastream.RuntimeContext = _RuntimeContext  # type: ignore[attr-defined]
    datastream.StreamExecutionEnvironment = _StreamExecutionEnvironment  # type: ignore[attr-defined]
    typeinfo.Types = _Types  # type: ignore[attr-defined]

    pyflink.datastream = datastream  # type: ignore[attr-defined]
    pyflink.common = common  # type: ignore[attr-defined]
    common.typeinfo = typeinfo  # type: ignore[attr-defined]

    sys.modules["pyflink"] = pyflink
    sys.modules["pyflink.datastream"] = datastream
    sys.modules["pyflink.common"] = common
    sys.modules["pyflink.common.typeinfo"] = typeinfo
    return True


_SURROGATE_OWNED = _install_pyflink_surrogate()

# Reload (or first-load) the flink module now that PyFlink is
# importable, so the real subclasses bind to the surrogate types.
import chio_streaming.flink as flink_module  # noqa: E402

flink_module = importlib.reload(flink_module)


@pytest.fixture(autouse=True, scope="session")
def _pyflink_surrogate_teardown() -> Any:
    """Restore ``sys.modules`` if this file installed the surrogate."""
    yield
    if not _SURROGATE_OWNED:
        return
    for name in _SURROGATE_MODULE_NAMES:
        sys.modules.pop(name, None)


ChioAsyncEvaluateFunction = flink_module.ChioAsyncEvaluateFunction
ChioEvaluateFunction = flink_module.ChioEvaluateFunction
ChioFlinkConfig = flink_module.ChioFlinkConfig
ChioVerdictSplitFunction = flink_module.ChioVerdictSplitFunction
EvaluationResult = flink_module.EvaluationResult
FlinkProcessingOutcome = flink_module.FlinkProcessingOutcome
RECEIPT_TAG_NAME = flink_module.RECEIPT_TAG_NAME
DLQ_TAG_NAME = flink_module.DLQ_TAG_NAME
register_dependencies = flink_module.register_dependencies


# ---------------------------------------------------------------------------
# Mocks
# ---------------------------------------------------------------------------


class MockMetricsGroup:
    """Minimal PyFlink metrics group surface."""

    def __init__(self) -> None:
        self.counters: dict[str, MockCounter] = {}
        self.gauges: dict[str, Any] = {}

    def counter(self, name: str) -> MockCounter:
        counter = MockCounter()
        self.counters[name] = counter
        return counter

    def gauge(self, name: str, supplier: Any) -> Any:
        self.gauges[name] = supplier
        return supplier


class MockCounter:
    def __init__(self) -> None:
        self.count = 0

    def inc(self, delta: int = 1) -> None:
        self.count += delta


class MockRuntimeContext:
    def __init__(self, *, subtask: int = 0, attempt: int = 0) -> None:
        self._subtask = subtask
        self._attempt = attempt
        self.metrics = MockMetricsGroup()

    def get_index_of_this_subtask(self) -> int:
        return self._subtask

    def get_attempt_number(self) -> int:
        return self._attempt

    def get_metrics_group(self) -> MockMetricsGroup:
        return self.metrics


class MockProcessContext:
    """Minimal ``ProcessFunction.Context`` surrogate.

    Records yielded side outputs via the generator protocol the real
    PyFlink uses (``yield (tag, value)``). We do not mock
    ``ctx.output(...)`` at all; the operator yields tuples.
    """

    def __init__(self) -> None:
        pass


class FailingChio:
    async def evaluate_tool_call(self, **_kwargs: Any) -> Any:
        raise ChioConnectionError("sidecar down")


class SpyChio:
    """Records the parameters passed to ``evaluate_tool_call``."""

    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self.calls: list[dict[str, Any]] = []

    async def evaluate_tool_call(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        return await self._inner.evaluate_tool_call(**kwargs)


class SpyClosableChio:
    """``allow_all`` wrapped so ``close()`` invocations are observable."""

    def __init__(self) -> None:
        self._inner = allow_all()
        self.close_calls = 0

    async def evaluate_tool_call(self, **kwargs: Any) -> Any:
        return await self._inner.evaluate_tool_call(**kwargs)

    async def close(self) -> None:
        self.close_calls += 1


class _FailingDLQRouter(DLQRouter):
    """DLQRouter whose ``build_record`` always raises."""

    def build_record(self, **_kwargs: Any) -> Any:  # type: ignore[override]
        raise RuntimeError("build_record failed")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _dlq_router_factory() -> DLQRouter:
    return DLQRouter(default_topic="chio-dlq")


def _base_config(
    *,
    chio_client: Any,
    receipt_topic: str | None = "chio-receipts",
    on_sidecar_error: str = "raise",
    scope_map: dict[str, str] | None = None,
    subject_extractor: Any = lambda _e: "orders",
    parameters_extractor: Any = None,
    request_id_prefix: str = "chio-flink",
    dlq_router_factory: Any = None,
    max_in_flight: int = 4,
) -> ChioFlinkConfig:
    kwargs: dict[str, Any] = dict(
        capability_id="cap-flink",
        tool_server="flink://prod",
        client_factory=lambda: chio_client,
        dlq_router_factory=dlq_router_factory or _dlq_router_factory,
        scope_map=scope_map or {"orders": "events:consume:orders"},
        receipt_topic=receipt_topic,
        max_in_flight=max_in_flight,
        on_sidecar_error=on_sidecar_error,  # type: ignore[arg-type]
        request_id_prefix=request_id_prefix,
    )
    if subject_extractor is not None:
        kwargs["subject_extractor"] = subject_extractor
    if parameters_extractor is not None:
        kwargs["parameters_extractor"] = parameters_extractor
    return ChioFlinkConfig(**kwargs)


def _drain(generator: Any) -> list[Any]:
    return list(generator)


def _split_outputs(
    yields: list[Any],
) -> tuple[list[Any], list[bytes], list[bytes]]:
    main: list[Any] = []
    receipts: list[bytes] = []
    dlq: list[bytes] = []
    for item in yields:
        if isinstance(item, tuple) and len(item) == 2 and hasattr(item[0], "name"):
            tag, payload = item
            if tag.name == RECEIPT_TAG_NAME:
                receipts.append(payload)
            elif tag.name == DLQ_TAG_NAME:
                dlq.append(payload)
            else:  # pragma: no cover - defensive
                pytest.fail(f"unexpected side-output tag {tag.name!r}")
        else:
            main.append(item)
    return main, receipts, dlq


def _run_sync(
    config: ChioFlinkConfig,
    element: Any,
) -> tuple[list[Any], list[bytes], list[bytes], MockRuntimeContext]:
    fn = ChioEvaluateFunction(config)
    rc = MockRuntimeContext()
    fn.open(rc)
    try:
        yields = _drain(fn.process_element(element, MockProcessContext()))
    finally:
        fn.close()
    main, receipts, dlq = _split_outputs(yields)
    return main, receipts, dlq, rc


async def _run_async(
    config: ChioFlinkConfig,
    element: Any,
    *,
    runtime_context: MockRuntimeContext | None = None,
) -> tuple[list[Any], MockRuntimeContext, ChioAsyncEvaluateFunction]:
    fn = ChioAsyncEvaluateFunction(config)
    rc = runtime_context or MockRuntimeContext()
    fn.open(rc)
    try:
        results = await fn.async_invoke(element)
    finally:
        # close() uses run_coroutine_threadsafe when a loop is running,
        # so invoke it from a worker thread (PyFlink's real call site
        # shape) to let the future complete.
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, fn.close)
    return results, rc, fn


# ---------------------------------------------------------------------------
# Config validation
# ---------------------------------------------------------------------------


def test_config_requires_capability_id() -> None:
    with pytest.raises(ChioStreamingConfigError):
        ChioFlinkConfig(
            capability_id="",
            tool_server="flink://prod",
            client_factory=lambda: allow_all(),
            dlq_router_factory=_dlq_router_factory,
        )


def test_config_requires_tool_server() -> None:
    with pytest.raises(ChioStreamingConfigError):
        ChioFlinkConfig(
            capability_id="cap",
            tool_server="",
            client_factory=lambda: allow_all(),
            dlq_router_factory=_dlq_router_factory,
        )


def test_config_requires_positive_max_in_flight() -> None:
    with pytest.raises(ChioStreamingConfigError):
        ChioFlinkConfig(
            capability_id="cap",
            tool_server="flink://prod",
            client_factory=lambda: allow_all(),
            dlq_router_factory=_dlq_router_factory,
            max_in_flight=0,
        )


def test_config_requires_valid_on_sidecar_error() -> None:
    with pytest.raises(ChioStreamingConfigError):
        ChioFlinkConfig(
            capability_id="cap",
            tool_server="flink://prod",
            client_factory=lambda: allow_all(),
            dlq_router_factory=_dlq_router_factory,
            on_sidecar_error="skip",  # type: ignore[arg-type]
        )


def test_config_requires_client_factory() -> None:
    with pytest.raises(ChioStreamingConfigError):
        ChioFlinkConfig(
            capability_id="cap",
            tool_server="flink://prod",
            client_factory=None,  # type: ignore[arg-type]
            dlq_router_factory=_dlq_router_factory,
        )


def test_config_requires_dlq_router_factory() -> None:
    with pytest.raises(ChioStreamingConfigError):
        ChioFlinkConfig(
            capability_id="cap",
            tool_server="flink://prod",
            client_factory=lambda: allow_all(),
            dlq_router_factory=None,  # type: ignore[arg-type]
        )


def test_config_requires_non_empty_request_id_prefix() -> None:
    with pytest.raises(ChioStreamingConfigError):
        ChioFlinkConfig(
            capability_id="cap",
            tool_server="flink://prod",
            client_factory=lambda: allow_all(),
            dlq_router_factory=_dlq_router_factory,
            request_id_prefix="",
        )


def test_config_requires_subject_extractor() -> None:
    # Flink elements have no broker-provided subject; without an
    # extractor resolve_scope would raise on every record and the
    # operator would live in a restart loop. Reject at config time.
    with pytest.raises(ChioStreamingConfigError, match="subject_extractor"):
        ChioFlinkConfig(
            capability_id="cap",
            tool_server="flink://prod",
            client_factory=lambda: allow_all(),
            dlq_router_factory=_dlq_router_factory,
            scope_map={"orders": "events:consume:orders"},
        )


# ---------------------------------------------------------------------------
# ChioEvaluateFunction (sync ProcessFunction)
# ---------------------------------------------------------------------------


def test_sync_allow_yields_main_and_receipt() -> None:
    config = _base_config(chio_client=allow_all())
    main, receipts, dlq, _ = _run_sync(config, {"id": 1})
    assert main == [{"id": 1}]
    assert len(receipts) == 1
    assert dlq == []
    payload = json.loads(receipts[0].decode("utf-8"))
    assert payload["verdict"] == "allow"


def test_sync_allow_without_receipt_topic_skips_receipt() -> None:
    config = _base_config(chio_client=allow_all(), receipt_topic=None)
    main, receipts, dlq, _ = _run_sync(config, {"id": 2})
    assert main == [{"id": 2}]
    assert receipts == []
    assert dlq == []


def test_sync_deny_yields_dlq_only_no_receipt_or_main() -> None:
    # Deny emits only the DLQ record. The deny receipt is embedded in
    # the DLQ payload; emitting a separate deny envelope to the receipt
    # topic would break the "single receipt consumer across all
    # brokers" guarantee (every other broker skips the receipt topic on
    # deny).
    chio = deny_all("missing scope", guard="scope-guard", raise_on_deny=False)
    config = _base_config(chio_client=chio)
    main, receipts, dlq, _ = _run_sync(config, {"id": 3})
    assert main == []
    assert receipts == []
    assert len(dlq) == 1
    payload = json.loads(dlq[0].decode("utf-8"))
    assert payload["verdict"] == "deny"
    assert payload["reason"] == "missing scope"
    # The deny receipt rides inside the DLQ payload for audit.
    assert payload["receipt"]["decision"]["verdict"] == "deny"


@pytest.mark.parametrize(
    ("on_error", "expect_raise"),
    [("raise", True), ("deny", False)],
)
def test_sync_sidecar_error_routing(on_error: str, expect_raise: bool) -> None:
    config = _base_config(chio_client=FailingChio(), on_sidecar_error=on_error)
    if expect_raise:
        fn = ChioEvaluateFunction(config)
        fn.open(MockRuntimeContext())
        try:
            with pytest.raises(ChioStreamingError):
                _drain(fn.process_element({"id": 4}, MockProcessContext()))
        finally:
            fn.close()
        return

    main, receipts, dlq, rc = _run_sync(config, {"id": 5})
    assert main == []
    # Deny path does not publish to the receipt topic; the synthesised
    # deny receipt rides inside the DLQ payload for audit.
    assert receipts == []
    assert len(dlq) == 1

    dlq_payload = json.loads(dlq[0].decode("utf-8"))
    assert dlq_payload["verdict"] == "deny"
    assert dlq_payload["receipt"]["metadata"]["chio_streaming_synthetic_marker"] == (
        SYNTHETIC_RECEIPT_MARKER
    )
    assert rc.metrics.counters["sidecar_errors_total"].count == 1
    assert rc.metrics.counters["deny_total"].count == 1


def test_sync_open_and_close_drive_factories_once() -> None:
    clients: list[SpyClosableChio] = []
    routers: list[DLQRouter] = []

    def client_factory() -> Any:
        client = SpyClosableChio()
        clients.append(client)
        return client

    def router_factory() -> DLQRouter:
        router = DLQRouter(default_topic="chio-dlq")
        routers.append(router)
        return router

    config = ChioFlinkConfig(
        capability_id="cap",
        tool_server="flink://prod",
        client_factory=client_factory,
        dlq_router_factory=router_factory,
        subject_extractor=lambda _e: "orders",
    )
    fn = ChioEvaluateFunction(config)
    fn.open(MockRuntimeContext())
    fn.close()
    assert len(clients) == 1
    assert len(routers) == 1
    assert clients[0].close_calls == 1


def test_sync_process_element_before_open_raises() -> None:
    config = _base_config(chio_client=allow_all())
    fn = ChioEvaluateFunction(config)
    with pytest.raises(ChioStreamingConfigError):
        _drain(fn.process_element({"id": 6}, MockProcessContext()))


@pytest.mark.parametrize(
    "prefix",
    ["chio-flink", "chio-fraud-job"],
)
def test_sync_request_id_prefix_applied(prefix: str) -> None:
    config = _base_config(chio_client=allow_all(), request_id_prefix=prefix)
    fn = ChioEvaluateFunction(config)
    fn.open(MockRuntimeContext())
    try:
        yields = _drain(fn.process_element({"id": 7}, MockProcessContext()))
    finally:
        fn.close()
    _, receipts, _ = _split_outputs(yields)
    payload = json.loads(receipts[0].decode("utf-8"))
    assert payload["request_id"].startswith(f"{prefix}-")


def test_sync_custom_subject_extractor_used() -> None:
    extractor_calls: list[Any] = []

    def extract(element: Any) -> str:
        extractor_calls.append(element)
        return "orders"

    config = _base_config(chio_client=allow_all(), subject_extractor=extract)
    _run_sync(config, {"id": 9})
    assert extractor_calls == [{"id": 9}]


def test_sync_custom_parameters_extractor_reaches_sidecar() -> None:
    def params(element: Any) -> dict[str, Any]:
        return {"custom": True, "element_id": element["id"]}

    spy = SpyChio(allow_all())
    config = _base_config(
        chio_client=spy,
        parameters_extractor=params,
    )
    main, receipts, _, _ = _run_sync(config, {"id": 10})
    assert main == [{"id": 10}]
    assert len(receipts) == 1
    assert len(spy.calls) == 1
    call_params = spy.calls[0]["parameters"]
    assert call_params["custom"] is True
    assert call_params["element_id"] == 10
    # Operator still back-fills request_id and subject for determinism.
    assert call_params["subject"] == "orders"
    assert call_params["request_id"].startswith("chio-flink-")


def test_sync_scope_map_resolution_uses_mapped_tool_name() -> None:
    spy = SpyChio(allow_all())
    config = _base_config(
        chio_client=spy,
        scope_map={"orders": "events:consume:orders-explicit"},
    )
    _run_sync(config, {"id": 11})
    assert spy.calls[0]["tool_name"] == "events:consume:orders-explicit"


def test_sync_scope_map_fallback_uses_default_prefix() -> None:
    spy = SpyChio(allow_all())
    config = _base_config(
        chio_client=spy,
        scope_map={},
        subject_extractor=lambda _e: "unknown-topic",
    )
    _run_sync(config, {"id": 12})
    assert spy.calls[0]["tool_name"] == "events:consume:unknown-topic"


@pytest.mark.parametrize(
    ("chio_factory", "expected_counter"),
    [
        (lambda: allow_all(), "allow_total"),
        (
            lambda: deny_all("denied", guard="g", raise_on_deny=False),
            "deny_total",
        ),
    ],
)
def test_sync_metrics_counter_increments(
    chio_factory: Any, expected_counter: str
) -> None:
    config = _base_config(chio_client=chio_factory())
    _, _, _, rc = _run_sync(config, {"id": 13})
    assert rc.metrics.counters["evaluations_total"].count == 1
    assert rc.metrics.counters[expected_counter].count == 1
    # in_flight gauge is registered and callable; post-drain it is zero.
    assert rc.metrics.gauges["in_flight"]() == 0


def test_sync_metrics_sidecar_errors_counter_increments() -> None:
    config = _base_config(chio_client=FailingChio(), on_sidecar_error="deny")
    _, _, _, rc = _run_sync(config, {"id": 14})
    assert rc.metrics.counters["sidecar_errors_total"].count == 1


# ---------------------------------------------------------------------------
# Sync backpressure and DLQ-publish-failure
# ---------------------------------------------------------------------------


async def test_sync_backpressure_respects_max_in_flight() -> None:
    # The sync operator runs its own event loop in open(); exercise the
    # underlying Slots directly via the shared evaluator so we can assert
    # the semaphore bounds concurrency without fighting the sync loop.
    release = asyncio.Event()
    started = 0
    first_started = asyncio.Event()

    class SlowChio:
        async def evaluate_tool_call(self, **_kwargs: Any) -> Any:
            nonlocal started
            started += 1
            if started == 1:
                first_started.set()
            await release.wait()
            return await allow_all().evaluate_tool_call(**_kwargs)

    config = _base_config(chio_client=SlowChio(), max_in_flight=1)
    evaluator = flink_module._ChioFlinkEvaluator(config)
    evaluator.bind(MockRuntimeContext())

    t1 = asyncio.create_task(evaluator.evaluate({"id": 1}, ctx=None))
    await first_started.wait()
    assert evaluator.slots.in_flight == 1

    t2 = asyncio.create_task(evaluator.evaluate({"id": 2}, ctx=None))
    await asyncio.sleep(0.05)
    assert started == 1, "second evaluation ran before slot released"

    release.set()
    await asyncio.wait_for(t1, timeout=2.0)
    await asyncio.wait_for(t2, timeout=2.0)
    assert started == 2
    assert evaluator.slots.in_flight == 0
    await evaluator.shutdown()


def test_sync_dlq_router_failure_propagates_and_suppresses_emission() -> None:
    # When DLQRouter.build_record raises, the exception propagates and
    # no main / receipt / DLQ emissions happen. Flink's task then fails
    # and the source rewinds; fail-closed is preserved.
    chio = deny_all("denied", guard="g", raise_on_deny=False)
    config = _base_config(
        chio_client=chio,
        dlq_router_factory=lambda: _FailingDLQRouter(default_topic="chio-dlq"),
    )
    fn = ChioEvaluateFunction(config)
    fn.open(MockRuntimeContext())
    try:
        with pytest.raises(RuntimeError, match="build_record failed"):
            _drain(fn.process_element({"id": 1}, MockProcessContext()))
    finally:
        fn.close()
    # After the failure the shared Slots returns to zero (released in finally).
    assert fn._evaluator.slots.in_flight == 0


# ---------------------------------------------------------------------------
# Outcome shape (FlinkProcessingOutcome): driven directly through evaluator
# ---------------------------------------------------------------------------


async def test_evaluator_outcome_populates_subtask_attempt_and_dlq_record() -> None:
    chio = deny_all("denied", guard="g", raise_on_deny=False)
    config = _base_config(chio_client=chio)
    evaluator = flink_module._ChioFlinkEvaluator(config)
    evaluator.bind(MockRuntimeContext(subtask=3, attempt=2))

    outcome = await evaluator.evaluate({"id": 7}, ctx=None)
    assert isinstance(outcome, FlinkProcessingOutcome)
    assert outcome.allowed is False
    assert outcome.subtask_index == 3
    assert outcome.attempt_number == 2
    assert outcome.element == {"id": 7}
    # Deny emits only the DLQ record; no allow-path receipt envelope.
    assert outcome.receipt_bytes is None
    assert outcome.dlq_bytes is not None
    assert outcome.dlq_record is not None
    assert outcome.dlq_record.value == outcome.dlq_bytes
    await evaluator.shutdown()


async def test_evaluator_outcome_allow_has_no_dlq_record() -> None:
    config = _base_config(chio_client=allow_all())
    evaluator = flink_module._ChioFlinkEvaluator(config)
    evaluator.bind(MockRuntimeContext(subtask=1, attempt=0))

    outcome = await evaluator.evaluate({"id": 8}, ctx=None)
    assert outcome.allowed is True
    assert outcome.subtask_index == 1
    assert outcome.attempt_number == 0
    assert outcome.receipt_bytes is not None
    assert outcome.dlq_bytes is None
    assert outcome.dlq_record is None
    await evaluator.shutdown()


# ---------------------------------------------------------------------------
# ChioAsyncEvaluateFunction
# ---------------------------------------------------------------------------


async def test_async_allow_returns_evaluation_result() -> None:
    config = _base_config(chio_client=allow_all())
    results, _, _ = await _run_async(config, {"id": 12})
    assert len(results) == 1
    result = results[0]
    assert isinstance(result, EvaluationResult)
    assert result.allowed is True
    assert result.element == {"id": 12}
    assert result.receipt_bytes is not None
    assert result.receipt_bytes.startswith(b"{")
    assert result.dlq_bytes is None


async def test_async_deny_returns_dlq_bytes_only() -> None:
    chio = deny_all("blocked", guard="scope-guard", raise_on_deny=False)
    config = _base_config(chio_client=chio)
    results, _, _ = await _run_async(config, {"id": 13})
    result = results[0]
    assert result.allowed is False
    # Deny emits only the DLQ bytes; the receipt_bytes side output is
    # reserved for allow-path envelopes to match cross-broker wire
    # semantics.
    assert result.receipt_bytes is None
    assert result.dlq_bytes is not None
    payload = json.loads(result.dlq_bytes.decode("utf-8"))
    assert payload["verdict"] == "deny"
    assert payload["receipt"]["decision"]["verdict"] == "deny"


@pytest.mark.parametrize(
    ("on_error", "expect_raise"),
    [("raise", True), ("deny", False)],
)
async def test_async_sidecar_error_routing(
    on_error: str, expect_raise: bool
) -> None:
    config = _base_config(chio_client=FailingChio(), on_sidecar_error=on_error)
    fn = ChioAsyncEvaluateFunction(config)
    fn.open(MockRuntimeContext())
    try:
        if expect_raise:
            with pytest.raises(ChioStreamingError):
                await fn.async_invoke({"id": 15})
            return

        results = await fn.async_invoke({"id": 14})
        result = results[0]
        assert result.allowed is False
        # Deny path does not emit receipt_bytes; the synthesised deny
        # receipt rides inside the DLQ payload.
        assert result.receipt_bytes is None
        assert result.dlq_bytes is not None

        dlq_payload = json.loads(result.dlq_bytes.decode("utf-8"))
        assert dlq_payload["receipt"]["metadata"][
            "chio_streaming_synthetic_marker"
        ] == SYNTHETIC_RECEIPT_MARKER
    finally:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, fn.close)


async def test_async_close_from_worker_thread_shuts_down_client() -> None:
    # close() is synchronous; calling it from the loop's thread would
    # leave shutdown as fire-and-forget (with a warning log). Production
    # PyFlink drives close() from a worker thread, exercising the
    # one-shot-loop path where we can actually await shutdown.
    spy = SpyClosableChio()
    config = ChioFlinkConfig(
        capability_id="cap",
        tool_server="flink://prod",
        client_factory=lambda: spy,
        dlq_router_factory=_dlq_router_factory,
        scope_map={"orders": "events:consume:orders"},
        receipt_topic="chio-receipts",
        max_in_flight=4,
        subject_extractor=lambda _e: "orders",
    )
    fn = ChioAsyncEvaluateFunction(config)
    fn.open(MockRuntimeContext())
    await fn.async_invoke({"id": 99})
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, fn.close)
    assert spy.close_calls == 1


async def test_async_close_from_loop_thread_raises() -> None:
    # close() is synchronous and cannot await the HTTP client shutdown
    # from the loop's own thread without deadlocking or leaking the
    # pool. Raise a ChioStreamingConfigError rather than either: tell
    # the caller to dispatch close() to a worker thread instead.
    spy = SpyClosableChio()
    config = ChioFlinkConfig(
        capability_id="cap",
        tool_server="flink://prod",
        client_factory=lambda: spy,
        dlq_router_factory=_dlq_router_factory,
        scope_map={"orders": "events:consume:orders"},
        receipt_topic="chio-receipts",
        max_in_flight=4,
        subject_extractor=lambda _e: "orders",
    )
    fn = ChioAsyncEvaluateFunction(config)
    fn.open(MockRuntimeContext())
    await fn.async_invoke({"id": 100})
    with pytest.raises(ChioStreamingConfigError, match="worker thread"):
        fn.close()
    # Cleanup: dispatch the real close to a worker thread so the client
    # is actually shut down before pytest-asyncio tears the loop down.
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, fn.close)
    assert spy.close_calls == 1


async def test_async_receipt_bytes_match_build_envelope_exactly() -> None:
    config = _base_config(chio_client=allow_all())
    results, _, _ = await _run_async(config, {"id": 50})
    result = results[0]
    payload = json.loads(result.receipt_bytes.decode("utf-8"))
    from chio_sdk.models import ChioReceipt

    receipt = ChioReceipt.model_validate(payload["receipt"])
    expected = build_envelope(
        request_id=payload["request_id"],
        receipt=receipt,
        source_topic="orders",
    )
    assert result.receipt_bytes == expected.value


async def test_async_dlq_bytes_match_dlq_router_build_record() -> None:
    chio = deny_all("denied", guard="g", raise_on_deny=False)
    config = _base_config(chio_client=chio)
    results, _, _ = await _run_async(config, {"id": 51})
    result = results[0]
    payload = json.loads(result.dlq_bytes.decode("utf-8"))
    assert payload["verdict"] == "deny"
    # Round-trip through DLQRouter with identical inputs to prove byte parity.
    from chio_sdk.models import ChioReceipt

    receipt = ChioReceipt.model_validate(payload["receipt"])
    router = DLQRouter(default_topic="chio-dlq")
    rebuilt = router.build_record(
        source_topic="orders",
        source_partition=None,
        source_offset=None,
        original_key=None,
        original_value=json.dumps(
            {"id": 51}, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8"),
        request_id=payload["request_id"],
        receipt=receipt,
    )
    assert result.dlq_bytes == rebuilt.value


# ---------------------------------------------------------------------------
# ChioVerdictSplitFunction
# ---------------------------------------------------------------------------


def _split_with_open() -> ChioVerdictSplitFunction:
    split = ChioVerdictSplitFunction()
    split.open(MockRuntimeContext())
    return split


def test_split_allow_yields_main_and_receipt() -> None:
    split = _split_with_open()
    result = EvaluationResult(
        allowed=True,
        element={"id": 16},
        receipt_bytes=b"{}",
        dlq_bytes=None,
    )
    yields = _drain(split.process_element(result, MockProcessContext()))
    main, receipts, dlq = _split_outputs(yields)
    assert main == [{"id": 16}]
    assert receipts == [b"{}"]
    assert dlq == []


def test_split_deny_yields_receipt_and_dlq_no_main() -> None:
    split = _split_with_open()
    result = EvaluationResult(
        allowed=False,
        element={"id": 17},
        receipt_bytes=b'{"verdict":"deny"}',
        dlq_bytes=b'{"verdict":"deny","reason":"x"}',
    )
    yields = _drain(split.process_element(result, MockProcessContext()))
    main, receipts, dlq = _split_outputs(yields)
    assert main == []
    assert receipts == [b'{"verdict":"deny"}']
    assert dlq == [b'{"verdict":"deny","reason":"x"}']


def test_split_allow_without_receipt_bytes_yields_main_only() -> None:
    split = _split_with_open()
    result = EvaluationResult(
        allowed=True,
        element={"id": 18},
        receipt_bytes=None,
        dlq_bytes=None,
    )
    yields = _drain(split.process_element(result, MockProcessContext()))
    main, receipts, dlq = _split_outputs(yields)
    assert main == [{"id": 18}]
    assert receipts == []
    assert dlq == []


# ---------------------------------------------------------------------------
# Envelope byte parity
# ---------------------------------------------------------------------------


def test_receipt_bytes_match_build_envelope_exactly() -> None:
    config = _base_config(chio_client=allow_all())
    _, receipts, _, _ = _run_sync(config, {"id": 19})
    envelope_payload = json.loads(receipts[0].decode("utf-8"))
    request_id = envelope_payload["request_id"]
    from chio_sdk.models import ChioReceipt

    receipt = ChioReceipt.model_validate(envelope_payload["receipt"])
    expected = build_envelope(
        request_id=request_id,
        receipt=receipt,
        source_topic="orders",
    )
    assert receipts[0] == expected.value


def test_sync_dlq_bytes_match_dlq_router_build_record() -> None:
    chio = deny_all("denied", guard="g", raise_on_deny=False)
    config = _base_config(chio_client=chio)
    _, _, dlq, _ = _run_sync(config, {"id": 20})
    payload = json.loads(dlq[0].decode("utf-8"))
    from chio_sdk.models import ChioReceipt

    receipt = ChioReceipt.model_validate(payload["receipt"])
    router = DLQRouter(default_topic="chio-dlq")
    rebuilt = router.build_record(
        source_topic="orders",
        source_partition=None,
        source_offset=None,
        original_key=None,
        original_value=json.dumps(
            {"id": 20}, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8"),
        request_id=payload["request_id"],
        receipt=receipt,
    )
    assert dlq[0] == rebuilt.value


def test_sync_deny_emits_no_receipt_envelope() -> None:
    # Complements the DLQ-byte-parity test: the allow-path receipt
    # stream must stay deny-free so a single consumer works across all
    # brokers. The deny receipt lives inside the DLQ payload.
    chio = deny_all("denied", guard="g", raise_on_deny=False)
    config = _base_config(chio_client=chio)
    _, receipts, dlq, _ = _run_sync(config, {"id": 21})
    assert receipts == []
    dlq_payload = json.loads(dlq[0].decode("utf-8"))
    assert dlq_payload["receipt"]["decision"]["verdict"] == "deny"


# ---------------------------------------------------------------------------
# register_dependencies
# ---------------------------------------------------------------------------


class FakeEnv:
    def __init__(self) -> None:
        self.python_files: list[str] = []
        self.requirements: list[str] = []

    def add_python_file(self, path: str) -> None:
        self.python_files.append(path)

    def set_python_requirements(self, path: str) -> None:
        self.requirements.append(path)


def test_register_dependencies_no_args_is_noop() -> None:
    env = FakeEnv()
    register_dependencies(env)
    assert env.python_files == []
    assert env.requirements == []


def test_register_dependencies_attaches_files_and_requirements() -> None:
    env = FakeEnv()
    register_dependencies(
        env,
        requirements_path="/tmp/requirements.txt",
        python_files=["/tmp/chio_pkg", "/tmp/extra.zip"],
    )
    assert env.python_files == ["/tmp/chio_pkg", "/tmp/extra.zip"]
    assert env.requirements == ["/tmp/requirements.txt"]


def test_register_dependencies_only_requirements() -> None:
    env = FakeEnv()
    register_dependencies(env, requirements_path="/tmp/requirements.txt")
    assert env.python_files == []
    assert env.requirements == ["/tmp/requirements.txt"]


def test_register_dependencies_only_python_files() -> None:
    env = FakeEnv()
    register_dependencies(env, python_files=["/tmp/pkg"])
    assert env.python_files == ["/tmp/pkg"]
    assert env.requirements == []
