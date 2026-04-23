"""Unit tests for :mod:`chio_streaming.flink`.

These tests exercise the operator classes at their public API surface
with PyFlink mocked out. The whole file is skipped when PyFlink is
not installed, so the chio-streaming test suite stays green on
machines without the Flink extra. Real PyFlink-mini-cluster tests
live outside the unit suite (gated behind ``FLINK_INTEGRATION=1``).
"""

from __future__ import annotations

import importlib
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


def _install_pyflink_surrogate() -> None:
    if "pyflink" in sys.modules and hasattr(sys.modules["pyflink"], "_chio_surrogate"):
        return

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


_install_pyflink_surrogate()

# Reload (or first-load) the flink module now that PyFlink is
# importable, so the real subclasses bind to the surrogate types.
import chio_streaming.flink as flink_module  # noqa: E402

flink_module = importlib.reload(flink_module)

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

    def __init__(self, *, topic: str | None = None) -> None:
        self._topic = topic

    def topic(self) -> str:
        return self._topic or ""

    def timestamp(self) -> int:
        return 1234567890


class FailingChio:
    async def evaluate_tool_call(self, **_kwargs: Any) -> Any:
        raise ChioConnectionError("sidecar down")


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
    subject_extractor: Any = None,
    parameters_extractor: Any = None,
    request_id_prefix: str = "chio-flink",
) -> ChioFlinkConfig:
    kwargs: dict[str, Any] = dict(
        capability_id="cap-flink",
        tool_server="flink://prod",
        client_factory=lambda: chio_client,
        dlq_router_factory=_dlq_router_factory,
        scope_map=scope_map or {"orders": "events:consume:orders"},
        receipt_topic=receipt_topic,
        max_in_flight=4,
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


# ---------------------------------------------------------------------------
# ChioEvaluateFunction (sync ProcessFunction)
# ---------------------------------------------------------------------------


def _run_sync(
    config: ChioFlinkConfig,
    element: Any,
    *,
    topic: str | None = "orders",
) -> tuple[list[Any], list[bytes], list[bytes], FlinkProcessingOutcome | None]:
    fn = ChioEvaluateFunction(config)
    rc = MockRuntimeContext()
    fn.open(rc)
    try:
        ctx = MockProcessContext(topic=topic)
        yields = _drain(fn.process_element(element, ctx))
    finally:
        fn.close()
    main, receipts, dlq = _split_outputs(yields)
    return main, receipts, dlq, None


def test_sync_allow_yields_main_and_receipt() -> None:
    config = _base_config(chio_client=allow_all())
    main, receipts, dlq, _ = _run_sync(config, {"id": 1})
    assert main == [{"id": 1}]
    assert len(receipts) == 1
    assert dlq == []


def test_sync_allow_without_receipt_topic_skips_receipt() -> None:
    config = _base_config(chio_client=allow_all(), receipt_topic=None)
    main, receipts, dlq, _ = _run_sync(config, {"id": 2})
    assert main == [{"id": 2}]
    assert receipts == []
    assert dlq == []


def test_sync_deny_yields_receipt_and_dlq_no_main() -> None:
    chio = deny_all("missing scope", guard="scope-guard", raise_on_deny=False)
    config = _base_config(chio_client=chio)
    main, receipts, dlq, _ = _run_sync(config, {"id": 3})
    assert main == []
    assert len(receipts) == 1
    assert len(dlq) == 1
    import json as _json

    payload = _json.loads(dlq[0].decode("utf-8"))
    assert payload["verdict"] == "deny"
    assert payload["reason"] == "missing scope"


def test_sync_sidecar_error_raises_by_default() -> None:
    config = _base_config(chio_client=FailingChio())
    fn = ChioEvaluateFunction(config)
    fn.open(MockRuntimeContext())
    try:
        with pytest.raises(ChioStreamingError):
            _drain(fn.process_element({"id": 4}, MockProcessContext(topic="orders")))
    finally:
        fn.close()


def test_sync_sidecar_error_fails_closed() -> None:
    config = _base_config(chio_client=FailingChio(), on_sidecar_error="deny")
    main, receipts, dlq, _ = _run_sync(config, {"id": 5})
    assert main == []
    # Both receipt (synthesised deny) and DLQ are emitted.
    assert len(receipts) == 1
    assert len(dlq) == 1
    import json as _json

    payload = _json.loads(dlq[0].decode("utf-8"))
    assert payload["verdict"] == "deny"
    assert payload["receipt"]["metadata"]["chio_streaming_synthetic_marker"] == (
        SYNTHETIC_RECEIPT_MARKER
    )


def test_sync_open_and_close_drive_factories_once() -> None:
    clients: list[Any] = []
    routers: list[DLQRouter] = []

    def client_factory() -> Any:
        client = allow_all()
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
    )
    fn = ChioEvaluateFunction(config)
    fn.open(MockRuntimeContext())
    fn.close()
    assert len(clients) == 1
    assert len(routers) == 1


def test_sync_process_element_before_open_raises() -> None:
    config = _base_config(chio_client=allow_all())
    fn = ChioEvaluateFunction(config)
    with pytest.raises(ChioStreamingConfigError):
        _drain(fn.process_element({"id": 6}, MockProcessContext(topic="orders")))


def test_sync_request_id_prefix_applied() -> None:
    config = _base_config(chio_client=allow_all())
    fn = ChioEvaluateFunction(config)
    fn.open(MockRuntimeContext())
    try:
        yields = _drain(fn.process_element({"id": 7}, MockProcessContext(topic="orders")))
    finally:
        fn.close()
    _, receipts, _ = _split_outputs(yields)
    import json as _json

    payload = _json.loads(receipts[0].decode("utf-8"))
    assert payload["request_id"].startswith("chio-flink-")


def test_sync_custom_request_id_prefix_applied() -> None:
    config = _base_config(chio_client=allow_all(), request_id_prefix="chio-fraud-job")
    fn = ChioEvaluateFunction(config)
    fn.open(MockRuntimeContext())
    try:
        yields = _drain(fn.process_element({"id": 8}, MockProcessContext(topic="orders")))
    finally:
        fn.close()
    _, receipts, _ = _split_outputs(yields)
    import json as _json

    payload = _json.loads(receipts[0].decode("utf-8"))
    assert payload["request_id"].startswith("chio-fraud-job-")


def test_sync_custom_subject_extractor_used() -> None:
    extractor_calls: list[Any] = []

    def extract(element: Any) -> str:
        extractor_calls.append(element)
        return "orders"

    config = _base_config(chio_client=allow_all(), subject_extractor=extract)
    _run_sync(config, {"id": 9}, topic=None)
    assert extractor_calls == [{"id": 9}]


def test_sync_custom_parameters_extractor_used() -> None:
    def params(element: Any) -> dict[str, Any]:
        return {"custom": True, "element_id": element.get("id")}

    config = _base_config(
        chio_client=allow_all(),
        parameters_extractor=params,
    )
    # Should succeed; the operator merges request_id / subject defaults.
    main, receipts, _, _ = _run_sync(config, {"id": 10})
    assert main == [{"id": 10}]
    assert len(receipts) == 1


def test_sync_metrics_registered() -> None:
    config = _base_config(chio_client=allow_all())
    fn = ChioEvaluateFunction(config)
    rc = MockRuntimeContext()
    fn.open(rc)
    try:
        _drain(fn.process_element({"id": 11}, MockProcessContext(topic="orders")))
    finally:
        fn.close()
    assert rc.metrics.counters["evaluations_total"].count == 1
    assert rc.metrics.counters["allow_total"].count == 1
    assert "in_flight" in rc.metrics.gauges


# ---------------------------------------------------------------------------
# ChioAsyncEvaluateFunction
# ---------------------------------------------------------------------------


async def test_async_allow_returns_evaluation_result() -> None:
    config = _base_config(
        chio_client=allow_all(),
        subject_extractor=lambda _e: "orders",
    )
    fn = ChioAsyncEvaluateFunction(config)
    fn.open(MockRuntimeContext())
    try:
        results = await fn.async_invoke({"id": 12})
    finally:
        fn.close()
    assert len(results) == 1
    result = results[0]
    assert isinstance(result, EvaluationResult)
    assert result.allowed is True
    assert result.element == {"id": 12}
    assert result.receipt_bytes is not None
    assert result.dlq_bytes is None


async def test_async_deny_returns_dlq_bytes() -> None:
    chio = deny_all("blocked", guard="scope-guard", raise_on_deny=False)
    config = _base_config(
        chio_client=chio,
        subject_extractor=lambda _e: "orders",
    )
    fn = ChioAsyncEvaluateFunction(config)
    fn.open(MockRuntimeContext())
    try:
        results = await fn.async_invoke({"id": 13})
    finally:
        fn.close()
    assert len(results) == 1
    result = results[0]
    assert result.allowed is False
    assert result.receipt_bytes is not None
    assert result.dlq_bytes is not None
    import json as _json

    payload = _json.loads(result.dlq_bytes.decode("utf-8"))
    assert payload["verdict"] == "deny"


async def test_async_sidecar_error_fails_closed() -> None:
    config = _base_config(
        chio_client=FailingChio(),
        on_sidecar_error="deny",
        subject_extractor=lambda _e: "orders",
    )
    fn = ChioAsyncEvaluateFunction(config)
    fn.open(MockRuntimeContext())
    try:
        results = await fn.async_invoke({"id": 14})
    finally:
        fn.close()
    result = results[0]
    assert result.allowed is False
    assert result.dlq_bytes is not None
    import json as _json

    payload = _json.loads(result.dlq_bytes.decode("utf-8"))
    assert payload["receipt"]["metadata"]["chio_streaming_synthetic_marker"] == (
        SYNTHETIC_RECEIPT_MARKER
    )


async def test_async_sidecar_error_raises_by_default() -> None:
    config = _base_config(
        chio_client=FailingChio(),
        subject_extractor=lambda _e: "orders",
    )
    fn = ChioAsyncEvaluateFunction(config)
    fn.open(MockRuntimeContext())
    try:
        with pytest.raises(ChioStreamingError):
            await fn.async_invoke({"id": 15})
    finally:
        fn.close()


# ---------------------------------------------------------------------------
# ChioVerdictSplitFunction
# ---------------------------------------------------------------------------


def test_split_allow_yields_main_and_receipt() -> None:
    split = ChioVerdictSplitFunction()
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
    split = ChioVerdictSplitFunction()
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
    split = ChioVerdictSplitFunction()
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
    chio = allow_all()
    config = _base_config(chio_client=chio)
    fn = ChioEvaluateFunction(config)
    fn.open(MockRuntimeContext())
    try:
        yields = _drain(fn.process_element({"id": 19}, MockProcessContext(topic="orders")))
    finally:
        fn.close()
    _, receipts, _ = _split_outputs(yields)
    import json as _json

    envelope_payload = _json.loads(receipts[0].decode("utf-8"))
    request_id = envelope_payload["request_id"]
    # Reconstruct the ChioReceipt from the envelope and rebuild to
    # prove byte-exactness of the canonical-JSON layer.
    from chio_sdk.models import ChioReceipt

    receipt = ChioReceipt.model_validate(envelope_payload["receipt"])
    expected = build_envelope(
        request_id=request_id,
        receipt=receipt,
        source_topic="chio-receipts",
    )
    assert receipts[0] == expected.value


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
