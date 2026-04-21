"""Unit tests for :class:`LangFuseBridge` with a mock LangFuse client."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest
from chio_sdk.models import ChioReceipt

from chio_observability import (
    ChioObservabilityConfigError,
    ChioObservabilityError,
    LangFuseBridge,
)

# ---------------------------------------------------------------------------
# Fake LangFuse client
# ---------------------------------------------------------------------------


@dataclass
class FakeLangFuseClient:
    """Captures arguments passed to :meth:`span`, :meth:`trace`, :meth:`flush`."""

    spans: list[dict[str, Any]] = field(default_factory=list)
    traces: list[dict[str, Any]] = field(default_factory=list)
    flushes: int = 0
    fail_span: bool = False
    fail_trace: bool = False

    def trace(self, **kwargs: Any) -> None:
        if self.fail_trace:
            raise RuntimeError("mock LangFuse trace failure")
        self.traces.append(kwargs)

    def span(self, **kwargs: Any) -> None:
        if self.fail_span:
            raise RuntimeError("mock LangFuse span failure")
        self.spans.append(kwargs)

    def flush(self) -> None:
        self.flushes += 1


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


class TestConfiguration:
    def test_missing_credentials_raises(self) -> None:
        with pytest.raises(ChioObservabilityConfigError):
            LangFuseBridge(secret_key="s", host="https://lf.example")

    def test_missing_secret_raises(self) -> None:
        with pytest.raises(ChioObservabilityConfigError):
            LangFuseBridge(public_key="pk", host="https://lf.example")

    def test_missing_host_raises(self) -> None:
        with pytest.raises(ChioObservabilityConfigError):
            LangFuseBridge(public_key="pk", secret_key="sk")

    def test_custom_client_bypasses_credentials(self) -> None:
        fake = FakeLangFuseClient()
        bridge = LangFuseBridge(client=fake)
        assert bridge.enricher is not None


# ---------------------------------------------------------------------------
# Publish allow
# ---------------------------------------------------------------------------


class TestPublishAllow:
    def test_creates_trace_when_no_trace_context(
        self, allow_receipt: ChioReceipt
    ) -> None:
        fake = FakeLangFuseClient()
        bridge = LangFuseBridge(client=fake)
        bridge.publish(allow_receipt)
        assert len(fake.traces) == 1
        assert fake.traces[0]["name"] == "chio.receipt.search"

    def test_span_attaches_to_synthetic_trace(
        self, allow_receipt: ChioReceipt
    ) -> None:
        fake = FakeLangFuseClient()
        bridge = LangFuseBridge(client=fake)
        span_kwargs = bridge.publish(allow_receipt)
        assert span_kwargs["trace_id"] == fake.traces[0]["id"]

    def test_allow_level_is_default(self, allow_receipt: ChioReceipt) -> None:
        fake = FakeLangFuseClient()
        bridge = LangFuseBridge(client=fake)
        span_kwargs = bridge.publish(allow_receipt)
        assert span_kwargs["level"] == "DEFAULT"
        assert "status_message" not in span_kwargs

    def test_inputs_are_parameters(self, allow_receipt: ChioReceipt) -> None:
        fake = FakeLangFuseClient()
        bridge = LangFuseBridge(client=fake)
        span_kwargs = bridge.publish(allow_receipt)
        assert span_kwargs["input"] == {"q": "hello"}

    def test_metadata_has_chio_fields(self, allow_receipt: ChioReceipt) -> None:
        fake = FakeLangFuseClient()
        bridge = LangFuseBridge(client=fake)
        span_kwargs = bridge.publish(allow_receipt)
        assert span_kwargs["metadata"]["chio.receipt_id"] == "rcpt_001"
        assert span_kwargs["metadata"]["chio.capability_id"] == "cap-abc"


# ---------------------------------------------------------------------------
# Publish deny
# ---------------------------------------------------------------------------


class TestPublishDeny:
    def test_uses_trace_context_from_receipt(
        self, deny_receipt: ChioReceipt
    ) -> None:
        fake = FakeLangFuseClient()
        bridge = LangFuseBridge(client=fake)
        span_kwargs = bridge.publish(deny_receipt)
        # Existing trace id is re-used, so we never call trace() for
        # context that the agent already established.
        assert fake.traces == []
        assert span_kwargs["trace_id"] == "trace_parent_xyz"
        assert span_kwargs["parent_observation_id"] == "obs_parent_456"

    def test_deny_level_is_error(self, deny_receipt: ChioReceipt) -> None:
        fake = FakeLangFuseClient()
        bridge = LangFuseBridge(client=fake)
        span_kwargs = bridge.publish(deny_receipt)
        assert span_kwargs["level"] == "ERROR"
        assert span_kwargs["status_message"] == "path not allowed"

    def test_evidence_in_metadata(self, deny_receipt: ChioReceipt) -> None:
        fake = FakeLangFuseClient()
        bridge = LangFuseBridge(client=fake)
        span_kwargs = bridge.publish(deny_receipt)
        names = {e["guard_name"] for e in span_kwargs["metadata"]["chio.evidence"]}
        assert names == {"PathGuard", "PiiGuard"}

    def test_cost_metadata_preserved(self, deny_receipt: ChioReceipt) -> None:
        fake = FakeLangFuseClient()
        bridge = LangFuseBridge(client=fake)
        span_kwargs = bridge.publish(deny_receipt)
        assert span_kwargs["metadata"]["chio.cost"] == {"units": 42, "currency": "USD"}

    def test_tags_include_verdict_tool_guard(
        self, deny_receipt: ChioReceipt
    ) -> None:
        fake = FakeLangFuseClient()
        bridge = LangFuseBridge(client=fake)
        span_kwargs = bridge.publish(deny_receipt)
        tags = set(span_kwargs["tags"])
        assert {"arc.verdict:deny", "arc.tool:write", "arc.guard:PathGuard"} <= tags
        assert "arc.cost:42USD" in tags


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


class TestErrorHandling:
    def test_span_failure_raises_observability_error(
        self, allow_receipt: ChioReceipt
    ) -> None:
        fake = FakeLangFuseClient(fail_span=True)
        bridge = LangFuseBridge(client=fake)
        with pytest.raises(ChioObservabilityError) as exc_info:
            bridge.publish(allow_receipt)
        assert exc_info.value.backend == "langfuse"
        assert exc_info.value.receipt_id == "rcpt_001"

    def test_trace_failure_raises_observability_error(
        self, allow_receipt: ChioReceipt
    ) -> None:
        fake = FakeLangFuseClient(fail_trace=True)
        bridge = LangFuseBridge(client=fake)
        with pytest.raises(ChioObservabilityError) as exc_info:
            bridge.publish(allow_receipt)
        assert exc_info.value.backend == "langfuse"

    def test_flush_forwards_to_client(self, allow_receipt: ChioReceipt) -> None:
        fake = FakeLangFuseClient()
        bridge = LangFuseBridge(client=fake)
        bridge.publish(allow_receipt)
        bridge.flush()
        assert fake.flushes == 1

    def test_publish_many(self, allow_receipt: ChioReceipt, deny_receipt: ChioReceipt) -> None:
        fake = FakeLangFuseClient()
        bridge = LangFuseBridge(client=fake)
        results = bridge.publish_many([allow_receipt, deny_receipt])
        assert len(results) == 2
        assert len(fake.spans) == 2
