"""Unit tests for :class:`LangSmithBridge` with a mock LangSmith client."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest
from chio_sdk.models import ChioReceipt

from chio_observability import (
    ChioObservabilityConfigError,
    ChioObservabilityError,
    LangSmithBridge,
    ReceiptEnricher,
)

# ---------------------------------------------------------------------------
# Fake LangSmith client
# ---------------------------------------------------------------------------


@dataclass
class FakeLangSmithClient:
    """Captures arguments passed to :meth:`create_run`."""

    calls: list[dict[str, Any]] = field(default_factory=list)
    fail: bool = False

    def create_run(self, **kwargs: Any) -> None:
        if self.fail:
            raise RuntimeError("mock LangSmith failure")
        self.calls.append(kwargs)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


class TestConfiguration:
    def test_missing_client_and_api_key_raises(self) -> None:
        with pytest.raises(ChioObservabilityConfigError):
            LangSmithBridge(project="p")

    def test_missing_project_raises(self) -> None:
        fake = FakeLangSmithClient()
        with pytest.raises(ChioObservabilityConfigError):
            LangSmithBridge(client=fake, project=None)

    def test_custom_client_bypasses_api_key(self) -> None:
        fake = FakeLangSmithClient()
        bridge = LangSmithBridge(client=fake, project="demo")
        assert bridge.project == "demo"


# ---------------------------------------------------------------------------
# Publish
# ---------------------------------------------------------------------------


class TestPublishAllow:
    def test_run_request_has_tool_run_type(self, allow_receipt: ChioReceipt) -> None:
        fake = FakeLangSmithClient()
        bridge = LangSmithBridge(client=fake, project="demo")
        request = bridge.publish(allow_receipt)
        assert request["run_type"] == "tool"
        assert request["name"] == "search"

    def test_inputs_match_parameters(self, allow_receipt: ChioReceipt) -> None:
        fake = FakeLangSmithClient()
        bridge = LangSmithBridge(client=fake, project="demo")
        request = bridge.publish(allow_receipt)
        assert request["inputs"] == {"q": "hello"}

    def test_outputs_include_decision(self, allow_receipt: ChioReceipt) -> None:
        fake = FakeLangSmithClient()
        bridge = LangSmithBridge(client=fake, project="demo")
        request = bridge.publish(allow_receipt)
        assert request["outputs"]["decision"] == {"verdict": "allow"}

    def test_tags_include_verdict_and_tool(self, allow_receipt: ChioReceipt) -> None:
        fake = FakeLangSmithClient()
        bridge = LangSmithBridge(client=fake, project="demo")
        request = bridge.publish(allow_receipt)
        assert "arc.verdict:allow" in request["tags"]
        assert "arc.tool:search" in request["tags"]

    def test_project_name_propagates(self, allow_receipt: ChioReceipt) -> None:
        fake = FakeLangSmithClient()
        bridge = LangSmithBridge(client=fake, project="observability-demo")
        request = bridge.publish(allow_receipt)
        assert request["project_name"] == "observability-demo"

    def test_extra_metadata_has_chio_fields(self, allow_receipt: ChioReceipt) -> None:
        fake = FakeLangSmithClient()
        bridge = LangSmithBridge(client=fake, project="demo")
        request = bridge.publish(allow_receipt)
        assert request["extra"]["metadata"]["chio.receipt_id"] == "rcpt_001"
        assert request["extra"]["metadata"]["chio.capability_id"] == "cap-abc"

    def test_client_receives_request(self, allow_receipt: ChioReceipt) -> None:
        fake = FakeLangSmithClient()
        bridge = LangSmithBridge(client=fake, project="demo")
        bridge.publish(allow_receipt)
        assert len(fake.calls) == 1
        assert fake.calls[0]["name"] == "search"


class TestPublishDeny:
    def test_deny_propagates_guard_tag(self, deny_receipt: ChioReceipt) -> None:
        fake = FakeLangSmithClient()
        bridge = LangSmithBridge(client=fake, project="demo")
        request = bridge.publish(deny_receipt)
        assert "arc.verdict:deny" in request["tags"]
        assert "arc.guard:PathGuard" in request["tags"]

    def test_deny_attaches_evidence_in_extra(self, deny_receipt: ChioReceipt) -> None:
        fake = FakeLangSmithClient()
        bridge = LangSmithBridge(client=fake, project="demo")
        request = bridge.publish(deny_receipt)
        evidence = request["extra"]["guard_evidence"]
        names = {e["guard_name"] for e in evidence}
        assert names == {"PathGuard", "PiiGuard"}

    def test_deny_includes_cost_metadata(self, deny_receipt: ChioReceipt) -> None:
        fake = FakeLangSmithClient()
        bridge = LangSmithBridge(client=fake, project="demo")
        request = bridge.publish(deny_receipt)
        assert request["extra"]["cost"] == {"units": 42, "currency": "USD"}
        assert "arc.cost:42USD" in request["tags"]

    def test_parent_run_id_used_from_trace_context(
        self, deny_receipt: ChioReceipt
    ) -> None:
        fake = FakeLangSmithClient()
        bridge = LangSmithBridge(client=fake, project="demo")
        request = bridge.publish(deny_receipt)
        assert request["parent_run_id"] == "run_parent_123"
        # The receipt's own run id is reused as the child run id so
        # duplicate polls map to the same LangSmith run rather than
        # creating orphans.
        assert request["id"] == "run_parent_123"


class TestPublishErrors:
    def test_client_failure_wraps_in_observability_error(
        self, allow_receipt: ChioReceipt
    ) -> None:
        fake = FakeLangSmithClient(fail=True)
        bridge = LangSmithBridge(client=fake, project="demo")
        with pytest.raises(ChioObservabilityError) as exc_info:
            bridge.publish(allow_receipt)
        err = exc_info.value
        assert err.backend == "langsmith"
        assert err.receipt_id == "rcpt_001"
        assert err.tool_name == "search"

    def test_tool_result_reaches_outputs(self, allow_receipt: ChioReceipt) -> None:
        fake = FakeLangSmithClient()
        bridge = LangSmithBridge(client=fake, project="demo")
        request = bridge.publish(allow_receipt, tool_result={"rows": 3})
        assert request["outputs"]["result"] == {"rows": 3}

    def test_publish_many_returns_all_requests(
        self, allow_receipt: ChioReceipt, deny_receipt: ChioReceipt
    ) -> None:
        fake = FakeLangSmithClient()
        bridge = LangSmithBridge(client=fake, project="demo")
        requests = bridge.publish_many([allow_receipt, deny_receipt])
        assert len(requests) == 2
        assert len(fake.calls) == 2


class TestCustomEnricher:
    def test_enricher_default_tags_flow_through(self, allow_receipt: ChioReceipt) -> None:
        enricher = ReceiptEnricher(default_tags=["env:staging"])
        fake = FakeLangSmithClient()
        bridge = LangSmithBridge(client=fake, project="demo", enricher=enricher)
        request = bridge.publish(allow_receipt)
        assert "env:staging" in request["tags"]
