"""Unit tests for :class:`ReceiptEnricher`."""

from __future__ import annotations

from arc_sdk.models import ArcReceipt
from conftest import build_receipt

from arc_observability import ReceiptEnricher


class TestEnrichAllowReceipt:
    def test_name_and_run_type(self, allow_receipt: ArcReceipt) -> None:
        payload = ReceiptEnricher().enrich(allow_receipt)
        assert payload.name == "search"
        assert payload.run_type == "tool"

    def test_inputs_are_parameters(self, allow_receipt: ArcReceipt) -> None:
        payload = ReceiptEnricher().enrich(allow_receipt)
        assert payload.inputs == {"q": "hello"}

    def test_outputs_include_decision(self, allow_receipt: ArcReceipt) -> None:
        payload = ReceiptEnricher().enrich(allow_receipt)
        assert payload.outputs["decision"]["verdict"] == "allow"
        assert "evidence" not in payload.outputs  # no evidence attached

    def test_verdict_tag_present(self, allow_receipt: ArcReceipt) -> None:
        payload = ReceiptEnricher().enrich(allow_receipt)
        assert "arc.verdict:allow" in payload.tags
        assert "arc.tool:search" in payload.tags
        assert "arc.server:tools-srv" in payload.tags

    def test_metadata_includes_receipt_id_and_capability(
        self, allow_receipt: ArcReceipt
    ) -> None:
        payload = ReceiptEnricher().enrich(allow_receipt)
        assert payload.metadata["arc.receipt_id"] == "rcpt_001"
        assert payload.metadata["arc.capability_id"] == "cap-abc"
        assert payload.metadata["arc.tool_name"] == "search"
        assert payload.metadata["arc.policy_hash"] == "b" * 64

    def test_trace_context_empty_when_metadata_missing(
        self, allow_receipt: ArcReceipt
    ) -> None:
        payload = ReceiptEnricher().enrich(allow_receipt)
        assert payload.trace_context.is_empty()

    def test_start_and_end_time_fallback_to_timestamp(
        self, allow_receipt: ArcReceipt
    ) -> None:
        payload = ReceiptEnricher().enrich(allow_receipt)
        assert payload.start_time == allow_receipt.timestamp
        assert payload.end_time == allow_receipt.timestamp


class TestEnrichDenyReceipt:
    def test_verdict_is_deny(self, deny_receipt: ArcReceipt) -> None:
        payload = ReceiptEnricher().enrich(deny_receipt)
        assert payload.outputs["decision"]["verdict"] == "deny"
        assert payload.outputs["decision"]["reason"] == "path not allowed"
        assert payload.outputs["decision"]["guard"] == "PathGuard"

    def test_tags_include_guard_and_evidence(self, deny_receipt: ArcReceipt) -> None:
        payload = ReceiptEnricher().enrich(deny_receipt)
        assert "arc.verdict:deny" in payload.tags
        assert "arc.guard:PathGuard" in payload.tags
        assert "arc.evidence:PathGuard:deny" in payload.tags
        assert "arc.evidence:PiiGuard:allow" in payload.tags

    def test_evidence_is_copied_to_outputs(self, deny_receipt: ArcReceipt) -> None:
        payload = ReceiptEnricher().enrich(deny_receipt)
        names = {e["guard_name"] for e in payload.outputs["evidence"]}
        assert names == {"PathGuard", "PiiGuard"}

    def test_trace_context_propagated(self, deny_receipt: ArcReceipt) -> None:
        payload = ReceiptEnricher().enrich(deny_receipt)
        assert payload.trace_context.langsmith_run_id == "run_parent_123"
        assert payload.trace_context.langfuse_trace_id == "trace_parent_xyz"
        assert (
            payload.trace_context.langfuse_parent_observation_id == "obs_parent_456"
        )

    def test_cost_metadata_populates_tag_and_metadata(
        self, deny_receipt: ArcReceipt
    ) -> None:
        payload = ReceiptEnricher().enrich(deny_receipt)
        assert payload.cost_metadata == {"units": 42, "currency": "USD"}
        assert payload.metadata["arc.cost"] == {"units": 42, "currency": "USD"}
        assert "arc.cost:42USD" in payload.tags

    def test_extra_metadata_preserved(self, deny_receipt: ArcReceipt) -> None:
        payload = ReceiptEnricher().enrich(deny_receipt)
        assert payload.metadata["arc.extra.extra_tag"] == "demo"


class TestEnricherOptions:
    def test_default_tags_are_prepended(self, allow_receipt: ArcReceipt) -> None:
        enricher = ReceiptEnricher(default_tags=["env:test", "service:arc"])
        payload = enricher.enrich(allow_receipt)
        assert payload.tags[0] == "env:test"
        assert payload.tags[1] == "service:arc"

    def test_tags_are_deduplicated(self, allow_receipt: ArcReceipt) -> None:
        enricher = ReceiptEnricher(default_tags=["arc.verdict:allow"])
        payload = enricher.enrich(allow_receipt)
        assert payload.tags.count("arc.verdict:allow") == 1

    def test_include_parameters_false_yields_empty_inputs(
        self, allow_receipt: ArcReceipt
    ) -> None:
        enricher = ReceiptEnricher(include_parameters=False)
        payload = enricher.enrich(allow_receipt)
        assert payload.inputs == {}
        # Hash is still captured for correlation.
        assert payload.metadata["arc.parameter_hash"]

    def test_truncate_parameters_replaces_long_values(self) -> None:
        receipt = build_receipt(parameters={"blob": "x" * 500})
        enricher = ReceiptEnricher(truncate_parameters=64)
        payload = enricher.enrich(receipt)
        assert payload.inputs["blob"] == {"truncated": True, "length": 502}

    def test_tool_result_is_attached_to_outputs(self, allow_receipt: ArcReceipt) -> None:
        payload = ReceiptEnricher().enrich(
            allow_receipt,
            tool_result={"rows": [1, 2, 3]},
        )
        assert payload.outputs["result"] == {"rows": [1, 2, 3]}

    def test_error_is_surfaced(self, allow_receipt: ArcReceipt) -> None:
        payload = ReceiptEnricher().enrich(allow_receipt, error="boom")
        assert payload.error == "boom"

    def test_to_dict_round_trips_fields(self, deny_receipt: ArcReceipt) -> None:
        payload = ReceiptEnricher().enrich(deny_receipt)
        as_dict = payload.to_dict()
        assert as_dict["name"] == "write"
        assert as_dict["run_type"] == "tool"
        assert as_dict["cost_metadata"] == {"units": 42, "currency": "USD"}
        assert as_dict["metadata"]["arc.verdict"] == "deny"
        assert as_dict["trace_context"]["langsmith_run_id"] == "run_parent_123"


class TestTimingFromMetadata:
    def test_explicit_timing_wins(self) -> None:
        receipt = build_receipt(
            metadata={"timing": {"started_at": 100, "completed_at": 200}},
            timestamp=500,
        )
        payload = ReceiptEnricher().enrich(receipt)
        assert payload.start_time == 100
        assert payload.end_time == 200

    def test_partial_timing_fills_from_timestamp(self) -> None:
        receipt = build_receipt(
            metadata={"timing": {"started_at": 100}},
            timestamp=500,
        )
        payload = ReceiptEnricher().enrich(receipt)
        assert payload.start_time == 100
        assert payload.end_time == 500
