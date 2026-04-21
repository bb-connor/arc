"""Unit tests for :func:`chio_iac.chio_pulumi`.

Pulumi is an optional dependency; these tests exercise the decorator
without importing the Pulumi runtime. Pulumi programs opt into the
plan-review pass by calling :func:`chio_iac.record_resource` (which is a
no-op outside the ``plan`` collection context), so we can fully test
the decorator's gating behaviour against a plain Python callable.
"""

from __future__ import annotations

from typing import Any

import pytest
from chio_sdk.testing import MockChioClient, MockVerdict, allow_all, deny_all

from chio_iac import (
    ChioIACConfigError,
    ChioIACError,
    ChioIACPlanReviewError,
    ResourceTypeAllowlist,
    ResourceTypeDenylist,
    chio_pulumi,
    record_resource,
)

# ---------------------------------------------------------------------------
# (a) Decorator validates its inputs at decoration time
# ---------------------------------------------------------------------------


class TestDecoratorValidation:
    def test_missing_capability_id_raises(self) -> None:
        with pytest.raises(ChioIACConfigError):

            @chio_pulumi(capability_id="")
            def program() -> None:
                return None

    def test_unknown_phase_raises(self) -> None:
        with pytest.raises(ChioIACConfigError):

            @chio_pulumi(capability_id="cap", phase="destroy")  # type: ignore[call-overload]
            def program() -> None:
                return None


# ---------------------------------------------------------------------------
# (b) Plan-phase gating (infra:plan scope)
# ---------------------------------------------------------------------------


class TestPlanPhase:
    def test_plan_phase_evaluates_sidecar_and_runs_program(self) -> None:
        chio = allow_all()
        ran: list[str] = []

        @chio_pulumi(
            capability_id="cap-plan",
            phase="plan",
            chio_client=chio,
        )
        def program() -> str:
            ran.append("ran")
            return "ok"

        result = program()
        assert result == "ok"
        assert ran == ["ran"]
        calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        assert len(calls) == 1
        assert calls[0].tool_name == "pulumi:preview"
        assert calls[0].parameters["scope_label"] == "infra:plan"

    def test_plan_phase_deny_short_circuits_program(self) -> None:
        chio = deny_all(reason="plan scope denied", guard="CapabilityGuard")
        ran: list[str] = []

        @chio_pulumi(
            capability_id="cap",
            phase="plan",
            chio_client=chio,
        )
        def program() -> None:
            ran.append("ran")

        with pytest.raises(ChioIACError) as exc_info:
            program()
        assert exc_info.value.guard == "CapabilityGuard"
        assert ran == []


# ---------------------------------------------------------------------------
# (c) Apply-phase plan-review (infra:apply scope + resource types)
# ---------------------------------------------------------------------------


class TestApplyPhase:
    def test_apply_with_in_scope_resources_is_allowed(self) -> None:
        chio = allow_all()

        @chio_pulumi(
            capability_id="cap-apply",
            phase="apply",
            allowlist=ResourceTypeAllowlist(patterns=["aws:rds/*"]),
            chio_client=chio,
        )
        def program() -> str:
            record_resource(
                "aws:rds/instance:Instance",
                name="db",
                action="create",
            )
            return "applied"

        assert program() == "applied"
        calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        assert len(calls) == 1
        assert calls[0].tool_name == "pulumi:up"
        assert calls[0].parameters["resource_types"] == ["aws:rds/instance:Instance"]
        assert calls[0].parameters["scope_label"] == "infra:apply"

    def test_apply_denies_out_of_scope_resources_before_sidecar(self) -> None:
        chio = allow_all()
        ran: list[str] = []

        @chio_pulumi(
            capability_id="cap-apply",
            phase="apply",
            allowlist=ResourceTypeAllowlist(patterns=["aws:rds/*"]),
            chio_client=chio,
        )
        def program() -> None:
            record_resource("aws:rds/instance:Instance", name="db", action="create")
            record_resource(
                "aws:iam/role:Role", name="db_access", action="create"
            )
            ran.append("ran")

        with pytest.raises(ChioIACPlanReviewError) as exc_info:
            program()

        types = [v["resource_type"] for v in exc_info.value.violations]
        assert "aws:iam/role:Role" in types

        # The program was invoked only in collection mode, which still
        # executes the program body once (appending 'ran'); the sidecar
        # must NOT have been consulted because plan-review denies first.
        assert ran == ["ran"]
        # But no sidecar calls.
        sidecar_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        assert sidecar_calls == []

    def test_apply_denies_destroy_by_default(self) -> None:
        chio = allow_all()

        @chio_pulumi(
            capability_id="cap",
            phase="apply",
            allowlist=ResourceTypeAllowlist(patterns=["aws:rds/*"]),
            chio_client=chio,
        )
        def program() -> None:
            record_resource(
                "aws:rds/instance:Instance", name="old_db", action="delete"
            )

        with pytest.raises(ChioIACPlanReviewError) as exc_info:
            program()
        assert any(
            "destroys are disabled" in v["reason"]
            for v in exc_info.value.violations
        )

    def test_apply_allows_destroy_when_opted_in(self) -> None:
        chio = allow_all()
        ran: list[str] = []

        @chio_pulumi(
            capability_id="cap",
            phase="apply",
            allowlist=ResourceTypeAllowlist(patterns=["aws:rds/*"]),
            allow_destroy=True,
            chio_client=chio,
        )
        def program() -> str:
            record_resource(
                "aws:rds/instance:Instance", name="old_db", action="delete"
            )
            ran.append("ran")
            return "destroyed"

        program()
        # The program ran twice: once in the collection pass, once in
        # the real invocation pass. Both append 'ran'; that's the
        # expected shape.
        assert ran == ["ran", "ran"]

    def test_apply_denylist_beats_allowlist(self) -> None:
        chio = allow_all()

        @chio_pulumi(
            capability_id="cap",
            phase="apply",
            allowlist=ResourceTypeAllowlist(patterns=["aws:*"]),
            denylist=ResourceTypeDenylist(patterns=["aws:iam/*"]),
            chio_client=chio,
        )
        def program() -> None:
            record_resource("aws:iam/role:Role", name="r", action="create")

        with pytest.raises(ChioIACPlanReviewError) as exc_info:
            program()
        assert any(
            "denylist" in v["reason"] for v in exc_info.value.violations
        )

    def test_apply_sidecar_deny_after_plan_review(self) -> None:
        # Plan-review passes but sidecar still denies (e.g. budget
        # guard). The wrapper surfaces ChioIACError.
        chio = deny_all(
            reason="monthly budget exceeded",
            guard="BudgetGuard",
            raise_on_deny=False,
        )

        @chio_pulumi(
            capability_id="cap",
            phase="apply",
            allowlist=ResourceTypeAllowlist(patterns=["aws:*"]),
            chio_client=chio,
        )
        def program() -> None:
            record_resource("aws:rds/instance:Instance", name="db", action="create")

        with pytest.raises(ChioIACError) as exc_info:
            program()
        assert exc_info.value.guard == "BudgetGuard"


# ---------------------------------------------------------------------------
# (d) record_resource outside chio_pulumi is a no-op
# ---------------------------------------------------------------------------


def test_record_resource_outside_decorator_is_noop() -> None:
    # Must not raise even though there is no collection context.
    record_resource("aws:rds/instance:Instance", name="db", action="create")


# ---------------------------------------------------------------------------
# (e) Async programs
# ---------------------------------------------------------------------------


class TestAsyncProgram:
    async def test_async_program_is_gated(self) -> None:
        chio = allow_all()
        ran: list[str] = []

        @chio_pulumi(
            capability_id="cap",
            phase="apply",
            allowlist=ResourceTypeAllowlist(patterns=["aws:rds/*"]),
            chio_client=chio,
        )
        async def program() -> str:
            record_resource("aws:rds/instance:Instance", name="db", action="create")
            ran.append("ran")
            return "ok"

        result = await program()
        assert result == "ok"
        # Collection pass + real pass.
        assert ran == ["ran", "ran"]


# ---------------------------------------------------------------------------
# (f) Tool-name / scope mapping
# ---------------------------------------------------------------------------


class TestToolNameMapping:
    def test_policy_can_branch_on_phase(self) -> None:
        def policy(
            tool_name: str,
            _scope: dict[str, Any],
            _ctx: dict[str, Any],
        ) -> MockVerdict:
            if tool_name == "pulumi:preview":
                return MockVerdict.allow_verdict()
            return MockVerdict.deny_verdict(
                "up scope not granted", guard="CapabilityGuard"
            )

        chio = MockChioClient(policy=policy, raise_on_deny=False)

        @chio_pulumi(
            capability_id="cap",
            phase="plan",
            chio_client=chio,
        )
        def plan_program() -> str:
            return "preview"

        @chio_pulumi(
            capability_id="cap",
            phase="apply",
            allowlist=ResourceTypeAllowlist(patterns=["aws:*"]),
            chio_client=chio,
        )
        def apply_program() -> str:
            record_resource("aws:rds/instance:Instance", name="db", action="create")
            return "up"

        assert plan_program() == "preview"
        with pytest.raises(ChioIACError) as exc_info:
            apply_program()
        assert exc_info.value.subcommand == "apply"
