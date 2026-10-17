"""Unit tests for ChioActivityInterceptor on the mediated caller-delivery route.

The tests exercise the inbound-interceptor path without a live Temporal
cluster or sidecar: we build an :class:`ExecuteActivityInput`, construct an
:class:`activity.Info`, patch ``activity.info()`` to return it, and invoke
``_ChioInboundInterceptor.execute_activity`` directly against
:class:`MediatedContractClient`. One test drives the real
:class:`chio_sdk.client.ChioClient` over HTTP with ``respx``.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
import respx
from _mediated_contract import (
    CONTROL_TOKEN,
    FIXED_NOW_MS,
    MediatedContractClient,
    activity_context,
    contract_interceptor,
)
from chio_sdk.client import ChioClient
from chio_sdk.errors import (
    ChioConnectionError,
    ChioDeniedError,
    ChioTimeoutError,
    ChioValidationError,
)
from chio_sdk.models import (
    CapabilityToken,
    ChioScope,
    Operation,
    ToolGrant,
)
from temporalio import activity
from temporalio.converter import DataConverter
from temporalio.exceptions import ApplicationError

from chio_temporal import (
    ChioActivityInterceptor,
    ChioTemporalConfigError,
    WorkflowGrant,
)
from chio_temporal.interceptor import (
    DENIED_ERROR_TYPE,
    SIDECAR_ERROR_TYPE,
    _ChioInboundInterceptor,
    _deny_receipt_from_error,
    _is_sha256_hex,
)

INVOKE_OPERATION = getattr(Operation, "INVOKE", Operation.invoke)


def _scope_for_tools(*tool_names: str, server_id: str = "srv") -> ChioScope:
    grants = [
        ToolGrant(
            server_id=server_id,
            tool_name=name,
            operations=[INVOKE_OPERATION],
        )
        for name in tool_names
    ]
    return ChioScope(grants=grants)


def _default_info(
    *,
    activity_type: str,
    activity_id: str = "act-1",
    workflow_id: str = "wf-1",
    workflow_run_id: str = "run-1",
    attempt: int = 1,
) -> activity.Info:
    """Build a minimal :class:`activity.Info` for direct interceptor testing."""
    utc_zero = datetime.fromtimestamp(0, tz=UTC)
    import temporalio.common as temporal_common

    return activity.Info(
        activity_id=activity_id,
        activity_type=activity_type,
        attempt=attempt,
        current_attempt_scheduled_time=utc_zero,
        heartbeat_details=[],
        heartbeat_timeout=None,
        is_local=False,
        namespace="default",
        schedule_to_close_timeout=timedelta(seconds=10),
        scheduled_time=utc_zero,
        start_to_close_timeout=timedelta(seconds=10),
        started_time=utc_zero,
        task_queue="tq",
        task_token=b"tt",
        workflow_id=workflow_id,
        workflow_namespace="default",
        workflow_run_id=workflow_run_id,
        workflow_type="TestWorkflow",
        priority=temporal_common.Priority.default,
        retry_policy=None,
        activity_run_id=None,
    )


class _NextInterceptor:
    """Stand-in for the downstream :class:`ActivityInboundInterceptor`."""

    def __init__(self, result: Any = "ok", error: BaseException | None = None) -> None:
        self.result = result
        self.error = error
        self.called = False

    def init(self, outbound: Any) -> None:  # pragma: no cover -- unused
        pass

    async def execute_activity(self, input: Any) -> Any:
        self.called = True
        if self.error is not None:
            raise self.error
        return self.result


@contextmanager
def _patched_activity_info(info: activity.Info):
    with activity_context(info):
        yield


def _make_input(*args: Any) -> Any:
    """Build an :class:`ExecuteActivityInput`-compatible object."""
    from temporalio.worker import ExecuteActivityInput

    async def _fn() -> None:  # pragma: no cover -- not invoked
        pass

    return ExecuteActivityInput(
        fn=_fn,
        args=list(args),
        executor=None,
        headers={},
    )


async def _wired(
    chio: MediatedContractClient,
    *tools: str,
    next_interceptor: _NextInterceptor | None = None,
    **interceptor_kwargs: Any,
) -> tuple[ChioActivityInterceptor, _ChioInboundInterceptor, _NextInterceptor]:
    token = await chio.create_capability(
        subject="agent:alice", scope=_scope_for_tools(*tools)
    )
    interceptor = contract_interceptor(chio, **interceptor_kwargs)
    interceptor.register_workflow_grant(
        WorkflowGrant(workflow_id="wf-1", token=token, tool_server="srv")
    )
    downstream = next_interceptor or _NextInterceptor()
    return interceptor, _ChioInboundInterceptor(downstream, interceptor), downstream


async def _run(
    inbound: _ChioInboundInterceptor, activity_type: str = "send_email", *args: Any
) -> Any:
    with _patched_activity_info(_default_info(activity_type=activity_type)):
        return await inbound.execute_activity(_make_input(*args))


def _payload_sha256(value: Any) -> str:
    payload = DataConverter.default.payload_converter.to_payloads([value])[0]
    return hashlib.sha256(payload.data).hexdigest()


ID_ONLY_METHODS = {"evaluate_tool_call", "evaluate_tool_call_advisory"}


# ---------------------------------------------------------------------------
# Allowed activities run the full reserve -> start -> run -> report lifecycle
# ---------------------------------------------------------------------------


class TestMediatedLifecycle:
    async def test_allow_reserves_starts_runs_and_reports(self) -> None:
        chio = MediatedContractClient()
        interceptor, inbound, downstream = await _wired(
            chio, "send_email", next_interceptor=_NextInterceptor(result="delivered")
        )

        result = await _run(inbound, "send_email", "hi")

        assert result == "delivered"
        assert downstream.called
        assert chio.methods() == [
            "evaluate_tool_call_mediated",
            "start_mediated_execution",
            "report_mediated_execution",
        ]
        assert chio.open_holds == set()

        reserve = chio.calls[0]
        assert reserve.capability["signature"]
        assert reserve.capability["scope"]["grants"][0]["tool_name"] == "send_email"
        assert reserve.request_id.startswith("temporal:")
        assert chio.calls[1].arguments == reserve.parameters

        report = chio.reports[0]["report"]
        assert report["output"] == {
            "outcome": "completed",
            "result_sha256": _payload_sha256("delivered"),
        }
        assert report["claim_id"] == reserve.request_id
        assert report["execution_started_at_unix_ms"] == FIXED_NOW_MS
        assert report["realized_cost"] is None

        receipt = interceptor.workflow_receipt("wf-1", "run-1")
        assert receipt is not None
        assert receipt.step_count == 1
        assert receipt.allow_count == 1
        step = receipt.steps[0]
        assert step.activity_type == "send_email"
        assert step.receipt.is_allowed
        assert step.reservation_receipt_id is not None
        assert step.receipt.id != step.reservation_receipt_id
        assert step.to_dict()["reservation_receipt_id"] == step.reservation_receipt_id

    async def test_allow_respects_activity_tool_server_map(self) -> None:
        chio = MediatedContractClient()
        _, inbound, _ = await _wired(
            chio,
            "send_email",
            activity_tool_server_map={"send_email": "email-srv"},
        )

        await _run(inbound, "send_email")

        assert chio.calls[0].tool_server == "email-srv"

    async def test_run_scoped_grant_rejects_missing_run_id(self) -> None:
        chio = MediatedContractClient()
        token = await chio.create_capability(
            subject="agent:alice", scope=_scope_for_tools("send_email")
        )
        grant = WorkflowGrant(
            workflow_id="wf-1", token=token, tool_server="srv", run_id="run-1"
        )

        assert grant.matches(workflow_id="wf-1", run_id="run-1")
        assert not grant.matches(workflow_id="wf-1", run_id="run-2")
        assert not grant.matches(workflow_id="wf-1", run_id=None)

    async def test_activity_failure_reports_failed_outcome_and_finalizes(self) -> None:
        chio = MediatedContractClient()
        interceptor, inbound, _ = await _wired(
            chio,
            "send_email",
            next_interceptor=_NextInterceptor(error=RuntimeError("smtp down")),
        )

        with pytest.raises(RuntimeError, match="smtp down"):
            await _run(inbound, "send_email")

        assert chio.methods()[-1] == "report_mediated_execution"
        assert chio.reports[0]["report"]["output"] == {
            "outcome": "failed",
            "error_type": "RuntimeError",
        }
        assert chio.open_holds == set()
        receipt = interceptor.workflow_receipt("wf-1", "run-1")
        assert receipt is not None
        assert receipt.steps[0].reservation_receipt_id is not None

    async def test_report_deny_withholds_the_result(self) -> None:
        chio = MediatedContractClient()
        chio.report_status = "deny"
        interceptor, inbound, downstream = await _wired(chio, "send_email")

        with pytest.raises(ApplicationError) as exc_info:
            await _run(inbound, "send_email")

        assert downstream.called
        assert exc_info.value.type == DENIED_ERROR_TYPE
        assert exc_info.value.non_retryable is True
        receipt = interceptor.workflow_receipt("wf-1", "run-1")
        assert receipt is not None
        assert receipt.deny_count == 1

    async def test_report_failure_after_success_is_non_retryable(self) -> None:
        chio = MediatedContractClient()
        chio.report_error = ChioTimeoutError("lost report reply")
        _, inbound, downstream = await _wired(chio, "send_email")

        with pytest.raises(ApplicationError) as exc_info:
            await _run(inbound, "send_email")

        assert downstream.called
        assert exc_info.value.type == SIDECAR_ERROR_TYPE
        assert exc_info.value.non_retryable is True

    async def test_report_failure_after_activity_error_is_non_retryable(self) -> None:
        chio = MediatedContractClient()
        chio.report_error = ChioTimeoutError("lost report reply")
        _, inbound, _ = await _wired(
            chio,
            "send_email",
            next_interceptor=_NextInterceptor(error=RuntimeError("smtp down")),
        )

        with pytest.raises(ApplicationError) as exc_info:
            await _run(inbound, "send_email")

        assert exc_info.value.type == SIDECAR_ERROR_TYPE
        assert exc_info.value.non_retryable is True
        assert isinstance(exc_info.value.__cause__, RuntimeError)


# ---------------------------------------------------------------------------
# The id-only evaluate path is gone
# ---------------------------------------------------------------------------


class TestIdOnlyPathRemoved:
    async def test_contract_double_never_sees_id_only_calls(self) -> None:
        chio = MediatedContractClient()
        _, inbound, _ = await _wired(chio, "send_email")

        await _run(inbound, "send_email")
        with pytest.raises(ApplicationError):
            await _run(inbound, "not_granted")

        assert ID_ONLY_METHODS.isdisjoint(chio.methods())

    @respx.mock
    async def test_real_client_drives_mediated_routes_only(self) -> None:
        contract = MediatedContractClient()
        base = "http://sidecar.test"

        def _json(request: httpx.Request) -> dict[str, Any]:
            return json.loads(request.content)

        def _bearer(request: httpx.Request) -> str:
            return request.headers.get("authorization", "").removeprefix("Bearer ")

        evaluate = respx.post(f"{base}/v1/evaluate").mock(
            side_effect=lambda request: httpx.Response(
                200,
                json=contract.reserve(
                    capability=_json(request)["capability"],
                    tool_server=_json(request)["tool_server"],
                    tool_name=_json(request)["tool_name"],
                    parameters=_json(request)["parameters"],
                    request_id=_json(request)["request_id"],
                ),
            )
        )
        start = respx.post(f"{base}/v1/caller/start").mock(
            side_effect=lambda request: httpx.Response(
                200,
                json=contract.start(
                    control_token=_bearer(request),
                    execution_nonce=_json(request)["execution_nonce"],
                    arguments=_json(request)["arguments"],
                ),
            )
        )
        report = respx.post(f"{base}/v1/caller/report").mock(
            side_effect=lambda request: httpx.Response(
                200,
                json=contract.report(
                    control_token=_bearer(request),
                    authorization=_json(request)["authorization"],
                    report=_json(request)["report"],
                ),
            )
        )
        advisory = respx.post(f"{base}/v1/evaluate/advisory").mock(
            return_value=httpx.Response(500)
        )

        async with ChioClient(base) as client:

            async def _id_only(**_kwargs: Any) -> Any:
                raise AssertionError("the id-only evaluate path must never be called")

            client.evaluate_tool_call = _id_only  # type: ignore[method-assign]
            token = await contract.create_capability(
                subject="agent:alice", scope=_scope_for_tools("send_email")
            )
            interceptor = ChioActivityInterceptor(
                executor=contract.executor,
                control_token=CONTROL_TOKEN,
                chio_client=client,
                clock_ms=lambda: FIXED_NOW_MS,
            )
            interceptor.register_workflow_grant(
                WorkflowGrant(workflow_id="wf-1", token=token, tool_server="srv")
            )
            downstream = _NextInterceptor(result={"sent": True})
            result = await _run(
                _ChioInboundInterceptor(downstream, interceptor), "send_email", "hi"
            )

        assert result == {"sent": True}
        assert evaluate.call_count == 1
        assert start.call_count == 1
        assert report.call_count == 1
        assert not advisory.called
        assert contract.open_holds == set()
        assert start.calls.last.request.headers["authorization"] == f"Bearer {CONTROL_TOKEN}"


# ---------------------------------------------------------------------------
# Deny, pending approval and every error stop the activity
# ---------------------------------------------------------------------------


class TestDenyAndFailClosed:
    async def test_reservation_deny_is_non_retryable_and_never_starts(self) -> None:
        chio = MediatedContractClient()
        interceptor, inbound, downstream = await _wired(chio, "send_email")

        with pytest.raises(ApplicationError) as exc_info:
            await _run(inbound, "write_file", "payload")

        err = exc_info.value
        assert err.non_retryable is True
        assert err.type == DENIED_ERROR_TYPE
        assert "Chio capability denied" in str(err)
        assert not downstream.called
        assert chio.methods() == ["evaluate_tool_call_mediated"]
        receipt = interceptor.workflow_receipt("wf-1", "run-1")
        assert receipt is not None
        assert receipt.deny_count == 1
        assert receipt.steps[0].reservation_receipt_id is None

    async def test_pending_approval_stops_the_activity(self) -> None:
        chio = MediatedContractClient(policy=lambda _tool, _cap: "pending_approval")
        _, inbound, downstream = await _wired(chio, "send_email")

        with pytest.raises(ApplicationError) as exc_info:
            await _run(inbound, "send_email")

        assert exc_info.value.non_retryable is True
        assert exc_info.value.type == DENIED_ERROR_TYPE
        assert not downstream.called
        assert chio.methods() == ["evaluate_tool_call_mediated"]

    async def test_reservation_403_records_synthetic_deny(self) -> None:
        chio = MediatedContractClient(policy=lambda _tool, _cap: "deny_403")
        interceptor, inbound, downstream = await _wired(chio, "send_email")

        with pytest.raises(ApplicationError) as exc_info:
            await _run(inbound, "send_email")

        assert exc_info.value.non_retryable is True
        assert exc_info.value.type == DENIED_ERROR_TYPE
        assert not downstream.called
        receipt = interceptor.workflow_receipt("wf-1", "run-1")
        assert receipt is not None
        assert receipt.steps[0].receipt.is_denied
        assert receipt.steps[0].receipt.metadata["synthetic"] is True

    async def test_start_deny_stops_the_activity(self) -> None:
        chio = MediatedContractClient()
        chio.start_error = ChioDeniedError("denied", guard="BudgetGuard", reason="over budget")
        _, inbound, downstream = await _wired(chio, "send_email")

        with pytest.raises(ApplicationError) as exc_info:
            await _run(inbound, "send_email")

        assert exc_info.value.type == DENIED_ERROR_TYPE
        assert exc_info.value.non_retryable is True
        assert not downstream.called

    @pytest.mark.parametrize(
        "error",
        [
            ChioTimeoutError("reserve reply lost"),
            ChioValidationError("Invalid caller reservation contract"),
            RuntimeError("unexpected client failure"),
        ],
    )
    async def test_reservation_errors_deny_non_retryably(self, error: Exception) -> None:
        chio = MediatedContractClient()
        _, inbound, downstream = await _wired(chio, "send_email")

        async def _fail(**_kwargs: Any) -> dict:
            raise error

        chio.evaluate_tool_call_mediated = _fail  # type: ignore[method-assign]
        with pytest.raises(ApplicationError) as exc_info:
            await _run(inbound, "send_email")

        assert exc_info.value.type == SIDECAR_ERROR_TYPE
        assert exc_info.value.non_retryable is True
        assert not downstream.called
        assert ID_ONLY_METHODS.isdisjoint(chio.methods())

    async def test_unreachable_sidecar_denies_and_allows_temporal_retry(self) -> None:
        chio = MediatedContractClient()
        _, inbound, downstream = await _wired(chio, "send_email")

        async def _fail(**_kwargs: Any) -> dict:
            raise ChioConnectionError("connection refused")

        chio.evaluate_tool_call_mediated = _fail  # type: ignore[method-assign]
        with pytest.raises(ApplicationError) as exc_info:
            await _run(inbound, "send_email")

        assert exc_info.value.type == SIDECAR_ERROR_TYPE
        assert exc_info.value.non_retryable is False
        assert not downstream.called

    @pytest.mark.parametrize(
        "error",
        [ChioTimeoutError("lost start reply"), ChioValidationError("bad start")],
    )
    async def test_start_errors_deny_non_retryably(self, error: Exception) -> None:
        chio = MediatedContractClient()
        chio.start_error = error
        _, inbound, downstream = await _wired(chio, "send_email")

        with pytest.raises(ApplicationError) as exc_info:
            await _run(inbound, "send_email")

        assert exc_info.value.type == SIDECAR_ERROR_TYPE
        assert exc_info.value.non_retryable is True
        assert not downstream.called

    @pytest.mark.parametrize(
        "override",
        [
            {"kernel_public_key": "07" * 32},
            {
                "executor": {
                    "executor_id": "someone-else",
                    "public_key": "01" * 32,
                    "key_epoch": 1,
                }
            },
            {"not_before_unix_ms": FIXED_NOW_MS + 1},
            {"expires_at_unix_ms": FIXED_NOW_MS},
        ],
    )
    async def test_unbound_or_expired_authorization_never_runs(
        self, override: dict[str, Any]
    ) -> None:
        chio = MediatedContractClient()
        chio.authorization_overrides = override
        _, inbound, downstream = await _wired(chio, "send_email")

        with pytest.raises(ApplicationError) as exc_info:
            await _run(inbound, "send_email")

        assert exc_info.value.type == SIDECAR_ERROR_TYPE
        assert exc_info.value.non_retryable is True
        assert not downstream.called

    async def test_authorization_for_another_tool_never_runs(self) -> None:
        chio = MediatedContractClient()
        original_start = chio.start

        def _retarget(**kwargs: Any) -> dict[str, Any]:
            started = original_start(**kwargs)
            started["authorization"]["authorization"]["invocation"]["tool_name"] = "other"
            return started

        chio.start = _retarget  # type: ignore[method-assign]
        _, inbound, downstream = await _wired(chio, "send_email")

        with pytest.raises(ApplicationError) as exc_info:
            await _run(inbound, "send_email")

        assert exc_info.value.type == SIDECAR_ERROR_TYPE
        assert not downstream.called

    async def test_forged_kernel_signature_never_runs(self) -> None:
        chio = MediatedContractClient()
        original_start = chio.start

        def _forge(**kwargs: Any) -> dict[str, Any]:
            started = original_start(**kwargs)
            started["authorization"]["signature"] = "0" * 128
            return started

        chio.start = _forge  # type: ignore[method-assign]
        _, inbound, downstream = await _wired(chio, "send_email")

        with pytest.raises(ApplicationError) as exc_info:
            await _run(inbound, "send_email")

        assert exc_info.value.type == SIDECAR_ERROR_TYPE
        assert not downstream.called


class TestConfiguration:
    async def test_missing_workflow_grant_raises_config_error(self) -> None:
        chio = MediatedContractClient()
        interceptor = contract_interceptor(chio)
        inbound = _ChioInboundInterceptor(_NextInterceptor(), interceptor)
        info = _default_info(activity_type="send_email", workflow_id="wf-missing")
        with _patched_activity_info(info):
            with pytest.raises(ChioTemporalConfigError):
                await inbound.execute_activity(_make_input())
        assert chio.calls == []

    def test_executor_and_control_token_are_required(self) -> None:
        chio = MediatedContractClient()
        with pytest.raises(ChioTemporalConfigError):
            ChioActivityInterceptor(
                executor=object(),  # type: ignore[arg-type]
                control_token=CONTROL_TOKEN,
                chio_client=chio,
            )
        with pytest.raises(ChioTemporalConfigError):
            ChioActivityInterceptor(
                executor=chio.executor, control_token="", chio_client=chio
            )


class TestDenyReceiptHelpers:
    def test_deny_receipt_preserves_schema_valid_sidecar_receipt_id(self) -> None:
        sidecar_receipt_id = "a" * 64
        info = _default_info(activity_type="send_email")
        receipt = _deny_receipt_from_error(
            info=info,
            capability_id="cap-1",
            tool_server="srv",
            parameters={"payload": "secret"},
            exc=ChioDeniedError(
                "denied",
                guard="ScopeGuard",
                reason="no write perms",
                receipt_id=sidecar_receipt_id,
            ),
        )

        assert receipt.id == sidecar_receipt_id
        assert receipt.metadata["sidecar_receipt_id"] == sidecar_receipt_id
        assert receipt.is_denied

    def test_deny_receipt_hashes_non_sha256_sidecar_receipt_id(self) -> None:
        import hashlib

        opaque_receipt_id = "receipt-from-sidecar-not-a-digest"
        info = _default_info(activity_type="send_email")
        receipt = _deny_receipt_from_error(
            info=info,
            capability_id="cap-1",
            tool_server="srv",
            parameters={"payload": "secret"},
            exc=ChioDeniedError(
                "denied",
                guard="ScopeGuard",
                reason="no write perms",
                receipt_id=opaque_receipt_id,
            ),
        )

        expected_id = hashlib.sha256(opaque_receipt_id.encode("utf-8")).hexdigest()
        assert receipt.id == expected_id
        assert receipt.id != opaque_receipt_id
        assert receipt.metadata["sidecar_receipt_id"] == opaque_receipt_id
        assert receipt.is_denied

    def test_deny_receipt_hashes_mixed_case_sidecar_receipt_id(self) -> None:
        import hashlib

        mixed_case_receipt_id = "A" * 64
        info = _default_info(activity_type="send_email")
        receipt = _deny_receipt_from_error(
            info=info,
            capability_id="cap-1",
            tool_server="srv",
            parameters={"payload": "secret"},
            exc=ChioDeniedError(
                "denied",
                guard="ScopeGuard",
                reason="no write perms",
                receipt_id=mixed_case_receipt_id,
            ),
        )

        expected_id = hashlib.sha256(mixed_case_receipt_id.encode("utf-8")).hexdigest()
        assert receipt.id == expected_id
        assert receipt.id != mixed_case_receipt_id.lower()
        assert receipt.metadata["sidecar_receipt_id"] == mixed_case_receipt_id

    def test_is_sha256_hex_accepts_only_lowercase_digest(self) -> None:
        assert _is_sha256_hex("a" * 64)
        assert not _is_sha256_hex("A" * 64)
        assert not _is_sha256_hex("not-a-digest")
        assert not _is_sha256_hex("a" * 63)

# ---------------------------------------------------------------------------
# Attenuated activity-level grant enforcement
# ---------------------------------------------------------------------------


class TestAttenuatedGrant:
    async def test_activity_override_narrows_scope_and_is_enforced(self) -> None:
        chio = MediatedContractClient()
        parent = await chio.create_capability(
            subject="agent:parent", scope=_scope_for_tools("search", "write")
        )
        parent_grant = WorkflowGrant(workflow_id="wf-1", token=parent, tool_server="srv")
        child_grant = await parent_grant.attenuate_for_activity(
            chio, new_scope=_scope_for_tools("search")
        )

        interceptor = contract_interceptor(chio)
        interceptor.register_workflow_grant(parent_grant)
        interceptor.register_activity_grant_override("write", lambda _info: child_grant)
        downstream = _NextInterceptor()
        inbound = _ChioInboundInterceptor(downstream, interceptor)

        info = _default_info(activity_type="write", activity_id="act-write")
        with _patched_activity_info(info):
            with pytest.raises(ApplicationError) as exc_info:
                await inbound.execute_activity(_make_input("/tmp/x"))

        assert exc_info.value.non_retryable is True
        assert exc_info.value.type == DENIED_ERROR_TYPE
        assert not downstream.called
        assert chio.calls[0].capability["id"] == child_grant.capability_id

    async def test_attenuation_rejects_broader_scope(self) -> None:
        chio = MediatedContractClient()
        parent = await chio.create_capability(
            subject="agent:parent", scope=_scope_for_tools("search")
        )
        parent_grant = WorkflowGrant(workflow_id="wf-1", token=parent, tool_server="srv")

        with pytest.raises(ChioValidationError):
            await parent_grant.attenuate_for_activity(
                chio, new_scope=_scope_for_tools("search", "write")
            )

    async def test_activity_override_rejects_scope_outside_parent(self) -> None:
        chio = MediatedContractClient()
        parent: CapabilityToken = await chio.create_capability(
            subject="agent:parent", scope=_scope_for_tools("search")
        )
        parent_grant = WorkflowGrant(workflow_id="wf-1", token=parent, tool_server="srv")
        rogue_grant = WorkflowGrant(
            workflow_id="wf-1",
            token=parent.model_copy(update={"scope": _scope_for_tools("search", "write")}),
            tool_server="srv",
        )

        interceptor = contract_interceptor(chio)
        interceptor.register_workflow_grant(parent_grant)
        interceptor.register_activity_grant_override("write", lambda _info: rogue_grant)
        inbound = _ChioInboundInterceptor(_NextInterceptor(), interceptor)

        info = _default_info(activity_type="write")
        with _patched_activity_info(info):
            with pytest.raises(ChioTemporalConfigError):
                await inbound.execute_activity(_make_input())
        assert chio.calls == []


# ---------------------------------------------------------------------------
# Result encoding, cancellation, async completion and retries
# ---------------------------------------------------------------------------


class _FailingConverter:
    """Payload converter whose encoding fails, as for an unsupported type."""

    def to_payloads(self, values: Any) -> Any:
        raise TypeError("Object of type Decimal is not JSON serializable")


class TestResultEncodingAndCancellation:
    async def test_hash_failure_after_success_reports_and_is_non_retryable(self) -> None:
        chio = MediatedContractClient()
        interceptor, inbound, downstream = await _wired(chio, "send_email")

        with activity_context(
            _default_info(activity_type="send_email"), _FailingConverter()  # type: ignore[arg-type]
        ):
            with pytest.raises(ApplicationError) as exc_info:
                await inbound.execute_activity(_make_input())

        assert downstream.called
        assert exc_info.value.type == SIDECAR_ERROR_TYPE
        assert exc_info.value.non_retryable is True
        assert isinstance(exc_info.value.__cause__, TypeError)
        assert chio.reports[0]["report"]["output"] == {
            "outcome": "completed_unencodable",
            "error_type": "TypeError",
        }
        assert chio.open_holds == set()
        receipt = interceptor.workflow_receipt("wf-1", "run-1")
        assert receipt is not None
        assert receipt.step_count == 1

    async def test_result_hash_uses_the_worker_payload_converter(self) -> None:
        class _TaggingConverter:
            def to_payloads(self, values: Any) -> Any:
                return [SimpleNamespace(data=b"worker-encoding")]

        chio = MediatedContractClient()
        _, inbound, _ = await _wired(chio, "send_email")
        with activity_context(
            _default_info(activity_type="send_email"), _TaggingConverter()  # type: ignore[arg-type]
        ):
            await inbound.execute_activity(_make_input())

        assert chio.reports[0]["report"]["output"]["result_sha256"] == (
            hashlib.sha256(b"worker-encoding").hexdigest()
        )

    async def test_cancellation_reports_and_stays_cancellation(self) -> None:
        chio = MediatedContractClient()
        _, inbound, _ = await _wired(
            chio, "send_email", next_interceptor=_NextInterceptor(error=asyncio.CancelledError())
        )

        with pytest.raises(asyncio.CancelledError):
            await _run(inbound, "send_email")

        assert chio.reports[0]["report"]["output"] == {
            "outcome": "failed",
            "error_type": "CancelledError",
        }
        assert chio.open_holds == set()

    async def test_cancellation_is_not_replaced_when_the_report_fails(self) -> None:
        chio = MediatedContractClient()
        chio.report_error = ChioTimeoutError("lost report reply")
        _, inbound, _ = await _wired(
            chio, "send_email", next_interceptor=_NextInterceptor(error=asyncio.CancelledError())
        )

        with pytest.raises(asyncio.CancelledError):
            await _run(inbound, "send_email")

    async def test_async_completion_is_not_reported_as_failure(self) -> None:
        chio = MediatedContractClient()
        _, inbound, _ = await _wired(
            chio, "send_email", next_interceptor=_NextInterceptor(error=activity._CompleteAsyncError())
        )

        with pytest.raises(activity._CompleteAsyncError):
            await _run(inbound, "send_email")

        assert "report_mediated_execution" not in chio.methods()
        assert len(chio.open_holds) == 1

    async def test_retry_attempt_is_a_new_reservation_and_the_old_hold_stays_open(
        self,
    ) -> None:
        chio = MediatedContractClient()
        interceptor, _, _ = await _wired(chio, "send_email")

        chio.report_error = ChioTimeoutError("worker lost the sidecar mid-attempt")
        first = _ChioInboundInterceptor(
            _NextInterceptor(error=asyncio.CancelledError()), interceptor
        )
        with activity_context(_default_info(activity_type="send_email", attempt=1)):
            with pytest.raises(asyncio.CancelledError):
                await first.execute_activity(_make_input())
        first_request = chio.calls[0].request_id
        stale_holds = set(chio.open_holds)
        assert len(stale_holds) == 1

        chio.report_error = None
        second_downstream = _NextInterceptor(result="ok")
        second = _ChioInboundInterceptor(second_downstream, interceptor)
        with activity_context(_default_info(activity_type="send_email", attempt=2)):
            assert await second.execute_activity(_make_input()) == "ok"

        reserves = [c for c in chio.calls if c.method == "evaluate_tool_call_mediated"]
        assert len(reserves) == 2
        assert reserves[1].request_id != first_request
        assert second_downstream.called
        # Attempt 1 was started but never reported; its hold is only released
        # by kernel expiry or recovery, never by attempt 2.
        assert chio.open_holds == stale_holds


# ---------------------------------------------------------------------------
# Receipt verification and start-route rejections
# ---------------------------------------------------------------------------


class TestReceiptVerification:
    async def test_forged_reservation_receipt_never_runs(self) -> None:
        chio = MediatedContractClient()
        chio.receipt_tamper = lambda receipt: receipt.update(signature="0" * 128)
        _, inbound, downstream = await _wired(chio, "send_email")

        with pytest.raises(ApplicationError) as exc_info:
            await _run(inbound, "send_email")

        assert exc_info.value.type == SIDECAR_ERROR_TYPE
        assert exc_info.value.non_retryable is True
        assert not downstream.called
        assert "start_mediated_execution" not in chio.methods()

    @pytest.mark.parametrize(
        "tamper",
        [
            lambda receipt: receipt.update(signature="0" * 128),
            lambda receipt: receipt.update(kernel_key="07" * 32),
            lambda receipt: receipt.update(tool_name="other"),
        ],
    )
    async def test_forged_terminal_receipt_fails_closed(self, tamper: Any) -> None:
        chio = MediatedContractClient()
        interceptor, inbound, downstream = await _wired(chio, "send_email")
        original_report = chio.report

        def _forged_report(**kwargs: Any) -> dict[str, Any]:
            response = original_report(**kwargs)
            tamper(response["receipt"])
            return response

        chio.report = _forged_report  # type: ignore[method-assign]
        with pytest.raises(ApplicationError) as exc_info:
            await _run(inbound, "send_email")

        assert downstream.called
        assert exc_info.value.type == SIDECAR_ERROR_TYPE
        assert exc_info.value.non_retryable is True
        receipt = interceptor.workflow_receipt("wf-1", "run-1")
        assert receipt is not None
        assert receipt.step_count == 0


class TestStartRejections:
    async def test_revoked_capability_409_at_start_never_runs(self) -> None:
        chio = MediatedContractClient()
        _, inbound, downstream = await _wired(chio, "send_email")
        chio.revoked.add("cap-1")

        with pytest.raises(ApplicationError) as exc_info:
            await _run(inbound, "send_email")

        assert exc_info.value.type == SIDECAR_ERROR_TYPE
        assert exc_info.value.non_retryable is True
        assert not downstream.called

    async def test_kernel_deny_at_start_never_runs(self) -> None:
        chio = MediatedContractClient()
        chio.start_denied = True
        interceptor, inbound, downstream = await _wired(chio, "send_email")

        with pytest.raises(ApplicationError) as exc_info:
            await _run(inbound, "send_email")

        assert exc_info.value.type == DENIED_ERROR_TYPE
        assert exc_info.value.non_retryable is True
        assert not downstream.called
        receipt = interceptor.workflow_receipt("wf-1", "run-1")
        assert receipt is not None
        assert receipt.deny_count == 1

    @pytest.mark.parametrize(
        ("status", "body", "error_type"),
        [
            (
                403,
                {"status": "deny", "protocol": "chio.caller-delivery.v1", "receipt": {}},
                DENIED_ERROR_TYPE,
            ),
            (
                409,
                {
                    "error": "chio_caller_delivery_rejected",
                    "message": "original committed caller delivery could not be "
                    "authenticated or finalized",
                },
                SIDECAR_ERROR_TYPE,
            ),
        ],
    )
    @respx.mock
    async def test_real_client_start_route_rejections(
        self, status: int, body: dict[str, Any], error_type: str
    ) -> None:
        contract = MediatedContractClient()
        base = "http://sidecar.test"
        respx.post(f"{base}/v1/evaluate").mock(
            side_effect=lambda request: httpx.Response(
                200,
                json=contract.reserve(
                    capability=json.loads(request.content)["capability"],
                    tool_server=json.loads(request.content)["tool_server"],
                    tool_name=json.loads(request.content)["tool_name"],
                    parameters=json.loads(request.content)["parameters"],
                    request_id=json.loads(request.content)["request_id"],
                ),
            )
        )
        respx.post(f"{base}/v1/caller/start").mock(
            return_value=httpx.Response(status, json=body)
        )
        report = respx.post(f"{base}/v1/caller/report").mock(
            return_value=httpx.Response(500)
        )
        async with ChioClient(base) as client:
            token = await contract.create_capability(
                subject="agent:alice", scope=_scope_for_tools("send_email")
            )
            interceptor = ChioActivityInterceptor(
                executor=contract.executor,
                control_token=CONTROL_TOKEN,
                chio_client=client,
                clock_ms=lambda: FIXED_NOW_MS,
            )
            interceptor.register_workflow_grant(
                WorkflowGrant(workflow_id="wf-1", token=token, tool_server="srv")
            )
            downstream = _NextInterceptor()
            with pytest.raises(ApplicationError) as exc_info:
                await _run(_ChioInboundInterceptor(downstream, interceptor), "send_email")

        assert exc_info.value.type == error_type
        assert exc_info.value.non_retryable is True
        assert not downstream.called
        assert not report.called

    async def test_report_409_names_the_clock_skew_cause(self) -> None:
        chio = MediatedContractClient()
        from chio_sdk.errors import ChioError

        chio.report_error = ChioError("Chio sidecar returned 409", code="HTTP_409")
        _, inbound, _ = await _wired(chio, "send_email")

        with pytest.raises(ApplicationError) as exc_info:
            await _run(inbound, "send_email")

        assert exc_info.value.non_retryable is True
        assert "clocks synchronized" in str(exc_info.value)
