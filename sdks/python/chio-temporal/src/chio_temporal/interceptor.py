"""Chio-governed Temporal Activity interceptor.

:class:`ChioActivityInterceptor` plugs into a Temporal
:class:`temporalio.worker.Worker`'s ``interceptors`` list. Every
activity runs through the sidecar's mediated ``chio.caller-delivery.v1``
lifecycle:

1. ``POST /v1/evaluate`` reserves the call against the workflow's signed
   capability token. ``deny`` and ``pending_approval`` stop the activity
   with a non-retryable :class:`temporalio.exceptions.ApplicationError`.
2. ``POST /v1/caller/start`` commits the reservation and returns a
   kernel-signed dispatch authorization. The interceptor checks it
   against the pinned kernel key and its own executor identity before
   the activity body runs.
3. The activity runs.
4. ``POST /v1/caller/report`` delivers an executor-signed report (the
   SHA-256 of the result's bytes under the worker's payload converter, or
   the failure type) so the reservation finalizes. The terminal receipt is recorded
   on the :class:`WorkflowReceipt` step.

Any sidecar or contract error stops the activity. Pending approvals are
not resumed by this package.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import logging
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from chio_adapter_base.redact import (
    DEFAULT_TOOL_POSITIONAL_NAMES,
    RedactionPolicy,
    bind_and_redact,
    build_alias_map,
)
from chio_sdk._generated import ChioSignedCallerDispatchAuthorization
from chio_sdk.client import ChioClient
from chio_sdk.errors import ChioConnectionError, ChioDeniedError, ChioError
from chio_sdk.models import ChioReceipt, Decision, ToolCallAction
from temporalio import activity
from temporalio.converter import PayloadConverter
from temporalio.exceptions import ApplicationError
from temporalio.worker import (
    ActivityInboundInterceptor,
    ExecuteActivityInput,
    Interceptor,
)

from chio_temporal.errors import ChioTemporalConfigError, ChioTemporalError
from chio_temporal.executor import CallerExecutor, canonical_json_bytes, signing_wrapper
from chio_temporal.grants import ChioClientLike, WorkflowGrant
from chio_temporal.receipt import WorkflowReceipt

logger = logging.getLogger(__name__)

#: ``ApplicationError.type`` for denied activities. Saga compensation
#: matches on this string -- see ``docs/protocols/TEMPORAL-INTEGRATION.md``.
DENIED_ERROR_TYPE = "ChioCapabilityDenied"

#: ``ApplicationError.type`` when the mediated lifecycle cannot complete.
SIDECAR_ERROR_TYPE = "ChioSidecarError"

CALLER_DELIVERY_PROTOCOL = "chio.caller-delivery.v1"
CALLER_DELIVERY_REPORT_SCHEMA = "chio.caller-delivery-report.v1"
CALLER_DISPATCH_AUTHORIZATION_SCHEMA = "chio.caller-dispatch-authorization.v1"
CHIO_RECEIPT_SCHEMA = "chio.receipt.v1"


def _wall_clock_ms() -> int:
    return time.time_ns() // 1_000_000

# Per-activity grant-override hook; ``None`` falls back to the workflow grant.
ActivityGrantOverride = Callable[[activity.Info], "WorkflowGrant | None"]


def _is_sha256_hex(value: str) -> bool:
    return len(value) == 64 and all(char in "0123456789abcdef" for char in value)


@dataclass
class _WorkflowRunState:
    """Per-(workflow_id, run_id) state; isolates concurrent runs on one worker."""

    receipt: WorkflowReceipt
    grant: WorkflowGrant
    overrides: dict[str, WorkflowGrant] = field(default_factory=dict)


class ChioActivityInterceptor(Interceptor):
    """Worker-level :class:`Interceptor` that gates every Activity on Chio.

    Redaction runs in the activity layer so workflow determinism is
    unaffected. Receipt-sink failures are logged and swallowed.

    ``executor`` and ``control_token`` are required: the interceptor is
    the caller executor for ``/v1/caller/start`` and
    ``/v1/caller/report``, which sit behind the sidecar-control bearer.
    """

    def __init__(
        self,
        *,
        executor: CallerExecutor,
        control_token: str,
        chio_client: ChioClientLike | None = None,
        sidecar_url: str = "http://127.0.0.1:9090",
        default_tool_server: str = "",
        activity_tool_server_map: dict[str, str] | None = None,
        receipt_sink: Callable[[dict[str, Any]], Awaitable[None] | None] | None = None,
        redaction_policy: RedactionPolicy | None = None,
        clock_ms: Callable[[], int] = _wall_clock_ms,
    ) -> None:
        if not isinstance(executor, CallerExecutor):
            raise ChioTemporalConfigError(
                "executor must implement chio_temporal.CallerExecutor"
            )
        if not control_token:
            raise ChioTemporalConfigError(
                "control_token (the sidecar-control bearer) must be non-empty"
            )
        self._executor = executor
        self._control_token = control_token
        self._clock_ms = clock_ms
        self._chio_client = chio_client
        self._owns_client = chio_client is None
        self._sidecar_url = sidecar_url
        self._default_tool_server = default_tool_server
        self._activity_tool_server_map: dict[str, str] = dict(
            activity_tool_server_map or {}
        )
        self._receipt_sink = receipt_sink
        self._redaction_policy = (
            redaction_policy
            if redaction_policy is not None
            else RedactionPolicy.chio_default()
        )
        self._runs: dict[tuple[str, str], _WorkflowRunState] = {}
        # Pre-registered grants keyed on workflow_id; per-run state is
        # materialised lazily on first activity execution.
        self._pending_grants: dict[str, WorkflowGrant] = {}
        self._override_hooks: dict[str, ActivityGrantOverride] = {}

    def register_workflow_grant(self, grant: WorkflowGrant) -> None:
        """Register a :class:`WorkflowGrant` for ``grant.workflow_id``.

        Must be called before the workflow starts so subsequent activity
        executions can resolve their capability.
        """
        if not isinstance(grant, WorkflowGrant):
            raise ChioTemporalConfigError(
                "register_workflow_grant expects a WorkflowGrant instance"
            )
        self._pending_grants[grant.workflow_id] = grant

    def register_activity_grant_override(
        self,
        activity_type: str,
        hook: ActivityGrantOverride,
    ) -> None:
        """Register a per-activity grant-override hook (``None`` -> workflow grant)."""
        if not activity_type:
            raise ChioTemporalConfigError(
                "activity_type must be a non-empty string"
            )
        self._override_hooks[activity_type] = hook

    def workflow_receipt(
        self,
        workflow_id: str,
        run_id: str | None = None,
    ) -> WorkflowReceipt | None:
        """Return the in-flight :class:`WorkflowReceipt` (``None`` if nothing yet)."""
        key = self._run_key(workflow_id, run_id)
        state = self._runs.get(key)
        return state.receipt if state else None

    def finalize_workflow(
        self,
        *,
        workflow_id: str,
        run_id: str | None = None,
        outcome: str = "success",
        completed_at: int | None = None,
    ) -> WorkflowReceipt | None:
        """Finalise the workflow receipt; call from a ``try/finally`` at workflow exit."""
        key = self._run_key(workflow_id, run_id)
        state = self._runs.get(key)
        if state is None:
            return None
        state.receipt.finalize(
            outcome=outcome,
            completed_at=completed_at if completed_at is not None else int(time.time()),
        )
        return state.receipt

    async def flush_workflow_receipt(
        self,
        *,
        workflow_id: str,
        run_id: str | None = None,
    ) -> dict[str, Any] | None:
        """Drain the finalised receipt to the sink; sink errors are swallowed."""
        key = self._run_key(workflow_id, run_id)
        state = self._runs.pop(key, None)
        if state is None:
            return None
        envelope = state.receipt.to_envelope()
        if self._receipt_sink is not None:
            try:
                result = self._receipt_sink(envelope)
                if isinstance(result, Awaitable):
                    await result
            except Exception:  # noqa: BLE001 -- sink must not fail the workflow
                logger.exception(
                    "chio-temporal receipt sink raised; envelope dropped"
                )
        return envelope

    def intercept_activity(
        self,
        next: ActivityInboundInterceptor,
    ) -> ActivityInboundInterceptor:
        return _ChioInboundInterceptor(next, self)

    async def close(self) -> None:
        """Close the underlying :class:`ChioClient` if we own it."""
        if self._owns_client and self._chio_client is not None:
            await self._chio_client.close()
            self._chio_client = None

    def _arc(self) -> ChioClientLike:
        if self._chio_client is None:
            self._chio_client = ChioClient(self._sidecar_url)
        return self._chio_client

    def _tool_server_for(self, info: activity.Info, grant: WorkflowGrant) -> str:
        """Resolve tool server: explicit map > grant.tool_server > interceptor default."""
        explicit = self._activity_tool_server_map.get(info.activity_type)
        if explicit:
            return explicit
        if grant.tool_server:
            return grant.tool_server
        return self._default_tool_server

    def _resolve_grant(self, info: activity.Info) -> WorkflowGrant:
        """Resolve the :class:`WorkflowGrant`; lazily materialise per-run state."""
        workflow_id = info.workflow_id
        run_id = info.workflow_run_id
        if not workflow_id:
            raise ChioTemporalConfigError(
                f"activity {info.activity_type!r} (id={info.activity_id!r}) has no "
                "workflow_id; chio-temporal requires activities to run under a workflow"
            )

        key = self._run_key(workflow_id, run_id)
        state = self._runs.get(key)
        if state is None:
            pending = self._pending_grants.get(workflow_id)
            if pending is None:
                raise ChioTemporalConfigError(
                    f"no WorkflowGrant registered for workflow_id={workflow_id!r}; "
                    "call ChioActivityInterceptor.register_workflow_grant(...) before "
                    "starting the workflow"
                )
            if not pending.matches(workflow_id=workflow_id, run_id=run_id):
                raise ChioTemporalConfigError(
                    f"WorkflowGrant for {workflow_id!r} is pinned to a different run_id "
                    f"({pending.run_id!r}); got {run_id!r}"
                )
            state = _WorkflowRunState(
                receipt=WorkflowReceipt(
                    workflow_id=workflow_id,
                    run_id=run_id,
                    parent_workflow_ids=list(
                        pending.metadata.get("parent_workflow_ids", [])
                    ),
                    started_at=int(time.time()),
                    metadata=dict(pending.metadata),
                ),
                grant=pending,
            )
            self._runs[key] = state

        override_hook = self._override_hooks.get(info.activity_type)
        if override_hook is not None:
            override = override_hook(info)
            if override is not None:
                if not override.scope.is_subset_of(state.grant.scope):
                    raise ChioTemporalConfigError(
                        f"activity-level grant for {info.activity_type!r} is not a "
                        "subset of the workflow grant scope"
                    )
                state.overrides[info.activity_id] = override
                return override

        return state.grant

    def _record_step(
        self,
        info: activity.Info,
        receipt: ChioReceipt,
        *,
        reservation_receipt_id: str | None = None,
    ) -> None:
        key = self._run_key(info.workflow_id, info.workflow_run_id)
        state = self._runs.get(key)
        if state is None:
            # Defensive no-op; _resolve_grant should have created state.
            logger.warning(
                "chio-temporal: no run state for workflow_id=%s run_id=%s",
                info.workflow_id,
                info.workflow_run_id,
            )
            return
        state.receipt.record_step(
            activity_type=info.activity_type,
            activity_id=info.activity_id,
            attempt=info.attempt,
            receipt=receipt,
            reservation_receipt_id=reservation_receipt_id,
        )

    @staticmethod
    def _run_key(
        workflow_id: str | None, run_id: str | None
    ) -> tuple[str, str]:
        return (workflow_id or "", run_id or "")


class _ChioInboundInterceptor(ActivityInboundInterceptor):
    """Per-activity inbound interceptor wired by :class:`ChioActivityInterceptor`."""

    def __init__(
        self,
        next: ActivityInboundInterceptor,
        parent: ChioActivityInterceptor,
    ) -> None:
        super().__init__(next)
        self._parent = parent

    async def execute_activity(self, input: ExecuteActivityInput) -> Any:
        info = activity.info()
        grant = self._parent._resolve_grant(info)
        tool_server = self._parent._tool_server_for(info, grant)

        parameters = _activity_parameters(
            input,
            tool_name=info.activity_type,
            policy=self._parent._redaction_policy,
        )
        if not grant.capability_id:
            raise _denied_application_error_from_config(
                info,
                reason="missing_capability",
                message=(
                    f"WorkflowGrant for {info.workflow_id!r} has an empty capability_id"
                ),
            )

        client = self._parent._arc()
        request_id = _request_id(info)
        reservation = await self._reserve(
            client,
            info=info,
            grant=grant,
            tool_server=tool_server,
            parameters=parameters,
            request_id=request_id,
        )
        reservation_receipt = self._verified_receipt(info, reservation)
        if reservation["status"] != "reserved":
            self._parent._record_step(info, reservation_receipt)
            raise _denied_application_error(info, reservation_receipt)

        authorization = await self._start(
            client,
            info=info,
            grant=grant,
            tool_server=tool_server,
            parameters=parameters,
            reservation=reservation,
            request_id=request_id,
        )
        started_at = self._parent._clock_ms()
        _require_live(info, authorization, started_at)

        try:
            result = await self.next.execute_activity(input)
        except activity._CompleteAsyncError:
            # Completion happens outside this worker, so there is no outcome to
            # report here; the committed hold is left for the kernel to expire.
            raise
        except BaseException as activity_error:
            await self._report_failure(
                client,
                info=info,
                authorization=authorization,
                request_id=request_id,
                started_at=started_at,
                reservation_receipt_id=reservation_receipt.id,
                activity_error=activity_error,
            )
            raise

        try:
            result_sha256 = _result_sha256(activity.payload_converter(), result)
        except Exception as encode_error:
            response = await self._report(
                client,
                info=info,
                authorization=authorization,
                request_id=request_id,
                started_at=started_at,
                output={
                    "outcome": "completed_unencodable",
                    "error_type": type(encode_error).__name__,
                },
            )
            self._parent._record_step(
                info,
                self._verified_receipt(info, response),
                reservation_receipt_id=reservation_receipt.id,
            )
            raise _sidecar_error(
                f"result of activity {info.activity_id!r} could not be encoded by the "
                "worker payload converter; it ran once and will not be retried"
            ) from encode_error

        response = await self._report(
            client,
            info=info,
            authorization=authorization,
            request_id=request_id,
            started_at=started_at,
            output={"outcome": "completed", "result_sha256": result_sha256},
        )
        terminal = self._verified_receipt(info, response)
        self._parent._record_step(
            info, terminal, reservation_receipt_id=reservation_receipt.id
        )
        if response["status"] != "reconciled" or terminal.is_denied:
            raise _denied_application_error(info, terminal)
        return result

    async def _report_failure(
        self,
        client: ChioClientLike,
        *,
        info: activity.Info,
        authorization: dict[str, Any],
        request_id: str,
        started_at: int,
        reservation_receipt_id: str,
        activity_error: BaseException,
    ) -> None:
        """Report a raised activity so the kernel finalizes the reservation.

        The kernel accounts this as a completed call whose output is the
        failure record. Cancellation always propagates as cancellation: a
        report failure during cancellation is logged, never substituted.
        """
        try:
            response = await self._report(
                client,
                info=info,
                authorization=authorization,
                request_id=request_id,
                started_at=started_at,
                output={"outcome": "failed", "error_type": type(activity_error).__name__},
            )
            receipt = self._verified_receipt(info, response)
        except ApplicationError as report_error:
            if isinstance(activity_error, asyncio.CancelledError):
                logger.error(
                    "chio-temporal: failure report for cancelled activity %s failed: %s",
                    info.activity_id,
                    report_error,
                )
                return
            raise report_error from activity_error
        self._parent._record_step(
            info, receipt, reservation_receipt_id=reservation_receipt_id
        )

    def _verified_receipt(
        self, info: activity.Info, response: dict[str, Any]
    ) -> ChioReceipt:
        """Parse a sidecar receipt and require the pinned kernel's signature."""
        raw = response.get("receipt") if isinstance(response, dict) else None
        executor = self._parent._executor
        try:
            if not isinstance(raw, dict) or raw.get("kernel_key") != executor.kernel_public_key:
                raise ValueError("receipt is not issued by the pinned kernel key")
            signing_bytes, id_input = _kernel_receipt_signing_bytes(raw)
            if hashlib.sha256(id_input).hexdigest() != raw.get("id"):
                raise ValueError("receipt id is not content-addressed")
            if executor.verify_kernel_signature(signing_bytes, raw["signature"]) is not True:
                raise ValueError("receipt signature does not verify")
            return ChioReceipt.model_validate(raw)
        except Exception as exc:
            raise _sidecar_error(
                f"Chio sidecar receipt for activity {info.activity_id!r} failed "
                f"verification: {exc}"
            ) from exc

    async def _reserve(
        self,
        client: ChioClientLike,
        *,
        info: activity.Info,
        grant: WorkflowGrant,
        tool_server: str,
        parameters: dict[str, Any],
        request_id: str,
    ) -> dict[str, Any]:
        """Reserve via ``/v1/evaluate``; a 403 becomes a synthetic deny receipt."""
        try:
            return await client.evaluate_tool_call_mediated(
                capability=grant.token.model_dump(
                    mode="json", by_alias=True, exclude_none=True
                ),
                tool_server=tool_server,
                tool_name=info.activity_type,
                parameters=parameters,
                request_id=request_id,
            )
        except ChioDeniedError as exc:
            receipt = _deny_receipt_from_error(
                info=info,
                capability_id=grant.capability_id,
                tool_server=tool_server,
                parameters=parameters,
                exc=exc,
            )
            self._parent._record_step(info, receipt)
            raise _denied_application_error(info, receipt) from exc
        except ChioConnectionError as exc:
            # The request never reached the sidecar, so no reservation exists
            # and Temporal's retry policy applies.
            raise ApplicationError(
                f"Chio sidecar unreachable: {exc}",
                type=SIDECAR_ERROR_TYPE,
                non_retryable=False,
            ) from exc
        except Exception as exc:
            raise _sidecar_error(f"Chio reservation failed: {exc}") from exc

    async def _start(
        self,
        client: ChioClientLike,
        *,
        info: activity.Info,
        grant: WorkflowGrant,
        tool_server: str,
        parameters: dict[str, Any],
        reservation: dict[str, Any],
        request_id: str,
    ) -> dict[str, Any]:
        """Commit the reservation and authenticate the dispatch authorization.

        Every failure is non-retryable: a lost start reply must never lead to
        an execution on a fresh reservation.
        """
        try:
            started = await client.start_mediated_execution(
                control_token=self._parent._control_token,
                execution_nonce=reservation["execution_nonce"],
                arguments=parameters,
            )
        except ChioDeniedError as exc:
            receipt = _deny_receipt_from_error(
                info=info,
                capability_id=grant.capability_id,
                tool_server=tool_server,
                parameters=parameters,
                exc=exc,
            )
            self._parent._record_step(info, receipt)
            raise _denied_application_error(info, receipt) from exc
        except Exception as exc:
            raise _sidecar_error(f"Chio caller start failed: {exc}") from exc

        authorization = started.get("authorization")
        try:
            ChioSignedCallerDispatchAuthorization.model_validate(authorization)
        except ValueError as exc:
            raise _sidecar_error(
                "Chio caller start returned a malformed dispatch authorization"
            ) from exc
        if not isinstance(authorization, dict):
            raise _sidecar_error("Chio caller start returned no dispatch authorization")
        body = authorization["authorization"]
        executor = self._parent._executor
        invocation = body["invocation"]
        expected_invocation = {
            "request_id": request_id,
            "capability_id": grant.capability_id,
            "server_id": tool_server,
            "tool_name": info.activity_type,
        }
        if (
            body["kernel_public_key"] != executor.kernel_public_key
            or body["executor"] != executor.identity
            or any(invocation[key] != value for key, value in expected_invocation.items())
        ):
            raise _sidecar_error(
                "Chio dispatch authorization does not bind this executor and activity"
            )
        try:
            signed = executor.verify_kernel_signature(
                signing_wrapper(CALLER_DISPATCH_AUTHORIZATION_SCHEMA, canonical_json_bytes(body)),
                authorization["signature"],
            )
        except Exception as exc:
            raise _sidecar_error(
                f"Chio dispatch authorization could not be verified: {exc}"
            ) from exc
        if signed is not True:
            raise _sidecar_error(
                "Chio dispatch authorization is not signed by the pinned kernel key"
            )
        return authorization

    async def _report(
        self,
        client: ChioClientLike,
        *,
        info: activity.Info,
        authorization: dict[str, Any],
        request_id: str,
        started_at: int,
        output: dict[str, Any],
    ) -> dict[str, Any]:
        """Sign and deliver the executor report; every failure is non-retryable."""
        executor = self._parent._executor
        try:
            completed_at = max(self._parent._clock_ms(), started_at)
            report_body = {
                "schema": CALLER_DELIVERY_REPORT_SCHEMA,
                "authorization_digest": hashlib.sha256(
                    canonical_json_bytes(authorization)
                ).hexdigest(),
                "executor": dict(executor.identity),
                "claim_id": request_id,
                "execution_started_at_unix_ms": started_at,
                "completed_at_unix_ms": completed_at,
                "output": output,
                "realized_cost": None,
            }
            report = {
                "report": report_body,
                "signature": executor.sign(
                    signing_wrapper(CALLER_DELIVERY_REPORT_SCHEMA, canonical_json_bytes(report_body))
                ),
            }
            return await client.report_mediated_execution(
                control_token=self._parent._control_token,
                authorization=authorization,
                report=report,
            )
        except ChioError as exc:
            if exc.code == "HTTP_409":
                raise _sidecar_error(
                    f"Chio sidecar rejected the caller report for activity "
                    f"{info.activity_id!r} (HTTP 409). The route does not name the "
                    "cause; one cause is a completed_at_unix_ms from this worker's "
                    "clock that is later than the kernel's trusted time, so keep "
                    "worker and sidecar clocks synchronized"
                ) from exc
            raise _sidecar_error(
                f"Chio caller report for activity {info.activity_id!r} failed: {exc}"
            ) from exc
        except Exception as exc:
            raise _sidecar_error(
                f"Chio caller report for activity {info.activity_id!r} failed: {exc}"
            ) from exc


def _request_id(info: activity.Info) -> str:
    """Attempt-scoped request id; a Temporal retry is a new reservation."""
    identity = json.dumps(
        [info.workflow_id, info.workflow_run_id, info.activity_id, info.attempt],
        separators=(",", ":"),
    )
    return "temporal:" + hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _require_live(
    info: activity.Info, authorization: dict[str, Any], now_ms: int
) -> None:
    body = authorization["authorization"]
    if not body["not_before_unix_ms"] <= now_ms < body["expires_at_unix_ms"]:
        raise _sidecar_error(
            f"Chio dispatch authorization for activity {info.activity_id!r} "
            "is outside its execution interval"
        )


def _result_sha256(converter: PayloadConverter, result: Any) -> str:
    """SHA-256 of the result's payload bytes under the worker's payload converter."""
    payloads = converter.to_payloads([result])
    return hashlib.sha256(payloads[0].data).hexdigest()


def _kernel_receipt_signing_bytes(raw: dict[str, Any]) -> tuple[bytes, bytes]:
    """Receipt signing-wrapper bytes and receipt-id input bytes.

    The id input is every receipt field except ``id``, ``signature`` and
    ``bbs_signature``; the signature covers the ``chio.receipt.v1`` wrapper
    of the canonical ``{"id", "body": <id input>, "bbs_signature"?}``.
    """
    id_input = {
        key: value
        for key, value in raw.items()
        if key not in {"id", "signature", "bbs_signature"}
    }
    signing: dict[str, Any] = {"id": raw["id"], "body": id_input}
    if raw.get("bbs_signature") is not None:
        signing["bbs_signature"] = raw["bbs_signature"]
    return (
        signing_wrapper(CHIO_RECEIPT_SCHEMA, canonical_json_bytes(signing)),
        canonical_json_bytes(id_input),
    )


def _sidecar_error(message: str) -> ApplicationError:
    return ApplicationError(message, type=SIDECAR_ERROR_TYPE, non_retryable=True)


def _fixed_positional_param_names(fn: Callable[..., Any] | None) -> tuple[str, ...]:
    """Return fixed positional parameter names from ``fn``, if introspectable."""
    if fn is None:
        return ()
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return ()
    return tuple(
        param.name
        for param in sig.parameters.values()
        if param.kind
        in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
    )


def _temporal_dict_lift(
    fn: Callable[..., Any] | None,
    *,
    tool_name: str,
    redacted_args: Sequence[Any],
    table_slots: tuple[str, ...],
    policy: RedactionPolicy,
) -> list[Any] | None:
    """Lift redacted positional values into Temporal's dict wire shape."""
    sig_names = _fixed_positional_param_names(fn)
    if sig_names:
        alias_map = build_alias_map(
            sig_names,
            table_slots,
            policy.body_fields.get(tool_name) or (),
            allow_ambiguous_cycling=tool_name in DEFAULT_TOOL_POSITIONAL_NAMES,
        )
        canonical_dict: dict[str, Any] = {}
        for idx, sig_name in enumerate(sig_names):
            if idx >= len(redacted_args):
                break
            canonical_name = alias_map.get(sig_name, sig_name)
            canonical_dict[canonical_name] = redacted_args[idx]
        extras = list(redacted_args[len(sig_names) :])
        return [canonical_dict, *extras]

    if len(redacted_args) >= len(table_slots):
        prefix_count = len(table_slots)
        bound = dict(zip(table_slots, redacted_args[:prefix_count], strict=True))
        extras = list(redacted_args[prefix_count:])
        return [bound, *extras]
    return None


def _activity_parameters(
    input: ExecuteActivityInput,
    *,
    tool_name: str | None = None,
    policy: RedactionPolicy | None = None,
) -> dict[str, Any]:
    """Build the sidecar payload, redacting body fields where possible.

    Positional activities delegate to
    :func:`chio_adapter_base.redact.bind_and_redact` using the activity
    callable supplied by the Temporal worker, then lift the redacted result
    into Temporal's dict wire shape.
    """
    args_list = list(input.args)
    if policy is None:
        return {"args": args_list}

    # Shape 1: single dict.
    if len(args_list) == 1 and isinstance(args_list[0], dict):
        _, redacted_kwargs = bind_and_redact(
            input.fn,
            (),
            args_list[0],
            tool_name=tool_name or "",
            policy=policy,
        )
        args_list[0] = redacted_kwargs
        return {"args": args_list}

    effective_tool_name = tool_name or ""
    redacted_args, redacted_kwargs = bind_and_redact(
        input.fn,
        args_list,
        {},
        tool_name=effective_tool_name,
        policy=policy,
    )
    if redacted_kwargs:
        return {"args": list(redacted_args), "kwargs": redacted_kwargs}

    table_slots = DEFAULT_TOOL_POSITIONAL_NAMES.get(effective_tool_name)
    if (
        table_slots is not None
        and effective_tool_name in policy.body_fields
        and redacted_args
    ):
        lifted = _temporal_dict_lift(
            input.fn,
            tool_name=effective_tool_name,
            redacted_args=redacted_args,
            table_slots=table_slots,
            policy=policy,
        )
        if lifted is not None:
            return {"args": lifted}

    return {"args": list(redacted_args)}


def _denied_application_error(
    info: activity.Info, receipt: ChioReceipt
) -> ApplicationError:
    reason = receipt.decision.reason or "denied by Chio kernel"
    guard = receipt.decision.guard or "unknown"
    tool_error = ChioTemporalError(
        reason,
        activity_type=info.activity_type,
        activity_id=info.activity_id,
        workflow_id=info.workflow_id,
        run_id=info.workflow_run_id,
        guard=guard,
        reason=reason,
        receipt_id=receipt.id,
        decision=receipt.decision.model_dump(exclude_none=True),
    )
    return ApplicationError(
        f"Chio capability denied: {reason}",
        tool_error.to_dict(),
        type=DENIED_ERROR_TYPE,
        non_retryable=True,
    )


def _deny_receipt_from_error(
    *,
    info: activity.Info,
    capability_id: str,
    tool_server: str,
    parameters: dict[str, Any],
    exc: ChioDeniedError,
) -> ChioReceipt:
    """Synthesise a deny :class:`ChioReceipt` for HTTP-403 sidecar responses."""
    canonical_parameters = json.dumps(
        parameters,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    parameter_hash = hashlib.sha256(canonical_parameters).hexdigest()
    fallback_receipt_id = (
        f"chio-temporal-deny-{info.workflow_id}-{info.activity_id}-{int(time.time())}"
    )
    receipt_id_source = exc.receipt_id or fallback_receipt_id
    if exc.receipt_id and _is_sha256_hex(exc.receipt_id):
        receipt_id = exc.receipt_id
    else:
        receipt_id = hashlib.sha256(receipt_id_source.encode("utf-8")).hexdigest()
    synthetic_hash = hashlib.sha256(
        f"synthetic-deny-receipt:{receipt_id_source}".encode()
    ).hexdigest()
    metadata = {
        "synthetic": True,
        "reason_code": exc.reason_code,
        "requested_action": exc.requested_action,
        "required_scope": exc.required_scope,
        "granted_scope": exc.granted_scope,
        "hint": exc.hint,
        "docs_url": exc.docs_url,
    }
    if exc.receipt_id:
        metadata["sidecar_receipt_id"] = exc.receipt_id
    return ChioReceipt(
        id=receipt_id,
        timestamp=int(time.time()),
        capability_id=capability_id,
        tool_server=exc.tool_server or tool_server,
        tool_name=exc.tool_name or info.activity_type,
        action=ToolCallAction(
            parameters=dict(parameters),
            parameter_hash=parameter_hash,
        ),
        decision=Decision.deny(
            reason=exc.reason or exc.message or "Chio capability denied",
            guard=exc.guard or "ChioDeniedError",
        ),
        receipt_kind="mediated_decision",
        boundary_class="prevent",
        observation_outcome=None,
        tool_origin="caller_executed",
        redaction_mode="none",
        actor_chain=[],
        content_hash=synthetic_hash,
        policy_hash=synthetic_hash,
        evidence=[],
        trust_level="mediated",
        metadata=metadata,
        kernel_key="0" * 64,
        signature="0" * 128,
    )


def _denied_application_error_from_config(
    info: activity.Info, *, reason: str, message: str
) -> ApplicationError:
    tool_error = ChioTemporalError(
        message,
        activity_type=info.activity_type,
        activity_id=info.activity_id,
        workflow_id=info.workflow_id,
        run_id=info.workflow_run_id,
        reason=reason,
    )
    return ApplicationError(
        message,
        tool_error.to_dict(),
        type=DENIED_ERROR_TYPE,
        non_retryable=True,
    )

__all__ = [
    "DENIED_ERROR_TYPE",
    "SIDECAR_ERROR_TYPE",
    "ActivityGrantOverride",
    "ChioActivityInterceptor",
]
