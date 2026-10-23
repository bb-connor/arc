"""Contract double for the sidecar's mediated ``chio.caller-delivery.v1`` route.

:class:`MediatedContractClient` implements the three
:class:`chio_sdk.client.ChioClient` methods the interceptor uses with the
real keyword signatures, returns the response shapes the real client
validates, and enforces the server-side rules the kernel applies:
control-token gating, exact start arguments, idempotent start, report
binding to the committed authorization and executor signature checks.

The id-only evaluation methods raise, so any call into them fails the test.

Signatures are modelled with SHA-512 over a role-tagged message. They are
the right length for the wire schema and bind the exact canonical bytes,
but they are not Ed25519; ``test_kernel_golden_vector.py`` checks the
canonical bytes, digests and Ed25519 signatures against vectors produced by
the Rust kernel.
"""

from __future__ import annotations

import hashlib
import itertools
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from types import SimpleNamespace
from typing import Any

from chio_sdk.errors import ChioDeniedError, ChioError
from chio_sdk.models import CapabilityToken, ChioScope
from temporalio import activity
from temporalio.converter import DataConverter, PayloadConverter

from chio_temporal import ChioActivityInterceptor
from chio_temporal.executor import canonical_json_bytes, signing_wrapper

CONTROL_TOKEN = "sidecar-control-test-token"
FIXED_NOW_MS = 1_700_000_000_000
PROTOCOL = "chio.caller-delivery.v1"
KERNEL_PUBLIC_KEY = "03" * 32
DIGEST = "a" * 64


def _role_signature(role: str, message: bytes) -> str:
    return hashlib.sha512(role.encode("utf-8") + b":" + message).hexdigest()


class ContractExecutor:
    """Executor key material double implementing ``CallerExecutor``."""

    def __init__(self, *, executor_id: str = "temporal-test-executor") -> None:
        self._identity = {
            "executor_id": executor_id,
            "public_key": "01" * 32,
            "key_epoch": 1,
        }
        self.signed: list[bytes] = []

    @property
    def identity(self) -> dict[str, Any]:
        return dict(self._identity)

    @property
    def kernel_public_key(self) -> str:
        return KERNEL_PUBLIC_KEY

    def sign(self, message: bytes) -> str:
        self.signed.append(message)
        return _role_signature(f"executor:{self._identity['executor_id']}", message)

    def verify_kernel_signature(self, message: bytes, signature: str) -> bool:
        return signature == _role_signature("kernel", message)


Policy = Callable[[str, dict[str, Any]], str]


def scope_policy(tool_name: str, capability: dict[str, Any]) -> str:
    """Allow a tool only when the presented signed token's scope grants it."""
    grants = capability.get("scope", {}).get("grants", [])
    if any(grant.get("tool_name") in (tool_name, "*") for grant in grants):
        return "allow"
    return "deny"


class MediatedContractClient:
    """Stand-in for :class:`chio_sdk.client.ChioClient` on the mediated route."""

    def __init__(
        self,
        *,
        policy: Policy = scope_policy,
        executor: ContractExecutor | None = None,
        window_ms: tuple[int, int] = (FIXED_NOW_MS - 1_000, FIXED_NOW_MS + 60_000),
    ) -> None:
        self.policy = policy
        self.executor = executor or ContractExecutor()
        self.window_ms = window_ms
        self.calls: list[SimpleNamespace] = []
        self.reports: list[dict[str, Any]] = []
        self._ids = itertools.count(1)
        self._reservations: dict[str, dict[str, Any]] = {}
        self._started: dict[str, dict[str, Any]] = {}
        self._finalized: dict[str, dict[str, Any]] = {}
        self.authorization_overrides: dict[str, Any] = {}
        self.start_error: Exception | None = None
        self.report_error: Exception | None = None
        self.report_status = "reconciled"
        self.revoked: set[str] = set()
        self.start_denied = False
        self.receipt_tamper: Callable[[dict[str, Any]], None] | None = None

    async def __aenter__(self) -> MediatedContractClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        return None

    async def close(self) -> None:
        return None

    @property
    def open_holds(self) -> set[str]:
        """Reservations committed by start but never finalized by a report."""
        return set(self._started) - set(self._finalized)

    def methods(self) -> list[str]:
        return [call.method for call in self.calls]

    async def create_capability(
        self,
        *,
        subject: str,
        scope: ChioScope,
        ttl_seconds: int = 3600,
    ) -> CapabilityToken:
        """Issue a token; a non-hex ``subject`` label is hashed into a key-shaped id."""
        if len(subject) != 64 or any(c not in "0123456789abcdef" for c in subject):
            subject = hashlib.sha256(subject.encode("utf-8")).hexdigest()
        return CapabilityToken.model_validate(
            {
                "schema": "chio.capability.v1",
                "id": f"cap-{next(self._ids)}",
                "issuer": "04" * 32,
                "subject": subject,
                "scope": scope.model_dump(mode="json", exclude_none=True),
                "issued_at": 1_700_000_000,
                "expires_at": 1_700_000_000 + ttl_seconds,
                "signature": "05" * 64,
            }
        )

    async def attenuate_capability(
        self,
        token: CapabilityToken,
        *,
        new_scope: ChioScope,
    ) -> CapabilityToken:
        if not new_scope.is_subset_of(token.scope):
            raise ChioError("attenuation must narrow scope", code="VALIDATION_ERROR")
        return await self.create_capability(subject=token.subject, scope=new_scope)

    async def evaluate_tool_call(self, **kwargs: Any) -> Any:
        self.calls.append(SimpleNamespace(method="evaluate_tool_call", **kwargs))
        raise AssertionError("the id-only evaluate path must never be called")

    async def evaluate_tool_call_advisory(self, **kwargs: Any) -> Any:
        self.calls.append(SimpleNamespace(method="evaluate_tool_call_advisory", **kwargs))
        raise AssertionError("advisory evaluation is not execution authorization")

    async def evaluate_tool_call_mediated(
        self,
        *,
        capability: dict,
        tool_server: str,
        tool_name: str,
        parameters: dict,
        request_id: str | None = None,
        governed_intent: dict[str, Any] | None = None,
        approval_id: str | None = None,
        dpop_proof: dict[str, Any] | None = None,
    ) -> dict:
        self.calls.append(
            SimpleNamespace(
                method="evaluate_tool_call_mediated",
                capability=capability,
                tool_server=tool_server,
                tool_name=tool_name,
                parameters=parameters,
                request_id=request_id,
            )
        )
        return self.reserve(
            capability=capability,
            tool_server=tool_server,
            tool_name=tool_name,
            parameters=parameters,
            request_id=request_id,
        )

    async def start_mediated_execution(
        self,
        *,
        control_token: str,
        execution_nonce: dict[str, Any],
        arguments: dict[str, Any],
        credentials: dict[str, Any] | None = None,
    ) -> dict:
        self.calls.append(
            SimpleNamespace(
                method="start_mediated_execution",
                execution_nonce=execution_nonce,
                arguments=arguments,
            )
        )
        if self.start_error is not None:
            raise self.start_error
        return self.start(
            control_token=control_token,
            execution_nonce=execution_nonce,
            arguments=arguments,
        )

    async def report_mediated_execution(
        self,
        *,
        control_token: str,
        authorization: dict[str, Any],
        report: dict[str, Any],
    ) -> dict:
        self.calls.append(
            SimpleNamespace(method="report_mediated_execution", report=report)
        )
        if self.report_error is not None:
            raise self.report_error
        return self.report(
            control_token=control_token, authorization=authorization, report=report
        )

    def reserve(
        self,
        *,
        capability: dict[str, Any],
        tool_server: str,
        tool_name: str,
        parameters: dict[str, Any],
        request_id: str | None,
    ) -> dict[str, Any]:
        if (
            capability.get("schema") != "chio.capability.v1"
            or not capability.get("signature")
            or not capability.get("id")
        ):
            raise ChioError("capability must be a full signed token", code="HTTP_400")
        verdict = self.policy(tool_name, capability)
        receipt = self._receipt(
            capability_id=capability["id"],
            tool_server=tool_server,
            tool_name=tool_name,
            parameters=parameters,
            verdict=verdict,
        )
        if verdict == "deny_403":
            raise ChioDeniedError(
                "denied",
                guard="RevocationGuard",
                reason="capability has been revoked",
                reason_code="chio_capability_revoked",
            )
        if verdict != "allow":
            return {
                "status": "deny" if verdict == "deny" else "pending_approval",
                "evidence_persisted": True,
                "protocol": PROTOCOL,
                "execution_authorized": False,
                "start_required": False,
                "receipt": receipt,
                "execution_nonce": None,
            }
        nonce_id = f"nonce-{next(self._ids)}"
        nonce = {
            "nonce": {
                "schema": "chio.operation_execution_nonce.v1",
                "nonce_id": nonce_id,
                "issued_at": FIXED_NOW_MS // 1000,
                "expires_at": FIXED_NOW_MS // 1000 + 30,
                "bound_to": {
                    "subject_id": capability["subject"],
                    "request_id": request_id,
                    "capability_id": capability["id"],
                    "tool_server": tool_server,
                    "tool_name": tool_name,
                    "parameter_hash": hashlib.sha256(
                        canonical_json_bytes(parameters)
                    ).hexdigest(),
                },
            },
            "signature": "11" * 64,
            "operation_id": DIGEST,
        }
        self._reservations[nonce_id] = {
            "capability_id": capability["id"],
            "tool_server": tool_server,
            "tool_name": tool_name,
            "parameters": parameters,
            "request_id": request_id,
        }
        return {
            "status": "reserved",
            "evidence_persisted": True,
            "protocol": PROTOCOL,
            "execution_authorized": False,
            "start_required": True,
            "receipt": receipt,
            "execution_nonce": nonce,
        }

    def start(
        self,
        *,
        control_token: str,
        execution_nonce: dict[str, Any],
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        if control_token != CONTROL_TOKEN:
            raise ChioDeniedError("sidecar control token required")
        if execution_nonce["nonce"]["bound_to"]["capability_id"] in self.revoked:
            # The start route answers a revoked capability with its generic 409.
            raise ChioError(
                "Chio sidecar returned 409: chio_caller_delivery_rejected", code="HTTP_409"
            )
        if self.start_denied:
            # A kernel deny at start is HTTP 403, which ChioClient raises as
            # ChioDeniedError without the receipt body.
            raise ChioDeniedError("denied", reason="denied at caller start")
        nonce_id = execution_nonce["nonce"]["nonce_id"]
        reservation = self._reservations.get(nonce_id)
        if reservation is None or reservation["parameters"] != arguments:
            raise ChioError("caller delivery rejected", code="HTTP_409")
        if nonce_id in self._started:
            return self._started[nonce_id]
        body = {
            "schema": "chio.caller-dispatch-authorization.v1",
            "kernel_public_key": KERNEL_PUBLIC_KEY,
            "executor": self.executor.identity,
            "invocation": {
                "operation_id": DIGEST,
                "request_id": reservation["request_id"],
                "request_binding_hash": DIGEST,
                "capability_id": reservation["capability_id"],
                "capability_digest": DIGEST,
                "server_id": reservation["tool_server"],
                "tool_name": reservation["tool_name"],
                "parameters_digest": DIGEST,
            },
            "committed": {
                "execution_nonce_id": nonce_id,
                "budget_hold_id": f"hold-{nonce_id}",
                "frozen_context_digest": DIGEST,
                "dispatch_commit": {
                    "committed_version": 1,
                    "coordinator_lease_id": "coordinator",
                    "coordinator_lease_epoch": 1,
                    "store_fence": {
                        "store_uuid": "store",
                        "lease_id": "lease",
                        "owner_epoch": 1,
                    },
                    "provider_attempt": {
                        "operation_id": DIGEST,
                        "attempt_id": f"attempt-{nonce_id}",
                        "transport_id": f"caller-report:{reservation['tool_server']}",
                        "transport_key_epoch": 1,
                    },
                    "dispatch_launch": {"native_launch": None, "worker_profile": None},
                },
            },
            "not_before_unix_ms": self.window_ms[0],
            "expires_at_unix_ms": self.window_ms[1],
        }
        body.update(self.authorization_overrides)
        authorization = {
            "authorization": body,
            "signature": _role_signature(
                "kernel",
                signing_wrapper("chio.caller-dispatch-authorization.v1", canonical_json_bytes(body)),
            ),
        }
        started = {
            "status": "dispatch_committed",
            "protocol": PROTOCOL,
            "authorization": authorization,
        }
        self._started[nonce_id] = started
        return started

    def report(
        self,
        *,
        control_token: str,
        authorization: dict[str, Any],
        report: dict[str, Any],
    ) -> dict[str, Any]:
        if control_token != CONTROL_TOKEN:
            raise ChioDeniedError("sidecar control token required")
        nonce_id = authorization["authorization"]["committed"]["execution_nonce_id"]
        started = self._started.get(nonce_id)
        body = report["report"]
        executor_id = self.executor.identity["executor_id"]
        expected_signature = _role_signature(
            f"executor:{executor_id}",
            signing_wrapper("chio.caller-delivery-report.v1", canonical_json_bytes(body)),
        )
        window = authorization["authorization"]
        if (
            started is None
            or started["authorization"] != authorization
            or body["schema"] != "chio.caller-delivery-report.v1"
            or body["authorization_digest"]
            != hashlib.sha256(canonical_json_bytes(authorization)).hexdigest()
            or body["executor"] != self.executor.identity
            or report["signature"] != expected_signature
            or not window["not_before_unix_ms"]
            <= body["execution_started_at_unix_ms"]
            < window["expires_at_unix_ms"]
            or body["completed_at_unix_ms"] < body["execution_started_at_unix_ms"]
        ):
            raise ChioError("caller delivery rejected", code="HTTP_409")
        if nonce_id in self._finalized:
            if self._finalized[nonce_id]["report"] != report:
                raise ChioError("conflicting caller report", code="HTTP_409")
            return self._finalized[nonce_id]["response"]
        reservation = self._reservations[nonce_id]
        verdict = "allow" if self.report_status == "reconciled" else "deny"
        response = {
            "status": self.report_status,
            "protocol": PROTOCOL,
            "receipt": self._receipt(
                capability_id=reservation["capability_id"],
                tool_server=reservation["tool_server"],
                tool_name=reservation["tool_name"],
                parameters=reservation["parameters"],
                verdict=verdict,
            ),
            "output": body["output"] if verdict == "allow" else None,
            "execution_authorized": False,
        }
        self._finalized[nonce_id] = {"report": report, "response": response}
        self.reports.append(report)
        return response

    def _receipt(
        self,
        *,
        capability_id: str,
        tool_server: str,
        tool_name: str,
        parameters: dict[str, Any],
        verdict: str,
    ) -> dict[str, Any]:
        content_hash = hashlib.sha256(f"content-{next(self._ids)}".encode()).hexdigest()
        if verdict == "allow":
            decision: dict[str, Any] = {"verdict": "allow"}
        elif verdict == "pending_approval":
            decision = {
                "verdict": "deny",
                "reason": "approval required",
                "guard": "ApprovalGuard",
            }
        else:
            decision = {
                "verdict": "deny",
                "reason": f"tool {tool_name!r} not in capability scope",
                "guard": "ScopeGuard",
            }
        body = {
            "timestamp": FIXED_NOW_MS // 1000,
            "capability_id": capability_id,
            "tool_server": tool_server,
            "tool_name": tool_name,
            "action": {
                "parameters": parameters,
                "parameter_hash": hashlib.sha256(
                    canonical_json_bytes(parameters)
                ).hexdigest(),
            },
            "decision": decision,
            "receipt_kind": "mediated_decision",
            "boundary_class": "prevent",
            "tool_origin": "caller_executed",
            "redaction_mode": "none",
            "content_hash": content_hash,
            "policy_hash": "4" * 64,
            "trust_level": "mediated",
            "kernel_key": KERNEL_PUBLIC_KEY,
        }
        receipt_id = hashlib.sha256(canonical_json_bytes(body)).hexdigest()
        signing = signing_wrapper(
            "chio.receipt.v1", canonical_json_bytes({"id": receipt_id, "body": body})
        )
        receipt = {"id": receipt_id, **body, "signature": _role_signature("kernel", signing)}
        if self.receipt_tamper is not None:
            self.receipt_tamper(receipt)
        return receipt


def contract_interceptor(
    chio: MediatedContractClient, **kwargs: Any
) -> ChioActivityInterceptor:
    """Interceptor wired to ``chio`` with the contract executor and a fixed clock."""
    kwargs.setdefault("clock_ms", lambda: FIXED_NOW_MS)
    return ChioActivityInterceptor(
        executor=chio.executor,
        control_token=CONTROL_TOKEN,
        chio_client=chio,
        **kwargs,
    )


@contextmanager
def activity_context(
    info: activity.Info, converter: PayloadConverter | None = None
) -> Iterator[None]:
    """Patch ``activity.info()`` and ``activity.payload_converter()`` for one call."""
    original_info = activity.info
    original_converter = activity.payload_converter
    chosen = converter or DataConverter.default.payload_converter
    activity.info = lambda: info  # type: ignore[assignment]
    activity.payload_converter = lambda: chosen  # type: ignore[assignment]
    try:
        yield
    finally:
        activity.info = original_info  # type: ignore[assignment]
        activity.payload_converter = original_converter  # type: ignore[assignment]
