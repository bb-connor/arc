# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: cff572cd647726251b5cdb39013d235e07916c80b9a46e5bc035b374e0fd7041
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class EvidenceItem(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    details: str | None = None
    guard_name: str
    verdict: bool


class ChioHttpReceiptV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    source: str


class Candidate(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    available: bool
    routeId: str
    selectedProtocols: list[str]
    targetProtocol: str


class RouteSelection(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    candidates: list[Candidate]
    decision: str
    requestedTargetProtocol: str
    routeSelectionId: str
    selectedProtocols: list[str]
    selectedRouteId: str
    selectedTargetProtocol: str
    sourceProtocol: str


class Step(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    observed_at: str
    payload: str
    phase: str
    pod_name: str


class Metadata(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    chio_decision_receipt_id: str | None = None
    chio_http_receipt_v1: ChioHttpReceiptV1 | None = None
    chio_http_status_scope: str | None = None
    chio_kernel_receipt_id: str | None = None
    chio_receipt_signing_nonce: str | None = None
    completed_at: str | None = None
    job_name: str | None = None
    job_uid: str | None = None
    namespace: str | None = None
    outcome: str | None = None
    route_selection: RouteSelection | None = None
    started_at: str | None = None
    steps: list[Step] | None = None
    submission_kind: str | None = None
    tags: list[str] | None = None
    trace_id: str | None = None


class Verdict(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    guard: str | None = None
    http_status: int | None = None
    reason: str | None = None
    verdict: str


class ChioHttpReceiptSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    boundary_class: str
    caller_identity_hash: str
    capability_id: str | None = None
    content_hash: str
    evidence: list[EvidenceItem] | None = None
    id: str
    kernel_key: str
    metadata: str | Metadata | None = None
    method: str
    observation_outcome: str | None = None
    policy_hash: str
    receipt_kind: str
    redaction_mode: str
    request_id: str
    response_status: int
    route_pattern: str
    session_id: str | None = None
    timestamp: int
    tool_origin: str
    trust_level: str
    verdict: Verdict
