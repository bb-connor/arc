# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: b55a701e44e8cab56a79619656a773cbb3b9fd63c65594e997f7efc988bc178c
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class DeliveryAck(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    acknowledgement: str
    receiptId: str
    requestHash: str
    requestId: str
    resultHash: str
    schema_: str = Field(..., alias="schema")


class Error(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    code: int
    message: str


class Action(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    parameter_hash: str
    parameters: Any


class Decision(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    verdict: str


class DispatchLaunch(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    native_launch: None
    worker_profile: None


class ProviderAttempt(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    attempt_id: str
    operation_id: str
    transport_id: str
    transport_key_epoch: int


class StoreFence(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    lease_id: str
    owner_epoch: int
    store_uuid: str


class RetainedDispatchCommit(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    committed_version: int
    coordinator_lease_epoch: int
    coordinator_lease_id: str
    dispatch_launch: DispatchLaunch
    provider_attempt: ProviderAttempt
    store_fence: StoreFence


class AdmissionOperation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    compensation_status: str | None = None
    coordinator_lease_epoch: int | None = None
    coordinator_lease_id: str | None = None
    operation_id: str | None = None
    projected_dispatch_state: str
    projected_operation_version: int | None = None
    projected_state: str
    request_binding_hash: str | None = None
    request_id: str
    request_namespace_digest: str | None = None
    retained_dispatch_commit: RetainedDispatchCommit | None = None
    schema_: str = Field(..., alias="schema")
    store_fence: StoreFence | None = None
    tool_outcome_id: str
    tool_outcome_version: int | None = None
    trusted_time_unix_ms: int | None = None


class Attribution(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    delegation_depth: int | None = None
    grant_index: int | None = None
    issuer_key: str | None = None
    subject_key: str


class ChioRuntime(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    identity_disposition: str


class ReceiptContext(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    request_id: str
    request_namespace_digest: str | None = None


class Metadata(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    admission_operation: AdmissionOperation
    attribution: Attribution
    chio_receipt_signing_nonce: str
    chio_runtime: ChioRuntime | None = None
    receipt_context: ReceiptContext


class Receipt(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    action: Action
    boundary_class: str
    capability_id: str
    content_hash: str
    decision: Decision
    id: str
    kernel_key: str
    metadata: Metadata
    policy_hash: str
    receipt_kind: str
    redaction_mode: str
    signature: str
    timestamp: int
    tool_name: str
    tool_origin: str
    tool_server: str
    trust_level: str


class TerminalState(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    state: str


class Chio(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    decision: str
    receipt: Receipt
    receiptId: str
    terminalState: TerminalState


class ChioDelivery(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    acknowledgement: str
    receiptId: str
    requestHash: str
    requestId: str
    resultHash: str
    schema_: str = Field(..., alias="schema")


class ContentItem(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    text: str
    type: str


class Output(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    content: list[ContentItem]
    isError: bool
    numbers: list[float] | None = None
    structuredContent: Any | None = None


class RetainedDispatchCommit2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    committed_version: int
    coordinator_lease_epoch: int
    coordinator_lease_id: str
    dispatch_launch: DispatchLaunch
    provider_attempt: ProviderAttempt
    store_fence: StoreFence


class AdmissionOperation2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    compensation_status: str | None = None
    coordinator_lease_epoch: int | None = None
    coordinator_lease_id: str | None = None
    operation_id: str | None = None
    projected_dispatch_state: str
    projected_operation_version: int | None = None
    projected_state: str
    request_binding_hash: str | None = None
    request_id: str
    request_namespace_digest: str | None = None
    retained_dispatch_commit: RetainedDispatchCommit2 | None = None
    schema_: str = Field(..., alias="schema")
    store_fence: StoreFence | None = None
    tool_outcome_id: str
    tool_outcome_version: int | None = None
    trusted_time_unix_ms: int | None = None


class Metadata6(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    admission_operation: AdmissionOperation2
    attribution: Attribution
    chio_receipt_signing_nonce: str
    chio_runtime: ChioRuntime | None = None
    receipt_context: ReceiptContext


class Receipt6(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    action: Action
    boundary_class: str
    capability_id: str
    content_hash: str
    decision: Decision
    id: str
    kernel_key: str
    metadata: Metadata6
    policy_hash: str
    receipt_kind: str
    redaction_mode: str
    signature: str
    timestamp: int
    tool_name: str
    tool_origin: str
    tool_server: str
    trust_level: str


class ChioEvidence(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    output: Output
    outputKind: str
    receipt: Receipt6
    requestId: str
    schema_: str = Field(..., alias="schema")
    terminalState: str


class BoundTo(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    capability_id: str
    parameter_hash: str
    request_id: str
    subject_id: str
    tool_name: str
    tool_server: str


class Nonce(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    bound_to: BoundTo
    expires_at: int
    issued_at: int
    nonce_id: str
    schema_: str = Field(..., alias="schema")


class ChioExecutionNonce(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    nonce: Nonce
    signature: str


class FieldMeta(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    chio: Chio
    chioDelivery: ChioDelivery
    chioEvidence: ChioEvidence
    chioExecutionNonce: ChioExecutionNonce | None = None


class Result(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    field_meta: FieldMeta | None = Field(None, alias="_meta")
    content: list[ContentItem] | None = None
    isError: bool | None = None
    numbers: list[float] | None = None
    ownerResult: bool | None = None
    structuredContent: Any | None = None


class Response(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    error: Error | None = None
    id: int
    jsonrpc: str
    result: Result | None = None


class ChioMcpSessionCredentialCallSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    capabilityIds: list[str]
    deliveryAck: DeliveryAck | None = None
    parameterHash: str
    requestHash: str
    requestId: str
    reservationId: str
    response: Response | None = None
    schema_: Literal["chio.mcp.session-credential-call.v1"] = Field(..., alias="schema")
    serverId: str
    sessionId: str
    startedAt: int
    state: str
    subjectKey: str
    toolName: str
