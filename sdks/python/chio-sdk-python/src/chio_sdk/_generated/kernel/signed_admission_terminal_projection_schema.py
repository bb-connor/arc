# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: f98e61fca1094fc6e2763340dae554e56c34e2d18e5720c6f3a7f9b589406726
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class AuthorizationConsumption(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authorizationReceiptId: str
    consumedAtUnixMs: int
    consumerReceiptId: str
    parameterHash: str
    requestId: str
    sessionId: str
    tenantId: str | None = None
    toolCallId: str


class StoreFence(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    lease_id: str
    owner_epoch: int
    store_uuid: str


class Context(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    coordinator_lease_epoch: int
    coordinator_lease_id: str
    expected_operation_version: int
    operation_id: str
    request_id: str
    store_fence: StoreFence
    trusted_time_unix_ms: int


class Pending(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    next_visible_at_ms: int


class Observer(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    pending: Pending
    receipt_id: str


class Record(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    canonical_json: str
    kind: str
    record_digest: str
    record_id: str


class BrokerAttempt(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    attempt_id: str
    operation_id: str
    transport_id: str
    transport_key_epoch: int


class Attachment(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    ApprovalSetHash: str | None = None
    BrokerAttempt_1: BrokerAttempt | None = Field(None, alias="BrokerAttempt")
    BudgetHoldId: str | None = None
    ChannelReservationDigest: str | None = None
    ChannelReservationProposalDigest: str | None = None
    ExecutionNonceId: str | None = None
    ExecutionNonceIssuanceDigest: str | None = None
    ExecutionNoncePreflightDigest: str | None = None
    PaymentParticipantId: str | None = None
    SupplementalAuthorizationDigest: str | None = None
    ThresholdProposalHash: str | None = None
    ToolOutcomeId: str | None = None


class ParticipantRequirements(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    approval: bool
    authorization_consumption: bool
    broker_attempt: bool
    budget_capture: bool
    channel: bool | None = None
    execution_nonce: bool
    obligation: bool
    observation_attempt_zero: bool
    outcome_eligibility: bool
    payment: bool
    supplemental_authorization: bool | None = None


class RequestBinding(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    action_parameter_hash: str
    immutable_request_hash: str
    participant_requirements: ParticipantRequirements
    request_binding_hash: str


class Binding(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authenticated_tenant_id: str
    authorization_capability_hash: str
    capability_id: str
    coordinator_authority_id: str
    effect_class: str
    kind: str
    operation_id: str
    policy_hash: str
    request_binding: RequestBinding
    request_id: str
    request_namespace_digest: str


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


class DispatchCommit(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    committed_version: int
    coordinator_lease_epoch: int
    coordinator_lease_id: str
    dispatch_launch: DispatchLaunch
    provider_attempt: ProviderAttempt | None = None
    store_fence: StoreFence


class SourceOperation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    attachments: list[Attachment]
    binding: Binding
    coordinator_lease_epoch: int
    dispatch_commit: DispatchCommit | None = None
    dispatch_state: str
    last_error: None
    schema_: str = Field(..., alias="schema")
    state: str
    terminal_replay: None
    version: int


class Attachment3(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    ApprovalSetHash: str | None = None
    BrokerAttempt_1: BrokerAttempt | None = Field(None, alias="BrokerAttempt")
    BudgetHoldId: str | None = None
    ChannelReservationDigest: str | None = None
    ChannelReservationProposalDigest: str | None = None
    ExecutionNonceId: str | None = None
    ExecutionNonceIssuanceDigest: str | None = None
    ExecutionNoncePreflightDigest: str | None = None
    PaymentParticipantId: str | None = None
    SupplementalAuthorizationDigest: str | None = None
    ThresholdProposalHash: str | None = None
    ToolOutcomeId: str | None = None


class RequestBinding4(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    action_parameter_hash: str
    immutable_request_hash: str
    participant_requirements: ParticipantRequirements
    request_binding_hash: str


class Binding8(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authenticated_tenant_id: str
    authorization_capability_hash: str
    capability_id: str
    coordinator_authority_id: str
    effect_class: str
    kind: str
    operation_id: str
    policy_hash: str
    request_binding: RequestBinding4
    request_id: str
    request_namespace_digest: str


class DispatchCommit6(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    committed_version: int
    coordinator_lease_epoch: int
    coordinator_lease_id: str
    dispatch_launch: DispatchLaunch
    provider_attempt: ProviderAttempt | None = None
    store_fence: StoreFence


class EconomicMutation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    projection_digest: str
    result_digest: str
    result_id: str


class Incident(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    incident_id: str
    projection_digest: str


class Receipt(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    projection_digest: str
    receipt_id: str


class TerminalReplay(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    economic_mutation: EconomicMutation | None = None
    incident: Incident | None = None
    receipt: Receipt | None = None


class TerminalOperation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    attachments: list[Attachment3]
    binding: Binding8
    coordinator_lease_epoch: int
    dispatch_commit: DispatchCommit6 | None = None
    dispatch_state: str
    last_error: None
    schema_: str = Field(..., alias="schema")
    state: str
    terminal_replay: TerminalReplay
    version: int


class ChioSignedAdmissionTerminalProjectionSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authorization_consumption: AuthorizationConsumption | None = None
    context: Context
    manifest_json: str
    observer: Observer | None = None
    projection_json: str
    records: list[Record]
    schema_: Literal["chio.signed-admission-terminal-projection.v1"] = Field(
        ..., alias="schema"
    )
    signer_key: str
    source_operation: SourceOperation
    terminal_operation: TerminalOperation
