# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 7c51d7910f0345879134e0bf5bbb042abd7b8dbfdcd23700753b77f6814a0f36
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class Body(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    max_invocations: int
    root_capability_hash: str
    root_capability_id: str
    root_expires_at: int
    root_issuer: str
    root_scope_hash: str
    root_subject: str
    schema_: str = Field(..., alias="schema")


class RootBinding(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body
    signature: str


class AggregateInvocationBudget(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    max_invocations: int
    root_binding: RootBinding
    scope: str


class AggregateBudget(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    max_invocations: int
    root_binding_digest: str


class SubsetRelation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    childIndex: int
    grantKind: str
    parentIndex: int
    subset: bool


class NormalizedSubsetProof(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    aggregateBudget: AggregateBudget
    normalizedChildScope: str
    normalizedParentScope: str
    subsetRelations: list[SubsetRelation]


class AttenuationProof(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    childScopeHash: str
    normalizedSubsetProof: NormalizedSubsetProof
    parentScopeHash: str


class DelegationChainItem(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    aggregate_budget: AggregateBudget
    capability_id: str
    delegatee: str
    delegator: str
    scope_hash: str
    signature: str
    timestamp: int


class Grant(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    operations: list[str]
    server_id: str
    tool_name: str


class Scope(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    grants: list[Grant]


class Alice(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    aggregate_invocation_budget: AggregateInvocationBudget
    attenuation_proof: AttenuationProof
    budget_share_bps: int
    delegation_chain: list[DelegationChainItem]
    expires_at: int
    id: str
    issued_at: int
    issuer: str
    schema_: str = Field(..., alias="schema")
    scope: Scope
    signature: str
    subject: str


class RootBinding2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body
    signature: str


class AggregateInvocationBudget2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    max_invocations: int
    root_binding: RootBinding2
    scope: str


class NormalizedSubsetProof2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    aggregateBudget: AggregateBudget
    normalizedChildScope: str
    normalizedParentScope: str
    subsetRelations: list[SubsetRelation]


class AttenuationProof2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    childScopeHash: str
    normalizedSubsetProof: NormalizedSubsetProof2
    parentScopeHash: str


class DelegationChainItem2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    aggregate_budget: AggregateBudget
    capability_id: str
    delegatee: str
    delegator: str
    scope_hash: str
    signature: str
    timestamp: int


class Scope20(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    grants: list[Grant]


class Bob(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    aggregate_invocation_budget: AggregateInvocationBudget2
    attenuation_proof: AttenuationProof2
    budget_share_bps: int
    delegation_chain: list[DelegationChainItem2]
    expires_at: int
    id: str
    issued_at: int
    issuer: str
    schema_: str = Field(..., alias="schema")
    scope: Scope20
    signature: str
    subject: str


class RootBinding3(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body
    signature: str


class AggregateInvocationBudget3(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    max_invocations: int
    root_binding: RootBinding3
    scope: str


class NormalizedSubsetProof3(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    aggregateBudget: AggregateBudget
    normalizedChildScope: str
    normalizedParentScope: str
    subsetRelations: list[SubsetRelation]


class AttenuationProof3(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    childScopeHash: str
    normalizedSubsetProof: NormalizedSubsetProof3
    parentScopeHash: str


class DelegationChainItem3(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    aggregate_budget: AggregateBudget
    capability_id: str
    delegatee: str
    delegator: str
    scope_hash: str
    signature: str
    timestamp: int


class Scope21(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    grants: list[Grant]


class Carol(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    aggregate_invocation_budget: AggregateInvocationBudget3
    attenuation_proof: AttenuationProof3
    budget_share_bps: int
    delegation_chain: list[DelegationChainItem3]
    expires_at: int
    id: str
    issued_at: int
    issuer: str
    schema_: str = Field(..., alias="schema")
    scope: Scope21
    signature: str
    subject: str


class RootBinding4(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body
    signature: str


class AggregateInvocationBudget4(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    max_invocations: int
    root_binding: RootBinding4
    scope: str


class NormalizedSubsetProof4(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    aggregateBudget: AggregateBudget
    normalizedChildScope: str
    normalizedParentScope: str
    subsetRelations: list[SubsetRelation]


class AttenuationProof4(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    childScopeHash: str
    normalizedSubsetProof: NormalizedSubsetProof4
    parentScopeHash: str


class DelegationChainItem4(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    aggregate_budget: AggregateBudget
    capability_id: str
    delegatee: str
    delegator: str
    scope_hash: str
    signature: str
    timestamp: int


class Scope22(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    grants: list[Grant]


class Dave(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    aggregate_invocation_budget: AggregateInvocationBudget4
    attenuation_proof: AttenuationProof4
    budget_share_bps: int
    delegation_chain: list[DelegationChainItem4]
    expires_at: int
    id: str
    issued_at: int
    issuer: str
    schema_: str = Field(..., alias="schema")
    scope: Scope22
    signature: str
    subject: str


class RootBinding5(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body
    signature: str


class AggregateInvocationBudget5(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    max_invocations: int
    root_binding: RootBinding5
    scope: str


class Scope23(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    grants: list[Grant]


class Root(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    aggregate_invocation_budget: AggregateInvocationBudget5
    expires_at: int
    id: str
    issued_at: int
    issuer: str
    schema_: str = Field(..., alias="schema")
    scope: Scope23
    signature: str
    subject: str


class Capabilities(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    alice: Alice
    bob: Bob
    carol: Carol
    dave: Dave
    root: Root


class Parameters1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    capabilities: Capabilities
    record_sha256: str
    runtime_id: str


class Action(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    parameter_hash: str
    parameters: Parameters1


class Bootstrap(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    action: Action
    boundary_class: str
    capability_id: str
    content_hash: str
    id: str
    kernel_key: str
    observation_outcome: str
    policy_hash: str
    receipt_kind: str
    redaction_mode: str
    signature: str
    timestamp: int
    tool_name: str
    tool_origin: str
    tool_server: str
    trust_level: str


class Context(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    capability_id: str
    process_id: str
    runtime_id: str


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
    BrokerAttempt_1: BrokerAttempt | None = Field(None, alias="BrokerAttempt")
    BudgetHoldId: str | None = None
    ExecutionNonceId: str | None = None
    ExecutionNonceIssuanceDigest: str | None = None
    ExecutionNoncePreflightDigest: str | None = None
    RuntimeParticipantLedgerDigest: str | None = None
    ToolOutcomeId: str | None = None


class ParticipantRequirements(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    approval: bool
    authorization_consumption: bool
    broker_attempt: bool
    budget_capture: bool
    execution_nonce: bool
    obligation: bool
    observation_attempt_zero: bool
    outcome_eligibility: bool
    payment: bool


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


class StoreFence(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    lease_id: str
    owner_epoch: int
    store_uuid: str


class DispatchCommit(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    committed_version: int
    coordinator_lease_epoch: int
    coordinator_lease_id: str
    dispatch_launch: DispatchLaunch
    provider_attempt: ProviderAttempt
    store_fence: StoreFence


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
    receipt: Receipt


class Operation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    attachments: list[Attachment]
    binding: Binding
    coordinator_lease_epoch: int
    dispatch_commit: DispatchCommit
    dispatch_state: str
    last_error: None
    schema_: str = Field(..., alias="schema")
    state: str
    terminal_replay: TerminalReplay
    version: int


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


class SignedNonce(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    nonce: Nonce
    signature: str


class Nonce2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    operation: Operation
    reserved_at_unix_ms: int
    signed_nonce: SignedNonce
    verified_at_unix_ms: int


class RequestBinding1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    action_parameter_hash: str
    immutable_request_hash: str
    participant_requirements: ParticipantRequirements
    request_binding_hash: str


class Binding5(BaseModel):
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
    request_binding: RequestBinding1
    request_id: str
    request_namespace_digest: str


class DispatchCommit4(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    committed_version: int
    coordinator_lease_epoch: int
    coordinator_lease_id: str
    dispatch_launch: DispatchLaunch
    provider_attempt: ProviderAttempt
    store_fence: StoreFence


class Resource(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    artifactDigest: str
    kind: str
    resourceId: str


class Intent(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    episodeId: str
    expectationId: str
    grantIndex: int
    phase: str
    planDigest: str
    requestBindingHash: str
    resources: list[Resource]
    runtimeAuthorityId: str


class Claim(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    intent: Intent
    ledgerDigest: str
    operationId: str
    recordedAtUnixMs: int
    schema_: str = Field(..., alias="schema")


class Intent2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    episodeId: str
    expectationId: str
    grantIndex: int
    phase: str
    planDigest: str
    requestBindingHash: str
    resources: list[Resource]
    runtimeAuthorityId: str


class Reference(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    claimDigest: str
    episodeId: str
    operationId: str


class History(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    disposition: str
    intent: Intent2
    reference: Reference


class Attachment1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    BrokerAttempt_1: BrokerAttempt | None = Field(None, alias="BrokerAttempt")
    ExecutionNonceIssuanceDigest: str | None = None
    ExecutionNoncePreflightDigest: str | None = None
    RuntimeParticipantLedgerDigest: str | None = None


class RequestBinding2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    action_parameter_hash: str
    immutable_request_hash: str
    participant_requirements: ParticipantRequirements
    request_binding_hash: str


class Binding6(BaseModel):
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
    request_binding: RequestBinding2
    request_id: str
    request_namespace_digest: str


class Operation21(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    attachments: list[Attachment1]
    binding: Binding6
    coordinator_lease_epoch: int
    dispatch_commit: None
    dispatch_state: str
    last_error: None
    schema_: str = Field(..., alias="schema")
    state: str
    terminal_replay: None
    version: int


class HistoryItem(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    claim: Claim
    history: History
    operation: Operation21


class TerminalReplay1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    receipt: Receipt


class Operation20(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    binding: Binding5
    dispatch_commit: DispatchCommit4
    dispatch_state: str
    execution_nonce_issuance_digest: str
    history: list[HistoryItem]
    state: str
    terminal_replay: TerminalReplay1
    version: int


class Body202(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    batch_end_seq: int
    batch_start_seq: int
    chain_root: str
    checkpoint_seq: int
    issued_at: int
    kernel_key: str
    merkle_root: str
    schema_: str = Field(..., alias="schema")
    tree_size: int


class Checkpoint(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body202
    signature: str


class Proof(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    audit_path: list[str]
    leaf_index: int
    tree_size: int


class Inclusion(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    checkpoint_seq: int
    leaf_index: int
    merkle_root: str
    proof: Proof
    receipt_seq: int


class ReceiptLog(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    checkpoint: Checkpoint
    inclusion: Inclusion


class Payload(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    from_: str = Field(..., alias="from")


class Arguments(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    message_key: str
    payload: Payload


class Request(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    arguments: Arguments
    known_outcome_only: bool
    operation_key: str
    server_id: str
    tool_name: str


class Value(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    sequence: str
    status: str


class Output(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: str
    value: Value


class TerminalState(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    state: str


class Response(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    execution_nonce_json: None
    output: Output
    reason: None
    receipt_json: str
    request_id: str
    terminal_state: TerminalState
    verdict: str


class Parameters(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    bootstrap: Bootstrap | None = None
    context: Context | None = None
    evidence_id: str | None = None
    finding_id: str | None = None
    kind: str | None = None
    nonce: Nonce2 | None = None
    observed_at_unix_ms: int | None = None
    operation: Operation20 | None = None
    path: str | None = None
    receipt_log: ReceiptLog | None = None
    record: str | None = None
    request: Request | None = None
    response: Response | None = None
    runtime_id: str | None = None
    schema_: str | None = Field(None, alias="schema")
    transition_id: str | None = None
    value: str | None = None


class Action1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    parameter_hash: str
    parameters: Parameters


class Decision(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    reason: str | None = None
    verdict: str


class EvidenceItem(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    details: str | None = None
    guard_name: str
    verdict: bool


class Target(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    session_id: str
    target_type: str


class Effect(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    contribution_hash: list[int]
    effect_id: str
    kind: str
    observed_base_version_hash: list[int]
    ordinal: int
    target: Target


class Outcome(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    resulting_version_hash: list[int]
    state: str


class Effect2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    effect: Effect
    outcome: Outcome


class Approval(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    admission_operation_id: str
    admission_operation_version: int
    approval_mode: str
    approval_set_hash: list[int]


class ExecutionDispatch(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    action_id: str
    admission_artifact_fingerprint: list[int]
    approval: Approval
    authorization_capability_hash: list[int]
    authorized_at_unix_ms: int
    dispatch_id: str
    executor_authority_generation: int
    executor_authority_id: str
    governed_intent_hash: list[int]
    plan_hash: list[int]
    policy_decision_hash: list[int]
    schema_version: int
    tenant_id: str


class Header(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    occurred_at_unix_ms: int
    prior_receipt_ids: list[str]
    schema_version: int
    tenant_id: str
    transition_id: str


class Policy(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    policy_hash: list[int]
    policy_version: str


class Response2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    action_id: str
    affected_set_hash: list[int]
    plan_expires_at_unix_ms: int
    plan_hash: list[int]
    policy: Policy
    trigger_finding_hash: list[int]
    trigger_finding_id: str
    trigger_finding_receipt_id: str


class Body203(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    dispatch_authorization_hash: list[int]
    effects: list[Effect2]
    error_code: None
    execution_dispatch: ExecutionDispatch
    final_state: str
    header: Header
    response: Response2
    response_body_hash: list[int]
    response_generation: int


class ActiveDefenseBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body203
    kind: str


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
    compensation_status: str
    coordinator_lease_epoch: int
    coordinator_lease_id: str
    operation_id: str
    projected_dispatch_state: str
    projected_operation_version: int
    projected_state: str
    request_binding_hash: str
    request_id: str
    request_namespace_digest: str
    retained_dispatch_commit: RetainedDispatchCommit
    schema_: str = Field(..., alias="schema")
    store_fence: StoreFence
    tool_outcome_id: str
    tool_outcome_version: int
    trusted_time_unix_ms: int


class Attribution(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    delegation_depth: int
    grant_index: int
    issuer_key: str
    subject_key: str


class Authority(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authority_id: str
    lease_epoch: int
    lease_id: str


class Authorize(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    budget_commit_index: int
    committed_cost_units_after: int
    event_id: str
    exposure_units: int


class Terminal(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    budget_commit_index: int
    committed_cost_units_after: int
    disposition: str
    event_id: str
    exposure_units: int
    realized_spend_units: int


class BudgetAuthority(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authority: Authority
    authority_profile: str
    authorize: Authorize
    budget_term: str
    cleanup_custody: str
    guarantee_level: str
    hold_id: str
    metering_profile: str
    terminal: Terminal


class CapabilityLeaseRef(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    expires_at_unix_ms: int
    issuer: str
    lease_id: str


class Digest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    alg: str
    value: str


class GovernanceReceiptRef(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    digest: Digest
    kernel_id: str
    receipt_id: str


class ServerAVerdict(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    policy_id: str
    policy_version: str
    verdict: str


class ServerBVerdict(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    policy_id: str
    policy_version: str
    verdict: str


class PolicyEvaluationSummary(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    joint_disposition: str
    server_a_verdict: ServerAVerdict
    server_b_verdict: ServerBVerdict


class TreatyBindingRef(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    action_class_id: str
    admission_report_sha256: str
    consistency_model: str
    continuation_sha256: str
    governance_refs: list[str]
    ladder_intersection_sha256: str
    lease_refs: list[str]
    lineage_bundle_sha256: str
    local_receipt_sha256: str
    outcome_sha256: str
    remote_receipt_sha256: str
    request_sha256: str
    signer_kernel_ids: list[str]
    treaty_id: str
    treaty_scope_sha256: str


class FederationTreatyDsse(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    capability_lease_ref: CapabilityLeaseRef
    consistency_anchor: str
    consistency_model: str
    cross_org_visibility: str
    governance_receipt_ref: GovernanceReceiptRef
    policy_evaluation_summary: PolicyEvaluationSummary
    treaty_binding_ref: TreatyBindingRef


class OperationOwnedReplay(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    bundle_sha256: str
    plan_sha256: str
    reference: Reference
    resources_sha256: str
    swarm_evidence_sha256: str
    treaty_evidence_sha256: str


class PheromoneAdvisory(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    accepted: bool
    distinctOriginPairs: int
    evaluatedAtUnixMs: int
    observeOnly: bool
    reputationEpoch: int
    sourceReportSha256: str
    subjectClass: str
    subjectClassNamespace: str
    totalStrength: float


class PheromonePolicyDecision(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    decision: str
    enforced: bool
    peerWeightsSha256: str
    policyId: str
    policySha256: str
    queryReportSha256: str
    reasonCode: str
    reputationEpoch: int
    schema_: str = Field(..., alias="schema")


class VerifiedSwarmRequestBinding(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    capability_sha256: str
    evidence_refs_sha256: str
    graph_id: str
    scope_sha256: str
    task_id: str


class Route(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    bridge: str
    protocolTarget: str
    selectedRoute: str


class VerifiedSwarmRouteMetadata(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    route: Route


class ChioRuntime(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    accepted: bool | None = None
    admission_id: str | None = None
    destructive: bool | None = None
    failure_code: None = None
    federation_treaty_dsse: FederationTreatyDsse | None = None
    governance_receipt_id: str | None = None
    identity_disposition: str | None = None
    lease_id: str | None = None
    operation_owned_replay: OperationOwnedReplay | None = None
    pheromone_advisory: PheromoneAdvisory | None = None
    pheromone_policy_decision: PheromonePolicyDecision | None = None
    step_index: int | None = None
    trust_bundle_sha256: str | None = None
    verification_context_sha256: str | None = None
    verified_swarm_request_binding: VerifiedSwarmRequestBinding | None = None
    verified_swarm_route_metadata: VerifiedSwarmRouteMetadata | None = None
    workflow_grant_id: str | None = None
    workflow_id: str | None = None


class DeliveryContract(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    expected_digest: str
    observed_digest: str
    result: str
    schema_: str = Field(..., alias="schema")


class ExecutionNonce(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    stage: str
    tool_dispatched: bool


class ReportedCost(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class Payment(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authorization_id: str
    budget_exposure_units: int
    preauthorized_units: int
    pricing_failure: None
    rail: str
    rail_mode: str
    recorded_units: int
    reported_cost: ReportedCost
    transaction_id: str


class CostBreakdown(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    payment: Payment


class Financial(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    budget_remaining: int
    budget_total: int
    cost_breakdown: CostBreakdown
    cost_charged: int
    currency: str
    delegation_depth: int
    grant_index: int
    payment_reference: str
    root_budget_holder: str
    settlement_status: str


class StatusProof(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    feed_id: str
    key_domain_nonce: int
    map_epoch: int
    non_inclusion_checked_at: int
    proof_sha256: str
    root_hash: str
    status_epoch_artifact_sha256: str


class FindingDelivery(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    accepted_bid_envelope_sha256: str
    authoritative_payment_operation_id: str
    digest_check: str
    finding_id: str
    listing_id: str
    media_type_check: str
    purchase_intent_id: str
    reservation_id: str
    schema_: str = Field(..., alias="schema")
    settlement_mode: str
    status_proof: StatusProof
    transform_profile: str
    venue_admission_envelope_sha256: str


class AcceptedPrice(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class StatusProof2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    feed_id: str
    key_domain_nonce: int
    map_epoch: int
    non_inclusion_checked_at: int
    operator_authorization_sha256: str
    proof_sha256: str
    root_hash: str
    service_bond_evidence_sha256: str
    status_epoch_artifact_sha256: str
    status_epoch_id: str


class Purchase(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    accepted_bid_envelope_sha256: str
    accepted_price: AcceptedPrice
    authoritative_payment_operation_id: str
    expected_status_feed_id: str
    finding_id: str
    listing_id: str
    payer_key_hex: str
    payload_media_type: str
    payload_sha256: str
    purchase_intent_id: str
    reservation_id: str
    status_proof: StatusProof2
    venue_admission_envelope_sha256: str


class FindingPurchaseReplaySnapshot(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    purchase: Purchase
    schema_: str = Field(..., alias="schema")


class Approval2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    approval_artifact_digest: str
    approved: bool
    approver_key: str
    token_id: str


class Autonomy(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    delegationBondId: str
    tier: str


class UpstreamProof(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    chainId: str
    delegatorSubject: str
    expiresAt: int
    issuedAt: int
    originSubject: str
    parentReceiptId: str
    parentRequestId: str
    signature: str
    signer: str
    subject: str


class CallChain(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    chainId: str
    delegatorSubject: str
    evidenceClass: str
    evidenceSources: list[str]
    originSubject: str
    parentReceiptId: str
    parentRequestId: str
    upstreamProof: UpstreamProof


class Commerce(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    seller: str
    settlement_destination_ref: str
    shared_payment_token_id: str


class ApprovedMax(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class HoldAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class SettlementCap(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class AmountBounds(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    approved_max: ApprovedMax
    hold_amount: HoldAmount
    settlement_cap: SettlementCap


class Budget(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    budget_remaining: int
    budget_total: int
    cost_charged: int
    currency: str
    delegation_depth: int
    grant_index: int
    root_budget_holder: str


class LiabilityRefs(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    bond_id: str
    dispute_policy_ref: str
    policy_id: str


class Merchant(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    merchant_id: str
    merchant_of_record: str
    order_ref: str


class Metering(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    billing_unit: str
    max_billable_units: int
    meter_profile_hash: str
    provider: str


class Payee(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    beneficiary_id: str
    settlement_destination_ref: str


class Payer(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    custody_provider: str
    funding_source_ref: str
    obligor_ref: str
    party_id: str


class PricingBasis(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    quote_expiry: int
    quote_hash: str
    tariff_hash: str


class Rail(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    asset: str
    contract_or_account_ref: str
    facilitator: str
    kind: str
    network: str


class Settlement(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    settlement_status: str


class EconomicAuthorization(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    amount_bounds: AmountBounds
    budget: Budget
    credit_authority_digest: str
    economic_intent_digest: str
    economic_mode: str
    liability_refs: LiabilityRefs
    merchant: Merchant
    metering: Metering
    payee: Payee
    payee_binding_digest: str
    payer: Payer
    pre_action_authority_digest: str
    pricing_basis: PricingBasis
    rail: Rail
    settlement: Settlement
    version: str


class MaxAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class QuotedCost(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class Quote(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    billingUnit: str
    expiresAt: int
    issuedAt: int
    provider: str
    quoteId: str
    quotedCost: QuotedCost
    quotedUnits: int


class UsageEvidence(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    evidenceId: str
    evidenceKind: str
    evidenceSha256: str
    observedUnits: int


class MeteredBilling(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    maxBilledUnits: int
    quote: Quote
    settlementMode: str
    usageEvidence: UsageEvidence


class RuntimeAssurance(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    evidenceSha256: str
    schema_: str = Field(..., alias="schema")
    tier: str
    verifier: str
    verifierFamily: str


class GovernedTransaction(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    approval: Approval2 | None = None
    autonomy: Autonomy | None = None
    call_chain: CallChain | None = None
    commerce: Commerce | None = None
    economic_authorization: EconomicAuthorization | None = None
    intent_hash: str
    intent_id: str
    max_amount: MaxAmount | None = None
    metered_billing: MeteredBilling | None = None
    purpose: str
    runtime_assurance: RuntimeAssurance | None = None
    server_id: str
    tool_name: str


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
    active_defense_body: ActiveDefenseBody | None = None
    active_defense_evidence_id: str | None = None
    admission_operation: AdmissionOperation | None = None
    attribution: Attribution | None = None
    budget_authority: BudgetAuthority | None = None
    chio_receipt_signing_nonce: str | None = None
    chio_runtime: ChioRuntime | None = None
    delivery_contract: DeliveryContract | None = None
    execution_nonce: ExecutionNonce | None = None
    financial: Financial | None = None
    finding_delivery: FindingDelivery | None = None
    finding_purchase_replay_snapshot: FindingPurchaseReplaySnapshot | None = None
    governed_transaction: GovernedTransaction | None = None
    occurred_at_unix_ms: int | None = None
    receipt_context: ReceiptContext | None = None
    route: Route | None = None


class Body196(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    action: Action1
    boundary_class: str
    capability_id: str
    content_hash: str
    decision: Decision | None = None
    evidence: list[EvidenceItem] | None = None
    kernel_key: str
    metadata: Metadata | None = None
    observation_outcome: str | None = None
    policy_hash: str
    receipt_kind: str
    redaction_mode: str
    tenant_id: str | None = None
    timestamp: int
    tool_name: str
    tool_origin: str
    tool_server: str
    trust_level: str


class ChioReceiptV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body196
    id: str
