# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 29f505f3691b4fbfea30cc6f60a7264757030799f7d4c23f1b591e15d011a565
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr


class Decision(Enum):
    accepted = "accepted"
    rejected = "rejected"


class BindingField(Enum):
    program_id = "program_id"
    command_id = "command_id"
    slot_id = "slot_id"
    allocation_hash = "allocation_hash"
    receiver_kernel_id = "receiver_kernel_id"
    request_id = "request_id"
    capability_hash = "capability_hash"
    profile_ref = "profile_ref"
    graph_sha256 = "graph_sha256"
    draft_ref = "draft_ref"
    permit = "permit"
    invocation_ref = "invocation_ref"


class Control(Enum):
    active = "active"
    cancel_requested = "cancel_requested"
    cancelled = "cancelled"
    quarantined = "quarantined"


class DelegationRecord(BaseModel):
    pass


class OpaqueId(
    RootModel[
        constr(
            pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", min_length=1, max_length=128
        )
    ]
):
    root: constr(
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", min_length=1, max_length=128
    )


class PolicyGeneration(RootModel[conint(ge=1, le=9007199254740991)]):
    root: conint(ge=1, le=9007199254740991)


class Artifact(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["subdivision"]
    subdivision: DelegationRecord


class Artifact9(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["selection"]
    selection: DelegationRecord


class Enforcement(Enum):
    local = "local"
    remote = "remote"


class RecoveryDigest32Item(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255) = Field(..., title="Recovery digest octet")


class RecoveryDigest32(RootModel[list[RecoveryDigest32Item]]):
    root: list[RecoveryDigest32Item] = Field(
        ..., max_length=32, min_length=32, title="Recovery digest32"
    )


class RecoveryEffectAdmissionUnresolvedV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["admission_unresolved"]
    admission_intent: OpaqueId


class RecoveryEffectNeverAdmittedV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["never_admitted"]


class RecoveryOperation(Enum):
    inspect_workflow = "inspect_workflow"
    select_offer = "select_offer"
    submit_approval = "submit_approval"
    resume_workflow = "resume_workflow"
    cancel_workflow = "cancel_workflow"


class RefusalCode(Enum):
    invalid_evidence = "invalid_evidence"
    unsupported_profile = "unsupported_profile"
    stale_basis = "stale_basis"
    revoked = "revoked"
    expired = "expired"
    budget_unavailable = "budget_unavailable"
    unknown_effect = "unknown_effect"
    audience_denied = "audience_denied"
    resource_exhausted = "resource_exhausted"


class RejectionCode(Enum):
    schema = "schema"
    malformed = "malformed"
    duplicate_key = "duplicate_key"
    unsafe_integer = "unsafe_integer"
    bounds = "bounds"
    identifier = "identifier"
    binding_mismatch = "binding_mismatch"
    conflict = "conflict"
    stale_version = "stale_version"
    stale_catalog = "stale_catalog"
    expired = "expired"
    revoked = "revoked"
    audience = "audience"
    role = "role"
    cross_tenant = "cross_tenant"
    unsupported_profile = "unsupported_profile"
    busy = "busy"


class Release(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["not_available"]


class Release12(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["pending"]
    release_id: OpaqueId


class Release13(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["withheld"]
    evidence: OpaqueId


class Release14(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["released"]
    release_id: OpaqueId


class Release15(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["denied"]
    reason: RefusalCode


class Release10(RootModel[Release | Release12 | Release13 | Release14 | Release15]):
    root: Release | Release12 | Release13 | Release14 | Release15


class SafeInteger(RootModel[conint(ge=0, le=9007199254740991)]):
    root: conint(ge=0, le=9007199254740991)


class Scope(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authority_domain: OpaqueId
    tenant_id: OpaqueId
    process_id: OpaqueId


class Execution(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["not_applicable"]


class Execution3(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["unavailable"]
    code: RejectionCode


class Acceptance1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["not_applicable"]


class Acceptance4(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["unavailable"]
    code: RejectionCode


class ResultReference(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["not_applicable"]


class ResultReference3(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["unavailable"]
    code: RejectionCode


class Recovery(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["not_applicable"]


class Recovery4(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["unavailable"]
    code: RejectionCode


class Settlement(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["not_applicable"]


class Settlement7(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["unavailable"]
    code: RejectionCode


class BilateralDelivery(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["not_applicable"]


class State(Enum):
    retained = "retained"
    delivered = "delivered"


class BilateralDelivery3(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["unavailable"]
    code: RejectionCode


class WorkDigest(RootModel[constr(pattern=r"^[0-9a-f]{64}$")]):
    root: constr(pattern=r"^[0-9a-f]{64}$")


class WorkId(
    RootModel[
        constr(
            pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", min_length=1, max_length=128
        )
    ]
):
    root: constr(
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", min_length=1, max_length=128
    )


class WorkSlotId(
    RootModel[
        constr(pattern=r"^[A-Za-z0-9._:/-]{1,256}$", min_length=1, max_length=256)
    ]
):
    root: constr(pattern=r"^[A-Za-z0-9._:/-]{1,256}$", min_length=1, max_length=256)


class Result(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["unavailable"]
    code: RejectionCode


class ArtifactVersionRef(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    scope: Scope
    artifact: OpaqueId
    version: OpaqueId
    provenance: RecoveryDigest32


class CatalogCursor(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    catalog_generation: PolicyGeneration
    position: WorkDigest


class CatalogRef(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    owner: WorkId
    catalog_id: WorkId


class CommandRef(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    program_id: WorkId
    command_id: WorkId
    command_digest: WorkDigest


class Result13(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["delegated"]
    slot: DelegationRecord


class Result14(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["selected"]
    revision: SafeInteger


class Result15(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["sealed"]
    permit: DelegationRecord


class Result16(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["extended"]
    bundle_sha256: WorkDigest


class Result19(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["cancel_observed"]
    control: Control


class DraftRef(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    draft_id: WorkId
    graph_sha256: WorkDigest


class Handle(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    program_id: WorkId
    slot_id: WorkSlotId
    allocation_hash: WorkDigest
    receiver_kernel_id: WorkId
    request_id: OpaqueId


class Operation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    operation_id: OpaqueId
    native_admission_digest: RecoveryDigest32
    operation_version: conint(ge=1, le=9007199254740991)


class OwnerOperationRef(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    operation: Operation
    scope: Scope


class PreparationRef(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    program_id: WorkId
    preparation_id: WorkId
    command_digest: WorkDigest


class Artifact8(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["offer"]
    offer: DelegationRecord
    invocation_ref: WorkDigest


class Artifact10(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["graph_draft"]
    draft_ref: DraftRef


class Artifact11(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["join_draft"]
    draft_ref: DraftRef


class Artifact12(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["agreement"]
    agreement_digest: WorkDigest


class Prepared1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["prepared"]
    preparation_ref: PreparationRef
    artifact: Artifact | Artifact8 | Artifact9 | Artifact10 | Artifact11 | Artifact12


class Prepared2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["pending"]
    preparation_ref: PreparationRef
    owner_operation_ref: OwnerOperationRef


class Condition(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    source: WorkId
    enforcement: Enforcement
    statement_digest: WorkDigest


class ProfileRef(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    owner: WorkId
    catalog_entry: WorkId
    deployment_digest: RecoveryDigest32
    policy_generation: PolicyGeneration
    profile_digest: RecoveryDigest32


class RecoveryEffectAwaitingApprovalV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["awaiting_approval"]
    operation: Operation


class RecoveryEffectAwaitingCallerReportV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["awaiting_caller_report"]
    operation: Operation


class RecoveryEffectClosedBeforeEffectV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["closed_before_effect"]
    operation: Operation
    closure: OpaqueId


class RecoveryEffectCompleteV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["complete"]
    operation: Operation
    effect_count: SafeInteger


class RecoveryEffectFailedAfterEffectV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["failed_after_effect"]
    operation: Operation
    applied_effects: conint(ge=1, le=9007199254740991)


class RecoveryEffectInFlightV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["in_flight"]
    operation: Operation


class RecoveryEffectPartialV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["partial"]
    operation: Operation
    applied_effects: conint(ge=1, le=9007199254740991)


class RecoveryEffectUnknownV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["unknown"]
    operation: Operation


class RecoveryLink(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.recovery.observation.v1"] = Field(..., alias="schema")
    version: Literal[1]
    scope: Scope
    workflow_id: OpaqueId
    step_id: OpaqueId
    continuation_id: OpaqueId
    control: Control
    available: list[RecoveryOperation] = Field(..., max_length=8)


class Rejection(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    code: RejectionCode
    field: BindingField | None = None
    reference: CommandRef | None = None


class Execution1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["pending"]
    owner_ref: OwnerOperationRef


class Acceptance2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["pending"]
    owner_ref: OwnerOperationRef


class ResultReference1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["pending"]
    owner_ref: OwnerOperationRef


class Value(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    artifact: ArtifactVersionRef
    release: Release10


class ResultReference2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["available"]
    source: WorkId
    revision: SafeInteger
    observed_at: SafeInteger
    value: Value


class Recovery2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["pending"]
    owner_ref: OwnerOperationRef


class Recovery3(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["available"]
    source: WorkId
    revision: SafeInteger
    observed_at: SafeInteger
    value: RecoveryLink


class Settlement5(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["pending"]
    owner_ref: OwnerOperationRef


class Value11(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    rail: WorkId
    agreement_digest: WorkDigest


class Settlement6(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["available"]
    source: WorkId
    revision: SafeInteger
    observed_at: SafeInteger
    value: Value11


class BilateralDelivery1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["pending"]
    owner_ref: OwnerOperationRef


class Value12(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    envelope_digest: WorkDigest
    state: State


class BilateralDelivery2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["available"]
    source: WorkId
    revision: SafeInteger
    observed_at: SafeInteger
    value: Value12


class Acceptance(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    handle: Handle
    producer: Operation
    artifact: ArtifactVersionRef
    artifact_digest: WorkDigest
    contract_digest: RecoveryDigest32
    procedure_digest: WorkDigest
    evaluator: OpaqueId
    decision: Decision
    evidence: list[OpaqueId] = Field(..., max_length=16)


class CatalogPage(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    catalog_ref: CatalogRef
    entries: list[ProfileRef] = Field(..., max_length=64)
    next: CatalogCursor | None = None


class Result17(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["submitted"]
    owner_operation_ref: OwnerOperationRef


class Outcome(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["pending"]
    owner_operation_ref: OwnerOperationRef


class Outcome13(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["refused"]
    rejection: Rejection


class Effect(
    RootModel[
        RecoveryEffectNeverAdmittedV1
        | RecoveryEffectAdmissionUnresolvedV1
        | RecoveryEffectClosedBeforeEffectV1
        | RecoveryEffectAwaitingApprovalV1
        | RecoveryEffectInFlightV1
        | RecoveryEffectAwaitingCallerReportV1
        | RecoveryEffectUnknownV1
        | RecoveryEffectCompleteV1
        | RecoveryEffectPartialV1
        | RecoveryEffectFailedAfterEffectV1
    ]
):
    root: (
        RecoveryEffectNeverAdmittedV1
        | RecoveryEffectAdmissionUnresolvedV1
        | RecoveryEffectClosedBeforeEffectV1
        | RecoveryEffectAwaitingApprovalV1
        | RecoveryEffectInFlightV1
        | RecoveryEffectAwaitingCallerReportV1
        | RecoveryEffectUnknownV1
        | RecoveryEffectCompleteV1
        | RecoveryEffectPartialV1
        | RecoveryEffectFailedAfterEffectV1
    )


class Prepared3(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["refused"]
    preparation_ref: PreparationRef
    rejection: Rejection


class Prepared(RootModel[Prepared1 | Prepared2 | Prepared3]):
    root: Prepared1 | Prepared2 | Prepared3


class Profile(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    profile_ref: ProfileRef
    server_id: WorkId
    tool_name: WorkId
    tool_schema_digest: WorkDigest
    implementation_digest: WorkDigest
    max_units: SafeInteger
    currency: WorkId
    acceptance_procedure: WorkDigest
    recovery_operations: list[RecoveryOperation] = Field(..., max_length=8)
    valid_until_unix_ms: SafeInteger
    conditions: list[Condition] = Field(..., max_length=64)
    funding_profile_id: WorkId | None = None


class Execution2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["available"]
    source: WorkId
    revision: SafeInteger
    observed_at: SafeInteger
    value: Effect


class Acceptance3(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["available"]
    source: WorkId
    revision: SafeInteger
    observed_at: SafeInteger
    value: Acceptance


class View(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    handle: Handle
    execution: Execution | Execution1 | Execution2 | Execution3
    acceptance: Acceptance1 | Acceptance2 | Acceptance3 | Acceptance4
    result_reference: (
        ResultReference | ResultReference1 | ResultReference2 | ResultReference3
    )
    recovery: Recovery | Recovery2 | Recovery3 | Recovery4
    settlement: Settlement | Settlement5 | Settlement6 | Settlement7
    bilateral_delivery: (
        BilateralDelivery | BilateralDelivery1 | BilateralDelivery2 | BilateralDelivery3
    )


class Body(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["prepared"]
    prepared: Prepared


class Result7(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["work"]
    view: View


class Result9(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["preparation"]
    prepared: Prepared


class Result10(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["catalog"]
    page: CatalogPage


class Result11(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["profile"]
    profile: Profile


class Result18(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["reconciled"]
    view: View


class Outcome11(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["applied"]
    revision: SafeInteger
    result: Result13 | Result14 | Result15 | Result16 | Result17 | Result18 | Result19


class CommandResult(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    command_ref: CommandRef
    outcome: Outcome11 | Outcome | Outcome13


class Body209(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["command"]
    result: CommandResult


class Result8(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["command"]
    result: CommandResult


class Body210(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["query"]
    result: Result7 | Result8 | Result9 | Result10 | Result11 | Result


class WorkResponseV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.work.response.v1"] = Field(..., alias="schema")
    version: Literal[1]
    body: Body | Body209 | Body210
