# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 9040b11ea385ff84e98e4063d81426678eceeb5a4d55e2f86191e7f0064502af
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr

from ..security import information_label_schema


class Integrity(Enum):
    native_owned = "native_owned"
    operator_verified = "operator_verified"
    provider_verified = "provider_verified"
    unverified = "unverified"


class Influence1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["unknown"]


class Fact(Enum):
    capability = "capability"
    policy = "policy"
    destination_acl = "destination_acl"
    authority_coverage = "authority_coverage"
    transformation = "transformation"
    prerequisite = "prerequisite"


class Source(Enum):
    native_authority = "native_authority"
    process_journal = "process_journal"
    operator_registry = "operator_registry"
    provider_acl = "provider_acl"


class Reason(Enum):
    unavailable = "unavailable"
    not_consulted = "not_consulted"
    unsupported = "unsupported"


class State(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["gap"]
    reason: Reason


class DestinationId(
    RootModel[
        constr(
            pattern=r"^[^\s\u0000-\u001F\u007F-\u009F](?:[^\u0000-\u001F\u007F-\u009F]*[^\s\u0000-\u001F\u007F-\u009F])?$",
            min_length=1,
            max_length=256,
        )
    ]
):
    root: constr(
        pattern=r"^[^\s\u0000-\u001F\u007F-\u009F](?:[^\u0000-\u001F\u007F-\u009F]*[^\s\u0000-\u001F\u007F-\u009F])?$",
        min_length=1,
        max_length=256,
    )


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
    admission_intent: OpaqueId
    kind: Literal["admission_unresolved"]


class RecoveryEffectNeverAdmittedV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["never_admitted"]


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


class SafeInteger(RootModel[conint(ge=0, le=9007199254740991)]):
    root: conint(ge=0, le=9007199254740991)


class Scope(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authority_domain: OpaqueId
    process_id: OpaqueId
    tenant_id: OpaqueId


class Influence(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    basis: RecoveryDigest32
    integrity: Integrity
    kind: Literal["observed"]


class State4(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    evidence: OpaqueId
    kind: Literal["known"]
    satisfied: bool
    version: conint(ge=1, le=9007199254740991)


class State6(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    evidence: OpaqueId
    kind: Literal["freshness_qualified"]
    satisfied: bool


class Target(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    intent: RecoveryDigest32
    kind: Literal["intent"]


class Target8(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    destination: DestinationId
    kind: Literal["destination"]


class Target9(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["authority"]
    scope: RecoveryDigest32


class Target10(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["template"]
    template: OpaqueId


class Operation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    native_admission_digest: RecoveryDigest32
    operation_id: OpaqueId
    operation_version: conint(ge=1, le=9007199254740991)


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
    closure: OpaqueId
    kind: Literal["closed_before_effect"]
    operation: Operation


class RecoveryEffectCompleteV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    effect_count: SafeInteger
    kind: Literal["complete"]
    operation: Operation


class RecoveryEffectFailedAfterEffectV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    applied_effects: conint(ge=1, le=9007199254740991)
    kind: Literal["failed_after_effect"]
    operation: Operation


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
    applied_effects: conint(ge=1, le=9007199254740991)
    kind: Literal["partial"]
    operation: Operation


class RecoveryEffectUnknownV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["unknown"]
    operation: Operation


class Observation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    expires_at_unix_ms: SafeInteger
    fact: Fact
    id: OpaqueId
    integrity: Integrity
    label: information_label_schema.InformationLabel
    object: OpaqueId
    observed_at_unix_ms: SafeInteger
    scope: Scope
    source: Source
    state: State4 | State | State6
    target: Target | Target8 | Target9 | Target10


class RecoveryExplanationSnapshotV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    context_label: information_label_schema.InformationLabel
    contract_digest: RecoveryDigest32
    deployment_digest: RecoveryDigest32
    effect: (
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
    expires_at_unix_ms: SafeInteger
    influence: Influence | Influence1
    intent_digest: RecoveryDigest32
    observations: list[Observation] = Field(..., max_length=32)
    observed_at_unix_ms: SafeInteger
    policy_digest: RecoveryDigest32
    schema_: Literal["chio.recovery.explanation-snapshot.v1"] = Field(
        ..., alias="schema"
    )
    scope: Scope
    version: Literal[1]
