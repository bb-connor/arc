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


class Latency(Enum):
    local = "local"
    remote = "remote"
    unspecified = "unspecified"


class Kind(Enum):
    existing_destination = "existing_destination"
    exact_approval = "exact_approval"
    transformation = "transformation"
    prerequisite = "prerequisite"


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


class Cost(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    approvals: conint(ge=0, le=8)
    budget_units: SafeInteger
    evidence: OpaqueId
    irreversible_effects: conint(ge=0, le=8)
    latency: Latency


class Template(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authority_scope: RecoveryDigest32
    classification: information_label_schema.InformationLabel
    cost: Cost
    destination: DestinationId
    disclosure_label: information_label_schema.InformationLabel
    family: RecoveryDigest32
    kind: Kind
    requirements: list[OpaqueId] = Field(..., max_length=8, min_length=1)
    requires_integrity: bool
    satisfies_task: bool
    template_id: OpaqueId


class RecoveryRemedyRegistryV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    classification: information_label_schema.InformationLabel
    contract_digest: RecoveryDigest32
    deployment_digest: RecoveryDigest32
    policy_digest: RecoveryDigest32
    schema_: Literal["chio.recovery.remedy-registry.v1"] = Field(..., alias="schema")
    scope: Scope
    templates: list[Template] = Field(..., max_length=16)
    version: Literal[1]


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
