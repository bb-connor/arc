# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: f9c25e1eb1ce1c8ea4083ef04968d45682cd9f79d853175aac0d03e295257b73
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr


class Control(Enum):
    active = "active"
    cancel_requested = "cancel_requested"
    cancelled = "cancelled"
    quarantined = "quarantined"


class Release(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["not_available"]


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


class SafeInteger(RootModel[conint(ge=0, le=9007199254740991)]):
    root: conint(ge=0, le=9007199254740991)


class Scope(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authority_domain: OpaqueId
    tenant_id: OpaqueId
    process_id: OpaqueId


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


class RecoveryDigest32Item(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255) = Field(..., title="Recovery digest octet")


class RecoveryDigest32(RootModel[list[RecoveryDigest32Item]]):
    root: list[RecoveryDigest32Item] = Field(
        ..., max_length=32, min_length=32, title="Recovery digest32"
    )


class RecoveryEffectNeverAdmittedV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["never_admitted"]


class RecoveryEffectAdmissionUnresolvedV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["admission_unresolved"]
    admission_intent: OpaqueId


class Release1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["pending"]
    release_id: OpaqueId


class Release2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["withheld"]
    evidence: OpaqueId


class Release3(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["released"]
    release_id: OpaqueId


class Release4(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["denied"]
    reason: RefusalCode


class Operation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    operation_id: OpaqueId
    native_admission_digest: RecoveryDigest32
    operation_version: conint(ge=1, le=9007199254740991)


class RecoveryEffectClosedBeforeEffectV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["closed_before_effect"]
    operation: Operation
    closure: OpaqueId


class RecoveryEffectAwaitingApprovalV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["awaiting_approval"]
    operation: Operation


class RecoveryEffectInFlightV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["in_flight"]
    operation: Operation


class RecoveryEffectAwaitingCallerReportV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["awaiting_caller_report"]
    operation: Operation


class RecoveryEffectUnknownV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["unknown"]
    operation: Operation


class RecoveryEffectCompleteV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["complete"]
    operation: Operation
    effect_count: SafeInteger


class RecoveryEffectPartialV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["partial"]
    operation: Operation
    applied_effects: conint(ge=1, le=9007199254740991)


class RecoveryEffectFailedAfterEffectV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["failed_after_effect"]
    operation: Operation
    applied_effects: conint(ge=1, le=9007199254740991)


class RecoveryCommandResponseV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    command_id: OpaqueId
    workflow_id: OpaqueId
    revision: SafeInteger
    control: Control
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
    release: Release | Release1 | Release2 | Release3 | Release4
