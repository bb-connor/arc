# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: b6f1812f92935a14019f86d41be473435cc0ec402c6c70767457f18fc119ce8a
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr

from ..security import information_label_schema


class Assessment(Enum):
    feasible_under_snapshot = "feasible_under_snapshot"
    requires_exact_approval = "requires_exact_approval"
    requires_transformation = "requires_transformation"
    requires_prerequisite = "requires_prerequisite"
    needs_fresh_evidence = "needs_fresh_evidence"
    blocked_by_capability = "blocked_by_capability"
    unknown_outcome = "unknown_outcome"
    no_registered_remedy = "no_registered_remedy"
    search_bound_reached = "search_bound_reached"


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


class Candidate(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    assessment: Assessment
    template_id: OpaqueId


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


class RecoveryExplanationEvaluationV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    assessment: Assessment
    candidates: list[Candidate] = Field(..., max_length=16)
    classification: information_label_schema.InformationLabel
    complete: bool
    planner_version: Literal["chio.recovery.planner.v1"]
    work_used: conint(ge=0, le=4096)
