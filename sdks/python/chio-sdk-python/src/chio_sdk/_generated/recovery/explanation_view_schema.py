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

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr


class Summary(Enum):
    authorized_inspection_required = "authorized_inspection_required"
    no_disclosable_advice = "no_disclosable_advice"
    alternatives_under_snapshot = "alternatives_under_snapshot"
    search_bound_reached = "search_bound_reached"


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


class SafeInteger(RootModel[conint(ge=0, le=9007199254740991)]):
    root: conint(ge=0, le=9007199254740991)


class Scope(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authority_domain: OpaqueId
    tenant_id: OpaqueId
    process_id: OpaqueId


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


class Operation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    operation_id: OpaqueId
    native_admission_digest: RecoveryDigest32
    operation_version: conint(ge=1, le=9007199254740991)


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


class Candidate(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    template_id: OpaqueId
    assessment: Assessment


class Projection(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    summary: Summary
    candidates: list[Candidate] = Field(..., max_length=16)


class RecoveryExplanationViewV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.recovery.explanation-view.v1"] = Field(..., alias="schema")
    version: Literal[1]
    planner_version: Literal["chio.recovery.planner.v1"]
    trust_domain: OpaqueId
    issuer: OpaqueId
    recipient: OpaqueId
    report_ref: OpaqueId
    issued_at_unix_ms: SafeInteger
    expires_at_unix_ms: SafeInteger
    projection: Projection
