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

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class DenyRatio(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    state: str
    value: float


class BoundaryPressure(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    deny_ratio: DenyRatio
    policies_observed: int
    receipts_observed: int


class CompositeScore(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    state: str
    value: float


class BudgetReductionRate(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    state: str
    value: float


class ScopeReductionRate(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    state: str
    value: float


class Score(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    state: str
    value: float


class TtlReductionRate(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    state: str
    value: float


class DelegationHygiene(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    budget_reduction_rate: BudgetReductionRate
    delegations_observed: int
    scope_reduction_rate: ScopeReductionRate
    score: Score
    ttl_reduction_rate: TtlReductionRate


class ActivityRatio(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    state: str
    value: float


class HistoryDepth(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    active_days: int
    activity_ratio: ActivityRatio
    first_seen: int
    last_seen: int
    receipt_count: int
    score: Score
    span_days: int


class IncidentCorrelation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    incidents_observed: int
    score: Score


class LeastPrivilege(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    capabilities_observed: int
    score: Score


class CancellationRate(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    state: str
    value: float


class CompletionRate(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    state: str
    value: float


class IncompletionRate(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    state: str
    value: float


class Reliability(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    cancellation_rate: CancellationRate
    completion_rate: CompletionRate
    incompletion_rate: IncompletionRate
    receipts_observed: int
    score: Score


class AverageUtilization(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    state: str
    value: float


class FitScore(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    state: str
    value: float


class ResourceStewardship(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    average_utilization: AverageUtilization
    capped_grants_observed: int
    fit_score: FitScore


class Specialization(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    distinct_tools: int
    score: Score


class Scorecard(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    boundary_pressure: BoundaryPressure
    composite_score: CompositeScore
    computed_at: int
    delegation_hygiene: DelegationHygiene
    effective_weight_sum: int
    history_depth: HistoryDepth
    incident_correlation: IncidentCorrelation
    least_privilege: LeastPrivilege
    reliability: Reliability
    resource_stewardship: ResourceStewardship
    specialization: Specialization
    subject_key: str


class Window(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    since: int | None = None
    until: int


class ChioPortableReputationSummarySignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    acceptedImportedSignalCount: int
    effectiveScore: float
    expiresAt: int
    importedSignalCount: int
    issuedAt: int
    issuerOperatorId: str
    probationary: bool
    schema_: Literal["chio.portable-reputation-summary.v1"] = Field(..., alias="schema")
    scorecard: Scorecard
    subjectKey: str
    summaryId: str
    window: Window
