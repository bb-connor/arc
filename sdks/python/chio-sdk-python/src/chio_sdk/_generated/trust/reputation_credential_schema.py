# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: cdaf59925a71448dee294bc7dd11837a988bac5f39ad022834183bd6833707a0
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class DenyRatio(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    state: str
    value: float | None = None


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
    value: float | None = None


class BudgetReductionRate(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    state: str
    value: int | None = None


class ScopeReductionRate(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    state: str
    value: int | None = None


class Score(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    state: str
    value: float | None = None


class TtlReductionRate(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    state: str
    value: int | None = None


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
    value: int | None = None


class HistoryDepth(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    active_days: int
    activity_ratio: ActivityRatio
    first_seen: int | None = None
    last_seen: int | None = None
    receipt_count: int
    score: Score
    span_days: int


class Score20(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    state: str


class IncidentCorrelation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    incidents_observed: None
    score: Score20


class Score21(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    state: str
    value: float | None = None


class LeastPrivilege(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    capabilities_observed: int
    score: Score21


class CancellationRate(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    state: str
    value: int | None = None


class CompletionRate(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    state: str
    value: int | None = None


class IncompletionRate(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    state: str
    value: int | None = None


class Reliability(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    cancellation_rate: CancellationRate
    completion_rate: CompletionRate
    incompletion_rate: IncompletionRate
    receipts_observed: int
    score: Score21


class AverageUtilization(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    state: str
    value: float | None = None


class FitScore(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    state: str
    value: float | None = None


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
    score: Score21


class Metrics(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    boundary_pressure: BoundaryPressure
    composite_score: CompositeScore
    computed_at: int
    delegation_hygiene: DelegationHygiene
    effective_weight_sum: float
    history_depth: HistoryDepth
    incident_correlation: IncidentCorrelation
    least_privilege: LeastPrivilege
    reliability: Reliability
    resource_stewardship: ResourceStewardship
    specialization: Specialization
    subject_key: str


class CredentialSubject(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    id: str
    metrics: Metrics


class AttributeSources(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    groups: str
    principal: str
    roles: str


class EnterpriseIdentityProvenance(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    attributeSources: AttributeSources
    clientId: str
    federationMethod: str
    groups: list[str]
    objectId: str
    organizationId: str
    principal: str
    providerId: str
    providerKind: str
    providerRecordId: str
    roles: list[str]
    sourceSubject: str
    subjectKey: str
    tenantId: str
    trustMaterialRef: str


class Query(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    since: int | None = None
    until: int


class Evidence(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    checkpointRoots: list[str]
    lineageRecords: int
    query: Query
    receiptCount: int
    receiptIds: list[str]
    receiptLogUrls: list[str] | None = None
    uncheckpointedReceipts: int


class ChioReputationCredentialSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    field_context: list[str] = Field(..., alias="@context")
    credentialSubject: CredentialSubject
    enterpriseIdentityProvenance: EnterpriseIdentityProvenance | None = None
    evidence: Evidence
    expirationDate: str
    issuanceDate: str
    issuer: str
    type: list[str]
