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

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Selector(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    credentialRefDigest: str
    family: str


class Body(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    challengeDigest: str
    challengeId: str
    expiresAt: str
    issuedAt: str
    nonce: str
    schema_: str = Field(..., alias="schema")
    selectors: list[Selector]
    sourcePassportId: str
    verifier: str
    verifierKeyEpoch: int


class Challenge(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body
    signature: str
    signerKey: str


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
    value: int


class ScopeReductionRate(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    state: str
    value: int


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
    value: int


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
    value: int


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


class Score8(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    state: str


class IncidentCorrelation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    incidents_observed: None
    score: Score8


class Score9(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    state: str
    value: float


class LeastPrivilege(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    capabilities_observed: int
    score: Score9


class CancellationRate(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    state: str
    value: int


class CompletionRate(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    state: str
    value: int


class IncompletionRate(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    state: str
    value: int


class Reliability(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    cancellation_rate: CancellationRate
    completion_rate: CompletionRate
    incompletion_rate: IncompletionRate
    receipts_observed: int
    score: Score9


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
    score: Score9


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


class Query(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    since: int
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
    uncheckpointedReceipts: int


class Proof(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    created: str
    proofPurpose: str
    proofValue: str
    type: str
    verificationMethod: str


class Credential(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    field_context: list[str] = Field(..., alias="@context")
    credentialSubject: CredentialSubject
    evidence: Evidence
    expirationDate: str
    issuanceDate: str
    issuer: str
    proof: Proof
    type: list[str]


class Credential1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    credential: Credential
    kind: str


class Leaf(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    credentialId: str
    credentialRefDigest: str
    family: str


class Proof5(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    audit_path: list[str]
    leaf_index: int
    tree_size: int


class MembershipProof(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    leaf: Leaf
    proof: Proof5


class Body161(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    credentialCount: int
    credentialRoot: str
    expiresAt: int
    issuedAt: int
    issuer: str
    merkleRoots: list[str]
    schema_: str = Field(..., alias="schema")
    sourcePassportId: str
    subject: str


class SourceManifest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body161
    signature: str
    signerKey: str


class Presentation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    challengeDigest: str
    credentials: list[Credential1]
    membershipProofs: list[MembershipProof]
    presentationDigest: str
    schema_: str = Field(..., alias="schema")
    sourceManifest: SourceManifest


class ChioFinancialAgentPassportPresentationResponseSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    challenge: Challenge
    presentation: Presentation
    schema_: Literal["chio.financial-agent-passport-presentation-response.v1"] = Field(
        ..., alias="schema"
    )
