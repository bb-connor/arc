# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 29e7de509b9e808e1385895b2caf534b995fb61bf99b87fab79bedc072f5a842
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Amount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class Recommendation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    action: str
    amount: Amount
    destination_ref: str | None = None
    rationale: str
    source_ref: str


class SupportBoundary(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    cross_currency_optimization_supported: bool
    live_mutation_supported: bool
    operator_override_required: bool
    scenario_comparison_supported: bool
    web3_reconciliation_required: bool


class BaselineOptimization(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    capital_book_ref: str
    currency: str
    facility_refs: list[str]
    issued_at: int
    max_bind_capacity_units: int
    max_facility_utilization_bps: int
    note: str
    optimization_id: str
    pending_claim_refs: list[str]
    pricing_decision_ref: str
    recommendations: list[Recommendation]
    schema_: str = Field(..., alias="schema")
    subject_key: str
    support_boundary: SupportBoundary
    target_reserve_ratio_bps: int


class Recommendation2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    action: str
    amount: Amount
    destination_ref: str | None = None
    rationale: str
    source_ref: str


class CandidateOptimization(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    capital_book_ref: str
    currency: str
    facility_refs: list[str]
    issued_at: int
    max_bind_capacity_units: int
    max_facility_utilization_bps: int
    note: str
    optimization_id: str
    pending_claim_refs: list[str]
    pricing_decision_ref: str
    recommendations: list[Recommendation2]
    schema_: str = Field(..., alias="schema")
    subject_key: str
    support_boundary: SupportBoundary
    target_reserve_ratio_bps: int


class Delta(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    baseline_units: int
    candidate_units: int
    description: str
    metric_name: str


class ChioCapitalPoolSimulationReportSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    baseline_optimization: BaselineOptimization
    candidate_optimization: CandidateOptimization
    currency: str
    deltas: list[Delta]
    generated_at: int
    note: str
    recommended_operator_action: str
    schema_: Literal["chio.capital-pool-simulation-report.v1"] = Field(
        ..., alias="schema"
    )
    simulation_id: str
    simulation_mode: str
    subject_key: str
