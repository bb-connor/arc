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

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class MaxCoverageAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class MaxPremiumAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class RequiresHumanReviewAbovePremium(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class SupportBoundary(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    delegated_authority_required: bool
    live_bind_supported: bool
    operator_override_supported: bool
    reserve_optimization_required: bool


class AuthorityEnvelope(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authority_chain_refs: list[str]
    automation_mode: str
    currency: str
    delegated_authority_reference: str
    envelope_id: str
    issued_at: int
    kind: str
    max_coverage_amount: MaxCoverageAmount
    max_daily_decisions: int
    max_premium_amount: MaxPremiumAmount
    max_rate_change_bps: int
    not_after: int
    not_before: int
    note: str
    permitted_actions: list[str]
    provider_id: str
    requires_human_review_above_premium: RequiresHumanReviewAbovePremium
    requires_human_review_for_bind: bool
    schema_: str = Field(..., alias="schema")
    subject_key: str
    support_boundary: SupportBoundary


class EvidenceRef(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: str
    locator: str
    observed_at: int
    reference_id: str


class ExplanationFactor(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    code: str
    description: str
    direction: str
    evidence_refs: list[EvidenceRef]
    weight_bps: int


class Model(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    engine_family: str
    explanation_version: str
    input_hash: str
    model_id: str
    model_version: str
    published_at: int
    supports_counterfactuals: bool
    supports_shadow_evaluation: bool
    training_cutoff: int


class RequestedCoverageAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class PricingInput(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    available_capital_units: int
    coverage_class: str
    currency: str
    evidence_refs: list[EvidenceRef]
    generated_at: int
    input_id: str
    latest_web3_settlement_state: str
    note: str
    pending_loss_units: int
    provider_id: str
    receipt_history_window_secs: int
    reputation_score_bps: int
    requested_coverage_amount: RequestedCoverageAmount
    runtime_assurance_tier: str
    schema_: str = Field(..., alias="schema")
    settled_loss_units: int
    subject_key: str
    support_boundary: SupportBoundary


class SuggestedCoverageAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class SuggestedPremiumAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class ChioAutonomousPricingDecisionSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authority_envelope: AuthorityEnvelope
    comparison_baseline_ref: str
    confidence_bps: int
    decision_id: str
    disposition: str
    explanation_factors: list[ExplanationFactor]
    issued_at: int
    model: Model
    note: str
    pricing_input: PricingInput
    review_state: str
    schema_: Literal["chio.autonomous-pricing-decision.v1"] = Field(..., alias="schema")
    suggested_ceiling_factor_bps: int
    suggested_coverage_amount: SuggestedCoverageAmount
    suggested_premium_amount: SuggestedPremiumAmount
