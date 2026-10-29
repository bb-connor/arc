# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: cff572cd647726251b5cdb39013d235e07916c80b9a46e5bc035b374e0fd7041
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


class ChioAutonomousPricingAuthorityEnvelopeSignedBody(BaseModel):
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
    schema_: Literal["chio.autonomous-pricing-authority-envelope.v1"] = Field(
        ..., alias="schema"
    )
    subject_key: str
    support_boundary: SupportBoundary
