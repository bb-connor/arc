# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 7c51d7910f0345879134e0bf5bbb042abd7b8dbfdcd23700753b77f6814a0f36
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class EvidenceRef(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: str
    locator: str
    observed_at: int
    reference_id: str


class RequestedCoverageAmount(BaseModel):
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


class ChioAutonomousPricingInputSignedBody(BaseModel):
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
    schema_: Literal["chio.autonomous-pricing-input.v1"] = Field(..., alias="schema")
    settled_loss_units: int
    subject_key: str
    support_boundary: SupportBoundary
