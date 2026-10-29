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


class RankingResult(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    provider_subject: str
    rank: int
    total_score: int


class RejectedCandidateSummary(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    provider_subject: str
    reason_codes: list[str]
    redacted_fields: list[str]


class ChioCommerceProviderSelectionReportV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    discovery_snapshot_ref: str
    id: str
    issued_at: str
    order_id: str
    override_receipt_ref: str
    passport_id: str
    price_quote_ref: str
    ranking_policy_ref: str
    ranking_results: list[RankingResult]
    rejected_candidate_summaries: list[RejectedCandidateSummary]
    risk_report_ref: str
    schema_: Literal["chio.commerce.provider-selection-report.v1"] = Field(
        ..., alias="schema"
    )
    scorecard_ref: str
    selected_provider_subject: str
    selection_reason_codes: list[str]
    sla_commitment_ref: str
