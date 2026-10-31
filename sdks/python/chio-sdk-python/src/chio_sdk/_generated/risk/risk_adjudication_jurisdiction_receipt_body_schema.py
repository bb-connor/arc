# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 29f505f3691b4fbfea30cc6f60a7264757030799f7d4c23f1b591e15d011a565
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class EffectiveWindow(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    end: str
    start: str


class RemedyLimit(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    maximum_remedy: int


class ChioRiskAdjudicationJurisdictionReceiptV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    adjudicator_subjects: list[str]
    appeal_authority_refs: list[str]
    covered_dispute_types: list[str]
    effective_window: EffectiveWindow
    evidence_rules_ref: str
    id: str
    issued_at: str
    jurisdiction_id: str
    order_id: str
    policy_ref: str
    remedy_limits: list[RemedyLimit]
    schema_: Literal["chio.risk.adjudication-jurisdiction-receipt.v1"] = Field(
        ..., alias="schema"
    )
    slash_authority_refs: list[str]
