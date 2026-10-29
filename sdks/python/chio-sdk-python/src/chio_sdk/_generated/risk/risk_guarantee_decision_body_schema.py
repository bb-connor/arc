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

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ClaimWindow(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    end: str
    start: str


class ChioRiskGuaranteeDecisionV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    adjudication_jurisdiction_ref: str
    backing_refs: list[str]
    beneficiary_subject: str
    claim_window: ClaimWindow
    coverage_decision_ref: str
    currency: str
    exclusions_ref: str
    guarantee_id: str
    guarantee_type: str
    id: str
    issued_at: str
    maximum_remedy: int
    order_id: str
    provider_subject: str
    schema_: Literal["chio.risk.guarantee-decision.v1"] = Field(..., alias="schema")
    sla_commitment_ref: str
    verdict: str
