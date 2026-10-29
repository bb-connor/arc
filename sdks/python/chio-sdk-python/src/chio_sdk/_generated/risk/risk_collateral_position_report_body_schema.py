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

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ChioRiskCollateralPositionReportV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    amount: int
    available_amount: int
    claim_priority: str
    collateral_id: str
    consumed_amount_refs: list[dict[str, Any]]
    currency_or_asset: str
    id: str
    issued_at: str
    lock_expiry: str
    lock_start: str
    order_id: str
    release_policy_ref: str
    schema_: Literal["chio.risk.collateral-position-report.v1"] = Field(
        ..., alias="schema"
    )
    slash_authority_ref: str
    source_ref: str
    source_type: str
    subject: str
