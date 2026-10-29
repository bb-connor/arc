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


class Entry(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    amount_units: int
    beneficiary_kind: str
    destination: str


class Slash(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class ChioFindingClaimAllocationV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    allocation_id: str
    buyer_pool_units: int
    community_fund_units: int
    cutoff_slot: int
    deterministic_allocation_sha256: str
    entries: list[Entry]
    liability_key: str
    purchase_snapshot_sha256: str
    recorded_at: int
    schema_: Literal["chio.finding.claim-allocation.v1"] = Field(..., alias="schema")
    slash: Slash
    total_realized_spend_units: int
