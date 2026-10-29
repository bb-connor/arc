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


class AvailableBudget(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class ChioFindingAuditEpochV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    audit_authority: str
    audit_epoch_id: str
    authorization_digest: str
    available_budget: AvailableBudget
    committed_at: int
    eligible_listing_count: int
    eligible_snapshot_at: int
    eligible_snapshot_digest: str
    epoch_index: int
    fee_schedule_envelope_sha256: str
    published_rate_bps: int
    schema_: Literal["chio.finding.audit-epoch.v1"] = Field(..., alias="schema")
    seed_commitment: str
    seed_witness: str
    seed_witness_signature: str
    seed_witnessed_at: int
    selection_algorithm_id: str
