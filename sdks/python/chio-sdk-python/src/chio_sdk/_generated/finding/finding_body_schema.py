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


class Descriptor(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    context_sha256: str
    outcome_class: str
    topic: str


class EvidenceCost(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class ChioFindingV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    bond_ref: str
    descriptor: Descriptor
    evidence_checkpoint_ref: str
    evidence_class: str
    evidence_cost: EvidenceCost
    evidence_receipt_ids: list[str]
    expires_at: int
    finding_id: str
    guarantee_class: str
    issued_at: int
    issuer: str
    payload_media_type: str
    payload_sha256: str
    price_hint_ref: str | None = None
    replay_recipe_sha256: str | None = None
    runtime_assurance_tier: str | None = None
    schema_: Literal["chio.finding.v1"] = Field(..., alias="schema")
    signature: str
    status_feed_ref: str
