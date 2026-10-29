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


class Amount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class Destination(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    amount: Amount
    destination: str


class EffectIntent(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    intent_id: str
    kind: str


class Vault(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    chain_id: str
    vault_contract: str
    vault_id: str


class ChioFindingChallengeEnforcementV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    amount: Amount
    bond_snapshot_envelope_sha256: str
    destinations: list[Destination]
    deterministic_allocation_digest: str
    effect_intents: list[EffectIntent]
    enforcement_id: str
    finalization_authority_id: str
    finalization_key: str
    finalization_key_epoch: int
    finalization_revocation_status_ref: str
    finalization_valid_from: int
    finalization_valid_until: int
    finalized_at: int
    finding_id: str
    liability_key: str
    listing_id: str
    outcome_envelope_sha256: str
    outcome_id: str
    penalty_authority_id: str
    penalty_envelope_sha256: str
    penalty_key: str
    penalty_key_epoch: int
    penalty_revocation_status_ref: str
    penalty_valid_from: int
    penalty_valid_until: int
    purchase_snapshot_digest: str
    schema_: Literal["chio.finding.challenge-enforcement.v1"] = Field(
        ..., alias="schema"
    )
    seller_allocation_id: str
    vault: Vault
