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


class Confirmations(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    depth: int


class ObservedFinality(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    confirmations: Confirmations


class ChioFindingFinalizedBondSnapshotV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    allocation_id: str
    block_hash: str
    block_number: int
    chain_id: str
    currency: str
    finality_policy: str
    held_amount: int
    identity_registry_record: str
    locked_amount: int
    observed_at: int
    observed_finality: str | ObservedFinality
    operator_key_epoch: int
    operator_key_hash: str
    schema_: Literal["chio.finding.finalized-bond-snapshot.v1"] = Field(
        ..., alias="schema"
    )
    seller: str
    slashed_amount: int
    snapshot_id: str
    vault_contract: str
    vault_id: str
