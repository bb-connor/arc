# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: f98e61fca1094fc6e2763340dae554e56c34e2d18e5720c6f3a7f9b589406726
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
