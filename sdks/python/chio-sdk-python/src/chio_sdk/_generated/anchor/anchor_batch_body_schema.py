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


class Proof(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    audit_path: list[str]
    leaf_index: int
    tree_size: int


class Inclusion(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    checkpointId: str
    leafHash: str
    proof: Proof


class Witness(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: str
    observedAt: int
    root: str
    witnessId: str


class Receipt(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    bodyHash: str
    externalUuid: str
    inclusionProof: str
    kind: str
    publishedAt: int
    witnessRoot: str


class WitnessState(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    error: str | None = None
    kind: str
    last_verified: int | None = None
    observed_at: int | None = None
    receipt: Receipt | None = None


class ChioAnchorBatchV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    checkpointIds: list[str]
    inclusions: list[Inclusion]
    issuedAt: int
    schema_: Literal["chio.anchor_batch.v1"] = Field(..., alias="schema")
    signerKey: str
    treeRoot: str
    witness: Witness
    witnessState: WitnessState
