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


class ChioFindingStatusEpochV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    anchor_refs: list[str]
    branch_domain: str
    empty_leaf_domain: str
    empty_leaf_hash: str
    feed_id: str
    generated_at: int
    hash_algorithm: str
    key_domain_nonce: int
    key_hash_domain: str
    map_epoch: int
    occupied_leaf_domain: str
    operator_id: str
    operator_key: str
    operator_key_epoch: int
    proof_semantics: str
    root_hash: str
    schema_: Literal["chio.finding.status-epoch.v1"] = Field(..., alias="schema")
    status_epoch_id: str
    status_map_version: str
    tree_depth: int
    valid_from: int
    valid_until: int
