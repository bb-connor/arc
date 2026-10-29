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


class ReplayAuthority(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    destination_store_uuid: str
    dpop_authority_id: str
    expectation_id: str
    max_clock_skew_secs: int
    proof_ttl_secs: int


class ChioDpopProofV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    action_hash: str
    agent_key: str
    capability_id: str
    issued_at: int
    nonce: str
    replay_authority: ReplayAuthority
    schema_: Literal["chio.dpop_proof.v1"] = Field(..., alias="schema")
    tool_name: str
    tool_server: str
