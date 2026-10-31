# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 29f505f3691b4fbfea30cc6f60a7264757030799f7d4c23f1b591e15d011a565
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class Effect(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    server: str
    tool: str


class Body(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    allocation_hash: str
    arguments_hash: str
    contract_hash: str
    effect: Effect
    expires_at: int
    price_units: int
    receiver: str
    slot_id: str


class ChioWorkOfferSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body
    signer: str
