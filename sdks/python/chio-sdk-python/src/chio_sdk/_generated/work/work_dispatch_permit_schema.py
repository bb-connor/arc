# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 9040b11ea385ff84e98e4063d81426678eceeb5a4d55e2f86191e7f0064502af
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


class Offer(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body
    signature: str
    signer: str


class Body187(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    capability_hash: str
    expected_revision: int
    offer: Offer
    request_id: str


class Selection(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body187
    signature: str
    signer: str


class Clause(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: str
    max: int
    min: int
    pointer: str


class Acceptance(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    clauses: list[Clause]


class Contract(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    acceptance: Acceptance
    currency: str
    depth: int
    effects: list[Effect]
    expires_at: int
    max_units: int
    readers: list[str]


class Slot(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    contract: Contract
    holder: str
    id: str


class Body186(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    allocation_hash: str
    issued_at: int
    root_id: str
    selection: Selection
    slot: Slot


class ChioWorkDispatchPermitSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body186
    signer: str
