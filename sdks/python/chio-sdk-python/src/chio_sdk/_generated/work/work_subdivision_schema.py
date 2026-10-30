# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: b6f1812f92935a14019f86d41be473435cc0ec402c6c70767457f18fc119ce8a
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class Clause(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: str
    max: int | None = None
    min: int | None = None
    pointer: str
    value: str | None = None


class Acceptance(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    clauses: list[Clause]


class Effect(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    server: str
    tool: str


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


class Child(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    contract: Contract
    holder: str
    id: str


class Body(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    child: Child
    parent_allocation_hash: str
    parent_id: str


class ChioWorkSubdivisionSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body
    signer: str
