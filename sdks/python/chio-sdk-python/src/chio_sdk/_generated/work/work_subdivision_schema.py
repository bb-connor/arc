# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: cff572cd647726251b5cdb39013d235e07916c80b9a46e5bc035b374e0fd7041
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
