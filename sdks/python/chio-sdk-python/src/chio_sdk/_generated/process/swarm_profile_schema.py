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


class Admission(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    expiresAtUnixMs: int
    issuedAtUnixMs: int
    localKernelId: str
    profileId: str
    schema_: str = Field(..., alias="schema")
    verifierId: str


class Binding(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    expectation_id: str
    runtime_authority_id: str


class Alice(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    bridge: str
    manifest_sha256: str
    protocol_target: str
    selected_route: str


class Routes(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    alice: Alice


class ChioProcessSwarmProfileSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    admission: Admission
    binding: Binding
    record_sha256: str
    routes: Routes
    runtime_id: str
    schema_: Literal["chio.process.swarm-profile.v1"] = Field(..., alias="schema")
