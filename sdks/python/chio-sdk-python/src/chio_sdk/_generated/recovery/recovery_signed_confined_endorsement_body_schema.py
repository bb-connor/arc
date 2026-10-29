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

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, RootModel, constr


class Scope(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authority_domain: str
    process_id: str
    tenant_id: str


class Artifact(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    artifact: str
    provenance: list[int]
    scope: Scope
    version: str


class Influence(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    commitment: list[int]
    externally_influenced: bool
    unknown: bool


class Observation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    artifact: str
    provenance: list[int]
    scope: Scope
    version: str


class Compartment(
    RootModel[
        constr(
            pattern=r"^[^\s\u0000-\u001F\u007F-\u009F](?:[^\u0000-\u001F\u007F-\u009F]*[^\s\u0000-\u001F\u007F-\u009F])?$",
            min_length=1,
            max_length=256,
        )
    ]
):
    root: constr(
        pattern=r"^[^\s\u0000-\u001F\u007F-\u009F](?:[^\u0000-\u001F\u007F-\u009F]*[^\s\u0000-\u001F\u007F-\u009F])?$",
        min_length=1,
        max_length=256,
    )


class Clearance(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    compartments: list[Compartment] = Field(..., max_length=64)
    kind: str
    owners: dict[str, Any]


class Sink(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: str


class Parent(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    clearance: Clearance
    context_generation: int
    isolation_epoch: str
    lineage: str
    principal: str
    recipient: str
    runtime: str
    scope: Scope
    sink: Sink


class Source(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    compartments: list[Compartment] = Field(..., max_length=64)
    kind: str
    owners: dict[str, Any]


class Target(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    compartments: list[Compartment] = Field(..., max_length=64)
    kind: str
    owners: dict[str, Any]


class ChioRecoverySignedConfinedEndorsementV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    artifact: Artifact
    boundary: list[int]
    content: list[int]
    contract: list[int]
    domain_version: int
    evidence: str
    expires_at_unix_ms: int
    implementation: list[int]
    influence: Influence
    issued_at_unix_ms: int
    launch: list[int]
    observation: Observation
    parent: Parent
    policy: list[int]
    size_bytes: int
    source: Source
    target: Target
