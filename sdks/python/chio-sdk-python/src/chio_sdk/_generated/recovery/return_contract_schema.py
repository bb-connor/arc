# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 8f4d04243cd350fcdbd87808b58e0b5565570e6b2d3406614efbe9dce3de495e
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr

from ..security import information_label_schema


class ArtifactSink22(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["agent"]


class ArtifactSink24(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["archive"]


class OpaqueId(
    RootModel[
        constr(
            pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", min_length=1, max_length=128
        )
    ]
):
    root: constr(
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", min_length=1, max_length=128
    )


class RecoveryDigest32Item(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255) = Field(..., title="Recovery digest octet")


class RecoveryDigest32(RootModel[list[RecoveryDigest32Item]]):
    root: list[RecoveryDigest32Item] = Field(
        ..., max_length=32, min_length=32, title="Recovery digest32"
    )


class SafeInteger(RootModel[conint(ge=0, le=9007199254740991)]):
    root: conint(ge=0, le=9007199254740991)


class Scope(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authority_domain: OpaqueId
    tenant_id: OpaqueId
    process_id: OpaqueId


class ArtifactInfluence(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    commitment: RecoveryDigest32
    externally_influenced: bool
    unknown: bool


class ArtifactReference(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    scope: Scope
    artifact: OpaqueId
    version: OpaqueId
    provenance: RecoveryDigest32


class ModelContext(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    context: OpaqueId
    provider: OpaqueId
    account: OpaqueId
    conversation: constr(min_length=1, max_length=128)
    cache: constr(min_length=1, max_length=128)
    side_files: list[ArtifactReference] = Field(..., max_length=8, min_length=0)
    contract: RecoveryDigest32


class ArtifactSink23(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["model"]
    context: ModelContext


class ArtifactSink(RootModel[ArtifactSink22 | ArtifactSink23 | ArtifactSink24]):
    root: ArtifactSink22 | ArtifactSink23 | ArtifactSink24


class ArtifactRecipient(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    recipient: OpaqueId
    scope: Scope
    runtime: constr(min_length=1, max_length=128)
    principal: constr(min_length=1, max_length=256)
    lineage: OpaqueId
    isolation_epoch: constr(min_length=1, max_length=128)
    context_generation: SafeInteger
    clearance: information_label_schema.InformationLabel
    sink: ArtifactSink


class ReturnContractV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    domain_version: Literal[1]
    contract: RecoveryDigest32
    schema_: RecoveryDigest32 = Field(..., alias="schema")
    implementation: RecoveryDigest32
    field: constr(min_length=1, max_length=128)
    parent: ArtifactRecipient
    source_ceiling: information_label_schema.InformationLabel
    target: information_label_schema.InformationLabel
    require_integrity: bool
    max_bytes: Literal[8]
    max_values: Literal[1]
    channels: list[str] = Field(..., max_length=1, min_length=1)
    expires_at_unix_ms: conint(ge=1, le=9007199254740991)
    policy: RecoveryDigest32
