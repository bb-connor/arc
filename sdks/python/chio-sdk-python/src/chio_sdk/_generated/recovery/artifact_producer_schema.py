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

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr


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


class Scope(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authority_domain: OpaqueId
    tenant_id: OpaqueId
    process_id: OpaqueId


class ArtifactProducerV11(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["native_operation"]
    operation: OpaqueId


class ArtifactProducerV12(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["checkpoint"]
    checkpoint: OpaqueId


class ArtifactProducerV13(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["derivation"]
    operation: OpaqueId


class ArtifactProducerV14(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["adoption"]
    evidence: OpaqueId


class ArtifactReference(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    scope: Scope
    artifact: OpaqueId
    version: OpaqueId
    provenance: RecoveryDigest32


class ArtifactProducerV15(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["import"]
    manifest: RecoveryDigest32
    origin: ArtifactReference


class ArtifactProducerV1(
    RootModel[
        ArtifactProducerV11
        | ArtifactProducerV12
        | ArtifactProducerV13
        | ArtifactProducerV14
        | ArtifactProducerV15
    ]
):
    root: (
        ArtifactProducerV11
        | ArtifactProducerV12
        | ArtifactProducerV13
        | ArtifactProducerV14
        | ArtifactProducerV15
    ) = Field(..., title="Artifact Producer V1")
