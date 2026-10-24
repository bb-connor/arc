# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 762578c96088419938225c2c4b88fbd19c43eb893686e68295264db18417432d
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr

from ..security import information_label_schema


class Retention(Enum):
    ephemeral = "ephemeral"
    checkpoint = "checkpoint"
    evidence = "evidence"


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
    process_id: OpaqueId
    tenant_id: OpaqueId


class ArtifactInfluence(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    commitment: RecoveryDigest32
    externally_influenced: bool
    unknown: bool


class ArtifactProducer6(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["native_operation"]
    operation: OpaqueId


class ArtifactProducer7(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    checkpoint: OpaqueId
    kind: Literal["checkpoint"]


class ArtifactProducer8(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["derivation"]
    operation: OpaqueId


class ArtifactProducer9(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    evidence: OpaqueId
    kind: Literal["adoption"]


class ArtifactReference(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    artifact: OpaqueId
    provenance: RecoveryDigest32
    scope: Scope
    version: OpaqueId


class ArtifactProducer10(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["import"]
    manifest: RecoveryDigest32
    origin: ArtifactReference


class ArtifactProducer(
    RootModel[
        ArtifactProducer6
        | ArtifactProducer7
        | ArtifactProducer8
        | ArtifactProducer9
        | ArtifactProducer10
    ]
):
    root: (
        ArtifactProducer6
        | ArtifactProducer7
        | ArtifactProducer8
        | ArtifactProducer9
        | ArtifactProducer10
    )


class ArtifactVersionV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    artifact: OpaqueId
    content: RecoveryDigest32
    contract: RecoveryDigest32
    creation_sequence: conint(ge=1, le=9007199254740991)
    dependencies: list[ArtifactReference] = Field(..., max_length=16, min_length=0)
    domain_version: Literal[1]
    evidence: list[OpaqueId] = Field(..., max_length=8, min_length=0)
    influence: ArtifactInfluence
    isolation_epoch: constr(min_length=1, max_length=128)
    label: information_label_schema.InformationLabel
    lineage: OpaqueId
    media_type: constr(min_length=1, max_length=128)
    policy: RecoveryDigest32
    producer: ArtifactProducer
    retention: Retention
    schema_: RecoveryDigest32 = Field(..., alias="schema")
    scope: Scope
    size_bytes: conint(ge=0, le=1048576)
    version: OpaqueId
