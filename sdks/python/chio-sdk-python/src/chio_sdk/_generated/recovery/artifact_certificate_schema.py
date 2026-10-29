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

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr

from ..security import information_label_schema


class Kind(Enum):
    classification = "classification"
    projection = "projection"


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
    process_id: OpaqueId
    tenant_id: OpaqueId


class ArtifactInfluence(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    commitment: RecoveryDigest32
    externally_influenced: bool
    unknown: bool


class ArtifactProducer1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["native_operation"]
    operation: OpaqueId


class ArtifactProducer2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    checkpoint: OpaqueId
    kind: Literal["checkpoint"]


class ArtifactProducer3(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["derivation"]
    operation: OpaqueId


class ArtifactProducer4(BaseModel):
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


class ArtifactProducer5(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["import"]
    manifest: RecoveryDigest32
    origin: ArtifactReference


class ArtifactProducer(
    RootModel[
        ArtifactProducer1
        | ArtifactProducer2
        | ArtifactProducer3
        | ArtifactProducer4
        | ArtifactProducer5
    ]
):
    root: (
        ArtifactProducer1
        | ArtifactProducer2
        | ArtifactProducer3
        | ArtifactProducer4
        | ArtifactProducer5
    )


class ArtifactCertificateV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    artifact: OpaqueId
    configuration: RecoveryDigest32
    content: RecoveryDigest32
    dependencies: list[ArtifactReference] = Field(..., max_length=16, min_length=0)
    domain_version: Literal[1]
    evidence: OpaqueId
    implementation: RecoveryDigest32
    influence: ArtifactInfluence
    issued_at_unix_ms: SafeInteger
    kind: Kind
    output_label: information_label_schema.InformationLabel
    producer: ArtifactProducer
    schema_: RecoveryDigest32 = Field(..., alias="schema")
    scope: Scope
    size_bytes: conint(ge=0, le=1048576)
    valid_until_unix_ms: SafeInteger
    version: OpaqueId
