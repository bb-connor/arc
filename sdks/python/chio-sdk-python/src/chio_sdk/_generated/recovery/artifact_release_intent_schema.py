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

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr

from ..security import information_label_schema


class State(Enum):
    admitted = "admitted"
    uncertain = "uncertain"
    delivered = "delivered"


class ArtifactSink4(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["agent"]


class ArtifactSink6(BaseModel):
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
    process_id: OpaqueId
    tenant_id: OpaqueId


class Kind(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["captured_output"]
    operation: OpaqueId


class Kind2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["independently_admitted"]
    request: OpaqueId


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
    artifact: OpaqueId
    provenance: RecoveryDigest32
    scope: Scope
    version: OpaqueId


class ModelContext(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    account: OpaqueId
    cache: constr(min_length=1, max_length=128)
    context: OpaqueId
    contract: RecoveryDigest32
    conversation: constr(min_length=1, max_length=128)
    provider: OpaqueId
    side_files: list[ArtifactReference] = Field(..., max_length=8, min_length=0)


class ArtifactSink5(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    context: ModelContext
    kind: Literal["model"]


class ArtifactSink(RootModel[ArtifactSink4 | ArtifactSink5 | ArtifactSink6]):
    root: ArtifactSink4 | ArtifactSink5 | ArtifactSink6


class ArtifactRecipient(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    clearance: information_label_schema.InformationLabel
    context_generation: SafeInteger
    isolation_epoch: constr(min_length=1, max_length=128)
    lineage: OpaqueId
    principal: constr(min_length=1, max_length=256)
    recipient: OpaqueId
    runtime: constr(min_length=1, max_length=128)
    scope: Scope
    sink: ArtifactSink


class ArtifactReleaseIntentV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    admitted_label: information_label_schema.InformationLabel
    artifact: ArtifactReference
    authorization: RecoveryDigest32
    domain_version: Literal[1]
    influence: ArtifactInfluence
    kind: Kind | Kind2
    observation_generation: SafeInteger
    observation_transition: OpaqueId
    policy: RecoveryDigest32
    recipient: ArtifactRecipient
    release: OpaqueId
    source_label: information_label_schema.InformationLabel
    state: State
