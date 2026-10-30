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

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr

from ..security import information_label_schema


class ArtifactSink1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["agent"]


class ArtifactSink3(BaseModel):
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


class ArtifactSink2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    context: ModelContext
    kind: Literal["model"]


class ArtifactSink(RootModel[ArtifactSink1 | ArtifactSink2 | ArtifactSink3]):
    root: ArtifactSink1 | ArtifactSink2 | ArtifactSink3


class ArtifactRecipientV1(BaseModel):
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
