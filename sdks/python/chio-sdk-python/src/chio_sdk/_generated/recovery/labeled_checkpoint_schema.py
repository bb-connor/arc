# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: a7762f49cfa77fd7ddcf7cfce82b6289601c6482fc8d9a869103048118492e74
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr

from ..security import information_label_schema


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


class LabeledCheckpointV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    artifacts: list[ArtifactReference] = Field(..., max_length=8, min_length=1)
    checkpoint: OpaqueId
    domain_version: Literal[1]
    influence: ArtifactInfluence
    isolation_epoch: constr(min_length=1, max_length=128)
    label: information_label_schema.InformationLabel
    lineage: OpaqueId
    model_contexts: list[ModelContext] = Field(..., max_length=8, min_length=0)
    native_evidence_sequence: conint(ge=1, le=9007199254740991)
    policy: RecoveryDigest32
    revision: conint(ge=1, le=9007199254740991)
    runtime: constr(min_length=1, max_length=128)
    scope: Scope
