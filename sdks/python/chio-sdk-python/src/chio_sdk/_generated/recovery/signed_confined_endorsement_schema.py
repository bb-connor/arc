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

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr

from ..security import information_label_schema
from . import confined_return_evidence_schema


class Algorithm(Enum):
    ed25519 = "ed25519"
    p256 = "p256"
    p384 = "p384"
    hybrid = "hybrid"


class ArtifactSink28(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["agent"]


class ArtifactSink30(BaseModel):
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


class ArtifactSink29(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["model"]
    context: ModelContext


class ArtifactSink(RootModel[ArtifactSink28 | ArtifactSink29 | ArtifactSink30]):
    root: ArtifactSink28 | ArtifactSink29 | ArtifactSink30


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


class SignedConfinedEndorsementV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: confined_return_evidence_schema.ConfinedReturnEvidenceV1
    authority_key: constr(
        pattern=r"^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\+mldsa65)$"
    )
    algorithm: Algorithm
    signature: constr(
        pattern=r"^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+):[0-9a-f]{6618}:(ed25519|p256|p384)\+mldsa65)$"
    )
