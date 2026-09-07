# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: c56ebd67862c888dd340e0ba3a14bf38d69abc45d8d02e706ed935cd512054ec
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr


class Identifier(
    RootModel[constr(pattern=r"^[A-Za-z0-9._:/-]+$", min_length=1, max_length=128)]
):
    root: constr(pattern=r"^[A-Za-z0-9._:/-]+$", min_length=1, max_length=128)


class Hash(RootModel[constr(pattern=r"^0x[0-9a-f]{64}$")]):
    root: constr(pattern=r"^0x[0-9a-f]{64}$")


class U64(RootModel[conint(ge=0, le=18446744073709551615)]):
    root: conint(ge=0, le=18446744073709551615)


class Type(Enum):
    receipt_checkpoint = "receipt_checkpoint"
    key_log_checkpoint = "key_log_checkpoint"


class CheckpointAnchor(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    type: Type
    checkpoint_sequence: U64
    checkpoint_hash: Hash


class ExternalAnchor(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    type: Literal["external"]
    commitment: Hash


class Anchor(RootModel[CheckpointAnchor | ExternalAnchor]):
    root: CheckpointAnchor | ExternalAnchor


class ChioKeyLogArtifactTimeAnchorBodyV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.key-log.artifact-time-anchor.v1"] = Field(
        ..., alias="schema"
    )
    anchor_id: Identifier
    artifact_hash: Hash
    anchored_at: U64
    anchor: Anchor
