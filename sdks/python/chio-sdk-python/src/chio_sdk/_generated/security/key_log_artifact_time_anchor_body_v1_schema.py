# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: e7734a10ce3d0e21e8497fad86bfb2a97e79c44ce827e678a869c592687f8837
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel


class Type(Enum):
    receipt_checkpoint = "receipt_checkpoint"
    key_log_checkpoint = "key_log_checkpoint"


class Hash(RootModel[str]):
    root: Annotated[str, Field(pattern="^0x[0-9a-f]{64}$")]


class Identifier(RootModel[str]):
    root: Annotated[
        str, Field(max_length=128, min_length=1, pattern="^[A-Za-z0-9._:/-]+$")
    ]


class U64(RootModel[int]):
    root: Annotated[int, Field(ge=0, le=18446744073709551615)]


class CheckpointAnchor(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    checkpoint_hash: Hash
    checkpoint_sequence: U64
    type: Type


class ExternalAnchor(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    commitment: Hash
    type: Literal["external"]


class Anchor(RootModel[CheckpointAnchor | ExternalAnchor]):
    root: CheckpointAnchor | ExternalAnchor


class ChioKeyLogArtifactTimeAnchorBodyV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    anchor: Anchor
    anchor_id: Identifier
    anchored_at: U64
    artifact_hash: Hash
    schema_: Annotated[
        Literal["chio.key-log.artifact-time-anchor.v1"], Field(alias="schema")
    ]
