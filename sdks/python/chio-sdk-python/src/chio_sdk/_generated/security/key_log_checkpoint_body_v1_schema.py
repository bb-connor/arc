# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 12f29b53e7b2b0f290d2f6e643bb969068e1777bf31ecf770aa23307b31bec09
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel


class Hash(RootModel[str]):
    root: Annotated[str, Field(pattern="^0x[0-9a-f]{64}$")]


class ChioKeyLogCheckpointBodyV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    checkpoint_sequence: Annotated[int, Field(ge=0)]
    issued_at: Annotated[int, Field(ge=0)]
    log_id: Annotated[
        str, Field(max_length=128, min_length=1, pattern="^[A-Za-z0-9._:/-]+$")
    ]
    previous_checkpoint_hash: Hash | None = None
    root_hash: Hash
    schema_: Annotated[Literal["chio.key-log.checkpoint.v1"], Field(alias="schema")]
    tree_size: Annotated[int, Field(ge=1)]
