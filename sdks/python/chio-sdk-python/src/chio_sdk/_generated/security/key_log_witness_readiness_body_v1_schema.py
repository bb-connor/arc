# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 44e2b5d0d537b81c385e782237c4b1d70e1b43804215a266d836346cbbe1448c
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel


class Count(RootModel[int]):
    root: Annotated[int, Field(ge=0, le=9007199254740991)]


class Hash(RootModel[str]):
    root: Annotated[str, Field(pattern="^0x[0-9a-f]{64}$")]


class Identifier(RootModel[str]):
    root: Annotated[
        str, Field(max_length=128, min_length=1, pattern="^[A-Za-z0-9._:/-]+$")
    ]


class KeyLogPin(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    checkpoint_hash: Hash
    checkpoint_sequence: Annotated[int, Field(ge=0, le=18446744073709551615)]
    root_hash: Hash
    signing_epoch: Annotated[int, Field(ge=0, le=18446744073709551615)]
    tree_size: Annotated[int, Field(ge=0, le=18446744073709551615)]


class Nonce(RootModel[str]):
    root: Annotated[
        str,
        Field(
            max_length=256, min_length=1, pattern="^[^\\u0000-\\u001F\\u007F-\\u009F]+$"
        ),
    ]


class PositiveU64(RootModel[int]):
    root: Annotated[int, Field(ge=1, le=18446744073709551615)]


class ChioKeyLogWitnessServiceReadinessBodyV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    configuration_binding: Hash
    conflict_count: Count
    gossip_observation_count: Count
    nonce: Nonce
    pin: KeyLogPin | None = None
    process_id: Annotated[int, Field(ge=1, le=4294967295)]
    schema_: Annotated[
        Literal["chio.key-log.witness-readiness.v1"], Field(alias="schema")
    ]
    started_at: PositiveU64
    storage_identity: Hash
    witness_id: Identifier
