# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 6a4145266d2febc07a862fffbc565f800ff133c6f0adb06aac524c0ff01e4f34
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr


class Identifier(
    RootModel[constr(pattern=r"^[A-Za-z0-9._:/-]+$", min_length=1, max_length=128)]
):
    root: constr(pattern=r"^[A-Za-z0-9._:/-]+$", min_length=1, max_length=128)


class Nonce(
    RootModel[
        constr(
            pattern=r"^[^\u0000-\u001F\u007F-\u009F]+$", min_length=1, max_length=256
        )
    ]
):
    root: constr(
        pattern=r"^[^\u0000-\u001F\u007F-\u009F]+$", min_length=1, max_length=256
    )


class Hash(RootModel[constr(pattern=r"^0x[0-9a-f]{64}$")]):
    root: constr(pattern=r"^0x[0-9a-f]{64}$")


class PositiveU64(RootModel[conint(ge=1, le=18446744073709551615)]):
    root: conint(ge=1, le=18446744073709551615)


class Count(RootModel[conint(ge=0, le=9007199254740991)]):
    root: conint(ge=0, le=9007199254740991)


class KeyLogPin(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    checkpoint_sequence: conint(ge=0, le=18446744073709551615)
    tree_size: conint(ge=0, le=18446744073709551615)
    checkpoint_hash: Hash
    root_hash: Hash
    signing_epoch: conint(ge=0, le=18446744073709551615)


class ChioKeyLogWitnessServiceReadinessBodyV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.key-log.witness-readiness.v1"] = Field(..., alias="schema")
    witness_id: Identifier
    configuration_binding: Hash
    nonce: Nonce
    process_id: conint(ge=1, le=4294967295)
    storage_identity: Hash
    started_at: PositiveU64
    pin: KeyLogPin | None = None
    conflict_count: Count
    gossip_observation_count: Count
