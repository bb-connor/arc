# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 0a3a1765a96b67781f41c28a0d27ad221b6ab37620da7ca89acc92357927dee9
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel

from . import key_log_witness_signature_v1_schema


class Hash(RootModel[str]):
    root: Annotated[str, Field(pattern="^0x[0-9a-f]{64}$")]


class KeyLogIdentifier(RootModel[str]):
    root: Annotated[
        str, Field(max_length=128, min_length=1, pattern="^[A-Za-z0-9._:/-]+$")
    ]


class ChioKeyLogActivationCommitBodyV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    checkpoint_body_hash: Hash
    checkpoint_hash: Hash
    checkpoint_sequence: Annotated[int, Field(ge=0)]
    committed_at: Annotated[int, Field(ge=0)]
    event_id: KeyLogIdentifier
    event_leaf_hash: Hash
    log_id: KeyLogIdentifier
    root_hash: Hash
    schema_: Annotated[
        Literal["chio.key-log.activation-commit.v1"], Field(alias="schema")
    ]
    signing_epoch: Annotated[int, Field(ge=1)]
    tree_size: Annotated[int, Field(ge=1)]
    witness_set_hash: Hash
    witness_signatures: Annotated[
        list[key_log_witness_signature_v1_schema.ChioKeyLogWitnessSignatureV1],
        Field(max_length=64, min_length=1),
    ]
