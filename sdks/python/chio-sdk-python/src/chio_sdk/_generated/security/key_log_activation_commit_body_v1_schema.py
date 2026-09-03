# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 389bcf1b0204c491a4db719480c568ace486987ea9871d15adefdc3bb3a365cc
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr

from . import key_log_witness_signature_v1_schema


class KeyLogIdentifier(
    RootModel[constr(pattern=r"^[A-Za-z0-9._:/-]+$", min_length=1, max_length=128)]
):
    root: constr(pattern=r"^[A-Za-z0-9._:/-]+$", min_length=1, max_length=128)


class Hash(RootModel[constr(pattern=r"^0x[0-9a-f]{64}$")]):
    root: constr(pattern=r"^0x[0-9a-f]{64}$")


class ChioKeyLogActivationCommitBodyV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.key-log.activation-commit.v1"] = Field(..., alias="schema")
    log_id: KeyLogIdentifier
    event_id: KeyLogIdentifier
    checkpoint_hash: Hash
    checkpoint_body_hash: Hash
    checkpoint_sequence: conint(ge=0)
    tree_size: conint(ge=1)
    root_hash: Hash
    event_leaf_hash: Hash
    witness_set_hash: Hash
    witness_signatures: list[
        key_log_witness_signature_v1_schema.ChioKeyLogWitnessSignatureV1
    ] = Field(..., max_length=64, min_length=1)
    committed_at: conint(ge=0)
    signing_epoch: conint(ge=1)
