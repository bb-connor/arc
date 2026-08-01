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

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, RootModel

from . import (
    key_log_activation_commit_envelope_v1_schema,
    key_log_checkpoint_envelope_v1_schema,
    key_log_event_envelope_v1_schema,
)


class Hash(RootModel[str]):
    root: Annotated[str, Field(pattern="^0x[0-9a-f]{64}$")]


class ConsistencyProof(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    audit_path: Annotated[list[Hash], Field(max_length=65)]
    new_size: Annotated[int, Field(ge=1)]
    old_size: Annotated[int, Field(ge=1)]


class ChioKeyLogSynchronizationResponseV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    activation_commits: Annotated[
        list[
            key_log_activation_commit_envelope_v1_schema.ChioSignedKeyLogActivationCommitEnvelopeV1
        ]
        | None,
        Field(max_length=4096, min_length=1),
    ] = None
    base_checkpoint_hash: Hash | None = None
    checkpoints: Annotated[
        list[
            key_log_checkpoint_envelope_v1_schema.ChioSignedKeyLogCheckpointEnvelopeV1
        ],
        Field(max_length=4096),
    ]
    consistency_proof: ConsistencyProof | None = None
    event_envelopes: Annotated[
        list[key_log_event_envelope_v1_schema.ChioSignedKeyLogEventEnvelopeV1],
        Field(max_length=4096),
    ]
