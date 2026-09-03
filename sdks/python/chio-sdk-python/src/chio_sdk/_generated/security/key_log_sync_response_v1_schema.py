# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: bab930356fcbf944c42cdbdaef62cc82db4c242eee4942218590770e15ff1c0e
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr

from . import (
    key_log_activation_commit_envelope_v1_schema,
    key_log_checkpoint_envelope_v1_schema,
    key_log_event_envelope_v1_schema,
)


class Hash(RootModel[constr(pattern=r"^0x[0-9a-f]{64}$")]):
    root: constr(pattern=r"^0x[0-9a-f]{64}$")


class ConsistencyProof(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    old_size: conint(ge=1)
    new_size: conint(ge=1)
    audit_path: list[Hash] = Field(..., max_length=65)


class ChioKeyLogSynchronizationResponseV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    base_checkpoint_hash: Hash | None = None
    checkpoints: list[
        key_log_checkpoint_envelope_v1_schema.ChioSignedKeyLogCheckpointEnvelopeV1
    ] = Field(..., max_length=4096)
    event_envelopes: list[
        key_log_event_envelope_v1_schema.ChioSignedKeyLogEventEnvelopeV1
    ] = Field(..., max_length=4096)
    activation_commits: (
        list[
            key_log_activation_commit_envelope_v1_schema.ChioSignedKeyLogActivationCommitEnvelopeV1
        ]
        | None
    ) = Field(None, max_length=4096, min_length=1)
    consistency_proof: ConsistencyProof | None = None
