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
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, RootModel

from . import key_log_checkpoint_body_v1_schema, key_log_witness_signature_v1_schema


class OperatorAlgorithm(Enum):
    ed25519 = "ed25519"
    p256 = "p256"
    p384 = "p384"
    hybrid = "hybrid"


class Signature(RootModel[str]):
    root: Annotated[
        str,
        Field(
            pattern="^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+):[0-9a-f]{6618}:(ed25519|p256|p384)\\+mldsa65)$"
        ),
    ]


class ChioSignedKeyLogCheckpointEnvelopeV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: key_log_checkpoint_body_v1_schema.ChioKeyLogCheckpointBodyV1
    operator_algorithm: OperatorAlgorithm
    operator_key_id: Annotated[str, Field(pattern="^0x[0-9a-f]{64}$")]
    operator_signature: Signature
    witness_signatures: Annotated[
        list[key_log_witness_signature_v1_schema.ChioKeyLogWitnessSignatureV1] | None,
        Field(max_length=64),
    ] = None
