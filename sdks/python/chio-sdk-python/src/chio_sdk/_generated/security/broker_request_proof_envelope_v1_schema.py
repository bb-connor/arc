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

from enum import Enum

from pydantic import BaseModel, ConfigDict

from . import broker_capability_envelope_v1_schema, broker_request_proof_body_v1_schema


class Algorithm(Enum):
    ed25519 = "ed25519"
    p256 = "p256"
    p384 = "p384"
    hybrid = "hybrid"


class ChioSignedBrokerRequestProofV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    algorithm: Algorithm
    body: broker_request_proof_body_v1_schema.ChioBrokerRequestProofBodyV1
    signature: broker_capability_envelope_v1_schema.Signature
