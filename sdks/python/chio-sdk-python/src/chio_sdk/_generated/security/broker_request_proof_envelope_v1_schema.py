# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: cff572cd647726251b5cdb39013d235e07916c80b9a46e5bc035b374e0fd7041
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from . import broker_capability_envelope_v1_schema, broker_request_proof_body_v1_schema


class ChioSignedBrokerRequestProofV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: broker_request_proof_body_v1_schema.ChioBrokerRequestProofBodyV1
    signature: broker_capability_envelope_v1_schema.Signature
