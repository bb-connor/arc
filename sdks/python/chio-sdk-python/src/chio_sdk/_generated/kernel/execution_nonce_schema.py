# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: c56ebd67862c888dd340e0ba3a14bf38d69abc45d8d02e706ed935cd512054ec
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, conint, constr


class Schema(Enum):
    """
    v1 signs the canonical nonce body. v2 signs the operation-bound context defined by PROTOCOL.md and is not accepted by legacy replay-store verifiers.
    """

    chio_execution_nonce_v1 = "chio.execution_nonce.v1"
    chio_execution_nonce_v2 = "chio.execution_nonce.v2"


class BoundTo(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    subject_id: constr(min_length=1)
    request_id: constr(min_length=1)
    capability_id: constr(min_length=1)
    tool_server: constr(min_length=1)
    tool_name: constr(min_length=1)
    parameter_hash: constr(pattern=r"^[0-9a-f]{64}$")


class Nonce(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Schema = Field(
        ...,
        alias="schema",
        description="v1 signs the canonical nonce body. v2 signs the operation-bound context defined by PROTOCOL.md and is not accepted by legacy replay-store verifiers.",
    )
    nonce_id: constr(min_length=1)
    issued_at: conint(ge=0)
    expires_at: conint(ge=0)
    bound_to: BoundTo
    reserved_hold_id: constr(min_length=1) | None = None
    reserving_request_id: constr(min_length=1) | None = None


class ChioSignedExecutionNonce(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    nonce: Nonce
    signature: constr(
        pattern=r"^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+):[0-9a-f]{6618}:(ed25519|p256|p384)\+mldsa65)$"
    )
