# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: b55a701e44e8cab56a79619656a773cbb3b9fd63c65594e997f7efc988bc178c
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum

from chio_sdk._manifest_wire import SecurityWireModel as BaseModel

from pydantic import ConfigDict, Field, conint, constr


class Schema(Enum):
    """
    chio.execution_nonce.v1 signs the canonical nonce body. chio.operation_execution_nonce.v1 signs the operation-bound context defined by PROTOCOL.md and is not accepted by the chio.execution_nonce.v1 replay-store verifier.
    """

    chio_execution_nonce_v1 = "chio.execution_nonce.v1"
    chio_operation_execution_nonce_v1 = "chio.operation_execution_nonce.v1"


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
        description="chio.execution_nonce.v1 signs the canonical nonce body. chio.operation_execution_nonce.v1 signs the operation-bound context defined by PROTOCOL.md and is not accepted by the chio.execution_nonce.v1 replay-store verifier.",
    )
    nonce_id: constr(min_length=1)
    issued_at: conint(strict=True, ge=0)
    expires_at: conint(strict=True, ge=0)
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
