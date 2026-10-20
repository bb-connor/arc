# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: f9c25e1eb1ce1c8ea4083ef04968d45682cd9f79d853175aac0d03e295257b73
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr


class KeyLogIdentifier(
    RootModel[constr(pattern=r"^[A-Za-z0-9._:/-]+$", min_length=1, max_length=128)]
):
    root: constr(pattern=r"^[A-Za-z0-9._:/-]+$", min_length=1, max_length=128)


class Hash(RootModel[constr(pattern=r"^0x[0-9a-f]{64}$")]):
    root: constr(pattern=r"^0x[0-9a-f]{64}$")


class Algorithm(Enum):
    ed25519 = "ed25519"
    p256 = "p256"
    p384 = "p384"
    hybrid = "hybrid"


class PublicKey(
    RootModel[
        constr(
            pattern=r"^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\+mldsa65)$"
        )
    ]
):
    root: constr(
        pattern=r"^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\+mldsa65)$"
    )


class Operation11(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    type: Literal["genesis"]


class Operation12(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    type: Literal["rotate"]
    previous_key_id: Hash
    witness_roster_id: KeyLogIdentifier
    witness_roster_binding: Hash


class Operation13(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    type: Literal["abort_rotation"]
    previous_key_id: Hash
    recovery_policy_id: KeyLogIdentifier | None = None
    recovery_policy_binding: Hash | None = None


class Operation14(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    type: Literal["retire"]


class Operation15(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    type: Literal["revoke"]


class Operation16(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    type: Literal["recover"]
    previous_key_id: Hash
    witness_roster_id: KeyLogIdentifier
    witness_roster_binding: Hash
    recovery_policy_id: KeyLogIdentifier
    recovery_policy_binding: Hash


class Operation(
    RootModel[
        Operation11
        | Operation12
        | Operation13
        | Operation14
        | Operation15
        | Operation16
    ]
):
    root: (
        Operation11
        | Operation12
        | Operation13
        | Operation14
        | Operation15
        | Operation16
    )


class ChioKeyLogEventBodyV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.key-log.event.v1"] = Field(..., alias="schema")
    log_id: KeyLogIdentifier
    sequence: conint(ge=0)
    event_id: KeyLogIdentifier
    previous_event_hash: Hash | None = None
    authority_id: KeyLogIdentifier
    key_id: Hash
    algorithm: Algorithm
    public_key: PublicKey
    operation: Operation
    effective_at: conint(ge=0)
    verify_until: conint(ge=0) | None = None
    reason: (
        constr(pattern=r"^[^\u0000-\u001f\u007f]+$", min_length=1, max_length=512)
        | None
    ) = None
    issued_at: conint(ge=0)
