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

from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel


class Algorithm(Enum):
    ed25519 = "ed25519"
    p256 = "p256"
    p384 = "p384"
    hybrid = "hybrid"


class Hash(RootModel[str]):
    root: Annotated[str, Field(pattern="^0x[0-9a-f]{64}$")]


class KeyLogIdentifier(RootModel[str]):
    root: Annotated[
        str, Field(max_length=128, min_length=1, pattern="^[A-Za-z0-9._:/-]+$")
    ]


class Operation7(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    type: Literal["genesis"]


class Operation8(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    previous_key_id: Hash
    type: Literal["rotate"]
    witness_roster_binding: Hash
    witness_roster_id: KeyLogIdentifier


class Operation9(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    previous_key_id: Hash
    recovery_policy_binding: Hash | None = None
    recovery_policy_id: KeyLogIdentifier | None = None
    type: Literal["abort_rotation"]


class Operation10(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    type: Literal["retire"]


class Operation11(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    type: Literal["revoke"]


class Operation12(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    previous_key_id: Hash
    recovery_policy_binding: Hash
    recovery_policy_id: KeyLogIdentifier
    type: Literal["recover"]
    witness_roster_binding: Hash
    witness_roster_id: KeyLogIdentifier


class Operation(
    RootModel[
        Operation7 | Operation8 | Operation9 | Operation10 | Operation11 | Operation12
    ]
):
    root: Operation7 | Operation8 | Operation9 | Operation10 | Operation11 | Operation12


class PublicKey(RootModel[str]):
    root: Annotated[
        str,
        Field(
            pattern="^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\\+mldsa65)$"
        ),
    ]


class ChioKeyLogEventBodyV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    algorithm: Algorithm
    authority_id: KeyLogIdentifier
    effective_at: Annotated[int, Field(ge=0)]
    event_id: KeyLogIdentifier
    issued_at: Annotated[int, Field(ge=0)]
    key_id: Hash
    log_id: KeyLogIdentifier
    operation: Operation
    previous_event_hash: Hash | None = None
    public_key: PublicKey
    reason: Annotated[
        str | None,
        Field(max_length=512, min_length=1, pattern="^[^\\u0000-\\u001f\\u007f]+$"),
    ] = None
    schema_: Annotated[Literal["chio.key-log.event.v1"], Field(alias="schema")]
    sequence: Annotated[int, Field(ge=0)]
    verify_until: Annotated[int | None, Field(ge=0)] = None
