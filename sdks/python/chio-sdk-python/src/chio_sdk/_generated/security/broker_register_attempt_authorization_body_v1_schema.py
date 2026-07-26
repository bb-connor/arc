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
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel


class Action(Enum):
    register = "register"
    prepare = "prepare"
    release = "release"


class Digest(RootModel[str]):
    root: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]


class Identifier(RootModel[str]):
    root: Annotated[str, Field(max_length=512, min_length=1)]


class PublicKey(RootModel[str]):
    root: Annotated[
        str,
        Field(
            pattern="^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\\+mldsa65)$"
        ),
    ]


class ChioBrokerRegisterAttemptAuthorizationBodyV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    action: Action
    authority: PublicKey
    issuedAtUnixSeconds: Annotated[int, Field(ge=1)]
    registrationDigest: Digest
    schema_: Annotated[
        Literal["chio.broker-register-attempt-authorization.v1"], Field(alias="schema")
    ]
    tenantScope: Identifier
