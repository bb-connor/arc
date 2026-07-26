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
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, RootModel

from . import key_log_event_body_v1_schema


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


class Signature(RootModel[str]):
    root: Annotated[
        str,
        Field(
            pattern="^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+):[0-9a-f]{6618}:(ed25519|p256|p384)\\+mldsa65)$"
        ),
    ]


class KeyAuthorization(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    algorithm: Algorithm
    key_id: Hash
    signature: Signature


class RecoveryAuthorization(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    algorithm: Algorithm
    authorizer_id: KeyLogIdentifier
    signature: Signature


class Authorizations(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    bootstrap: KeyAuthorization | None = None
    new_key: KeyAuthorization | None = None
    old_key: KeyAuthorization | None = None
    recovery: Annotated[list[RecoveryAuthorization] | None, Field(max_length=64)] = None


class ChioSignedKeyLogEventEnvelopeV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authorizations: Authorizations
    body: key_log_event_body_v1_schema.ChioKeyLogEventBodyV1
