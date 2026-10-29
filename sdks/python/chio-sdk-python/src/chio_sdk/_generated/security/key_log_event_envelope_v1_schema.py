# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: f98e61fca1094fc6e2763340dae554e56c34e2d18e5720c6f3a7f9b589406726
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, RootModel, constr

from . import key_log_event_body_v1_schema


class Hash(RootModel[constr(pattern=r"^0x[0-9a-f]{64}$")]):
    root: constr(pattern=r"^0x[0-9a-f]{64}$")


class Signature(
    RootModel[
        constr(
            pattern=r"^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+):[0-9a-f]{6618}:(ed25519|p256|p384)\+mldsa65)$"
        )
    ]
):
    root: constr(
        pattern=r"^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+):[0-9a-f]{6618}:(ed25519|p256|p384)\+mldsa65)$"
    )


class KeyLogIdentifier(
    RootModel[constr(pattern=r"^[A-Za-z0-9._:/-]+$", min_length=1, max_length=128)]
):
    root: constr(pattern=r"^[A-Za-z0-9._:/-]+$", min_length=1, max_length=128)


class KeyAuthorization(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    key_id: Hash
    signature: Signature


class RecoveryAuthorization(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authorizer_id: KeyLogIdentifier
    signature: Signature


class Authorizations(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    bootstrap: KeyAuthorization | None = None
    old_key: KeyAuthorization | None = None
    new_key: KeyAuthorization | None = None
    recovery: list[RecoveryAuthorization] | None = Field(None, max_length=64)


class ChioSignedKeyLogEventEnvelopeV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: key_log_event_body_v1_schema.ChioKeyLogEventBodyV1
    authorizations: Authorizations
