# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 9040b11ea385ff84e98e4063d81426678eceeb5a4d55e2f86191e7f0064502af
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr


class OpaqueId(
    RootModel[
        constr(
            pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", min_length=1, max_length=128
        )
    ]
):
    root: constr(
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", min_length=1, max_length=128
    )


class RecoveryDigest32Item(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255) = Field(..., title="Recovery digest octet")


class RecoveryDigest32(RootModel[list[RecoveryDigest32Item]]):
    root: list[RecoveryDigest32Item] = Field(
        ..., max_length=32, min_length=32, title="Recovery digest32"
    )


class SafeInteger(RootModel[conint(ge=0, le=9007199254740991)]):
    root: conint(ge=0, le=9007199254740991)


class Scope(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authority_domain: OpaqueId
    tenant_id: OpaqueId
    process_id: OpaqueId


class Target(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["exact_action"]
    action: RecoveryDigest32


class Target20(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["persistent_artifact"]
    artifact: RecoveryDigest32


class ScopedEndorsementV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    domain_version: Literal[1]
    evidence: OpaqueId
    scope: Scope
    target: Target | Target20
    influence: RecoveryDigest32
    assertions: list[OpaqueId] = Field(..., max_length=8, min_length=1)
    destination: OpaqueId
    purpose: constr(min_length=1, max_length=256)
    issued_at_unix_ms: SafeInteger
    valid_until_unix_ms: SafeInteger
