# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 762578c96088419938225c2c4b88fbd19c43eb893686e68295264db18417432d
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


class Scope(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authority_domain: OpaqueId
    tenant_id: OpaqueId
    process_id: OpaqueId


class SafeInteger(RootModel[conint(ge=0, le=9007199254740991)]):
    root: conint(ge=0, le=9007199254740991)


class RecoverySetupProbeV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    domain_version: Literal[1]
    scope: Scope
    probe_id: OpaqueId
    native_authority: RecoveryDigest32
    deployment: RecoveryDigest32
    source_profile: RecoveryDigest32
    required_coverage: RecoveryDigest32
    benign_workflow: OpaqueId
    denied_command: OpaqueId
    issued_at_unix_ms: SafeInteger
    expires_at_unix_ms: SafeInteger
