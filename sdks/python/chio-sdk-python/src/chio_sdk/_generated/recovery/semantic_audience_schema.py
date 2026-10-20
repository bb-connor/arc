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

from ..security import information_label_schema


class Completeness(Enum):
    complete = "complete"
    partial = "partial"
    ambiguous = "ambiguous"
    outage = "outage"
    rate_limited = "rate_limited"


class Cursor(Enum):
    complete = "complete"
    pending = "pending"


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
    process_id: OpaqueId
    tenant_id: OpaqueId


class Pagination(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    cursor: Cursor
    pages_expected: SafeInteger
    pages_observed: SafeInteger


class SemanticAudienceV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    account: OpaqueId
    audience: information_label_schema.InformationLabel
    completeness: Completeness
    domain_version: Literal[1]
    observed_at_unix_ms: SafeInteger
    pagination: Pagination
    provider: OpaqueId
    provider_version: constr(min_length=1, max_length=128)
    query: RecoveryDigest32
    resource: OpaqueId
    scope: Scope
    subject_mapping: RecoveryDigest32
    valid_until_unix_ms: SafeInteger
