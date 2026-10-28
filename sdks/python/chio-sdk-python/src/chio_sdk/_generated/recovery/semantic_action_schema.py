# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: a7762f49cfa77fd7ddcf7cfce82b6289601c6482fc8d9a869103048118492e74
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr

from ..security import information_label_schema


class Output(Enum):
    return_value = "return_value"
    withhold = "withhold"


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


class SemanticInputVersion(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    content: RecoveryDigest32
    resource: OpaqueId
    version: RecoveryDigest32


class SemanticNativeSource(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    generation: SafeInteger
    key: RecoveryDigest32
    lineage_label: information_label_schema.InformationLabel
    principal_label: information_label_schema.InformationLabel
    session_label: information_label_schema.InformationLabel


class SemanticActionV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    capability: RecoveryDigest32
    destination: OpaqueId
    domain_version: Literal[1]
    externally_influenced: bool
    generation: SafeInteger
    influence: RecoveryDigest32
    inputs: list[SemanticInputVersion] = Field(..., max_length=16, min_length=1)
    issued_at_unix_ms: SafeInteger
    native_source: SemanticNativeSource
    operation: OpaqueId
    output: Output
    payload: RecoveryDigest32
    plan: RecoveryDigest32
    registry: RecoveryDigest32
    request_id: OpaqueId
    request_namespace: RecoveryDigest32
    request_semantics: RecoveryDigest32
    scope: Scope
    source_label: information_label_schema.InformationLabel
    step: OpaqueId
    valid_until_unix_ms: SafeInteger
