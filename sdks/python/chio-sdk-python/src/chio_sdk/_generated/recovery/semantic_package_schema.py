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

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr

from ..security import information_label_schema


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


class Channel(Enum):
    input = "input"
    success = "success"
    error = "error"
    no_value = "no_value"
    nested = "nested"
    batch = "batch"
    pagination = "pagination"
    redirect = "redirect"
    stream = "stream"
    file = "file"
    log = "log"
    shell = "shell"
    model = "model"


class SemanticChannel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    channel: Channel
    enabled: bool


class Kind(Enum):
    support_read = "support_read"
    issue_write = "issue_write"
    field_projection = "field_projection"


class Kind14(Enum):
    historical_fact = "historical_fact"
    current_predicate = "current_predicate"
    held_reservation = "held_reservation"


class SemanticPrerequisiteRequirement(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    fact: OpaqueId
    kind: Kind14
    resource: OpaqueId


class SemanticSelector4(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    field: OpaqueId
    kind: Literal["present"]


class SemanticSelector6(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    bytes: SafeInteger
    field: OpaqueId
    kind: Literal["text_bytes_at_most"]


class SemanticValue4(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["text"]
    value: constr(min_length=1, max_length=4096)


class SemanticValue5(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["integer"]
    value: SafeInteger


class SemanticValue6(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["boolean"]
    value: bool


class SemanticValue(RootModel[SemanticValue4 | SemanticValue5 | SemanticValue6]):
    root: SemanticValue4 | SemanticValue5 | SemanticValue6


class SemanticSelector5(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    field: OpaqueId
    kind: Literal["equals"]
    value: SemanticValue


class SemanticSelector(
    RootModel[SemanticSelector4 | SemanticSelector5 | SemanticSelector6]
):
    root: SemanticSelector4 | SemanticSelector5 | SemanticSelector6


class SemanticWithheldStatus(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    audience: information_label_schema.InformationLabel


class SemanticOperation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    channels: list[SemanticChannel] = Field(..., max_length=13, min_length=1)
    external_influence: bool
    implementation: RecoveryDigest32
    input_fields: list[OpaqueId] = Field(..., max_length=16, min_length=0)
    input_schema: RecoveryDigest32
    kind: Kind
    operation: OpaqueId
    output_schema: RecoveryDigest32
    prerequisites: list[SemanticPrerequisiteRequirement] = Field(
        ..., max_length=8, min_length=0
    )
    projection_fields: list[OpaqueId] = Field(..., max_length=8, min_length=0)
    required_assertions: list[OpaqueId] = Field(..., max_length=8, min_length=0)
    selectors: list[SemanticSelector] = Field(..., max_length=16, min_length=0)
    source_label: information_label_schema.InformationLabel
    withheld_status: SemanticWithheldStatus | None = None


class SemanticPackageV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    dependencies: list[RecoveryDigest32] = Field(..., max_length=16, min_length=0)
    domain_version: Literal[1]
    operations: list[SemanticOperation] = Field(..., max_length=16, min_length=1)
    package: OpaqueId
