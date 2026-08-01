# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 44e2b5d0d537b81c385e782237c4b1d70e1b43804215a266d836346cbbe1448c
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel

from . import cage_enforcement_prepared_v1_schema, cage_enforcement_record_v1_schema


class Stage(Enum):
    rejection = "rejection"
    bootstrap = "bootstrap"
    enforcement = "enforcement"
    terminal_exit = "terminal_exit"


class Digest(RootModel[str]):
    root: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]


class Identifier(RootModel[str]):
    root: Annotated[str, Field(max_length=512, min_length=1)]


class Bindings(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    fd_table_digest: Digest
    helper_binding_digest: Digest
    manifest_digest: Digest
    plan_digest: Digest
    profile_digest: Digest
    target_binding_digest: Digest
    target_identity: cage_enforcement_prepared_v1_schema.RegularFileIdentity


class ChioCageReceiptBodyV11(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    attempt_id: Identifier
    bindings: Bindings | None = None
    enforcement_record: cage_enforcement_record_v1_schema.ChioCageEnforcementRecordV1
    recorded_at_unix_ms: Annotated[int, Field(ge=1000)]
    schema_: Annotated[Literal["chio.cage.receipt-body.v1"], Field(alias="schema")]
    stage: Literal["rejection"]
    started_at_unix_ms: Annotated[int, Field(ge=1)]


class ChioCageReceiptBodyV12(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    attempt_id: Identifier
    bindings: Bindings
    enforcement_record: cage_enforcement_record_v1_schema.ChioCageEnforcementRecordV1
    recorded_at_unix_ms: Annotated[int, Field(ge=1000)]
    schema_: Annotated[Literal["chio.cage.receipt-body.v1"], Field(alias="schema")]
    stage: Literal["bootstrap"]
    started_at_unix_ms: Annotated[int, Field(ge=1)]


class ChioCageReceiptBodyV13(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    attempt_id: Identifier
    bindings: Bindings
    enforcement_record: cage_enforcement_record_v1_schema.ChioCageEnforcementRecordV1
    recorded_at_unix_ms: Annotated[int, Field(ge=1000)]
    schema_: Annotated[Literal["chio.cage.receipt-body.v1"], Field(alias="schema")]
    stage: Literal["enforcement"]
    started_at_unix_ms: Annotated[int, Field(ge=1)]


class ChioCageReceiptBodyV14(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    attempt_id: Identifier
    bindings: Bindings
    enforcement_record: cage_enforcement_record_v1_schema.ChioCageEnforcementRecordV1
    recorded_at_unix_ms: Annotated[int, Field(ge=1000)]
    schema_: Annotated[Literal["chio.cage.receipt-body.v1"], Field(alias="schema")]
    stage: Literal["terminal_exit"]
    started_at_unix_ms: Annotated[int, Field(ge=1)]


class ChioCageReceiptBodyV1(
    RootModel[
        ChioCageReceiptBodyV11
        | ChioCageReceiptBodyV12
        | ChioCageReceiptBodyV13
        | ChioCageReceiptBodyV14
    ]
):
    root: Annotated[
        ChioCageReceiptBodyV11
        | ChioCageReceiptBodyV12
        | ChioCageReceiptBodyV13
        | ChioCageReceiptBodyV14,
        Field(title="Chio cage receipt body v1"),
    ]
