# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: c56ebd67862c888dd340e0ba3a14bf38d69abc45d8d02e706ed935cd512054ec
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr

from . import cage_enforcement_prepared_v1_schema, cage_enforcement_record_v1_schema


class Stage(Enum):
    rejection = "rejection"
    bootstrap = "bootstrap"
    enforcement = "enforcement"
    terminal_exit = "terminal_exit"


class Identifier(RootModel[constr(min_length=1, max_length=512)]):
    root: constr(min_length=1, max_length=512)


class Digest(RootModel[constr(pattern=r"^[0-9a-f]{64}$")]):
    root: constr(pattern=r"^[0-9a-f]{64}$")


class Bindings(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    manifest_digest: Digest
    profile_digest: Digest
    plan_digest: Digest
    fd_table_digest: Digest
    helper_binding_digest: Digest
    target_binding_digest: Digest
    target_identity: cage_enforcement_prepared_v1_schema.RegularFileIdentity


class ChioCageReceiptBodyV11(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.cage.receipt-body.v1"] = Field(..., alias="schema")
    attempt_id: Identifier
    stage: Literal["rejection"]
    bindings: Bindings | None = None
    enforcement_record: cage_enforcement_record_v1_schema.ChioCageEnforcementRecordV1
    started_at_unix_ms: conint(ge=1)
    recorded_at_unix_ms: conint(ge=1000)


class ChioCageReceiptBodyV12(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.cage.receipt-body.v1"] = Field(..., alias="schema")
    attempt_id: Identifier
    stage: Literal["bootstrap"]
    bindings: Bindings
    enforcement_record: cage_enforcement_record_v1_schema.ChioCageEnforcementRecordV1
    started_at_unix_ms: conint(ge=1)
    recorded_at_unix_ms: conint(ge=1000)


class ChioCageReceiptBodyV13(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.cage.receipt-body.v1"] = Field(..., alias="schema")
    attempt_id: Identifier
    stage: Literal["enforcement"]
    bindings: Bindings
    enforcement_record: cage_enforcement_record_v1_schema.ChioCageEnforcementRecordV1
    started_at_unix_ms: conint(ge=1)
    recorded_at_unix_ms: conint(ge=1000)


class ChioCageReceiptBodyV14(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.cage.receipt-body.v1"] = Field(..., alias="schema")
    attempt_id: Identifier
    stage: Literal["terminal_exit"]
    bindings: Bindings
    enforcement_record: cage_enforcement_record_v1_schema.ChioCageEnforcementRecordV1
    started_at_unix_ms: conint(ge=1)
    recorded_at_unix_ms: conint(ge=1000)


class ChioCageReceiptBodyV1(
    RootModel[
        ChioCageReceiptBodyV11
        | ChioCageReceiptBodyV12
        | ChioCageReceiptBodyV13
        | ChioCageReceiptBodyV14
    ]
):
    root: (
        ChioCageReceiptBodyV11
        | ChioCageReceiptBodyV12
        | ChioCageReceiptBodyV13
        | ChioCageReceiptBodyV14
    ) = Field(..., title="Chio cage receipt body v1")
