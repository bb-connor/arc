# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 06789f7cc8fb9ed55f9aba55aadcbf4ec7c60d519627433209cdf916fda34f0d
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr


class Template(Enum):
    support_ticket_public_issue = "support_ticket_public_issue"


class Decision(Enum):
    accepted = "accepted"
    declined = "declined"
    needs_review = "needs_review"


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


class Command(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["create_workflow"]
    creation_key: OpaqueId
    template: Template
    request_seed: constr(min_length=1, max_length=32768)


class Command1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["inspect_workflow"]
    workflow_id: OpaqueId


class Command2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["select_offer"]
    workflow_id: OpaqueId
    expected_revision: SafeInteger
    offer_id: OpaqueId


class Command3(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["submit_approval"]
    workflow_id: OpaqueId
    expected_revision: SafeInteger
    approval: constr(min_length=1, max_length=32768)


class Command4(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["resume_workflow"]
    workflow_id: OpaqueId
    expected_revision: SafeInteger


class Command5(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["cancel_workflow"]
    workflow_id: OpaqueId
    expected_revision: SafeInteger


class Command6(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["report_decision"]
    workflow_id: OpaqueId
    expected_revision: SafeInteger
    decision: Decision


class RecoveryCommandV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.recovery.command.v1"] = Field(..., alias="schema")
    version: Literal[1]
    command_id: OpaqueId
    command: Command | Command1 | Command2 | Command3 | Command4 | Command5 | Command6
