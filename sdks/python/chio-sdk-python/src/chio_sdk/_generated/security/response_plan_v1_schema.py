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

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr

from . import response_effect_v1_schema


class Identifier(
    RootModel[
        constr(
            pattern=r"^[^\s\u0000-\u001F\u007F-\u009F](?:[^\u0000-\u001F\u007F-\u009F]*[^\s\u0000-\u001F\u007F-\u009F])?$",
            min_length=1,
            max_length=256,
        )
    ]
):
    root: constr(
        pattern=r"^[^\s\u0000-\u001F\u007F-\u009F](?:[^\u0000-\u001F\u007F-\u009F]*[^\s\u0000-\u001F\u007F-\u009F])?$",
        min_length=1,
        max_length=256,
    )


class DigestItem(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255)


class Digest(RootModel[list[DigestItem]]):
    root: list[DigestItem] = Field(..., max_length=32, min_length=32)


class Time(RootModel[conint(ge=0, le=9007199254740991)]):
    root: conint(ge=0, le=9007199254740991)


class OperatorCapability(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    capability_id: Identifier
    capability_digest: Digest
    expires_at_unix_ms: Time
    executor_subject: Identifier


class ApprovalRequirement1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    approval_type: Literal["automatic"]


class ApprovalRequirement2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    approval_type: Literal["governed"]
    policy_id: Identifier


class ApprovalRequirement(RootModel[ApprovalRequirement1 | ApprovalRequirement2]):
    root: ApprovalRequirement1 | ApprovalRequirement2


class ChioResponsePlanV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    action_id: Identifier
    trigger_finding_id: Identifier
    trigger_finding_hash: Digest
    trigger_finding_receipt_id: Identifier
    tenant_id: Identifier
    policy_version: Identifier
    policy_hash: Digest
    affected_ids: list[Identifier] = Field(..., max_length=4096, min_length=1)
    affected_set_hash: Digest
    effects: list[response_effect_v1_schema.ChioResponseEffectV1] = Field(
        ..., max_length=64, min_length=1
    )
    ttl_ms: Time
    created_at_unix_ms: Time
    expires_at_unix_ms: Time
    operator_capability: OperatorCapability
    approval_requirement: ApprovalRequirement
    submitter: Identifier
    reason_hash: Digest
    plan_hash: Digest
