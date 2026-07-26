# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 12f29b53e7b2b0f290d2f6e643bb969068e1777bf31ecf770aa23307b31bec09
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel

from . import response_effect_v1_schema


class ApprovalRequirement1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    approval_type: Literal["automatic"]


class DigestItem(RootModel[int]):
    root: Annotated[int, Field(ge=0, le=255)]


class Digest(RootModel[list[DigestItem]]):
    root: Annotated[list[DigestItem], Field(max_length=32, min_length=32)]


class Identifier(RootModel[str]):
    root: Annotated[
        str,
        Field(
            max_length=256,
            min_length=1,
            pattern="^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$",
        ),
    ]


class Time(RootModel[int]):
    root: Annotated[int, Field(ge=0, le=9007199254740991)]


class ApprovalRequirement2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    approval_type: Literal["governed"]
    policy_id: Identifier


class ApprovalRequirement(RootModel[ApprovalRequirement1 | ApprovalRequirement2]):
    root: ApprovalRequirement1 | ApprovalRequirement2


class OperatorCapability(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    capability_digest: Digest
    capability_id: Identifier
    executor_subject: Identifier
    expires_at_unix_ms: Time


class ChioResponsePlanV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    action_id: Identifier
    affected_ids: Annotated[list[Identifier], Field(max_length=4096, min_length=1)]
    affected_set_hash: Digest
    approval_requirement: ApprovalRequirement
    created_at_unix_ms: Time
    effects: Annotated[
        list[response_effect_v1_schema.ChioResponseEffectV1],
        Field(max_length=64, min_length=1),
    ]
    expires_at_unix_ms: Time
    operator_capability: OperatorCapability
    plan_hash: Digest
    policy_hash: Digest
    policy_version: Identifier
    reason_hash: Digest
    submitter: Identifier
    tenant_id: Identifier
    trigger_finding_hash: Digest
    trigger_finding_id: Identifier
    trigger_finding_receipt_id: Identifier
    ttl_ms: Time
