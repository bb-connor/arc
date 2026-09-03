# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 6a4145266d2febc07a862fffbc565f800ff133c6f0adb06aac524c0ff01e4f34
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint

from . import (
    effect_transition_receipt_body_v1_schema,
    response_state_transition_receipt_body_v1_schema,
)
from .response_state_transition_receipt_body_v1_schema import Header as Header_1


class FinalState(Enum):
    active = "active"
    apply_partial = "apply_partial"
    failed = "failed"


class DispatchApproval1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    approval_mode: Literal["automatic"]


class CompletionOutcome1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    state: Literal["planned"]


class Header(Header_1):
    prior_receipt_ids: list | None = Field(None, max_length=1)


class DispatchApproval2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    approval_mode: Literal["governed"]
    admission_operation_id: response_state_transition_receipt_body_v1_schema.Identifier
    admission_operation_version: conint(ge=1, le=9007199254740991)
    approval_set_hash: response_state_transition_receipt_body_v1_schema.Digest


class DispatchApproval(RootModel[DispatchApproval1 | DispatchApproval2]):
    root: DispatchApproval1 | DispatchApproval2


class CompletionOutcome2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    state: Literal["applied"]
    resulting_version_hash: response_state_transition_receipt_body_v1_schema.Digest


class CompletionOutcome3(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    state: Literal["apply_failed"]
    error_code: response_state_transition_receipt_body_v1_schema.Identifier


class CompletionOutcome(
    RootModel[CompletionOutcome1 | CompletionOutcome2 | CompletionOutcome3]
):
    root: CompletionOutcome1 | CompletionOutcome2 | CompletionOutcome3


class Effect(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    effect: effect_transition_receipt_body_v1_schema.Effect
    outcome: CompletionOutcome


class ExecutionDispatch(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    schema_version: Literal[1]
    tenant_id: response_state_transition_receipt_body_v1_schema.Identifier
    dispatch_id: response_state_transition_receipt_body_v1_schema.Identifier
    action_id: response_state_transition_receipt_body_v1_schema.Identifier
    plan_hash: response_state_transition_receipt_body_v1_schema.Digest
    executor_authority_id: response_state_transition_receipt_body_v1_schema.Identifier
    executor_authority_generation: conint(ge=1, le=9007199254740991)
    authorization_capability_hash: (
        response_state_transition_receipt_body_v1_schema.Digest
    )
    governed_intent_hash: response_state_transition_receipt_body_v1_schema.Digest
    policy_decision_hash: response_state_transition_receipt_body_v1_schema.Digest
    approval: DispatchApproval
    authorized_at_unix_ms: conint(ge=1, le=9007199254740991)


class ChioResponseCompletionReceiptBodyV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    header: Header
    response: response_state_transition_receipt_body_v1_schema.Response
    execution_dispatch: ExecutionDispatch | None = None
    dispatch_authorization_hash: (
        response_state_transition_receipt_body_v1_schema.Digest | None
    ) = None
    response_generation: conint(ge=1, le=9007199254740991)
    response_body_hash: response_state_transition_receipt_body_v1_schema.Digest
    final_state: FinalState
    error_code: response_state_transition_receipt_body_v1_schema.Identifier | None = (
        None
    )
    effects: list[Effect] = Field(..., max_length=64, min_length=1)
