# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 0a3a1765a96b67781f41c28a0d27ad221b6ab37620da7ca89acc92357927dee9
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel

from . import (
    effect_transition_receipt_body_v1_schema,
    response_state_transition_receipt_body_v1_schema,
)
from .response_state_transition_receipt_body_v1_schema import Header as Header_1


class FinalState(Enum):
    active = "active"
    apply_partial = "apply_partial"
    failed = "failed"


class CompletionOutcome1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    state: Literal["planned"]


class DispatchApproval1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    approval_mode: Literal["automatic"]


class CompletionOutcome2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    resulting_version_hash: response_state_transition_receipt_body_v1_schema.Digest
    state: Literal["applied"]


class CompletionOutcome3(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    error_code: response_state_transition_receipt_body_v1_schema.Identifier
    state: Literal["apply_failed"]


class CompletionOutcome(
    RootModel[CompletionOutcome1 | CompletionOutcome2 | CompletionOutcome3]
):
    root: CompletionOutcome1 | CompletionOutcome2 | CompletionOutcome3


class DispatchApproval2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    admission_operation_id: response_state_transition_receipt_body_v1_schema.Identifier
    admission_operation_version: Annotated[int, Field(ge=1, le=9007199254740991)]
    approval_mode: Literal["governed"]
    approval_set_hash: response_state_transition_receipt_body_v1_schema.Digest


class DispatchApproval(RootModel[DispatchApproval1 | DispatchApproval2]):
    root: DispatchApproval1 | DispatchApproval2


class ExecutionDispatch(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    action_id: response_state_transition_receipt_body_v1_schema.Identifier
    approval: DispatchApproval
    authorization_capability_hash: (
        response_state_transition_receipt_body_v1_schema.Digest
    )
    authorized_at_unix_ms: Annotated[int, Field(ge=1, le=9007199254740991)]
    dispatch_id: response_state_transition_receipt_body_v1_schema.Identifier
    executor_authority_generation: Annotated[int, Field(ge=1, le=9007199254740991)]
    executor_authority_id: response_state_transition_receipt_body_v1_schema.Identifier
    governed_intent_hash: response_state_transition_receipt_body_v1_schema.Digest
    plan_hash: response_state_transition_receipt_body_v1_schema.Digest
    policy_decision_hash: response_state_transition_receipt_body_v1_schema.Digest
    schema_version: Literal[1]
    tenant_id: response_state_transition_receipt_body_v1_schema.Identifier


class Effect(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    effect: effect_transition_receipt_body_v1_schema.Effect
    outcome: CompletionOutcome


class Header(Header_1):
    prior_receipt_ids: Annotated[list | None, Field(max_length=1)] = None


class ChioResponseCompletionReceiptBodyV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    dispatch_authorization_hash: (
        response_state_transition_receipt_body_v1_schema.Digest | None
    ) = None
    effects: Annotated[list[Effect], Field(max_length=64, min_length=1)]
    error_code: response_state_transition_receipt_body_v1_schema.Identifier | None = (
        None
    )
    execution_dispatch: ExecutionDispatch | None = None
    final_state: FinalState
    header: Header
    response: response_state_transition_receipt_body_v1_schema.Response
    response_body_hash: response_state_transition_receipt_body_v1_schema.Digest
    response_generation: Annotated[int, Field(ge=1, le=9007199254740991)]
