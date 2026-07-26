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
    response_completion_receipt_body_v1_schema,
    response_state_transition_receipt_body_v1_schema,
)
from .response_state_transition_receipt_body_v1_schema import Header as Header_1


class FinalState(Enum):
    lifted = "lifted"
    rollback_partial = "rollback_partial"


class LiftOutcome1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    state: Literal["planned"]


class LiftOutcome5(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    state: Literal["no_rollback_required"]


class LiftOutcome2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    error_code: response_state_transition_receipt_body_v1_schema.Identifier
    state: Literal["apply_failed"]


class LiftOutcome3(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    resulting_version_hash: response_state_transition_receipt_body_v1_schema.Digest
    state: Literal["restored"]


class LiftOutcome4(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    error_code: response_state_transition_receipt_body_v1_schema.Identifier
    state: Literal["rollback_failed"]


class LiftOutcome(
    RootModel[LiftOutcome1 | LiftOutcome2 | LiftOutcome3 | LiftOutcome4 | LiftOutcome5]
):
    root: LiftOutcome1 | LiftOutcome2 | LiftOutcome3 | LiftOutcome4 | LiftOutcome5


class Effect(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    effect: effect_transition_receipt_body_v1_schema.Effect
    outcome: LiftOutcome


class Header(Header_1):
    prior_receipt_ids: Annotated[list | None, Field(max_length=1)] = None


class ChioLiftOrRollbackCompletionReceiptBodyV11(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    dispatch_authorization_hash: (
        response_state_transition_receipt_body_v1_schema.Digest | None
    ) = None
    effects: Annotated[list[Effect], Field(max_length=64, min_length=1)]
    execution_dispatch: (
        response_completion_receipt_body_v1_schema.ExecutionDispatch | None
    ) = None
    final_state: FinalState
    header: Header
    response: response_state_transition_receipt_body_v1_schema.Response
    response_body_hash: response_state_transition_receipt_body_v1_schema.Digest
    response_generation: Annotated[int, Field(ge=1, le=9007199254740991)]


class ChioLiftOrRollbackCompletionReceiptBodyV12(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    dispatch_authorization_hash: response_state_transition_receipt_body_v1_schema.Digest
    effects: Annotated[list[Effect], Field(max_length=64, min_length=1)]
    execution_dispatch: response_completion_receipt_body_v1_schema.ExecutionDispatch
    final_state: FinalState
    header: Header
    response: response_state_transition_receipt_body_v1_schema.Response
    response_body_hash: response_state_transition_receipt_body_v1_schema.Digest
    response_generation: Annotated[int, Field(ge=1, le=9007199254740991)]


class ChioLiftOrRollbackCompletionReceiptBodyV1(
    RootModel[
        ChioLiftOrRollbackCompletionReceiptBodyV11
        | ChioLiftOrRollbackCompletionReceiptBodyV12
    ]
):
    root: Annotated[
        ChioLiftOrRollbackCompletionReceiptBodyV11
        | ChioLiftOrRollbackCompletionReceiptBodyV12,
        Field(title="Chio lift or rollback completion receipt body v1"),
    ]
