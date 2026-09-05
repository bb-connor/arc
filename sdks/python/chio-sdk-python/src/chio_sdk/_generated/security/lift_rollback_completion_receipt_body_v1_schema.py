# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 9695e2b405d3cd46de929a925e1a3b9b33ec4a67a0a5e93f625c433f820e1920
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


class Header(Header_1):
    prior_receipt_ids: list | None = Field(None, max_length=1)


class LiftOutcome2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    state: Literal["apply_failed"]
    error_code: response_state_transition_receipt_body_v1_schema.Identifier


class LiftOutcome3(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    state: Literal["restored"]
    resulting_version_hash: response_state_transition_receipt_body_v1_schema.Digest


class LiftOutcome4(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    state: Literal["rollback_failed"]
    error_code: response_state_transition_receipt_body_v1_schema.Identifier


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


class ChioLiftOrRollbackCompletionReceiptBodyV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    header: Header
    response: response_state_transition_receipt_body_v1_schema.Response
    execution_dispatch: (
        response_completion_receipt_body_v1_schema.ExecutionDispatch | None
    ) = None
    dispatch_authorization_hash: (
        response_state_transition_receipt_body_v1_schema.Digest | None
    ) = None
    response_generation: conint(ge=1, le=9007199254740991)
    response_body_hash: response_state_transition_receipt_body_v1_schema.Digest
    final_state: FinalState
    effects: list[Effect] = Field(..., max_length=64, min_length=1)
