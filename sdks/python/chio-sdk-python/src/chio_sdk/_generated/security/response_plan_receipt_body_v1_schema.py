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

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

from . import (
    effect_transition_receipt_body_v1_schema,
    response_state_transition_receipt_body_v1_schema,
)


class ChioResponsePlanReceiptBodyV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    effects: Annotated[
        list[effect_transition_receipt_body_v1_schema.Effect],
        Field(max_length=64, min_length=1),
    ]
    header: response_state_transition_receipt_body_v1_schema.Header
    plan_created_at_unix_ms: response_state_transition_receipt_body_v1_schema.Time
    response: response_state_transition_receipt_body_v1_schema.Response
