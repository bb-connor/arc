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

from pydantic import BaseModel, ConfigDict, Field

from . import (
    effect_transition_receipt_body_v1_schema,
    response_state_transition_receipt_body_v1_schema,
)


class ChioResponsePlanReceiptBodyV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    header: response_state_transition_receipt_body_v1_schema.Header
    response: response_state_transition_receipt_body_v1_schema.Response
    plan_created_at_unix_ms: response_state_transition_receipt_body_v1_schema.Time
    effects: list[effect_transition_receipt_body_v1_schema.Effect] = Field(
        ..., max_length=64, min_length=1
    )
