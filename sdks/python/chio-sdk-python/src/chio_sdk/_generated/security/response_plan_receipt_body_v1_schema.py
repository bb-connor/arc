# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 134bcf5f7a1c21c17db9942de59edf0bc67aa92d820f3d66aa78326a9f8a0110
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
