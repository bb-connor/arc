# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 35f8e30cf30553986a159b074ee485804a85db29547a8102522cd7bfa3080d2e
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.

from __future__ import annotations
from pydantic import BaseModel, ConfigDict, Field
from . import effect_transition_receipt_body_v1_schema, response_state_transition_receipt_body_v1_schema

class ChioResponsePlanReceiptBodyV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    header: response_state_transition_receipt_body_v1_schema.SecurityResponseStateTransitionReceiptBodyV1DefinitionsHeader
    response: response_state_transition_receipt_body_v1_schema.SecurityResponseStateTransitionReceiptBodyV1DefinitionsResponse
    plan_created_at_unix_ms: response_state_transition_receipt_body_v1_schema.Time
    effects: list[effect_transition_receipt_body_v1_schema.SecurityEffectTransitionReceiptBodyV1DefinitionsEffect] = Field(..., max_length=64, min_length=1)

# Public compatibility aliases reference the actual current model classes.
SecurityResponsePlanReceiptBodyV1ChioResponsePlanReceiptBodyV1 = ChioResponsePlanReceiptBodyV1
