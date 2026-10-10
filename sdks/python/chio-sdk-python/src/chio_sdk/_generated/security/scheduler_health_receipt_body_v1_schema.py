# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: d2b29cbbc9a0070d3666a33fd5a06bbda07a8e70f6d54bf33c15ca8b74893ff9
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.

from __future__ import annotations
from pydantic import BaseModel, ConfigDict, conint
from . import response_state_transition_receipt_body_v1_schema

class ChioSchedulerHealthReceiptBodyV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    header: response_state_transition_receipt_body_v1_schema.SecurityResponseStateTransitionReceiptBodyV1DefinitionsHeader
    response: response_state_transition_receipt_body_v1_schema.SecurityResponseStateTransitionReceiptBodyV1DefinitionsResponse
    event_id: response_state_transition_receipt_body_v1_schema.Identifier
    first_failure_at_unix_ms: response_state_transition_receipt_body_v1_schema.Time
    attempts: conint(ge=1, le=4294967295)
    scheduler_fencing_token: conint(ge=1, le=9007199254740991)
    error_code: response_state_transition_receipt_body_v1_schema.Identifier
    evidence_hash: response_state_transition_receipt_body_v1_schema.Digest

# Public compatibility aliases reference the actual current model classes.
SecuritySchedulerHealthReceiptBodyV1ChioSchedulerHealthReceiptBodyV1 = ChioSchedulerHealthReceiptBodyV1
