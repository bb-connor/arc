# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: f98e61fca1094fc6e2763340dae554e56c34e2d18e5720c6f3a7f9b589406726
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from pydantic import BaseModel, ConfigDict, conint

from . import response_state_transition_receipt_body_v1_schema


class ChioSchedulerHealthReceiptBodyV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    header: response_state_transition_receipt_body_v1_schema.Header
    response: response_state_transition_receipt_body_v1_schema.Response
    event_id: response_state_transition_receipt_body_v1_schema.Identifier
    first_failure_at_unix_ms: response_state_transition_receipt_body_v1_schema.Time
    attempts: conint(ge=1, le=4294967295)
    scheduler_fencing_token: conint(ge=1, le=9007199254740991)
    error_code: response_state_transition_receipt_body_v1_schema.Identifier
    evidence_hash: response_state_transition_receipt_body_v1_schema.Digest
