# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: e7734a10ce3d0e21e8497fad86bfb2a97e79c44ce827e678a869c592687f8837
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

from . import response_state_transition_receipt_body_v1_schema


class ChioSchedulerHealthReceiptBodyV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    attempts: Annotated[int, Field(ge=1, le=4294967295)]
    error_code: response_state_transition_receipt_body_v1_schema.Identifier
    event_id: response_state_transition_receipt_body_v1_schema.Identifier
    evidence_hash: response_state_transition_receipt_body_v1_schema.Digest
    first_failure_at_unix_ms: response_state_transition_receipt_body_v1_schema.Time
    header: response_state_transition_receipt_body_v1_schema.Header
    response: response_state_transition_receipt_body_v1_schema.Response
    scheduler_fencing_token: Annotated[int, Field(ge=1, le=9007199254740991)]
