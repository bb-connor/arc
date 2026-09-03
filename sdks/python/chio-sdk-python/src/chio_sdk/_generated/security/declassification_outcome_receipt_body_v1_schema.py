# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 6a4145266d2febc07a862fffbc565f800ff133c6f0adb06aac524c0ff01e4f34
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict

from . import flow_denial_receipt_body_v1_schema


class ToState(Enum):
    released = "released"
    dispatch_failed = "dispatch_failed"
    outcome_unknown = "outcome_unknown"


class ChioDeclassificationOutcomeReceiptBodyV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    header: flow_denial_receipt_body_v1_schema.Header
    policy: flow_denial_receipt_body_v1_schema.Policy
    grant_id: flow_denial_receipt_body_v1_schema.Identifier
    grant_hash: flow_denial_receipt_body_v1_schema.Digest
    request_hash: flow_denial_receipt_body_v1_schema.Digest
    event_id: flow_denial_receipt_body_v1_schema.Identifier
    from_state: Literal["consumed_pending_dispatch"]
    to_state: ToState
