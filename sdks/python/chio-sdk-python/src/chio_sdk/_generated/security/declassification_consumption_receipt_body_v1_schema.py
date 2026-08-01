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

from typing import Literal

from pydantic import BaseModel, ConfigDict

from . import flow_denial_receipt_body_v1_schema


class ChioDeclassificationConsumptionReceiptBodyV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    event_id: flow_denial_receipt_body_v1_schema.Identifier
    grant_hash: flow_denial_receipt_body_v1_schema.Digest
    grant_id: flow_denial_receipt_body_v1_schema.Identifier
    header: flow_denial_receipt_body_v1_schema.Header
    policy: flow_denial_receipt_body_v1_schema.Policy
    request_hash: flow_denial_receipt_body_v1_schema.Digest
    state: Literal["consumed_pending_dispatch"]
