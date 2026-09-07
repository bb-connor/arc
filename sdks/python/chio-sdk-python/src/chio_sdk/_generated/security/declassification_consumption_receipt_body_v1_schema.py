# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: c56ebd67862c888dd340e0ba3a14bf38d69abc45d8d02e706ed935cd512054ec
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
    header: flow_denial_receipt_body_v1_schema.Header
    policy: flow_denial_receipt_body_v1_schema.Policy
    grant_id: flow_denial_receipt_body_v1_schema.Identifier
    grant_hash: flow_denial_receipt_body_v1_schema.Digest
    request_hash: flow_denial_receipt_body_v1_schema.Digest
    event_id: flow_denial_receipt_body_v1_schema.Identifier
    state: Literal["consumed_pending_dispatch"]
