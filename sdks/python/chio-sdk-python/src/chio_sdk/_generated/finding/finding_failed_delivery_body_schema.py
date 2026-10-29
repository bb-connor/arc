# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: b55a701e44e8cab56a79619656a773cbb3b9fd63c65594e997f7efc988bc178c
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ChioFindingFailedDeliveryV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    accepted_bid_envelope_sha256: str
    authoritative_payment_operation_id: str
    buyer: str
    currency: str
    deny_checkpoint_ref: str
    deny_checkpoint_sha256: str
    deny_receipt_id: str
    deny_receipt_sha256: str
    failed_delivery_id: str
    finding_id: str
    hold_attempt_reference: str
    listing_id: str
    payout_eligible: bool
    purchase_intent_id: str
    realized_spend_units: int
    recorded_at: int
    release_terminal: str
    reservation_id: str
    schema_: Literal["chio.finding.failed-delivery.v1"] = Field(..., alias="schema")
    seller_backing_envelope_sha256: str
    venue_admission_envelope_sha256: str
