# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: cff572cd647726251b5cdb39013d235e07916c80b9a46e5bc035b374e0fd7041
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class AcceptedPrice(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class RealizedSpend(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class ChioFindingPurchaseResultV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    accepted_price: AcceptedPrice
    authoritative_payment_operation_id: str
    delivery_receipt_sha256: str
    failed_delivery_sha256: str | None = None
    finding_id: str
    output_sha256: str | None = None
    payer: str
    purchase_intent_id: str
    purchase_record_sha256: str | None = None
    realized_spend: RealizedSpend
    recorded_at: int
    request_id: str
    reservation_id: str
    result_id: str
    schema_: Literal["chio.finding.purchase-result.v1"] = Field(..., alias="schema")
    settlement: str
    verdict: str
