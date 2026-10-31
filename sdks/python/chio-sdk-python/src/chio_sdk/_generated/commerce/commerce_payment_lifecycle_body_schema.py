# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 29f505f3691b4fbfea30cc6f60a7264757030799f7d4c23f1b591e15d011a565
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ChioCommercePaymentLifecycleV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    amount_minor: int
    authorization_ref: str
    balance_transaction_ref: str
    capture_before: str
    capture_mode: str
    capture_ref: str
    captured_at: str
    charge_ref: str
    chargeback_status: str
    currency: str
    dispute_status: str
    fraud_outcome: str
    id: str
    issued_at: str
    issuer: str
    merchant_subject: str
    order_id: str
    payment_intent_id: str
    payment_status: str
    psp: str
    quote_sha256: str
    refund_status: str
    schema_: Literal["chio.commerce.payment-lifecycle.v1"] = Field(..., alias="schema")
    transfer_group: str
    transfer_reversal_status: str
