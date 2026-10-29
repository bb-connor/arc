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

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr

from ..root_authority import root_anchor_schema


class Rail(Enum):
    x402 = "x402"


class SettlementState(Enum):
    settled = "settled"
    authorized_pending = "authorized_pending"
    failed = "failed"


class Asset(
    RootModel[
        constr(
            pattern=r"^(iso4217:[A-Z]{3}|caip19:[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}/[-a-z0-9]{3,8}:[-.%a-zA-Z0-9]{1,128})$"
        )
    ]
):
    root: constr(
        pattern=r"^(iso4217:[A-Z]{3}|caip19:[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}/[-a-z0-9]{3,8}:[-.%a-zA-Z0-9]{1,128})$"
    ) = Field(
        ...,
        description="Typed asset: `iso4217:<CODE>` or `caip19:<chain>/<namespace>:<reference>`.",
    )


class Kind(Enum):
    x402_payment_requirements = "x402.payment_requirements"
    x402_payment_payload = "x402.payment_payload"
    x402_settlement_response = "x402.settlement_response"


class RailRef(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Kind
    id: constr(pattern=r"^[^\u0000]+$", min_length=1, max_length=256) | None = None
    digest: root_anchor_schema.Digest = Field(
        ..., description="Digest over the canonical JSON of the decoded base64 payload."
    )


class ChioSettlementClosure(BaseModel):
    """
    `chio.settlement-closure.v1`, signed by the kernel key. Exactly one closure may exist per `authorized_pending` terminal receipt, and its `hold_id` must match that receipt's settlement block.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.settlement-closure.v1"] = Field(..., alias="schema")
    terminal_receipt_id: constr(pattern=r"^[0-9a-f]{64}$")
    hold_id: root_anchor_schema.Identifier
    rail: Rail
    state: SettlementState
    asset: Asset
    amount: constr(pattern=r"^(0|[1-9][0-9]{0,38})$", max_length=39) = Field(
        ..., description="Integer minor units as a decimal string."
    )
    rail_refs: list[RailRef] = Field(..., max_length=8, min_length=1)
    observed_at: conint(ge=0)
    kernel_key: root_anchor_schema.PublicKeyHex
    signature: root_anchor_schema.SignatureHex
