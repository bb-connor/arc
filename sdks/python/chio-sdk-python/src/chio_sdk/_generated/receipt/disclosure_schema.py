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

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, constr

from ..root_authority import root_anchor_schema


class Opening(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    salt_ref: root_anchor_schema.SaltRef = Field(
        ...,
        description="Names the commitment this opening opens (`params`, `content`, `anchor.sub`, `anchor.tenant` or a committed claim).",
    )
    salt: root_anchor_schema.Salt
    payload: Any = Field(
        ...,
        description="The committed value. `null` is a salt-only opening, valid only where the holder already has the payload (the caller copy, `caller` bundles and the PDP response to the enforcement point that sent the arguments).",
    )


class ChioReceiptDisclosure(BaseModel):
    """
    `chio.receipt-disclosure.v1`: an unsigned, self-verifying opening of a committed receipt's salted commitments. A verifier opens a commitment by recomputing it; the commitment domain comes from the commitment's position in the receipt, never from the opening. The same salt under two `salt_ref` values marks the receipt as tampered disclosure.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.receipt-disclosure.v1"] = Field(..., alias="schema")
    receipt_id: constr(pattern=r"^[0-9a-f]{64}$") = Field(
        ..., description="`id` of the receipt whose commitments these openings open."
    )
    openings: list[Opening] = Field(..., max_length=64, min_length=1)
