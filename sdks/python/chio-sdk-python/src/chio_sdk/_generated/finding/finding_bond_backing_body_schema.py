# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: b6f1812f92935a14019f86d41be473435cc0ec402c6c70767457f18fc119ce8a
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class LockedAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class MaximumSaleExposure(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class VenueLedger(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    ledger_account: str
    operator_epoch: int


class Vault(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    venue_ledger: VenueLedger


class ChioFindingBondBackingV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    allocation_id: str
    appeal_horizon_secs: int
    audit_horizon_secs: int
    authorization_envelope_sha256: str
    bond_class: str
    claim_horizon_secs: int
    collateral_authority: str
    expires_at: int
    fee_requirement_sha256: str
    fee_schedule_envelope_sha256: str
    finding_id: str
    issued_at: int
    listing_id: str
    locked_amount: LockedAmount
    maximum_sale_exposure: MaximumSaleExposure
    profile_envelope_sha256: str
    schema_: Literal["chio.finding.bond-backing.v1"] = Field(..., alias="schema")
    seller: str
    settlement_buffer_secs: int
    terms_envelope_sha256: str
    vault: Vault
