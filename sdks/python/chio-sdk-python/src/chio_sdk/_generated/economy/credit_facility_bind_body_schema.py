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


class Amount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class EffectiveCeiling(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class ChioCreditFacilityBindV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    actionNonce: str
    amount: Amount
    authorityId: str
    authorityKeyEpoch: int
    authoritySetDigest: str
    bindId: str
    capabilityId: str
    creditorKeyEpoch: int
    debtorId: str
    debtorKeyEpoch: int
    dueAtUnixMs: int
    economicIntentDigest: str
    effectiveCeiling: EffectiveCeiling
    expectedExposureFence: int
    expectedExposureVersion: int
    expiresAtUnixMs: int
    facilityArtifactDigest: str
    facilityId: str
    issuedAtUnixMs: int
    operationId: str
    originalCreditorId: str
    originalSettlementDestinationRef: str
    payeeBindingDigest: str
    requestId: str
    schema_: Literal["chio.credit.facility-bind.v1"] = Field(..., alias="schema")
    scopeDigest: str
    toolName: str
    toolServer: str
