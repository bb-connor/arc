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


class Amount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class AuthoritySignature(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    partyId: str
    partyKeyEpoch: int
    signature: str
    signerKey: str


class EffectiveCeiling(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class Body(BaseModel):
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
    schema_: str = Field(..., alias="schema")
    scopeDigest: str
    toolName: str
    toolServer: str


class CreditorSignature(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    partyId: str
    partyKeyEpoch: int
    signature: str
    signerKey: str


class DebtorSignature(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    partyId: str
    partyKeyEpoch: int
    signature: str
    signerKey: str


class CreditFacilityBind(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authoritySignature: AuthoritySignature
    body: Body
    creditorSignature: CreditorSignature
    debtorSignature: DebtorSignature


class ChioCreditReceivableIouEnvelopeV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    amount: Amount
    capabilityId: str
    creditAuthorityDigest: str
    creditFacilityBind: CreditFacilityBind
    currentDispositionDigest: str
    debtorId: str
    dueAtUnixMs: int
    facilityId: str
    iouId: str
    issuedAtUnixMs: int
    issuerId: str
    issuerKeyEpoch: int
    obligationAtomDigest: str
    obligationId: str
    operationId: str
    originalCreditorId: str
    originalSettlementDestinationRef: str
    payeeBindingDigest: str
    receiptContentHash: str
    receiptDigest: str
    receiptId: str
    receiptPolicyHash: str
    receiptTimestampUnixSeconds: int
    schema_: Literal["chio.credit.receivable-iou-envelope.v1"] = Field(
        ..., alias="schema"
    )
    tenantId: str | None = None
    toolName: str
    toolServer: str
