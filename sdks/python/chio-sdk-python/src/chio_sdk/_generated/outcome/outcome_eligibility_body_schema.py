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


class OutcomePrice(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class ChioOutcomeEligibilityV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    capabilityId: str
    deliveryAckDeadlineUnixMs: int
    eligibilityId: str
    expiresAtUnixMs: int
    issuedAtUnixMs: int
    kernelAuthorityId: str
    kernelKeyEpoch: int
    listingDigest: str
    listingId: str
    outcomePrice: OutcomePrice
    postGuardPolicyDigest: str
    preActionAuthorityDigest: str
    predicateDigest: str
    predicateId: str
    pricingDigest: str
    pricingId: str
    providerBindingDigest: str
    providerId: str
    qualifiedRailCapabilityDigest: str
    qualifiedRailId: str
    quoteDigest: str
    railCaptureDeadlineUnixMs: int
    receiverBindingDigest: str
    requestExtensionDigest: str
    requestId: str
    schema_: Literal["chio.outcome.eligibility.v1"] = Field(..., alias="schema")
    settlementMode: str
    slaDigest: str
    toolName: str
    toolServer: str
