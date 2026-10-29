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


class AgreedPrice(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class ChioFactorAssignmentAgreementV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    agreedDiscountBps: int
    agreedPrice: AgreedPrice
    agreementId: str
    assignmentAuthorityDigest: str
    buyerId: str
    buyerSettlementDestinationRef: str
    claimDigest: str
    claimId: str
    dueAtUnixMs: int
    effectiveAtUnixMs: int
    expectedDispositionLifecycleFence: int
    expectedDispositionVersion: int
    expectedSettlementLifecycleFence: int
    expectedSettlementLifecycleVersion: int
    normalizedRequestDigest: str
    obligationAtomDigest: str
    obligationId: str
    offerDigest: str
    offerId: str
    operationId: str
    schema_: Literal["chio.factor.assignment-agreement.v1"] = Field(..., alias="schema")
    sellerId: str
