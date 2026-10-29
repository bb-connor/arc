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


class PricePerCall(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class Sla(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    availabilityBps: int
    maxLatencyMs: int
    throughputRps: int


class ChioMarketplaceListingPricingHintSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    capabilityScope: str
    expiresAt: int
    issuedAt: int
    listingId: str
    namespace: str
    pricePerCall: PricePerCall
    providerOperatorId: str
    recentReceiptsVolume: int
    revocationRateBps: int
    schema_: Literal["chio.marketplace.listing-pricing-hint.v1"] = Field(
        ..., alias="schema"
    )
    sla: Sla
