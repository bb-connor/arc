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

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Eligibility(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    allowedActorKinds: list[str]
    allowedPublisherRoles: list[str]
    allowedStatuses: list[str]
    policyReference: str
    requireBondBacking: bool
    requireFreshListing: bool
    requiredListingOperatorIds: list[str] | None = None


class Freshness(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    ageSecs: int
    generatedAt: int
    maxAgeSecs: int
    state: str
    validUntil: int


class Publisher(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    operatorId: str
    operatorName: str | None = None
    registryUrl: str
    role: str


class ReviewContext(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    freshness: Freshness
    publisher: Publisher


class ChioRegistryTrustActivationSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    activationId: str
    admissionClass: str
    disposition: str
    eligibility: Eligibility
    expiresAt: int
    listingId: str
    listingPublishedAt: int
    listingSha256: str
    localOperatorId: str
    localOperatorName: str | None = None
    namespace: str
    note: str | None = None
    requestedAt: int
    requestedBy: str
    reviewContext: ReviewContext
    reviewedAt: int | None = None
    reviewedBy: str | None = None
    schema_: Literal["chio.registry.trust-activation.v1"] = Field(..., alias="schema")
