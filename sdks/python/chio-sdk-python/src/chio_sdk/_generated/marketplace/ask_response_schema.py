# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 9040b11ea385ff84e98e4063d81426678eceeb5a4d55e2f86191e7f0064502af
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class QuotedPrice(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class Settlement(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    mode: str


class Value(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    finding_id: str
    listing_id: str
    settlement: Settlement


class Constraint(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    type: str
    value: str | Value


class MaxCostPerInvocation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class MaxTotalCost(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class Grant(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    constraints: list[Constraint] | None = None
    dpop_required: bool | None = None
    max_cost_per_invocation: MaxCostPerInvocation
    max_invocations: int
    max_total_cost: MaxTotalCost
    operations: list[str]
    server_id: str
    tool_name: str


class PromptGrant(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    operations: list[str]
    prompt_name: str


class ResourceGrant(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    operations: list[str]
    uri_pattern: str


class Scope(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    grants: list[Grant]
    prompt_grants: list[PromptGrant] | None = None
    resource_grants: list[ResourceGrant] | None = None


class TokenOffer(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    expires_at: int
    id: str
    issued_at: int
    issuer: str
    schema_: str = Field(..., alias="schema")
    scope: Scope
    signature: str
    subject: str


class ChioMarketplaceAskResponseSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    agentId: str
    bidDigest: str
    expiresAt: int
    issuedAt: int
    listingId: str
    quotedPrice: QuotedPrice
    schema_: Literal["chio.marketplace.ask-response.v1"] = Field(..., alias="schema")
    tokenOffer: TokenOffer
