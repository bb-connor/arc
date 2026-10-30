# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: cdaf59925a71448dee294bc7dd11837a988bac5f39ad022834183bd6833707a0
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class MaxCoverageAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class Policy(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    claimsSupported: bool
    coverageClasses: list[str]
    jurisdiction: str
    maxCoverageAmount: MaxCoverageAmount
    quoteTtlSeconds: int
    requiredEvidence: list[str]
    supportedCurrencies: list[str]


class Provenance(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    changeReason: str
    configuredAt: int
    configuredBy: str
    sourceRef: str


class SupportBoundary(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    automaticTrustAdmission: bool
    boundCoverageSupported: bool
    curatedRegistryOnly: bool
    permissionlessFederationSupported: bool


class Report(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    displayName: str
    lifecycleState: str
    policies: list[Policy]
    provenance: Provenance
    providerId: str
    providerType: str
    providerUrl: str
    schema_: str = Field(..., alias="schema")
    supportBoundary: SupportBoundary


class ChioMarketProviderSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    issuedAt: int
    lifecycleState: str
    providerRecordId: str
    report: Report
    schema_: Literal["chio.market.provider.v1"] = Field(..., alias="schema")
    supersedesProviderRecordId: str | None = None
