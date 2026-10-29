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


class NormalizedAssertions(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    attestationType: str
    runtimeIdentity: str | None = None


class NormalizedClaim(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    category: str
    code: str
    confidence: str
    freshness: str
    provenance: str
    value: str


class VendorClaims(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    attestationType: str


class Claims(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    normalizedAssertions: NormalizedAssertions
    normalizedClaims: list[NormalizedClaim]
    vendorClaims: VendorClaims


class Evidence(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    evidenceSha256: str
    expiresAt: int
    issuedAt: int
    schema_: str = Field(..., alias="schema")
    verifier: str


class Reason(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    code: str
    description: str
    disposition: str
    group: str


class Policy(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    effectiveTier: str
    reasonCodes: list[str]
    reasons: list[Reason]
    verdict: str


class Verifier(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    adapter: str
    verifierFamily: str


class Artifact(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    claims: Claims
    evidence: Evidence
    policy: Policy
    schema_: str = Field(..., alias="schema")
    verifier: Verifier


class Appraisal(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    adapter: str
    artifact: Artifact
    effectiveTier: str
    evidence: Evidence
    normalizedAssertions: NormalizedAssertions
    normalizedClaims: list[NormalizedClaim]
    reasonCodes: list[str]
    reasons: list[Reason]
    schema_: str = Field(..., alias="schema")
    vendorClaims: VendorClaims
    verdict: str
    verifierFamily: str


class PolicyOutcome(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    accepted: bool
    effectiveTier: str
    reason: str
    trustPolicyConfigured: bool


class ChioRuntimeAttestationAppraisalReportSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    appraisal: Appraisal
    generatedAt: int
    policyOutcome: PolicyOutcome
    schema_: Literal["chio.runtime-attestation.appraisal-report.v1"] = Field(
        ..., alias="schema"
    )
