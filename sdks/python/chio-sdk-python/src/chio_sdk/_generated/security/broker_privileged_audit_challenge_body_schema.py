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


class RunnerAuthorizationBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    auditId: str
    brokerInstanceId: str
    canonicalRequestSha256: str
    capabilitySha256: str
    credentialProvider: str
    deploymentId: str
    expiresAtUnixSeconds: int
    issuedAtUnixSeconds: int
    proofSha256: str
    providerAdapterId: str
    providerAdapterVersion: int
    referenceCommitmentSha256: str
    referenceSource: str
    revocationAuthorityDomain: str
    runnerId: str
    schema_: str = Field(..., alias="schema")
    tenantScope: str


class ChioBrokerPrivilegedAuditChallengeV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    expiresAtUnixSeconds: int
    issuedAtUnixSeconds: int
    runnerAuthorizationBody: RunnerAuthorizationBody
    schema_: Literal["chio.broker-privileged-audit-challenge.v1"] = Field(
        ..., alias="schema"
    )
    sessionCommitmentSha256: str
    sessionNonce: str
