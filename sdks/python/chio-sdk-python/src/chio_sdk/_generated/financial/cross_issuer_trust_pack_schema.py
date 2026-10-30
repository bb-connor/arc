# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: b6f1812f92935a14019f86d41be473435cc0ec402c6c70767457f18fc119ce8a
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class CredentialBinding(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    credentialId: str
    envelopeDigest: str
    family: str


class Body(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    certificationRefs: list[str]
    credentialBindings: list[CredentialBinding]
    decidedAt: int
    decision: str
    decisionDigest: str
    entryId: str
    issuer: str
    lifecycleEvidenceDigest: str
    lifecyclePinDigest: str
    migrationEnvelopeDigests: list[str]
    packId: str
    presentationDigest: str
    profileFamily: str
    reason: str
    schema_: str = Field(..., alias="schema")
    signerKeyEpoch: int
    signerKeyId: str
    sourceKind: str
    sourceManifestDigest: str
    sourcePassportId: str
    verifierId: str


class Decision(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body
    signature: str
    signerKey: str


class ChioFinancialCrossIssuerTrustPackSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    createdAt: int
    decisions: list[Decision]
    expiresAt: int
    packId: str
    policy: dict[str, Any]
    schema_: Literal["chio.financial.cross-issuer-trust-pack.v1"] = Field(
        ..., alias="schema"
    )
    signerKeyEpoch: int
    signerKeyId: str
    verifierId: str
