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


class Body(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    adapter: str
    appraisalArtifactSchema: str
    appraisalResultSchema: str
    attestationSchemas: list[str]
    descriptorId: str
    expiresAt: int
    issuedAt: int
    referenceValuesUri: str | None = None
    schema_: str = Field(..., alias="schema")
    signingKeyFingerprints: list[str]
    verifier: str
    verifierFamily: str


class Descriptor(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body
    signature: str
    signerKey: str


class Measurements(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    mrEnclave: str


class Body214(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    attestationSchema: str
    descriptorId: str
    expiresAt: int
    issuedAt: int
    measurements: Measurements
    referenceValueId: str
    schema_: str = Field(..., alias="schema")
    sourceUri: str
    state: str
    verifierFamily: str


class ReferenceValue(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body214
    signature: str
    signerKey: str


class ChioRuntimeAttestationTrustBundleSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    bundleId: str
    descriptors: list[Descriptor]
    expiresAt: int
    issuedAt: int
    publisher: str
    referenceValues: list[ReferenceValue] | None = None
    schema_: Literal["chio.runtime-attestation.trust-bundle.v1"] = Field(
        ..., alias="schema"
    )
    version: int
