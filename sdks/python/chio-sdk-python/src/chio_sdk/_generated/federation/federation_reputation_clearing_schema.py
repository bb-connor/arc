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


class Continuity(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    continuityId: str


class ArtifactRef(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    artifactId: str
    kind: str
    operatorId: str
    schema_: str = Field(..., alias="schema")
    sha256: str
    uri: str


class Input(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    artifactRef: ArtifactRef
    blocking: bool
    expiresAt: int
    issuerIndependenceGroupId: str
    issuerOperatorId: str
    kind: str
    note: str
    publishedAt: int
    subjectKey: str
    weightBps: int


class SybilControl(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    localWeightingRequired: bool
    maximumInputsPerIssuer: int
    minimumIndependentIssuers: int
    negativeEventCorroborationRequired: bool
    oracleCapBps: int


class ChioFederationReputationClearingSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    acceptedInputIds: list[str]
    admissionPolicyRef: str
    clearingId: str
    continuity: Continuity
    effectiveAdmissionClass: str
    generatedAt: int
    inputs: list[Input]
    localWeightingPolicyRef: str
    namespace: str
    note: str
    participatingOperatorIds: list[str]
    rejectedInputIds: list[str]
    schema_: Literal["chio.federation-reputation-clearing.v1"] = Field(
        ..., alias="schema"
    )
    subjectKey: str
    sybilControl: SybilControl
