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


class AntiEclipsePolicy(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    maxUpstreamHops: int
    minimumDistinctOperators: int
    requireIndexerObservation: bool
    requireOriginPublisher: bool


class Freshness(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    ageSecs: int
    generatedAt: int
    maxAgeSecs: int
    state: str
    validUntil: int


class Publisher1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    operatorId: str
    operatorName: str
    registryUrl: str
    role: str
    upstreamRegistryUrls: list[str] | None = None


class ReportRef(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    artifactId: str
    kind: str
    operatorId: str
    schema_: str = Field(..., alias="schema")
    sha256: str
    uri: str


class Publisher(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    freshness: Freshness
    observedAt: int
    observedListingSha256: str
    publisher: Publisher1
    reportRef: ReportRef
    upstreamHopCount: int


class ChioFederationQuorumReportSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    antiEclipsePolicy: AntiEclipsePolicy
    finalState: str
    generatedAt: int
    listingId: str
    maxReplicaAgeSecs: int
    namespace: str
    note: str
    originOperatorId: str
    publishers: list[Publisher]
    quorumThreshold: int
    reportId: str
    schema_: Literal["chio.federation-quorum-report.v1"] = Field(..., alias="schema")
