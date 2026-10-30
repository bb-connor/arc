# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: cff572cd647726251b5cdb39013d235e07916c80b9a46e5bc035b374e0fd7041
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Criterion(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    description: str
    id: str
    status: str


class Evidence(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    evidenceProfile: str
    generatedReportBytes: int
    generatedReportMediaType: str
    generatedReportSha256: str
    normalizedResultsSha256: str
    normalizedScenariosSha256: str
    provenanceMode: str
    resultsDir: str
    scenariosDir: str


class Finding(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: str
    message: str


class Summary(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    evaluatedPeerCount: int
    failCount: int
    missingScenariosCount: int
    passCount: int
    resultCount: int
    scenarioCount: int
    skippedCount: int
    unknownResultsCount: int
    unsupportedCount: int
    xfailCount: int


class Target(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    toolServerId: str
    toolServerName: str | None = None


class ChioCertifyCheckSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    checkedAt: int
    criteria: list[Criterion]
    criteriaProfile: str
    evidence: Evidence
    findings: list[Finding]
    schema_: Literal["chio.certify.check.v1"] = Field(..., alias="schema")
    summary: Summary
    target: Target
    verdict: str
