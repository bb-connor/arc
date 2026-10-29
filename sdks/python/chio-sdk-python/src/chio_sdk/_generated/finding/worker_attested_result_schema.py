# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 7c51d7910f0345879134e0bf5bbb042abd7b8dbfdcd23700753b77f6814a0f36
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class GuestEnforcement(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    openFilesBoundary: str
    openFilesHardLimit: int
    openFilesLimitHits: int
    openFilesLimitProbePassed: bool
    openFilesSoftLimit: int
    processBoundary: str
    processLimit: int
    processLimitHits: int
    processLimitProbePassed: bool
    schema_: str = Field(..., alias="schema")


class OutputArtifact(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    name: str
    sha256: str
    sizeBytes: int


class ResourceUsage(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    cpuTimeMillis: int
    openFilesPeak: int
    outputBytes: int
    peakMemoryBytes: int
    processPeak: int
    wallTimeMillis: int
    workspaceBytes: int


class Result(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    classification: str
    diagnostics: list[dict[str, Any]]
    findingArtifactSha256: str
    guestEnforcement: GuestEnforcement
    jobId: str
    outputArtifacts: list[OutputArtifact]
    requestSha256: str
    resourceUsage: ResourceUsage
    schema_: str = Field(..., alias="schema")
    tenantId: str


class ChioFindingWorkerAttestedResultSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    completedAtUnixSecs: int
    firecrackerSha256: str
    guestResultSha256: str
    jailerSha256: str
    jobId: str
    kernelSha256: str
    requestSha256: str
    result: Result
    rootfsSha256: str
    schema_: Literal["chio.finding.worker-attested-result.v1"] = Field(
        ..., alias="schema"
    )
    tenantId: str
    workerBinarySha256: str
