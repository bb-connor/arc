# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 29e7de509b9e808e1385895b2caf534b995fb61bf99b87fab79bedc072f5a842
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Active(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    scheduleDigest: str
    scheduleId: str
    sequence: int


class LastKnownGood(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    scheduleDigest: str
    scheduleId: str
    sequence: int


class Domain(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    active: Active | None = None
    domain: str
    everActivated: bool
    lastKnownGood: LastKnownGood | None = None


class StagedTransition(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    transitionDigest: str
    transitionId: str


class ChioFiscalContinuityCheckpointV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    anchorId: str
    anchorNamespace: str
    checkpointId: str
    continuitySequence: int
    domains: list[Domain]
    genesisPolicyDigest: str
    genesisPolicyId: str
    governingOperatorId: str
    pinnedCharterDigest: str
    pinnedCharterId: str
    pinnedCharterSequence: int
    previousCheckpointDigest: str | None = None
    runtimeReadinessDigest: str
    schema_: Literal["chio.fiscal.continuity-checkpoint.v1"] = Field(
        ..., alias="schema"
    )
    signerKeyEpoch: int
    signerKeyId: str
    stagedTransition: StagedTransition | None = None
    trustedClockHighWater: int
