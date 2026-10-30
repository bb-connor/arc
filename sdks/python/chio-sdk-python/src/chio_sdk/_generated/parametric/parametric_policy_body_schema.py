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

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class CoverageAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class EvaluatorAuthority(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authorityId: str
    keyEpoch: int
    keyId: str


class PayoutMode(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: str
    windowSeconds: int | None = None


class PayoutRail(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    destinationAccountDigest: str
    kind: str
    railId: str


class Amount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class PayoutSchedule(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    amount: Amount
    kind: str


class Predicate(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: str
    minEvents: int
    thresholdBps: int


class ChioParametricPolicyV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    beneficiaryId: str
    boundCoverageBodyDigest: str
    boundCoverageEnvelopeDigest: str
    coverageAmount: CoverageAmount
    coverageAuthorityId: str
    effectiveFrom: int
    effectiveUntil: int
    evaluatorAuthority: EvaluatorAuthority
    fundingFacilityId: str
    issuedAt: int
    maxCheckpointLagSeconds: int
    payerId: str
    payoutMode: PayoutMode
    payoutRail: PayoutRail
    payoutSchedule: PayoutSchedule
    preActionAuthorityDigest: str
    predicate: Predicate
    schema_: Literal["chio.parametric.policy.v1"] = Field(..., alias="schema")
    subjectKey: str
    windowAnchor: int
    windowSeconds: int
