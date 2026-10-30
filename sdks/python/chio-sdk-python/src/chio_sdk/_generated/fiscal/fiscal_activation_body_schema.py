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


class Body(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    admissionDigest: str
    admissionId: str
    approvalExpiresAt: int
    approvalId: str
    approvedAt: int
    proposalDigest: str
    proposalId: str
    schema_: str = Field(..., alias="schema")
    signerKeyId: str


class Approval(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body
    signature: str
    signerKey: str


class Ceiling(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class Params(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    ceilings: list[Ceiling]
    kind: str


class Body165(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    charterDigest: str
    charterId: str
    domain: str
    issuedAt: int
    issuedBy: str
    params: Params
    scheduleId: str
    schema_: str = Field(..., alias="schema")
    sequence: int
    supersedesScheduleId: str
    validFrom: int
    validUntil: int


class SuccessorSchedule(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body165
    signature: str
    signerKey: str


class Target(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: str
    predecessorCharterDigest: str | None = None
    scheduleId: str | None = None
    successorCharterDigest: str | None = None
    successorSchedules: list[SuccessorSchedule] | None = None
    supersedesScheduleId: str | None = None


class ChioFiscalActivationV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    activatedAt: int
    activationId: str
    activationNotBefore: int
    admissionDigest: str
    admissionId: str
    approvalSetDigest: str
    approvals: list[Approval]
    charterDigest: str
    charterId: str
    issuedBy: str
    proposalDigest: str
    proposalId: str
    schema_: Literal["chio.fiscal.activation.v1"] = Field(..., alias="schema")
    target: Target
