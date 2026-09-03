# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 389bcf1b0204c491a4db719480c568ace486987ea9871d15adefdc3bb3a365cc
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr


class Stage(Enum):
    admission = "admission"
    hold = "hold"
    capture = "capture"
    dispatch = "dispatch"
    response = "response"
    receipt_persistence = "receipt_persistence"


class Outcome(Enum):
    denied = "denied"
    reversed = "reversed"
    failed = "failed"
    unknown = "unknown"


class DispatchKnowledge(Enum):
    not_started = "not_started"
    not_committed = "not_committed"
    committed = "committed"
    unknown = "unknown"


class Identifier(RootModel[constr(min_length=1, max_length=512)]):
    root: constr(min_length=1, max_length=512)


class IdentifierOrNull(RootModel[Identifier | None]):
    root: Identifier | None


class Digest(RootModel[constr(pattern=r"^[0-9a-f]{64}$")]):
    root: constr(pattern=r"^[0-9a-f]{64}$")


class DigestOrNull(RootModel[Digest | None]):
    root: Digest | None


class ChioBrokerExecutionFailureReceiptBodyV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.broker-execution-failure-receipt.v1"] = Field(
        ..., alias="schema"
    )
    receiptId: Identifier
    issuedAtUnixSeconds: conint(ge=1)
    stage: Stage
    outcome: Outcome
    diagnosticCode: constr(
        pattern=r"^chio\.[a-z0-9._-]+$", min_length=6, max_length=128
    )
    requestDigest: Digest
    capabilityDigest: DigestOrNull
    attemptId: IdentifierOrNull
    invocationId: IdentifierOrNull
    holdId: IdentifierOrNull
    parentCapabilityId: IdentifierOrNull
    brokerCapabilityId: IdentifierOrNull
    dispatchKnowledge: DispatchKnowledge
