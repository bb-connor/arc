# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 0a3a1765a96b67781f41c28a0d27ad221b6ab37620da7ca89acc92357927dee9
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel


class DispatchKnowledge(Enum):
    not_started = "not_started"
    not_committed = "not_committed"
    committed = "committed"
    unknown = "unknown"


class Outcome(Enum):
    denied = "denied"
    reversed = "reversed"
    failed = "failed"
    unknown = "unknown"


class Stage(Enum):
    admission = "admission"
    hold = "hold"
    capture = "capture"
    dispatch = "dispatch"
    response = "response"
    receipt_persistence = "receipt_persistence"


class Digest(RootModel[str]):
    root: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]


class DigestOrNull(RootModel[Digest | None]):
    root: Digest | None


class Identifier(RootModel[str]):
    root: Annotated[str, Field(max_length=512, min_length=1)]


class IdentifierOrNull(RootModel[Identifier | None]):
    root: Identifier | None


class ChioBrokerExecutionFailureReceiptBodyV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    attemptId: IdentifierOrNull
    brokerCapabilityId: IdentifierOrNull
    capabilityDigest: DigestOrNull
    diagnosticCode: Annotated[
        str, Field(max_length=128, min_length=6, pattern="^chio\\.[a-z0-9._-]+$")
    ]
    dispatchKnowledge: DispatchKnowledge
    holdId: IdentifierOrNull
    invocationId: IdentifierOrNull
    issuedAtUnixSeconds: Annotated[int, Field(ge=1)]
    outcome: Outcome
    parentCapabilityId: IdentifierOrNull
    receiptId: Identifier
    requestDigest: Digest
    schema_: Annotated[
        Literal["chio.broker-execution-failure-receipt.v1"], Field(alias="schema")
    ]
    stage: Stage
