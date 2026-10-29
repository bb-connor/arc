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

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class Result(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    storage: str
    value: Any


class TerminalResult(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    result: Result
    resultDigest: str
    resultId: str


class ChioChannelTerminalOutcomeCommitmentV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    operationId: str
    outcomeRecordedAtUnixMs: int
    receiptDigest: str
    receiptId: str
    reservationDigest: str
    reservationId: str
    schema_: Literal["chio.channel.terminal-outcome-commitment.v1"] = Field(
        ..., alias="schema"
    )
    terminalResult: TerminalResult
    terminalizedAtUnixMs: int
