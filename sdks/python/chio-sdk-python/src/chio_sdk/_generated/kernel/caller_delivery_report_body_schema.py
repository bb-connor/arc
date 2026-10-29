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


class Executor(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    executor_id: str
    key_epoch: int
    public_key: str


class Output(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    closed: bool | None = None
    effect: str | None = None
    external: bool | None = None
    historical: bool | None = None
    original_native_effect: bool | None = None
    outcome: str | None = None
    private_result: str | None = None
    result_sha256: str | None = None
    returned: bool | None = None
    safe: bool | None = None


class RealizedCost(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class ChioCallerDeliveryReportV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authorization_digest: str
    claim_id: str
    completed_at_unix_ms: int
    execution_started_at_unix_ms: int
    executor: Executor
    output: Output
    realized_cost: RealizedCost | None = None
    schema_: Literal["chio.caller-delivery-report.v1"] = Field(..., alias="schema")
