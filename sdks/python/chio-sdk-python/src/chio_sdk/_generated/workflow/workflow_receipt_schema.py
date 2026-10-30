# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: cdaf59925a71448dee294bc7dd11837a988bac5f39ad022834183bd6833707a0
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Outcome(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str | None = None
    elapsed_secs: int | None = None
    limit_secs: int | None = None
    limit_units: int | None = None
    reason: str | None = None
    spent_units: int | None = None
    status: str
    step_index: int | None = None


class Cost(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class Step(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    allowed: bool
    bilateral_dsse_sha256: str | None = None
    consistency_anchor: str | None = None
    cost: Cost | None = None
    destructive: bool | None = None
    duration_ms: int
    governance_receipt_id: str | None = None
    outcome: str
    output_hash: str | None = None
    parent_receipt_sha256: str | None = None
    server_id: str
    step_index: int
    tool_name: str
    tool_receipt_id: str | None = None


class TotalCost(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class ChioWorkflowReceiptSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    agent_id: str
    capability_id: str
    completed_at: int
    duration_ms: int
    id: str
    kernel_key: str
    outcome: Outcome
    schema_: Literal["chio.workflow-receipt.v1"] = Field(..., alias="schema")
    session_id: str | None = None
    skill_id: str
    skill_version: str
    started_at: int
    steps: list[Step]
    total_cost: TotalCost | None = None
