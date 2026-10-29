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

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Arguments(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    message: str


class Decision(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    approver: str
    decision: str
    expires_at: int
    governed_intent_hash: str
    id: str
    issued_at: int
    request_id: str
    signature: str
    subject: str


class Value(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    capability_id: str
    parameters_hash: str


class Body(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: str
    value: Value


class ChioToolApproval(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    arguments: Arguments
    capability_hash: str
    policy_hash: str
    request_id: str
    schema_: str = Field(..., alias="schema")
    tenant_id: str


class Context(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    chio_tool_approval: ChioToolApproval
    mcpSessionId: str


class Intent(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body
    context: Context
    id: str
    purpose: str
    server_id: str
    tool_name: str


class ChioMcpOperatorApprovalSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    arguments: Arguments
    capability_id: str
    created_at: int
    decision: Decision | None = None
    expires_at: int
    id: str
    intent: Intent
    policy_fingerprint: str
    request_id: str
    runtime_contract_fingerprint: str
    schema_: Literal["chio.mcp.operator-approval.v1"] = Field(..., alias="schema")
    session_id: str
    subject: str
