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

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class Action(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    parameter_hash: str
    parameters: dict[str, Any]


class Decision(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    verdict: str


class Metadata(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    chio_receipt_signing_nonce: str


class Receipt(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    action: Action
    boundary_class: str
    capability_id: str
    content_hash: str
    decision: Decision
    id: str
    kernel_key: str
    metadata: Metadata
    policy_hash: str
    receipt_kind: str
    redaction_mode: str
    signature: str
    timestamp: int
    tool_name: str
    tool_origin: str
    tool_server: str
    trust_level: str


class ChioRegulatoryReceiptExportSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    after: int | None = None
    agentId: str | None = None
    before: int | None = None
    generatedAt: int
    matchingReceipts: int
    receipts: list[Receipt]
    schema_: Literal["chio.regulatory.receipt-export.v1"] = Field(..., alias="schema")
