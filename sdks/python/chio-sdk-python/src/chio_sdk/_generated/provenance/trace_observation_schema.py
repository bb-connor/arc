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


class Parameters(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    nonce: int


class Action(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    parameter_hash: str
    parameters: Parameters


class Decision(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    guard: str | None = None
    reason: str | None = None
    verdict: str


class Attribution(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    delegation_depth: int
    grant_index: int | None = None
    issuer_key: str
    subject_key: str


class ChioRuntime(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    identity_disposition: str


class ReceiptContext(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    evaluation_id: str | None = None
    request_id: str
    request_namespace_digest: str | None = None


class Metadata(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    attribution: Attribution | None = None
    chio_receipt_signing_nonce: str
    chio_runtime: ChioRuntime | None = None
    receipt_context: ReceiptContext


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


class Event(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    admission_sequence: int | None = None
    capability_id: str | None = None
    delegation_depth: int | None = None
    epoch: int | None = None
    kind: str
    receipt: Receipt | None = None
    receipt_time: int | None = None
    request_id: str | None = None
    revocation_admitted: bool | None = None
    revocation_source_id: str | None = None
    revocation_subject_ids: list[str] | None = None
    seen_epoch: int | None = None


class ChioTraceObservationSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authorityKey: str
    delegationDepthLimit: int
    event: Event
    runtimeEventCount: int
    schema_: Literal["chio.trace-observation.v1"] = Field(..., alias="schema")
    sequence: int
    sourceSequence: int
    traceId: str
    traceLength: int
