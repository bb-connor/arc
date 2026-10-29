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


class Indicator(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    admission_envelope_sha256: str | None = None
    blob: str | None = None
    capability_scope: str | None = None
    digest: str | None = None
    finding_id: str | None = None
    indicatorDigest: str | None = None
    kind: str | None = None
    listing_envelope_sha256: str | None = None
    listing_id: str | None = None
    schema_: str | None = Field(None, alias="schema")
    workflowId: str | None = None


class WorkflowContext(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    bilateral_dsse_sha256: str
    consistency_anchor: str
    schema_: str = Field(..., alias="schema")
    step_index: int
    tool_receipt_id: str
    workflow_id: str
    workflow_intersection_id: str
    workflow_intersection_sha256: str
    workflow_receipt_id: str
    workflow_receipt_sha256: str


class ChioPheromoneDepositV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    agent_passport_jwk_thumbprint: str
    agent_passport_key_hash: str
    confidence: float
    decay_half_life_secs: int
    evaporation_floor: float | None = None
    indicator: Indicator
    kernel_id: str
    nonce: str
    schema_: Literal["chio.pheromone-deposit.v1"] = Field(..., alias="schema")
    severity: str
    subject_class: str
    subject_class_namespace: str
    timestamp_unix_ms: int
    treaty_scope: list[str]
    workflow_context: WorkflowContext | None = None
