# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 29e7de509b9e808e1385895b2caf534b995fb61bf99b87fab79bedc072f5a842
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class EffectiveWindow(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    end: str
    start: str


class MetricDefinition(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    metric: str
    target: int
    unit: str


class ChioCommerceSlaCommitmentV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    buyer_subject: str
    collateral_position_ref: str
    effective_window: EffectiveWindow
    exclusions_ref: str
    guarantee_decision_ref: str
    id: str
    issued_at: str
    measurement_policy_ref: str
    metric_definitions: list[MetricDefinition]
    order_id: str
    provider_subject: str
    remedy_policy_ref: str
    schema_: Literal["chio.commerce.sla-commitment.v1"] = Field(..., alias="schema")
    service_scope: str
