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


class ComputedMetricResult(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    metric: str
    passed: bool
    unit: str
    value: int


class ChioCommerceSlaPerformanceReportV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    breach_verdict: str
    computed_metric_results: list[ComputedMetricResult]
    dispute_ref: str
    id: str
    issued_at: str
    measured_at: str
    measurement_evidence_refs: list[str]
    measurement_policy_ref: str
    order_id: str
    performance_id: str
    provider_subject: str
    remedy_ref: str
    schema_: Literal["chio.commerce.sla-performance-report.v1"] = Field(
        ..., alias="schema"
    )
    sla_ref: str
