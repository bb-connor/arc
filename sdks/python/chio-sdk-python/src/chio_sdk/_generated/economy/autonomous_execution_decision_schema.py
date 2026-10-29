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


class RollbackControl(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    human_interrupt_contact: str
    interruptible: bool
    rollback_plan_ref: str


class SafetyGate(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    description: str
    name: str
    passed: bool


class ChioAutonomousExecutionDecisionSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    action: str
    authority_envelope_ref: str
    auto_bind_decision_ref: str
    bound_coverage_ref: str
    currency: str
    execution_id: str
    issued_at: int
    lifecycle_state: str
    note: str
    optimization_ref: str
    pricing_decision_ref: str
    provider_id: str
    quote_response_ref: str
    rollback_control: RollbackControl
    safety_gates: list[SafetyGate]
    schema_: Literal["chio.autonomous-execution-decision.v1"] = Field(
        ..., alias="schema"
    )
    settlement_dispatch_ref: str
    subject_key: str
