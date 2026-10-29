# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: f98e61fca1094fc6e2763340dae554e56c34e2d18e5720c6f3a7f9b589406726
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class AggregateBudget(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    max_invocations: int
    root_binding_digest: str


class Constraint(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    type: str
    value: int | str


class Attenuation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    constraint: Constraint | None = None
    max_invocations: int | None = None
    operation: str | None = None
    server_id: str
    tool_name: str
    type: str


class Binding(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    approval_budget_epoch: int
    approval_budget_id: str
    currency: str
    root_binding_digest: str


class CumulativeApproval(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    bindings: list[Binding]


class ChioDelegationLinkSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    aggregate_budget: AggregateBudget | None = None
    attenuations: list[Attenuation] | None = None
    capability_id: str | None = None
    cumulative_approval: CumulativeApproval | None = None
    delegatee: str | None = None
    delegator: str | None = None
    fixture: str | None = None
    n: int | None = None
    scope_hash: str | None = None
    timestamp: int | None = None
