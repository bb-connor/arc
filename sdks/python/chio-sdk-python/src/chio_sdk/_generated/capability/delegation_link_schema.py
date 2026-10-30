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
