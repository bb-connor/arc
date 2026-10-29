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

from typing import Any, Literal

from chio_sdk._manifest_wire import SecurityWireModel as BaseModel

from pydantic import ConfigDict, Field, RootModel, conint

from . import aggregate_budget_root_schema


class ChioAggregateInvocationBudget1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    scope: Literal["capability"]
    max_invocations: conint(strict=True, ge=0, le=4294967295)
    root_binding: Any | None = None


class ChioAggregateInvocationBudget2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    scope: Literal["delegation_family"]
    max_invocations: conint(strict=True, ge=0, le=4294967295)
    root_binding: aggregate_budget_root_schema.ChioAggregateBudgetRootBinding


class ChioAggregateInvocationBudget(
    RootModel[ChioAggregateInvocationBudget1 | ChioAggregateInvocationBudget2]
):
    root: ChioAggregateInvocationBudget1 | ChioAggregateInvocationBudget2 = Field(
        ..., title="Chio Aggregate Invocation Budget"
    )
