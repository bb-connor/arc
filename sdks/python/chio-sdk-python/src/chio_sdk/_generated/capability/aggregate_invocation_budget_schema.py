# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 12f29b53e7b2b0f290d2f6e643bb969068e1777bf31ecf770aa23307b31bec09
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel

from . import aggregate_budget_root_binding_schema


class Scope(Enum):
    capability = "capability"
    delegation_family = "delegation_family"


class ChioAggregateInvocationBudget2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    max_invocations: Annotated[int, Field(ge=0, le=4294967295)]
    root_binding: Any
    scope: Literal["delegation_family"]


class ChioAggregateInvocationBudget1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    max_invocations: Annotated[int, Field(ge=0, le=4294967295)]
    root_binding: (
        aggregate_budget_root_binding_schema.ChioSignedAggregateBudgetRootBinding | None
    ) = None
    scope: Literal["capability"]


class ChioAggregateInvocationBudget(
    RootModel[ChioAggregateInvocationBudget1 | ChioAggregateInvocationBudget2]
):
    root: Annotated[
        ChioAggregateInvocationBudget1 | ChioAggregateInvocationBudget2,
        Field(title="Chio aggregate invocation budget"),
    ]
