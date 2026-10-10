# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: d2b29cbbc9a0070d3666a33fd5a06bbda07a8e70f6d54bf33c15ca8b74893ff9
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.

from __future__ import annotations
from typing import Any, Literal
from chio_sdk._manifest_wire import SecurityWireModel as BaseModel
from pydantic import ConfigDict, Field, RootModel, conint
from . import aggregate_budget_root_schema

class CapabilityAggregateInvocationBudgetVariant0(BaseModel):
    model_config = ConfigDict(extra='forbid')
    scope: Literal['capability']
    max_invocations: conint(strict=True, ge=0, le=4294967295)
    root_binding: Any | None = None

class CapabilityAggregateInvocationBudgetVariant1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    scope: Literal['delegation_family']
    max_invocations: conint(strict=True, ge=0, le=4294967295)
    root_binding: aggregate_budget_root_schema.ChioAggregateBudgetRootBinding

class ChioAggregateInvocationBudget(RootModel[CapabilityAggregateInvocationBudgetVariant0 | CapabilityAggregateInvocationBudgetVariant1]):
    root: CapabilityAggregateInvocationBudgetVariant0 | CapabilityAggregateInvocationBudgetVariant1 = Field(..., title='Chio Aggregate Invocation Budget')

# Public compatibility aliases reference the actual current model classes.
CapabilityAggregateInvocationBudgetChioAggregateInvocationBudget = ChioAggregateInvocationBudget
ChioAggregateInvocationBudget1 = CapabilityAggregateInvocationBudgetVariant0
ChioAggregateInvocationBudget2 = CapabilityAggregateInvocationBudgetVariant1
