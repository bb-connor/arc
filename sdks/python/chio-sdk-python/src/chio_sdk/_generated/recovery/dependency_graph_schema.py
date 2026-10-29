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

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from . import observation_schema


class Node(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    step_id: observation_schema.OpaqueId
    template_id: observation_schema.OpaqueId
    dependencies: list[observation_schema.OpaqueId] = Field(..., max_length=16)
    estimated_cost_units: observation_schema.SafeInteger


class RecoveryDependencyGraphV1(BaseModel):
    """
    Symbolic graph only. Rust verifies canonical dependency order, unique steps, dependency closure, cycles, total cost and the shared work budget.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.recovery.dependency-graph.v1"] = Field(..., alias="schema")
    version: Literal[1]
    nodes: list[Node] = Field(..., max_length=16, min_length=1)
