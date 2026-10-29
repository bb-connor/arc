# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: b55a701e44e8cab56a79619656a773cbb3b9fd63c65594e997f7efc988bc178c
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Edge(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    edgeType: str
    fromTaskId: str
    toTaskId: str


class Join(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    joinId: str
    nextTaskId: str
    parentTaskIds: list[str]


class Node(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    budgetAllocationRef: str | None = None
    continuationTokenRef: str | None = None
    depth: int
    parentTaskId: str | None = None
    routePlanRef: str | None = None
    scopeHash: str
    taskId: str


class ChioSwarmTaskGraphV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    budgetPoolRef: str
    createdAtUnixMs: int
    edges: list[Edge]
    expiresAtUnixMs: int
    graphId: str
    issuer: str
    joins: list[Join]
    maxDepth: int
    maxFanout: int
    multiHopWitnessChains: bool | None = None
    nodes: list[Node]
    plannerSubject: str
    revocationEpochRef: str
    rootTransactionRef: str
    routePlanRefs: list[str]
    schema_: Literal["chio.swarm.task-graph.v1"] = Field(..., alias="schema")
