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

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ComponentScore(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    component: str
    evidence_ref: str
    score: int
    stale: bool
    weight: int


class FreshnessWindow(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    valid_from: str
    valid_until: str


class ChioTrustScorecardSnapshotV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    component_scores: list[ComponentScore]
    computed_score: int
    downgrade_reasons: list[dict[str, Any]]
    freshness_window: FreshnessWindow
    id: str
    issued_at: str
    issuer_trust_roots: list[str]
    negative_event_refs: list[dict[str, Any]]
    portable_reputation_import_refs: list[str]
    reputation_snapshot_refs: list[str]
    schema_: Literal["chio.trust.scorecard-snapshot.v1"] = Field(..., alias="schema")
    scope: str
    score_ceiling: int
    score_floor: int
    sla_performance_refs: list[str]
    subject: str
    verifier_policy_ref: str
