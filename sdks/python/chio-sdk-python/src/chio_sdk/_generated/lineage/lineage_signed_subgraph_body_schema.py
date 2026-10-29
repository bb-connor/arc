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

from pydantic import BaseModel, ConfigDict, Field


class Edge(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    disclosure_state: str
    edge_id: str
    evidence_class: str
    from_: str = Field(..., alias="from")
    kind: str
    relation: str
    source_artifact_sha256: str
    statement_sha256: str
    to: str


class Node(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    artifact_schema: str
    artifact_sha256: str
    depth: int
    disclosure_state: str
    evidence_class: str
    id: str
    kind: str
    parent_ids: list[str]
    receipt_ref: str
    source_id_hash: str
    source_table: str
    tenant_hash: str


class Redaction(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    node_id: str
    reason: str


class ChioLineageSignedSubgraphV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    audience: str
    challenge_nonce: str
    checkpoint_inclusion_sha256: str
    checkpoint_ref: str
    edges: list[Edge]
    frontier_sha256: str
    generated_at: str
    id: str
    leakage_ledger_sha256: str
    lineage_anchor_ref: str
    max_depth: int
    nodes: list[Node]
    policy_profile_id: str
    projection_manifest_sha256: str
    redaction_map_sha256: str
    redactions: list[Redaction]
    required_evidence_class: str
    root_receipt_ids: list[str]
    transaction_passport_ref: str
