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


class Owners(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    bob: list[str] | None = None


class TargetLabel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    compartments: list[str]
    kind: str
    owners: Owners


class Claims(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    agent_id: str
    authority_key_id: str
    capability_id: str
    destination_id: str
    domain_version: int
    expires_at_unix_seconds: int
    grant_id: str
    issued_at_unix_seconds: int
    purpose: str
    request_hash: list[int]
    session_id: str
    source_label_hash: list[int]
    subject_id: str
    target_label: TargetLabel
    tenant_id: str
    tool_name: str


class Recovery(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    action_intent: list[int]
    approval_intent: str
    approved_plan: list[int]
    authority_domain: str
    authority_scope: list[int]
    authorization_requirements: list[int]
    challenge: str
    continuation_id: str
    contract_digest: list[int]
    coverage_digest: list[int]
    isolation_epoch: int
    isolation_lineage: str
    output_disposition: list[int]
    policy_digest: list[int]
    process_id: str
    request_id: str
    request_namespace: list[int]
    schema_: str = Field(..., alias="schema")
    selected_offer: list[int]
    step_id: str
    version: int
    workflow_id: str


class ChioRecoveryGrantV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    claims: Claims
    recovery: Recovery
    schema_: Literal["chio.recovery.grant.v1"] = Field(..., alias="schema")
    version: int
