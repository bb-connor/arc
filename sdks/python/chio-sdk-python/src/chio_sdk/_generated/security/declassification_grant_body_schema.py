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

from pydantic import BaseModel, ConfigDict, Field


class Owners(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    owner_a: list[str] = Field(..., alias="owner-a")


class TargetLabel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    compartments: list[str]
    kind: str
    owners: Owners


class ChioDeclassificationGrantV1SignedBody(BaseModel):
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
