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

from pydantic import BaseModel, ConfigDict, Field


class ChioTrustReputationImportReportV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    decay_policy_ref: str
    id: str
    import_verdict: str
    issued_at: str
    issuer: str
    issuer_trust_ref: str
    local_weight: int
    negative_event_refs: list[dict[str, Any]]
    privacy_profile_ref: str
    schema_: Literal["chio.trust.reputation-import-report.v1"] = Field(
        ..., alias="schema"
    )
    source_network: str
    source_reputation_ref: str
    subject: str
    subject_binding_ref: str
    usage: str
