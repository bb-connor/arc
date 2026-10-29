# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 7c51d7910f0345879134e0bf5bbb042abd7b8dbfdcd23700753b77f6814a0f36
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, constr


class ChioAgentWebProofEnvelopeV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    agent_web_passport_scope_sha256: str | None = None
    chio_claim_refs: list[str]
    disclosure_capsule_refs: list[constr(min_length=1)]
    envelope_id: str
    external_subject: str
    external_subject_digest: str
    external_subject_path: str
    external_subject_signature_ref: str
    limitations: list[str]
    projection_manifest_ref: str
    projection_manifest_sha256: str
    receipt_refs: list[str]
    risk_refs: list[str]
    schema_: Literal["chio.agent-web-proof-envelope.v1"] = Field(..., alias="schema")
    settlement_refs: list[constr(min_length=1)]
    source_protocol: str
    source_protocol_version: str
    transaction_passport_ref: str
