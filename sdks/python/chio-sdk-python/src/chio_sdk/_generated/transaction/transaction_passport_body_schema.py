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

from pydantic import BaseModel, ConfigDict, Field


class OmissionPolicyItem(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    claim_id: str
    reason: str
    status: str


class ChioTransactionPassportV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    claim_set_path: str
    claim_set_sha256: str
    evidence_graph_path: str
    evidence_graph_sha256: str
    id: str
    issued_at: str
    issuer: str
    omission_policy: list[OmissionPolicyItem] | None = None
    schema_: Literal["chio.transaction-passport.v1"] = Field(..., alias="schema")
    verifier_policy_path: str
    verifier_policy_sha256: str
