# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 29f505f3691b4fbfea30cc6f60a7264757030799f7d4c23f1b591e15d011a565
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ChioOutcomeOutputProvenanceV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authorityId: str
    authorityKeyEpoch: int
    eligibilityDigest: str
    expiresAtUnixMs: int
    finalOutputDigest: str
    issuedAtUnixMs: int
    postGuardEvidenceDigest: str
    postGuardPolicyDigest: str
    provenanceClass: str
    provenanceId: str
    providerAcceptanceDigest: str
    providerOutputDigest: str
    redactionProofDigest: str | None = None
    requestId: str
    schema_: Literal["chio.outcome.output-provenance.v1"] = Field(..., alias="schema")
