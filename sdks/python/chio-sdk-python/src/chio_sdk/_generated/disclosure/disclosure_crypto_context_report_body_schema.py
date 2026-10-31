# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: cdaf59925a71448dee294bc7dd11837a988bac5f39ad022834183bd6833707a0
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, constr


class RejectedCheck(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    code: constr(min_length=1)
    message: constr(min_length=1)


class ChioDisclosureCryptoContextReportV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    artifact_ref: str
    context_id: str
    cryptographic_proof_verified: bool
    disclosed_fields: list[str]
    evidence_class: str
    id: str
    projection_manifest_ref: str
    rejected_checks: list[RejectedCheck]
    schema_: Literal["chio.disclosure.crypto-context-report.v1"] = Field(
        ..., alias="schema"
    )
    verdict: str
    verified_claims: list[str]
