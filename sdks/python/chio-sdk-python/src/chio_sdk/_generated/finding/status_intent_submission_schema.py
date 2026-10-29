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

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Body(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    feed_id: str
    finding_id: str
    issued_at: int
    key_domain_nonce: int
    schema_: str = Field(..., alias="schema")
    source_authority_id: str


class SourceReceipt(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body
    signature: str
    signerKey: str


class ChioFindingStatusIntentSubmissionSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    feed_id: str
    finding_id: str
    inclusion_deadline: int
    intent_id: str
    issued_at: int
    key_domain_nonce: int
    operator_id: str
    operator_key_epoch: int
    schema_: Literal["chio.finding.status-intent-submission.v1"] = Field(
        ..., alias="schema"
    )
    source: str
    source_authority_id: str
    source_receipt: SourceReceipt
    source_receipt_sha256: str
