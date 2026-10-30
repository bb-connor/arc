# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: b6f1812f92935a14019f86d41be473435cc0ec402c6c70767457f18fc119ce8a
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Checks(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    allowed_mediated_receipt_limit: str
    required_guards: str
    tenant: str
    tool_targets: str


class Body(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    batch_end_seq: int
    batch_start_seq: int
    chain_root: str
    checkpoint_seq: int
    issued_at: int
    kernel_key: str
    merkle_root: str
    previous_checkpoint_sha256: str | None = None
    schema_: str = Field(..., alias="schema")
    tree_size: int


class Checkpoint(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body
    signature: str


class Coverage(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    archived_through_entry_seq: int | None = None
    checkpoint: Checkpoint | None = None
    kind: str
    session_id: str | None = None
    snapshot_end_entry_seq: int | None = None
    tenant_id: None = None


class ChioComplianceCertificateSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    all_signatures_valid: bool
    anomalies: list[str]
    budget_compliant: bool
    chain_continuous: bool
    checks: Checks
    compliance_profile_digest: str
    coverage: Coverage
    first_receipt_at: int
    guards_compliant: bool
    invocation_count: int
    issued_at: int
    kernel_key: str
    last_receipt_at: int
    receipt_count: int
    receipt_set_digest: str
    schema_: Literal["chio.compliance.certificate.v1"] = Field(..., alias="schema")
    scope_compliant: bool
    session_id: str
