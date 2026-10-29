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

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, conint, constr


class ExitClass(Enum):
    integer_0 = 0
    integer_10 = 10


class Column(Enum):
    identity_root = "identity_root"
    delegation_chain = "delegation_chain"
    decision = "decision"
    content = "content"
    settlement = "settlement"


class EvidenceClass(Enum):
    verified = "verified"
    observed = "observed"
    asserted = "asserted"
    unverifiable = "unverifiable"
    rejected = "rejected"


class ColumnResult(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    class_: EvidenceClass = Field(..., alias="class")
    reason: constr(min_length=1) | None = None


class Columns(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    identity_root: ColumnResult
    delegation_chain: ColumnResult
    decision: ColumnResult
    content: ColumnResult
    settlement: ColumnResult


class ReceiptReport(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    receipt_id: constr(min_length=1)
    seq: conint(ge=0)
    columns: Columns


class ChioBundleVerifyReport(BaseModel):
    """
    `chio.bundle-verify-report.v1`: the unsigned per-receipt column report an offline bundle verifier prints. Every class is computed from the bundle and the verifier-owned trust file.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.bundle-verify-report.v1"] = Field(..., alias="schema")
    envelope_signer: constr(
        pattern=r"^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\+mldsa65)$"
    ) = Field(
        ...,
        description="The kernel key that signed the export envelope, in `PublicKey::to_hex` form.",
    )
    manifest_sha256: constr(pattern=r"^[0-9a-f]{64}$")
    required_columns: list[Column] = Field(..., max_length=5)
    receipts: list[ReceiptReport]
    exit_class: ExitClass
