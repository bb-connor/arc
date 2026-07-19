# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: e7734a10ce3d0e21e8497fad86bfb2a97e79c44ce827e678a869c592687f8837
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field


class EvidenceClass(Enum):
    asserted = "asserted"
    observed = "observed"
    verified = "verified"


class RelationKind(Enum):
    local_child = "local_child"
    continued = "continued"


class SessionAnchorReference(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    sessionAnchorHash: Annotated[str, Field(min_length=1)]
    sessionAnchorId: Annotated[str, Field(min_length=1)]


class ChioReceiptLineageStatement(BaseModel):
    """
    Signed pairwise receipt lineage statement. Multi-parent lineage views are derived aggregates over these signed parent-child statements.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    childReceiptId: Annotated[str, Field(min_length=1)]
    childRequestId: Annotated[str, Field(min_length=1)]
    childSessionAnchor: SessionAnchorReference
    continuationTokenId: Annotated[str | None, Field(min_length=1)] = None
    evidenceClass: EvidenceClass
    id: Annotated[str, Field(min_length=1)]
    issuedAt: Annotated[int, Field(ge=0)]
    kernelKey: Annotated[
        str,
        Field(
            pattern="^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\\+mldsa65)$"
        ),
    ]
    parentReceiptId: Annotated[str, Field(min_length=1)]
    parentRequestId: Annotated[str, Field(min_length=1)]
    parentSessionAnchor: SessionAnchorReference
    relationKind: RelationKind
    schema_: Annotated[
        Literal["chio.receipt_lineage_statement.v1"], Field(alias="schema")
    ]
    signature: Annotated[
        str,
        Field(
            pattern="^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+):[0-9a-f]{6618}:(ed25519|p256|p384)\\+mldsa65)$"
        ),
    ]
