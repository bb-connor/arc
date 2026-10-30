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


class EvidenceRef(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: str
    referenceId: str


class ChioRegistryGovernanceCaseSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    activationId: str | None = None
    appealOfCaseId: str | None = None
    caseId: str
    charterId: str
    evidenceRefs: list[EvidenceRef]
    expiresAt: int
    governingOperatorId: str
    issuedBy: str
    kind: str
    listingId: str
    namespace: str
    note: str | None = None
    openedAt: int
    schema_: Literal["chio.registry.governance-case.v1"] = Field(..., alias="schema")
    state: str
    subjectOperatorId: str
    supersedesCaseId: str | None = None
    updatedAt: int
