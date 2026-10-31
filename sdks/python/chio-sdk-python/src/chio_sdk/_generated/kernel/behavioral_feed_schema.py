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

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class Decisions(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    allowCount: int
    cancelledCount: int
    denyCount: int
    incompleteCount: int


class Filters(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    receiptLimit: int


class GovernedActions(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    approvalReceipts: int
    approvedReceipts: int
    commerceReceipts: int
    governedReceipts: int
    maxAmountReceipts: int


class MeteredBilling(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    actionableReceipts: int
    evidenceAttachedReceipts: int
    financialMismatchReceipts: int
    meteredReceipts: int
    missingEvidenceReceipts: int
    overMaxBilledUnitsReceipts: int
    overQuotedCostReceipts: int
    overQuotedUnitsReceipts: int
    reconciledReceipts: int


class ReadBoundary(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: str


class ExportQuery(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    readBoundary: ReadBoundary


class Privacy(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    childReceiptScope: str
    directEvidenceExportSupported: bool
    exportQuery: ExportQuery
    matchingReceipts: int
    proofsComplete: bool
    returnedReceipts: int


class Settlements(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    actionableReceipts: int
    failedReceipts: int
    notApplicableReceipts: int
    pendingReceipts: int
    reconciledReceipts: int
    settledReceipts: int


class SharedEvidence(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    distinctRemoteSubjects: int
    matchingLocalReceipts: int
    matchingReferences: int
    matchingShares: int
    proofRequiredShares: int
    remoteLineageRecords: int
    remoteToolReceipts: int
    truncated: bool


class ChioBehavioralFeedSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    decisions: Decisions
    filters: Filters
    generatedAt: int
    governedActions: GovernedActions
    meteredBilling: MeteredBilling
    privacy: Privacy
    receipts: list[dict[str, Any]]
    schema_: Literal["chio.behavioral-feed.v1"] = Field(..., alias="schema")
    settlements: Settlements
    sharedEvidence: SharedEvidence
