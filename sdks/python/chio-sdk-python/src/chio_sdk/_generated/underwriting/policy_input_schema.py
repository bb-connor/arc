# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 29e7de509b9e808e1385895b2caf534b995fb61bf99b87fab79bedc072f5a842
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Filters(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    agentSubject: str
    receiptLimit: int


class ReceiptRef(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: str
    locator: str
    observedAt: int
    referenceId: str


class Receipts(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    actionableMeteredReceipts: int
    actionableSettlementReceipts: int
    allowCount: int
    approvalReceipts: int
    approvedReceipts: int
    callChainReceipts: int
    cancelledCount: int
    denyCount: int
    failedSettlementReceipts: int
    governedReceipts: int
    incompleteCount: int
    matchingReceipts: int
    meteredReceipts: int
    pendingSettlementReceipts: int
    receiptRefs: list[ReceiptRef]
    returnedReceipts: int
    runtimeAssuranceReceipts: int
    sharedEvidenceProofRequiredCount: int
    sharedEvidenceReferenceCount: int


class Reputation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    acceptedImportedSignalCount: int
    effectiveScore: float
    importedSignalCount: int
    probationary: bool
    resolvedTier: str
    subjectKey: str


class RuntimeAssurance(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    governedReceipts: int
    highestTier: str
    latestEvidenceSha256: str
    latestSchema: str
    latestVerifier: str
    latestVerifierFamily: str
    observedVerifierFamilies: list[str]
    runtimeAssuranceReceipts: int


class Taxonomy(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    supportedClasses: list[str]
    supportedReasons: list[str]
    version: str


class ChioUnderwritingPolicyInputSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    filters: Filters
    generatedAt: int
    receipts: Receipts
    reputation: Reputation
    runtimeAssurance: RuntimeAssurance
    schema_: Literal["chio.underwriting.policy-input.v1"] = Field(..., alias="schema")
    taxonomy: Taxonomy
