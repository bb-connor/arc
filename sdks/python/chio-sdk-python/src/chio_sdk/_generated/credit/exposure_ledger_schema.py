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

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class Filters(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    agentSubject: str | None = None
    decisionLimit: int
    receiptLimit: int


class Position(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    activeQuotedPremiumUnits: int
    currency: str
    failedUnits: int
    governedMaxExposureUnits: int
    pendingUnits: int
    provisionalLossUnits: int
    quotedPremiumUnits: int
    recoveredUnits: int
    reservedUnits: int
    settledUnits: int


class Summary(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    actionableReceipts: int
    activeDecisions: int
    currencies: list[str]
    failedSettlementReceipts: int
    matchingDecisions: int
    matchingReceipts: int
    mixedCurrencyBook: bool
    pendingSettlementReceipts: int
    returnedDecisions: int
    returnedReceipts: int
    supersededDecisions: int
    truncatedDecisions: bool
    truncatedReceipts: bool


class SupportBoundary(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    claimAdjudicationSupported: bool
    crossCurrencyNettingSupported: bool
    governedReceiptsAuthoritative: bool
    recoveryLifecycleSupported: bool
    settlementReconciliationAuthoritative: bool
    underwritingDecisionsAuthoritative: bool


class ChioCreditExposureLedgerSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    decisions: list[dict[str, Any]]
    filters: Filters
    generatedAt: int
    positions: list[Position]
    receipts: list[dict[str, Any]]
    schema_: Literal["chio.credit.exposure-ledger.v1"] = Field(..., alias="schema")
    summary: Summary
    supportBoundary: SupportBoundary
