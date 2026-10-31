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

from pydantic import BaseModel, ConfigDict, Field


class Amount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class EvidenceRef(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: str
    locator: str
    observedAt: int
    referenceId: str


class Event(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    amount: Amount
    counterpartyId: str
    counterpartyRole: str
    description: str
    eventId: str
    evidenceRefs: list[EvidenceRef]
    facilityId: str
    kind: str
    occurredAt: int
    ownerRole: str
    sourceId: str


class Query(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    agentSubject: str
    bondLimit: int
    facilityLimit: int
    lossEventLimit: int
    receiptLimit: int


class CommittedAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class DisbursedAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class DrawnAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class HeldAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class ImpairedAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class ReleasedAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class RepaidAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class Source(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    bondId: str | None = None
    capitalSource: str
    committedAmount: CommittedAmount | None = None
    counterpartyId: str
    counterpartyRole: str
    currency: str
    description: str
    disbursedAmount: DisbursedAmount | None = None
    drawnAmount: DrawnAmount | None = None
    facilityId: str
    heldAmount: HeldAmount | None = None
    impairedAmount: ImpairedAmount | None = None
    jurisdiction: str | None = None
    kind: str
    ownerRole: str
    releasedAmount: ReleasedAmount | None = None
    repaidAmount: RepaidAmount | None = None
    sourceId: str


class Summary(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currencies: list[str]
    fundingSources: int
    ledgerEvents: int
    matchingBonds: int
    matchingFacilities: int
    matchingLossEvents: int
    matchingReceipts: int
    mixedCurrencyBook: bool
    returnedBonds: int
    returnedFacilities: int
    returnedLossEvents: int
    returnedReceipts: int
    truncatedBonds: bool
    truncatedFacilities: bool
    truncatedLossEvents: bool
    truncatedReceipts: bool


class SupportBoundary(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    automaticCapitalExecutionSupported: bool
    custodyExecutionSupported: bool
    mixedCurrencyNettingSupported: bool
    sourceOfFundsAuthoritative: bool


class ChioCreditCapitalBookSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    events: list[Event]
    generatedAt: int
    query: Query
    schema_: Literal["chio.credit.capital-book.v1"] = Field(..., alias="schema")
    sources: list[Source]
    subjectKey: str
    summary: Summary
    supportBoundary: SupportBoundary
