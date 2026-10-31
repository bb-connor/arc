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

from pydantic import BaseModel, ConfigDict, Field


class AssetBinding(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    chainId: str
    currency: str
    protocolMinorUnitDecimals: int
    schema_: str = Field(..., alias="schema")
    settlementPolicyDigest: str
    tokenAddress: str
    tokenDecimals: int
    tokenSymbol: str


class BlockPin(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    blockHash: str
    blockNumber: int
    blockTimestampUnixSecs: int
    finalityMode: str
    finalityStatus: str
    finalizedHeadHash: str
    finalizedHeadNumber: int
    observedAtUnixMs: int
    observedConfirmations: int
    requiredConfirmations: int


class CreationEvent(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    beneficiary: str
    capabilityId: str
    deadlineUnixSecs: int
    depositor: str
    escrowId: str
    eventSignature: str
    logEmitter: str
    logIndex: int
    maxTokenBaseUnits: str
    operator: str
    receiptBlockHash: str
    receiptBlockNumber: int
    tokenAddress: str
    transactionHash: str
    transactionSucceeded: bool
    transactionTo: str


class EscrowReference(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    chainId: str
    escrowContract: str
    escrowId: str


class EscrowState(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    depositedTokenBaseUnits: str
    refunded: bool
    refundedTokenBaseUnits: str
    releasedTokenBaseUnits: str


class EscrowStateRead(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    blockHash: str
    blockNumber: int
    callDataDigest: str
    contract: str
    returnDataDigest: str


class EscrowTerms(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    beneficiary: str
    capabilityId: str
    deadlineUnixSecs: int
    depositor: str
    maxTokenBaseUnits: str
    operator: str
    operatorKeyHash: str
    tokenAddress: str


class IdentityObservation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    active: bool
    blockHash: str
    blockNumber: int
    operator: str
    operatorKeyHash: str
    registryContract: str


class TokenObservation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    allowed: bool
    blockHash: str
    blockNumber: int
    escrowContract: str
    tokenAddress: str
    tokenDecimals: int
    tokenSymbol: str


class Body(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    assetBinding: AssetBinding
    blockPin: BlockPin
    creationEvent: CreationEvent
    escrowReference: EscrowReference
    escrowState: EscrowState
    escrowStateRead: EscrowStateRead
    escrowTerms: EscrowTerms
    evidenceExpiresAtUnixMs: int
    identityObservation: IdentityObservation
    schema_: str = Field(..., alias="schema")
    tokenObservation: TokenObservation


class ChioChannelFundingEvidenceV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body
    keyEpoch: int
    signerId: str
    signerKey: str
