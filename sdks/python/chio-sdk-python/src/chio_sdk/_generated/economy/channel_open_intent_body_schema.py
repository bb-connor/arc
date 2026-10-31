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


class Bound(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class EscrowReference(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    chainId: str
    escrowContract: str
    escrowId: str


class Body(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    assetBinding: AssetBinding
    bound: Bound
    boundTokenBaseUnits: str
    channelExpiryUnixSecs: int
    closeSubmissionCutoffUnixSecs: int
    currency: str
    disputeTierUpperBoundUnits: int
    disputeWindowSecs: int
    escrowReference: EscrowReference
    finalityMode: str
    fixedFinalityBroadcastMarginSecs: int
    fundingEvidenceDigest: str
    openIntentId: str
    originalOperator: str
    originalOperatorKeyHash: str
    originalWeb3DispatchDigest: str
    participantSnapshotDigest: str
    payeeBeneficiaryAddress: str
    payeeId: str
    payeeKey: str
    payeeKeyEpoch: int
    payerId: str
    payerKey: str
    payerKeyEpoch: int
    payerRefundAddress: str
    requiredConfirmations: int
    schema_: str = Field(..., alias="schema")
    settlementAuthorityScopeId: str


class ChioChannelOpenIntentV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body
    keyEpoch: int
    signerId: str
    signerKey: str
