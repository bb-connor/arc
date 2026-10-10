# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 35f8e30cf30553986a159b074ee485804a85db29547a8102522cd7bfa3080d2e
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.

from __future__ import annotations
from enum import Enum
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr

class AuthorityRpcResponseIdentifier(RootModel[constr(pattern='^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$', min_length=1, max_length=512)]):
    root: constr(pattern='^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$', min_length=1, max_length=512)

class Digest(RootModel[constr(pattern='^[0-9a-f]{64}$')]):
    root: constr(pattern='^[0-9a-f]{64}$')

class PositiveU64(RootModel[conint(ge=1, le=18446744073709551615)]):
    root: conint(ge=1, le=18446744073709551615)

class U64(RootModel[conint(ge=0, le=18446744073709551615)]):
    root: conint(ge=0, le=18446744073709551615)

class PublicKey(RootModel[constr(pattern='^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\\+mldsa65)$')]):
    root: constr(pattern='^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\\+mldsa65)$')

class SecurityBrokerAuthorityResponseBodyV1DefinitionsCapabilities(BaseModel):
    model_config = ConfigDict(extra='forbid')
    profile: Literal['authoritative_hold_event']
    atomicMultiKeyHolds: bool
    combinedCaptureAndRevocation: bool
    queryById: bool
    sharedRevocationWriteDomain: bool

class SecurityBrokerAuthorityResponseBodyV1DefinitionsAuthorityRpcResponseQuota(BaseModel):
    model_config = ConfigDict(extra='forbid')
    keyId: AuthorityRpcResponseIdentifier
    maximumExecutions: conint(ge=1, le=4294967295)

class SecurityBrokerAuthorityResponseBodyV1DefinitionsTrustedExecutionContext(BaseModel):
    model_config = ConfigDict(extra='forbid')
    admissionOperationId: AuthorityRpcResponseIdentifier
    preparedDispatchId: AuthorityRpcResponseIdentifier
    quotas: list[SecurityBrokerAuthorityResponseBodyV1DefinitionsAuthorityRpcResponseQuota] = Field(..., max_length=8, min_length=1)
    authorityMetadataDigest: Digest
    revocationAuthorityDomain: AuthorityRpcResponseIdentifier
    sourceReceiptIds: list[AuthorityRpcResponseIdentifier] = Field(..., max_length=64)

class SecurityBrokerAuthorityResponseBodyV1DefinitionsLiveParent(BaseModel):
    model_config = ConfigDict(extra='forbid')
    capabilityId: AuthorityRpcResponseIdentifier
    subject: PublicKey
    audience: AuthorityRpcResponseIdentifier
    delegationAncestorIds: list[AuthorityRpcResponseIdentifier] = Field(..., max_length=128)
    expiresAtUnixSeconds: PositiveU64
    verifiedAtUnixSeconds: PositiveU64
    authoritySnapshotDigest: Digest

class SecurityBrokerAuthorityResponseBodyV1DefinitionsRevocationSnapshot(BaseModel):
    model_config = ConfigDict(extra='forbid')
    revoked: bool
    observedAtUnixSeconds: PositiveU64
    commitIndex: U64
    authorityDomain: AuthorityRpcResponseIdentifier

class SecurityBrokerAuthorityResponseBodyV1DefinitionsCaptureCommit(BaseModel):
    model_config = ConfigDict(extra='forbid')
    checkedRevocationSetDigest: Digest
    budgetCommitIndex: U64
    revocationCommitIndex: U64
    authorityCommitIndex: U64
    leaderEpoch: U64

class SecurityBrokerAuthorityResponseBodyV1DefinitionsHoldStateVariant0(Enum):
    unknown = 'unknown'
    denied = 'denied'
    held = 'held'
    reversed = 'reversed'

class SecurityBrokerAuthorityResponseBodyV1DefinitionsHoldStateVariant1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    captured: SecurityBrokerAuthorityResponseBodyV1DefinitionsCaptureCommit

class HoldState(RootModel[SecurityBrokerAuthorityResponseBodyV1DefinitionsHoldStateVariant0 | SecurityBrokerAuthorityResponseBodyV1DefinitionsHoldStateVariant1]):
    root: SecurityBrokerAuthorityResponseBodyV1DefinitionsHoldStateVariant0 | SecurityBrokerAuthorityResponseBodyV1DefinitionsHoldStateVariant1

class SecurityBrokerAuthorityResponseBodyV1DefinitionsCapabilitiesResult(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['capabilities']
    response: SecurityBrokerAuthorityResponseBodyV1DefinitionsCapabilities

class SecurityBrokerAuthorityResponseBodyV1DefinitionsPreparedResult(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['prepared']
    response: SecurityBrokerAuthorityResponseBodyV1DefinitionsTrustedExecutionContext

class SecurityBrokerAuthorityResponseBodyV1DefinitionsLiveParentResult(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['live_parent']
    response: SecurityBrokerAuthorityResponseBodyV1DefinitionsLiveParent

class SecurityBrokerAuthorityResponseBodyV1DefinitionsRevocationResult(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['revocation']
    response: SecurityBrokerAuthorityResponseBodyV1DefinitionsRevocationSnapshot

class SecurityBrokerAuthorityResponseBodyV1DefinitionsHoldResult(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['hold']
    response: HoldState

class ResponseItem(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255)

class SecurityBrokerAuthorityResponseBodyV1DefinitionsControlResult(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['control']
    response: list[ResponseItem] = Field(..., max_length=1048576)

class SecurityBrokerAuthorityResponseBodyV1DefinitionsRejectedResultResponse(BaseModel):
    model_config = ConfigDict(extra='forbid')
    code: AuthorityRpcResponseIdentifier

class SecurityBrokerAuthorityResponseBodyV1DefinitionsRejectedResult(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['rejected']
    response: SecurityBrokerAuthorityResponseBodyV1DefinitionsRejectedResultResponse

class Result(RootModel[SecurityBrokerAuthorityResponseBodyV1DefinitionsCapabilitiesResult | SecurityBrokerAuthorityResponseBodyV1DefinitionsPreparedResult | SecurityBrokerAuthorityResponseBodyV1DefinitionsLiveParentResult | SecurityBrokerAuthorityResponseBodyV1DefinitionsRevocationResult | SecurityBrokerAuthorityResponseBodyV1DefinitionsHoldResult | SecurityBrokerAuthorityResponseBodyV1DefinitionsControlResult | SecurityBrokerAuthorityResponseBodyV1DefinitionsRejectedResult]):
    root: SecurityBrokerAuthorityResponseBodyV1DefinitionsCapabilitiesResult | SecurityBrokerAuthorityResponseBodyV1DefinitionsPreparedResult | SecurityBrokerAuthorityResponseBodyV1DefinitionsLiveParentResult | SecurityBrokerAuthorityResponseBodyV1DefinitionsRevocationResult | SecurityBrokerAuthorityResponseBodyV1DefinitionsHoldResult | SecurityBrokerAuthorityResponseBodyV1DefinitionsControlResult | SecurityBrokerAuthorityResponseBodyV1DefinitionsRejectedResult

class ChioBrokerAuthorityRPCResponseBodyV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    schema_: Literal['chio.broker-authority-rpc.v1'] = Field(..., alias='schema')
    requestId: AuthorityRpcResponseIdentifier
    requestDigest: Digest
    issuedAtUnixSeconds: PositiveU64
    authority: PublicKey
    result: Result

# Public compatibility aliases reference the actual current model classes.
AuthorityRpcResponseQuota = SecurityBrokerAuthorityResponseBodyV1DefinitionsAuthorityRpcResponseQuota
Capabilities = SecurityBrokerAuthorityResponseBodyV1DefinitionsCapabilities
CapabilitiesResult = SecurityBrokerAuthorityResponseBodyV1DefinitionsCapabilitiesResult
CaptureCommit = SecurityBrokerAuthorityResponseBodyV1DefinitionsCaptureCommit
ChioBrokerAuthorityRpcResponseBodyV1 = ChioBrokerAuthorityRPCResponseBodyV1
ControlResult = SecurityBrokerAuthorityResponseBodyV1DefinitionsControlResult
HoldResult = SecurityBrokerAuthorityResponseBodyV1DefinitionsHoldResult
HoldState1 = SecurityBrokerAuthorityResponseBodyV1DefinitionsHoldStateVariant0
HoldState2 = SecurityBrokerAuthorityResponseBodyV1DefinitionsHoldStateVariant1
LiveParent = SecurityBrokerAuthorityResponseBodyV1DefinitionsLiveParent
LiveParentResult = SecurityBrokerAuthorityResponseBodyV1DefinitionsLiveParentResult
PreparedResult = SecurityBrokerAuthorityResponseBodyV1DefinitionsPreparedResult
RejectedResult = SecurityBrokerAuthorityResponseBodyV1DefinitionsRejectedResult
Response = SecurityBrokerAuthorityResponseBodyV1DefinitionsRejectedResultResponse
RevocationResult = SecurityBrokerAuthorityResponseBodyV1DefinitionsRevocationResult
RevocationSnapshot = SecurityBrokerAuthorityResponseBodyV1DefinitionsRevocationSnapshot
SecurityBrokerAuthorityResponseBodyV1AuthorityRpcResponseIdentifier = AuthorityRpcResponseIdentifier
SecurityBrokerAuthorityResponseBodyV1ChioBrokerAuthorityRPCResponseBodyV1 = ChioBrokerAuthorityRPCResponseBodyV1
SecurityBrokerAuthorityResponseBodyV1Digest = Digest
SecurityBrokerAuthorityResponseBodyV1HoldState = HoldState
SecurityBrokerAuthorityResponseBodyV1PositiveU64 = PositiveU64
SecurityBrokerAuthorityResponseBodyV1PublicKey = PublicKey
SecurityBrokerAuthorityResponseBodyV1ResponseItem = ResponseItem
SecurityBrokerAuthorityResponseBodyV1Result = Result
SecurityBrokerAuthorityResponseBodyV1U64 = U64
TrustedExecutionContext = SecurityBrokerAuthorityResponseBodyV1DefinitionsTrustedExecutionContext
