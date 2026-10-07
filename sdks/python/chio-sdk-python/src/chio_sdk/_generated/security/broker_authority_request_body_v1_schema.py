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
from . import broker_execute_request_v1_schema

class AuthorityRpcIdentifier(RootModel[constr(pattern='^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$', min_length=1, max_length=512)]):
    root: constr(pattern='^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$', min_length=1, max_length=512)

class AuthorityRpcDigest(RootModel[constr(pattern='^[0-9a-f]{64}$')]):
    root: constr(pattern='^[0-9a-f]{64}$')

class PositiveU64(RootModel[conint(ge=1, le=18446744073709551615)]):
    root: conint(ge=1, le=18446744073709551615)

class U32(RootModel[conint(ge=0, le=4294967295)]):
    root: conint(ge=0, le=4294967295)

class ByteArrayItem(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255)

class ByteArray(RootModel[list[ByteArrayItem]]):
    root: list[ByteArrayItem] = Field(..., max_length=1048576)

class PublicKey(RootModel[constr(pattern='^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\\+mldsa65)$')]):
    root: constr(pattern='^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\\+mldsa65)$')

class SecurityBrokerAuthorityRequestBodyV1DefinitionsCapabilitiesOperation(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['capabilities']

class SecurityBrokerAuthorityRequestBodyV1DefinitionsCapabilityLivenessRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    parentCapabilityId: AuthorityRpcIdentifier
    expectedSubject: PublicKey
    expectedAudience: AuthorityRpcIdentifier
    nowUnixSeconds: PositiveU64

class SecurityBrokerAuthorityRequestBodyV1DefinitionsVerifyLiveParentOperation(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['verify_live_parent']
    request: SecurityBrokerAuthorityRequestBodyV1DefinitionsCapabilityLivenessRequest

class SecurityBrokerAuthorityRequestBodyV1DefinitionsBrokerRevocationRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    brokerCapabilityId: AuthorityRpcIdentifier
    revocationId: AuthorityRpcIdentifier
    nowUnixSeconds: PositiveU64

class SecurityBrokerAuthorityRequestBodyV1DefinitionsCheckBrokerRevocationOperation(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['check_broker_revocation']
    request: SecurityBrokerAuthorityRequestBodyV1DefinitionsBrokerRevocationRequest

class SecurityBrokerAuthorityRequestBodyV1DefinitionsQuota(BaseModel):
    model_config = ConfigDict(extra='forbid')
    keyId: AuthorityRpcIdentifier
    maximumExecutions: conint(ge=1, le=4294967295)

class SecurityBrokerAuthorityRequestBodyV1DefinitionsAuthorizeHoldRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    operationId: AuthorityRpcIdentifier
    invocationId: AuthorityRpcIdentifier
    parentCapabilityId: AuthorityRpcIdentifier
    brokerCapabilityId: AuthorityRpcIdentifier
    holdId: AuthorityRpcIdentifier
    authorizeEventId: AuthorityRpcIdentifier
    quotas: list[SecurityBrokerAuthorityRequestBodyV1DefinitionsQuota] = Field(..., max_length=8, min_length=1)
    authorityMetadataDigest: AuthorityRpcDigest

class SecurityBrokerAuthorityRequestBodyV1DefinitionsQueryHoldRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    operationId: AuthorityRpcIdentifier
    invocationId: AuthorityRpcIdentifier
    parentCapabilityId: AuthorityRpcIdentifier
    brokerCapabilityId: AuthorityRpcIdentifier
    holdId: AuthorityRpcIdentifier
    authorizeEventId: AuthorityRpcIdentifier
    reverseEventId: AuthorityRpcIdentifier
    captureEventId: AuthorityRpcIdentifier

class SecurityBrokerAuthorityRequestBodyV1DefinitionsReverseHoldRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    operationId: AuthorityRpcIdentifier
    invocationId: AuthorityRpcIdentifier
    parentCapabilityId: AuthorityRpcIdentifier
    brokerCapabilityId: AuthorityRpcIdentifier
    holdId: AuthorityRpcIdentifier
    reverseEventId: AuthorityRpcIdentifier
    proofDispatchDidNotBegin: Literal[True]

class SecurityBrokerAuthorityRequestBodyV1DefinitionsCaptureHoldRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    operationId: AuthorityRpcIdentifier
    invocationId: AuthorityRpcIdentifier
    parentCapabilityId: AuthorityRpcIdentifier
    brokerCapabilityId: AuthorityRpcIdentifier
    holdId: AuthorityRpcIdentifier
    captureEventId: AuthorityRpcIdentifier
    revocationIds: list[AuthorityRpcIdentifier] = Field(..., max_length=128, min_length=1)
    revocationSetDigest: AuthorityRpcDigest
    authorizationArtifactDigest: AuthorityRpcDigest
    authorityMetadataDigest: AuthorityRpcDigest

class SecurityBrokerAuthorityRequestBodyV1DefinitionsHoldOperationQueryExecutionHold(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['query_execution_hold']
    request: SecurityBrokerAuthorityRequestBodyV1DefinitionsQueryHoldRequest

class SecurityBrokerAuthorityRequestBodyV1DefinitionsHoldOperationAuthorizeExecutionHold(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['authorize_execution_hold']
    request: SecurityBrokerAuthorityRequestBodyV1DefinitionsAuthorizeHoldRequest

class SecurityBrokerAuthorityRequestBodyV1DefinitionsHoldOperationReverseExecutionHold(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['reverse_execution_hold']
    request: SecurityBrokerAuthorityRequestBodyV1DefinitionsReverseHoldRequest

class SecurityBrokerAuthorityRequestBodyV1DefinitionsHoldOperationCaptureExecutionHold(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['capture_execution_hold']
    request: SecurityBrokerAuthorityRequestBodyV1DefinitionsCaptureHoldRequest

class HoldOperation(RootModel[SecurityBrokerAuthorityRequestBodyV1DefinitionsHoldOperationQueryExecutionHold | SecurityBrokerAuthorityRequestBodyV1DefinitionsHoldOperationAuthorizeExecutionHold | SecurityBrokerAuthorityRequestBodyV1DefinitionsHoldOperationReverseExecutionHold | SecurityBrokerAuthorityRequestBodyV1DefinitionsHoldOperationCaptureExecutionHold]):
    root: SecurityBrokerAuthorityRequestBodyV1DefinitionsHoldOperationQueryExecutionHold | SecurityBrokerAuthorityRequestBodyV1DefinitionsHoldOperationAuthorizeExecutionHold | SecurityBrokerAuthorityRequestBodyV1DefinitionsHoldOperationReverseExecutionHold | SecurityBrokerAuthorityRequestBodyV1DefinitionsHoldOperationCaptureExecutionHold

class SecurityBrokerAuthorityRequestBodyV1DefinitionsControlRequestOperation(Enum):
    issue = 'issue'
    revoke = 'revoke'
    status = 'status'

class AuthorizationItem(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255)

class PayloadItem(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255)

class SecurityBrokerAuthorityRequestBodyV1DefinitionsControlRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    operation: SecurityBrokerAuthorityRequestBodyV1DefinitionsControlRequestOperation
    tenantScope: AuthorityRpcIdentifier
    authorization: list[AuthorizationItem] = Field(..., max_length=65536, min_length=1)
    payload: list[PayloadItem] = Field(..., max_length=1048576, min_length=1)

class SecurityBrokerAuthorityRequestBodyV1DefinitionsControlOperation(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['control']
    request: SecurityBrokerAuthorityRequestBodyV1DefinitionsControlRequest

class SecurityBrokerAuthorityRequestBodyV1DefinitionsPrepareExecutionOperation(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['prepare_execution']
    request: broker_execute_request_v1_schema.ChioBrokerExecuteRequestV1

class Operation(RootModel[SecurityBrokerAuthorityRequestBodyV1DefinitionsCapabilitiesOperation | SecurityBrokerAuthorityRequestBodyV1DefinitionsPrepareExecutionOperation | SecurityBrokerAuthorityRequestBodyV1DefinitionsVerifyLiveParentOperation | SecurityBrokerAuthorityRequestBodyV1DefinitionsCheckBrokerRevocationOperation | HoldOperation | SecurityBrokerAuthorityRequestBodyV1DefinitionsControlOperation]):
    root: SecurityBrokerAuthorityRequestBodyV1DefinitionsCapabilitiesOperation | SecurityBrokerAuthorityRequestBodyV1DefinitionsPrepareExecutionOperation | SecurityBrokerAuthorityRequestBodyV1DefinitionsVerifyLiveParentOperation | SecurityBrokerAuthorityRequestBodyV1DefinitionsCheckBrokerRevocationOperation | HoldOperation | SecurityBrokerAuthorityRequestBodyV1DefinitionsControlOperation

class ChioBrokerAuthorityRPCRequestBodyV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    schema_: Literal['chio.broker-authority-rpc.v1'] = Field(..., alias='schema')
    requestId: AuthorityRpcIdentifier
    issuedAtUnixSeconds: PositiveU64
    broker: PublicKey
    operation: Operation

# Public compatibility aliases reference the actual current model classes.
AuthorizeHoldRequest = SecurityBrokerAuthorityRequestBodyV1DefinitionsAuthorizeHoldRequest
BrokerRevocationRequest = SecurityBrokerAuthorityRequestBodyV1DefinitionsBrokerRevocationRequest
CapabilitiesOperation = SecurityBrokerAuthorityRequestBodyV1DefinitionsCapabilitiesOperation
CapabilityLivenessRequest = SecurityBrokerAuthorityRequestBodyV1DefinitionsCapabilityLivenessRequest
CaptureHoldRequest = SecurityBrokerAuthorityRequestBodyV1DefinitionsCaptureHoldRequest
CheckBrokerRevocationOperation = SecurityBrokerAuthorityRequestBodyV1DefinitionsCheckBrokerRevocationOperation
ChioBrokerAuthorityRpcRequestBodyV1 = ChioBrokerAuthorityRPCRequestBodyV1
ControlOperation = SecurityBrokerAuthorityRequestBodyV1DefinitionsControlOperation
ControlRequest = SecurityBrokerAuthorityRequestBodyV1DefinitionsControlRequest
HoldOperation1 = SecurityBrokerAuthorityRequestBodyV1DefinitionsHoldOperationQueryExecutionHold
HoldOperation2 = SecurityBrokerAuthorityRequestBodyV1DefinitionsHoldOperationAuthorizeExecutionHold
HoldOperation3 = SecurityBrokerAuthorityRequestBodyV1DefinitionsHoldOperationReverseExecutionHold
HoldOperation4 = SecurityBrokerAuthorityRequestBodyV1DefinitionsHoldOperationCaptureExecutionHold
Operation2 = SecurityBrokerAuthorityRequestBodyV1DefinitionsControlRequestOperation
Operation3 = SecurityBrokerAuthorityRequestBodyV1DefinitionsControlRequestOperation
PrepareExecutionOperation = SecurityBrokerAuthorityRequestBodyV1DefinitionsPrepareExecutionOperation
QueryHoldRequest = SecurityBrokerAuthorityRequestBodyV1DefinitionsQueryHoldRequest
Quota = SecurityBrokerAuthorityRequestBodyV1DefinitionsQuota
ReverseHoldRequest = SecurityBrokerAuthorityRequestBodyV1DefinitionsReverseHoldRequest
SecurityBrokerAuthorityRequestBodyV1AuthorityRpcDigest = AuthorityRpcDigest
SecurityBrokerAuthorityRequestBodyV1AuthorityRpcIdentifier = AuthorityRpcIdentifier
SecurityBrokerAuthorityRequestBodyV1AuthorizationItem = AuthorizationItem
SecurityBrokerAuthorityRequestBodyV1ByteArray = ByteArray
SecurityBrokerAuthorityRequestBodyV1ByteArrayItem = ByteArrayItem
SecurityBrokerAuthorityRequestBodyV1ChioBrokerAuthorityRPCRequestBodyV1 = ChioBrokerAuthorityRPCRequestBodyV1
SecurityBrokerAuthorityRequestBodyV1HoldOperation = HoldOperation
SecurityBrokerAuthorityRequestBodyV1Operation = Operation
SecurityBrokerAuthorityRequestBodyV1PayloadItem = PayloadItem
SecurityBrokerAuthorityRequestBodyV1PositiveU64 = PositiveU64
SecurityBrokerAuthorityRequestBodyV1PublicKey = PublicKey
SecurityBrokerAuthorityRequestBodyV1U32 = U32
VerifyLiveParentOperation = SecurityBrokerAuthorityRequestBodyV1DefinitionsVerifyLiveParentOperation
