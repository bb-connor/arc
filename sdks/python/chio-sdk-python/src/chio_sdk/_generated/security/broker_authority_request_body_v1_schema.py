# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: c56ebd67862c888dd340e0ba3a14bf38d69abc45d8d02e706ed935cd512054ec
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr

from . import broker_execute_request_v1_schema


class AuthorityRpcIdentifier(
    RootModel[
        constr(
            pattern=r"^[^\s\u0000-\u001F\u007F-\u009F](?:[^\u0000-\u001F\u007F-\u009F]*[^\s\u0000-\u001F\u007F-\u009F])?$",
            min_length=1,
            max_length=512,
        )
    ]
):
    root: constr(
        pattern=r"^[^\s\u0000-\u001F\u007F-\u009F](?:[^\u0000-\u001F\u007F-\u009F]*[^\s\u0000-\u001F\u007F-\u009F])?$",
        min_length=1,
        max_length=512,
    )


class AuthorityRpcDigest(RootModel[constr(pattern=r"^[0-9a-f]{64}$")]):
    root: constr(pattern=r"^[0-9a-f]{64}$")


class PositiveU64(RootModel[conint(ge=1, le=18446744073709551615)]):
    root: conint(ge=1, le=18446744073709551615)


class U32(RootModel[conint(ge=0, le=4294967295)]):
    root: conint(ge=0, le=4294967295)


class ByteArrayItem(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255)


class ByteArray(RootModel[list[ByteArrayItem]]):
    root: list[ByteArrayItem] = Field(..., max_length=1048576)


class PublicKey(
    RootModel[
        constr(
            pattern=r"^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\+mldsa65)$"
        )
    ]
):
    root: constr(
        pattern=r"^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\+mldsa65)$"
    )


class CapabilitiesOperation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["capabilities"]


class CapabilityLivenessRequest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    parentCapabilityId: AuthorityRpcIdentifier
    expectedSubject: PublicKey
    expectedAudience: AuthorityRpcIdentifier
    nowUnixSeconds: PositiveU64


class VerifyLiveParentOperation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["verify_live_parent"]
    request: CapabilityLivenessRequest


class BrokerRevocationRequest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    brokerCapabilityId: AuthorityRpcIdentifier
    revocationId: AuthorityRpcIdentifier
    nowUnixSeconds: PositiveU64


class CheckBrokerRevocationOperation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["check_broker_revocation"]
    request: BrokerRevocationRequest


class Quota(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    keyId: AuthorityRpcIdentifier
    maximumExecutions: conint(ge=1, le=4294967295)


class AuthorizeHoldRequest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    operationId: AuthorityRpcIdentifier
    invocationId: AuthorityRpcIdentifier
    parentCapabilityId: AuthorityRpcIdentifier
    brokerCapabilityId: AuthorityRpcIdentifier
    holdId: AuthorityRpcIdentifier
    authorizeEventId: AuthorityRpcIdentifier
    quotas: list[Quota] = Field(..., max_length=8, min_length=1)
    authorityMetadataDigest: AuthorityRpcDigest


class QueryHoldRequest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    operationId: AuthorityRpcIdentifier
    invocationId: AuthorityRpcIdentifier
    parentCapabilityId: AuthorityRpcIdentifier
    brokerCapabilityId: AuthorityRpcIdentifier
    holdId: AuthorityRpcIdentifier
    authorizeEventId: AuthorityRpcIdentifier
    reverseEventId: AuthorityRpcIdentifier
    captureEventId: AuthorityRpcIdentifier


class ReverseHoldRequest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    operationId: AuthorityRpcIdentifier
    invocationId: AuthorityRpcIdentifier
    parentCapabilityId: AuthorityRpcIdentifier
    brokerCapabilityId: AuthorityRpcIdentifier
    holdId: AuthorityRpcIdentifier
    reverseEventId: AuthorityRpcIdentifier
    proofDispatchDidNotBegin: Literal[True]


class CaptureHoldRequest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    operationId: AuthorityRpcIdentifier
    invocationId: AuthorityRpcIdentifier
    parentCapabilityId: AuthorityRpcIdentifier
    brokerCapabilityId: AuthorityRpcIdentifier
    holdId: AuthorityRpcIdentifier
    captureEventId: AuthorityRpcIdentifier
    revocationIds: list[AuthorityRpcIdentifier] = Field(
        ..., max_length=128, min_length=1
    )
    revocationSetDigest: AuthorityRpcDigest
    authorizationArtifactDigest: AuthorityRpcDigest
    authorityMetadataDigest: AuthorityRpcDigest


class HoldOperation1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["query_execution_hold"]
    request: QueryHoldRequest


class HoldOperation2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["authorize_execution_hold"]
    request: AuthorizeHoldRequest


class HoldOperation3(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["reverse_execution_hold"]
    request: ReverseHoldRequest


class HoldOperation4(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["capture_execution_hold"]
    request: CaptureHoldRequest


class HoldOperation(
    RootModel[HoldOperation1 | HoldOperation2 | HoldOperation3 | HoldOperation4]
):
    root: HoldOperation1 | HoldOperation2 | HoldOperation3 | HoldOperation4


class Operation2(Enum):
    issue = "issue"
    revoke = "revoke"
    status = "status"


class AuthorizationItem(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255)


class PayloadItem(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255)


class ControlRequest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    operation: Operation2
    tenantScope: AuthorityRpcIdentifier
    authorization: list[AuthorizationItem] = Field(..., max_length=65536, min_length=1)
    payload: list[PayloadItem] = Field(..., max_length=1048576, min_length=1)


class ControlOperation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["control"]
    request: ControlRequest


class PrepareExecutionOperation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["prepare_execution"]
    request: broker_execute_request_v1_schema.ChioBrokerExecuteRequestV1


class Operation(
    RootModel[
        CapabilitiesOperation
        | PrepareExecutionOperation
        | VerifyLiveParentOperation
        | CheckBrokerRevocationOperation
        | HoldOperation
        | ControlOperation
    ]
):
    root: (
        CapabilitiesOperation
        | PrepareExecutionOperation
        | VerifyLiveParentOperation
        | CheckBrokerRevocationOperation
        | HoldOperation
        | ControlOperation
    )


class ChioBrokerAuthorityRpcRequestBodyV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.broker-authority-rpc.v1"] = Field(..., alias="schema")
    requestId: AuthorityRpcIdentifier
    issuedAtUnixSeconds: PositiveU64
    broker: PublicKey
    operation: Operation
