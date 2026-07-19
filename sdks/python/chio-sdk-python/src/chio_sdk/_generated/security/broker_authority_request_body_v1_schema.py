# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: e7734a10ce3d0e21e8497fad86bfb2a97e79c44ce827e678a869c592687f8837
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel

from . import broker_execute_request_v1_schema


class AuthorityRpcDigest(RootModel[str]):
    root: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]


class AuthorityRpcIdentifier(RootModel[str]):
    root: Annotated[
        str,
        Field(
            max_length=512,
            min_length=1,
            pattern="^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$",
        ),
    ]


class ByteArrayItem(RootModel[int]):
    root: Annotated[int, Field(ge=0, le=255)]


class ByteArray(RootModel[list[ByteArrayItem]]):
    root: Annotated[list[ByteArrayItem], Field(max_length=1048576)]


class CapabilitiesOperation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["capabilities"]


class CaptureHoldRequest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authorityMetadataDigest: AuthorityRpcDigest
    authorizationArtifactDigest: AuthorityRpcDigest
    brokerCapabilityId: AuthorityRpcIdentifier
    captureEventId: AuthorityRpcIdentifier
    holdId: AuthorityRpcIdentifier
    invocationId: AuthorityRpcIdentifier
    operationId: AuthorityRpcIdentifier
    parentCapabilityId: AuthorityRpcIdentifier
    revocationIds: Annotated[
        list[AuthorityRpcIdentifier], Field(max_length=128, min_length=1)
    ]
    revocationSetDigest: AuthorityRpcDigest


class AuthorizationItem(RootModel[int]):
    root: Annotated[int, Field(ge=0, le=255)]


class Operation2(Enum):
    issue = "issue"
    revoke = "revoke"
    status = "status"


class PayloadItem(RootModel[int]):
    root: Annotated[int, Field(ge=0, le=255)]


class ControlRequest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authorization: Annotated[
        list[AuthorizationItem], Field(max_length=65536, min_length=1)
    ]
    operation: Operation2
    payload: Annotated[list[PayloadItem], Field(max_length=1048576, min_length=1)]
    tenantScope: AuthorityRpcIdentifier


class HoldOperation4(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["capture_execution_hold"]
    request: CaptureHoldRequest


class PositiveU64(RootModel[int]):
    root: Annotated[int, Field(ge=1, le=18446744073709551615)]


class PublicKey(RootModel[str]):
    root: Annotated[
        str,
        Field(
            pattern="^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\\+mldsa65)$"
        ),
    ]


class QueryHoldRequest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authorizeEventId: AuthorityRpcIdentifier
    brokerCapabilityId: AuthorityRpcIdentifier
    captureEventId: AuthorityRpcIdentifier
    holdId: AuthorityRpcIdentifier
    invocationId: AuthorityRpcIdentifier
    operationId: AuthorityRpcIdentifier
    parentCapabilityId: AuthorityRpcIdentifier
    reverseEventId: AuthorityRpcIdentifier


class Quota(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    keyId: AuthorityRpcIdentifier
    maximumExecutions: Annotated[int, Field(ge=1, le=4294967295)]


class ReverseHoldRequest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    brokerCapabilityId: AuthorityRpcIdentifier
    holdId: AuthorityRpcIdentifier
    invocationId: AuthorityRpcIdentifier
    operationId: AuthorityRpcIdentifier
    parentCapabilityId: AuthorityRpcIdentifier
    proofDispatchDidNotBegin: Literal[True]
    reverseEventId: AuthorityRpcIdentifier


class U32(RootModel[int]):
    root: Annotated[int, Field(ge=0, le=4294967295)]


class AuthorizeHoldRequest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authorityMetadataDigest: AuthorityRpcDigest
    authorizeEventId: AuthorityRpcIdentifier
    brokerCapabilityId: AuthorityRpcIdentifier
    holdId: AuthorityRpcIdentifier
    invocationId: AuthorityRpcIdentifier
    operationId: AuthorityRpcIdentifier
    parentCapabilityId: AuthorityRpcIdentifier
    quotas: Annotated[list[Quota], Field(max_length=8, min_length=1)]


class BrokerRevocationRequest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    brokerCapabilityId: AuthorityRpcIdentifier
    nowUnixSeconds: PositiveU64
    revocationId: AuthorityRpcIdentifier


class CapabilityLivenessRequest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    expectedAudience: AuthorityRpcIdentifier
    expectedSubject: PublicKey
    nowUnixSeconds: PositiveU64
    parentCapabilityId: AuthorityRpcIdentifier


class CheckBrokerRevocationOperation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["check_broker_revocation"]
    request: BrokerRevocationRequest


class ControlOperation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["control"]
    request: ControlRequest


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


class HoldOperation(
    RootModel[HoldOperation1 | HoldOperation2 | HoldOperation3 | HoldOperation4]
):
    root: HoldOperation1 | HoldOperation2 | HoldOperation3 | HoldOperation4


class VerifyLiveParentOperation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["verify_live_parent"]
    request: CapabilityLivenessRequest


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
    broker: PublicKey
    issuedAtUnixSeconds: PositiveU64
    operation: Operation
    requestId: AuthorityRpcIdentifier
    schema_: Annotated[Literal["chio.broker-authority-rpc.v1"], Field(alias="schema")]
