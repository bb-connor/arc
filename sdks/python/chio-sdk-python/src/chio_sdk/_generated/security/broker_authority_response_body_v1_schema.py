# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 0a3a1765a96b67781f41c28a0d27ad221b6ab37620da7ca89acc92357927dee9
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel


class Capabilities(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    atomicMultiKeyHolds: bool
    combinedCaptureAndRevocation: bool
    profile: Literal["authoritative_hold_event"]
    queryById: bool
    sharedRevocationWriteDomain: bool


class CapabilitiesResult(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["capabilities"]
    response: Capabilities


class ResponseItem(RootModel[int]):
    root: Annotated[int, Field(ge=0, le=255)]


class ControlResult(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["control"]
    response: Annotated[list[ResponseItem], Field(max_length=1048576)]


class Digest(RootModel[str]):
    root: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]


class HoldState1(Enum):
    unknown = "unknown"
    denied = "denied"
    held = "held"
    reversed = "reversed"


class Identifier(RootModel[str]):
    root: Annotated[
        str,
        Field(
            max_length=512,
            min_length=1,
            pattern="^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$",
        ),
    ]


class PositiveU64(RootModel[int]):
    root: Annotated[int, Field(ge=1, le=18446744073709551615)]


class PublicKey(RootModel[str]):
    root: Annotated[
        str,
        Field(
            pattern="^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\\+mldsa65)$"
        ),
    ]


class Quota(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    keyId: Identifier
    maximumExecutions: Annotated[int, Field(ge=1, le=4294967295)]


class Response(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    code: Identifier


class RejectedResult(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["rejected"]
    response: Response


class TrustedExecutionContext(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    admissionOperationId: Identifier
    authorityMetadataDigest: Digest
    preparedDispatchId: Identifier
    quotas: Annotated[list[Quota], Field(max_length=8, min_length=1)]
    revocationAuthorityDomain: Identifier
    sourceReceiptIds: Annotated[list[Identifier], Field(max_length=64)]


class U64(RootModel[int]):
    root: Annotated[int, Field(ge=0, le=18446744073709551615)]


class CaptureCommit(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authorityCommitIndex: U64
    budgetCommitIndex: U64
    checkedRevocationSetDigest: Digest
    leaderEpoch: U64
    revocationCommitIndex: U64


class HoldState2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    captured: CaptureCommit


class HoldState(RootModel[HoldState1 | HoldState2]):
    root: HoldState1 | HoldState2


class LiveParent(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    audience: Identifier
    authoritySnapshotDigest: Digest
    capabilityId: Identifier
    delegationAncestorIds: Annotated[list[Identifier], Field(max_length=128)]
    expiresAtUnixSeconds: PositiveU64
    subject: PublicKey
    verifiedAtUnixSeconds: PositiveU64


class LiveParentResult(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["live_parent"]
    response: LiveParent


class PreparedResult(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["prepared"]
    response: TrustedExecutionContext


class RevocationSnapshot(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authorityDomain: Identifier
    commitIndex: U64
    observedAtUnixSeconds: PositiveU64
    revoked: bool


class HoldResult(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["hold"]
    response: HoldState


class RevocationResult(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["revocation"]
    response: RevocationSnapshot


class Result(
    RootModel[
        CapabilitiesResult
        | PreparedResult
        | LiveParentResult
        | RevocationResult
        | HoldResult
        | ControlResult
        | RejectedResult
    ]
):
    root: (
        CapabilitiesResult
        | PreparedResult
        | LiveParentResult
        | RevocationResult
        | HoldResult
        | ControlResult
        | RejectedResult
    )


class ChioBrokerAuthorityRpcResponseBodyV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authority: PublicKey
    issuedAtUnixSeconds: PositiveU64
    requestDigest: Digest
    requestId: Identifier
    result: Result
    schema_: Annotated[Literal["chio.broker-authority-rpc.v1"], Field(alias="schema")]
