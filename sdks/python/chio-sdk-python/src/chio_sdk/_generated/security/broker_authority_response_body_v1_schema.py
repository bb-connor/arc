# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 9695e2b405d3cd46de929a925e1a3b9b33ec4a67a0a5e93f625c433f820e1920
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr


class AuthorityRpcResponseIdentifier(
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


class Digest(RootModel[constr(pattern=r"^[0-9a-f]{64}$")]):
    root: constr(pattern=r"^[0-9a-f]{64}$")


class PositiveU64(RootModel[conint(ge=1, le=18446744073709551615)]):
    root: conint(ge=1, le=18446744073709551615)


class U64(RootModel[conint(ge=0, le=18446744073709551615)]):
    root: conint(ge=0, le=18446744073709551615)


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


class Capabilities(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    profile: Literal["authoritative_hold_event"]
    atomicMultiKeyHolds: bool
    combinedCaptureAndRevocation: bool
    queryById: bool
    sharedRevocationWriteDomain: bool


class AuthorityRpcResponseQuota(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    keyId: AuthorityRpcResponseIdentifier
    maximumExecutions: conint(ge=1, le=4294967295)


class TrustedExecutionContext(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    admissionOperationId: AuthorityRpcResponseIdentifier
    preparedDispatchId: AuthorityRpcResponseIdentifier
    quotas: list[AuthorityRpcResponseQuota] = Field(..., max_length=8, min_length=1)
    authorityMetadataDigest: Digest
    revocationAuthorityDomain: AuthorityRpcResponseIdentifier
    sourceReceiptIds: list[AuthorityRpcResponseIdentifier] = Field(..., max_length=64)


class LiveParent(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    capabilityId: AuthorityRpcResponseIdentifier
    subject: PublicKey
    audience: AuthorityRpcResponseIdentifier
    delegationAncestorIds: list[AuthorityRpcResponseIdentifier] = Field(
        ..., max_length=128
    )
    expiresAtUnixSeconds: PositiveU64
    verifiedAtUnixSeconds: PositiveU64
    authoritySnapshotDigest: Digest


class RevocationSnapshot(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    revoked: bool
    observedAtUnixSeconds: PositiveU64
    commitIndex: U64
    authorityDomain: AuthorityRpcResponseIdentifier


class CaptureCommit(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    checkedRevocationSetDigest: Digest
    budgetCommitIndex: U64
    revocationCommitIndex: U64
    authorityCommitIndex: U64
    leaderEpoch: U64


class HoldState1(Enum):
    unknown = "unknown"
    denied = "denied"
    held = "held"
    reversed = "reversed"


class HoldState2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    captured: CaptureCommit


class HoldState(RootModel[HoldState1 | HoldState2]):
    root: HoldState1 | HoldState2


class CapabilitiesResult(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["capabilities"]
    response: Capabilities


class PreparedResult(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["prepared"]
    response: TrustedExecutionContext


class LiveParentResult(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["live_parent"]
    response: LiveParent


class RevocationResult(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["revocation"]
    response: RevocationSnapshot


class HoldResult(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["hold"]
    response: HoldState


class ResponseItem(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255)


class ControlResult(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["control"]
    response: list[ResponseItem] = Field(..., max_length=1048576)


class Response(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    code: AuthorityRpcResponseIdentifier


class RejectedResult(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["rejected"]
    response: Response


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
    schema_: Literal["chio.broker-authority-rpc.v1"] = Field(..., alias="schema")
    requestId: AuthorityRpcResponseIdentifier
    requestDigest: Digest
    issuedAtUnixSeconds: PositiveU64
    authority: PublicKey
    result: Result
