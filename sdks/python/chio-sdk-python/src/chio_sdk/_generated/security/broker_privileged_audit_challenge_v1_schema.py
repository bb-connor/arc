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

from . import broker_audit_runner_authorization_body_v1_schema


class Algorithm(Enum):
    ed25519 = "ed25519"
    p256 = "p256"
    p384 = "p384"
    hybrid = "hybrid"


class Digest(RootModel[str]):
    root: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]


class PositiveU64(RootModel[int]):
    root: Annotated[int, Field(ge=1, le=18446744073709551615)]


class PublicKey(RootModel[str]):
    root: Annotated[
        str,
        Field(
            pattern="^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\\+mldsa65)$"
        ),
    ]


class Signature(RootModel[str]):
    root: Annotated[
        str,
        Field(
            pattern="^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+):[0-9a-f]{6618}:(ed25519|p256|p384)\\+mldsa65)$"
        ),
    ]


class ChallengeBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    expiresAtUnixSeconds: PositiveU64
    issuedAtUnixSeconds: PositiveU64
    runnerAuthorizationBody: (
        broker_audit_runner_authorization_body_v1_schema.ChioBrokerAuditRunnerAuthorizationBodyV1
    )
    schema_: Annotated[
        Literal["chio.broker-privileged-audit-challenge.v1"], Field(alias="schema")
    ]
    sessionCommitmentSha256: Digest
    sessionNonce: Digest


class ChioSignedBrokerPrivilegedAuditChallengeV1(BaseModel):
    """
    Broker-signed challenge binding one privileged audit session to an exact runner authorization body.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    algorithm: Algorithm
    body: ChallengeBody
    signature: Signature
    signer: PublicKey
