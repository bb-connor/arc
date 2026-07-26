# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 12f29b53e7b2b0f290d2f6e643bb969068e1777bf31ecf770aa23307b31bec09
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel

from . import (
    broker_audit_comparison_envelope_v1_schema,
    broker_audit_runner_authorization_envelope_v1_schema,
    broker_authority_request_envelope_v1_schema,
    broker_authority_response_envelope_v1_schema,
    broker_privileged_audit_challenge_v1_schema,
)


class GovernedAdminAuthorizationItem(RootModel[int]):
    root: Annotated[int, Field(ge=0, le=255)]


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


class AuthorityExchange(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    maximumClockSkewSeconds: Annotated[int, Field(ge=1, le=60)]
    request: (
        broker_authority_request_envelope_v1_schema.ChioSignedBrokerAuthorityRpcRequestV1
    )
    requestSha256: Digest
    response: (
        broker_authority_response_envelope_v1_schema.ChioSignedBrokerAuthorityRpcResponseV1
    )
    responseSha256: Digest
    trustedAuthority: PublicKey
    verifiedAtUnixSeconds: PositiveU64


class ChioBrokerPrivilegedAuditEvidenceBundleV1(BaseModel):
    """
    Canonical evidence returned after one privileged broker audit comparison.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    challenge: (
        broker_privileged_audit_challenge_v1_schema.ChioSignedBrokerPrivilegedAuditChallengeV1
    )
    comparison: (
        broker_audit_comparison_envelope_v1_schema.ChioSignedBrokerAuditComparisonV1
    )
    governedAdminAuthorization: Annotated[
        list[GovernedAdminAuthorizationItem], Field(max_length=65536, min_length=1)
    ]
    livenessAuthorityExchange: AuthorityExchange
    revocationAuthorityExchange: AuthorityExchange
    runnerAuthorization: (
        broker_audit_runner_authorization_envelope_v1_schema.ChioSignedBrokerAuditRunnerAuthorizationV1
    )
    schema_: Annotated[
        Literal["chio.broker-privileged-audit-evidence.v1"], Field(alias="schema")
    ]
