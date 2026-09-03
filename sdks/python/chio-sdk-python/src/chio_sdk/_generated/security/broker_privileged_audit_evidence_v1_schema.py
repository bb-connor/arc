# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 389bcf1b0204c491a4db719480c568ace486987ea9871d15adefdc3bb3a365cc
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr

from . import (
    broker_audit_comparison_envelope_v1_schema,
    broker_audit_runner_authorization_envelope_v1_schema,
    broker_authority_request_envelope_v1_schema,
    broker_authority_response_envelope_v1_schema,
    broker_privileged_audit_challenge_v1_schema,
)


class GovernedAdminAuthorizationItem(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255)


class Digest(RootModel[constr(pattern=r"^[0-9a-f]{64}$")]):
    root: constr(pattern=r"^[0-9a-f]{64}$")


class PositiveU64(RootModel[conint(ge=1, le=18446744073709551615)]):
    root: conint(ge=1, le=18446744073709551615)


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


class AuthorityExchange(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    request: (
        broker_authority_request_envelope_v1_schema.ChioSignedBrokerAuthorityRpcRequestV1
    )
    response: (
        broker_authority_response_envelope_v1_schema.ChioSignedBrokerAuthorityRpcResponseV1
    )
    trustedAuthority: PublicKey
    verifiedAtUnixSeconds: PositiveU64
    maximumClockSkewSeconds: conint(ge=1, le=60)
    requestSha256: Digest
    responseSha256: Digest


class ChioBrokerPrivilegedAuditEvidenceBundleV1(BaseModel):
    """
    Canonical evidence returned after one privileged broker audit comparison.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.broker-privileged-audit-evidence.v1"] = Field(
        ..., alias="schema"
    )
    challenge: (
        broker_privileged_audit_challenge_v1_schema.ChioSignedBrokerPrivilegedAuditChallengeV1
    )
    runnerAuthorization: (
        broker_audit_runner_authorization_envelope_v1_schema.ChioSignedBrokerAuditRunnerAuthorizationV1
    )
    governedAdminAuthorization: list[GovernedAdminAuthorizationItem] = Field(
        ..., max_length=65536, min_length=1
    )
    livenessAuthorityExchange: AuthorityExchange
    revocationAuthorityExchange: AuthorityExchange
    comparison: (
        broker_audit_comparison_envelope_v1_schema.ChioSignedBrokerAuditComparisonV1
    )
