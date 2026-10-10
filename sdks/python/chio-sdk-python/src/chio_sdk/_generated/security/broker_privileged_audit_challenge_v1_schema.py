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
from . import broker_audit_runner_authorization_body_v1_schema

class Digest(RootModel[constr(pattern='^[0-9a-f]{64}$')]):
    root: constr(pattern='^[0-9a-f]{64}$')

class PositiveU64(RootModel[conint(ge=1, le=18446744073709551615)]):
    root: conint(ge=1, le=18446744073709551615)

class PublicKey(RootModel[constr(pattern='^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\\+mldsa65)$')]):
    root: constr(pattern='^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\\+mldsa65)$')

class SecurityBrokerPrivilegedAuditChallengeV1DefinitionsAlgorithm(Enum):
    ed25519 = 'ed25519'
    p256 = 'p256'
    p384 = 'p384'
    hybrid = 'hybrid'

class Signature(RootModel[constr(pattern='^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+):[0-9a-f]{6618}:(ed25519|p256|p384)\\+mldsa65)$')]):
    root: constr(pattern='^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+):[0-9a-f]{6618}:(ed25519|p256|p384)\\+mldsa65)$')

class SecurityBrokerPrivilegedAuditChallengeV1DefinitionsChallengeBody(BaseModel):
    model_config = ConfigDict(extra='forbid')
    schema_: Literal['chio.broker-privileged-audit-challenge.v1'] = Field(..., alias='schema')
    sessionNonce: Digest
    sessionCommitmentSha256: Digest
    runnerAuthorizationBody: broker_audit_runner_authorization_body_v1_schema.ChioBrokerAuditRunnerAuthorizationBodyV1
    issuedAtUnixSeconds: PositiveU64
    expiresAtUnixSeconds: PositiveU64

class ChioSignedBrokerPrivilegedAuditChallengeV1(BaseModel):
    """
    Broker-signed challenge binding one privileged audit session to an exact runner authorization body.
    """
    model_config = ConfigDict(extra='forbid')
    body: SecurityBrokerPrivilegedAuditChallengeV1DefinitionsChallengeBody
    signer: PublicKey
    algorithm: SecurityBrokerPrivilegedAuditChallengeV1DefinitionsAlgorithm
    signature: Signature

# Public compatibility aliases reference the actual current model classes.
Algorithm = SecurityBrokerPrivilegedAuditChallengeV1DefinitionsAlgorithm
ChallengeBody = SecurityBrokerPrivilegedAuditChallengeV1DefinitionsChallengeBody
SecurityBrokerPrivilegedAuditChallengeV1ChioSignedBrokerPrivilegedAuditChallengeV1 = ChioSignedBrokerPrivilegedAuditChallengeV1
SecurityBrokerPrivilegedAuditChallengeV1Digest = Digest
SecurityBrokerPrivilegedAuditChallengeV1PositiveU64 = PositiveU64
SecurityBrokerPrivilegedAuditChallengeV1PublicKey = PublicKey
SecurityBrokerPrivilegedAuditChallengeV1Signature = Signature
