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
from pydantic import BaseModel, ConfigDict, Field, RootModel, constr
from . import key_log_event_body_v1_schema

class Hash(RootModel[constr(pattern='^0x[0-9a-f]{64}$')]):
    root: constr(pattern='^0x[0-9a-f]{64}$')

class SecurityKeyLogEventEnvelopeV1DefinitionsAlgorithm(Enum):
    ed25519 = 'ed25519'
    p256 = 'p256'
    p384 = 'p384'
    hybrid = 'hybrid'

class Signature(RootModel[constr(pattern='^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+):[0-9a-f]{6618}:(ed25519|p256|p384)\\+mldsa65)$')]):
    root: constr(pattern='^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+):[0-9a-f]{6618}:(ed25519|p256|p384)\\+mldsa65)$')

class KeyLogIdentifier(RootModel[constr(pattern='^[A-Za-z0-9._:/-]+$', min_length=1, max_length=128)]):
    root: constr(pattern='^[A-Za-z0-9._:/-]+$', min_length=1, max_length=128)

class SecurityKeyLogEventEnvelopeV1DefinitionsKeyAuthorization(BaseModel):
    model_config = ConfigDict(extra='forbid')
    key_id: Hash
    algorithm: SecurityKeyLogEventEnvelopeV1DefinitionsAlgorithm
    signature: Signature

class SecurityKeyLogEventEnvelopeV1DefinitionsRecoveryAuthorization(BaseModel):
    model_config = ConfigDict(extra='forbid')
    authorizer_id: KeyLogIdentifier
    algorithm: SecurityKeyLogEventEnvelopeV1DefinitionsAlgorithm
    signature: Signature

class SecurityKeyLogEventEnvelopeV1Authorizations(BaseModel):
    model_config = ConfigDict(extra='forbid')
    bootstrap: SecurityKeyLogEventEnvelopeV1DefinitionsKeyAuthorization | None = None
    old_key: SecurityKeyLogEventEnvelopeV1DefinitionsKeyAuthorization | None = None
    new_key: SecurityKeyLogEventEnvelopeV1DefinitionsKeyAuthorization | None = None
    recovery: list[SecurityKeyLogEventEnvelopeV1DefinitionsRecoveryAuthorization] | None = Field(None, max_length=64)

class ChioSignedKeyLogEventEnvelopeV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    body: key_log_event_body_v1_schema.ChioKeyLogEventBodyV1
    authorizations: SecurityKeyLogEventEnvelopeV1Authorizations

# Public compatibility aliases reference the actual current model classes.
Algorithm = SecurityKeyLogEventEnvelopeV1DefinitionsAlgorithm
Authorizations = SecurityKeyLogEventEnvelopeV1Authorizations
KeyAuthorization = SecurityKeyLogEventEnvelopeV1DefinitionsKeyAuthorization
RecoveryAuthorization = SecurityKeyLogEventEnvelopeV1DefinitionsRecoveryAuthorization
SecurityKeyLogEventEnvelopeV1ChioSignedKeyLogEventEnvelopeV1 = ChioSignedKeyLogEventEnvelopeV1
SecurityKeyLogEventEnvelopeV1Hash = Hash
SecurityKeyLogEventEnvelopeV1KeyLogIdentifier = KeyLogIdentifier
SecurityKeyLogEventEnvelopeV1Signature = Signature
