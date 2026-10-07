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

class KeyLogIdentifier(RootModel[constr(pattern='^[A-Za-z0-9._:/-]+$', min_length=1, max_length=128)]):
    root: constr(pattern='^[A-Za-z0-9._:/-]+$', min_length=1, max_length=128)

class Hash(RootModel[constr(pattern='^0x[0-9a-f]{64}$')]):
    root: constr(pattern='^0x[0-9a-f]{64}$')

class SecurityKeyLogEventBodyV1DefinitionsAlgorithm(Enum):
    ed25519 = 'ed25519'
    p256 = 'p256'
    p384 = 'p384'
    hybrid = 'hybrid'

class PublicKey(RootModel[constr(pattern='^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\\+mldsa65)$')]):
    root: constr(pattern='^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\\+mldsa65)$')

class SecurityKeyLogEventBodyV1DefinitionsOperationGenesis(BaseModel):
    model_config = ConfigDict(extra='forbid')
    type: Literal['genesis']

class SecurityKeyLogEventBodyV1DefinitionsOperationRotate(BaseModel):
    model_config = ConfigDict(extra='forbid')
    type: Literal['rotate']
    previous_key_id: Hash
    witness_roster_id: KeyLogIdentifier
    witness_roster_binding: Hash

class SecurityKeyLogEventBodyV1DefinitionsOperationAbortRotation(BaseModel):
    model_config = ConfigDict(extra='forbid')
    type: Literal['abort_rotation']
    previous_key_id: Hash
    recovery_policy_id: KeyLogIdentifier | None = None
    recovery_policy_binding: Hash | None = None

class SecurityKeyLogEventBodyV1DefinitionsOperationRetire(BaseModel):
    model_config = ConfigDict(extra='forbid')
    type: Literal['retire']

class SecurityKeyLogEventBodyV1DefinitionsOperationRevoke(BaseModel):
    model_config = ConfigDict(extra='forbid')
    type: Literal['revoke']

class SecurityKeyLogEventBodyV1DefinitionsOperationRecover(BaseModel):
    model_config = ConfigDict(extra='forbid')
    type: Literal['recover']
    previous_key_id: Hash
    witness_roster_id: KeyLogIdentifier
    witness_roster_binding: Hash
    recovery_policy_id: KeyLogIdentifier
    recovery_policy_binding: Hash

class Operation(RootModel[SecurityKeyLogEventBodyV1DefinitionsOperationGenesis | SecurityKeyLogEventBodyV1DefinitionsOperationRotate | SecurityKeyLogEventBodyV1DefinitionsOperationAbortRotation | SecurityKeyLogEventBodyV1DefinitionsOperationRetire | SecurityKeyLogEventBodyV1DefinitionsOperationRevoke | SecurityKeyLogEventBodyV1DefinitionsOperationRecover]):
    root: SecurityKeyLogEventBodyV1DefinitionsOperationGenesis | SecurityKeyLogEventBodyV1DefinitionsOperationRotate | SecurityKeyLogEventBodyV1DefinitionsOperationAbortRotation | SecurityKeyLogEventBodyV1DefinitionsOperationRetire | SecurityKeyLogEventBodyV1DefinitionsOperationRevoke | SecurityKeyLogEventBodyV1DefinitionsOperationRecover

class ChioKeyLogEventBodyV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    schema_: Literal['chio.key-log.event.v1'] = Field(..., alias='schema')
    log_id: KeyLogIdentifier
    sequence: conint(ge=0)
    event_id: KeyLogIdentifier
    previous_event_hash: Hash | None = None
    authority_id: KeyLogIdentifier
    key_id: Hash
    algorithm: SecurityKeyLogEventBodyV1DefinitionsAlgorithm
    public_key: PublicKey
    operation: Operation
    effective_at: conint(ge=0)
    verify_until: conint(ge=0) | None = None
    reason: constr(pattern='^[^\\u0000-\\u001f\\u007f]+$', min_length=1, max_length=512) | None = None
    issued_at: conint(ge=0)

# Public compatibility aliases reference the actual current model classes.
Algorithm = SecurityKeyLogEventBodyV1DefinitionsAlgorithm
Operation11 = SecurityKeyLogEventBodyV1DefinitionsOperationGenesis
Operation12 = SecurityKeyLogEventBodyV1DefinitionsOperationRotate
Operation13 = SecurityKeyLogEventBodyV1DefinitionsOperationAbortRotation
Operation14 = SecurityKeyLogEventBodyV1DefinitionsOperationRetire
Operation15 = SecurityKeyLogEventBodyV1DefinitionsOperationRevoke
Operation16 = SecurityKeyLogEventBodyV1DefinitionsOperationRecover
Operation3 = SecurityKeyLogEventBodyV1DefinitionsOperationGenesis
Operation4 = SecurityKeyLogEventBodyV1DefinitionsOperationRotate
Operation5 = SecurityKeyLogEventBodyV1DefinitionsOperationAbortRotation
Operation6 = SecurityKeyLogEventBodyV1DefinitionsOperationRetire
Operation7 = SecurityKeyLogEventBodyV1DefinitionsOperationRevoke
Operation8 = SecurityKeyLogEventBodyV1DefinitionsOperationRecover
SecurityKeyLogEventBodyV1ChioKeyLogEventBodyV1 = ChioKeyLogEventBodyV1
SecurityKeyLogEventBodyV1Hash = Hash
SecurityKeyLogEventBodyV1KeyLogIdentifier = KeyLogIdentifier
SecurityKeyLogEventBodyV1Operation = Operation
SecurityKeyLogEventBodyV1PublicKey = PublicKey
