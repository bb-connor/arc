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
from pydantic import field_validator
from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr
from ..security import declassification_grant_schema
from . import grant_binding_schema

class RecoverySignedGrantV2Algorithm(Enum):
    ed25519 = 'ed25519'
    p256 = 'p256'
    p384 = 'p384'
    hybrid = 'hybrid'

class OpaqueId(RootModel[constr(pattern='^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$', min_length=1, max_length=128)]):
    root: constr(pattern='^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$', min_length=1, max_length=128)

class RecoveryDigestOctet(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255) = Field(..., title='Recovery digest octet')

class RecoveryDigest32(RootModel[list[RecoveryDigestOctet]]):
    root: list[RecoveryDigestOctet] = Field(..., max_length=32, min_length=32, title='Recovery digest32')

class SafeInteger(RootModel[conint(ge=0, le=9007199254740991)]):
    root: conint(ge=0, le=9007199254740991)

class RecoverySignedGrantV2DefinitionsScope(BaseModel):
    model_config = ConfigDict(extra='forbid')
    authority_domain: OpaqueId
    tenant_id: OpaqueId
    process_id: OpaqueId

class RecoverySignedGrantV2Body(BaseModel):
    model_config = ConfigDict(extra='forbid')
    schema_: Literal['chio.declassification-grant.v2'] = Field(..., alias='schema')
    domain_version: Literal[2]
    claims: declassification_grant_schema.SecurityDeclassificationGrantBodyReferenced
    recovery: grant_binding_schema.RecoveryMandatoryGrantBindingV1

    @field_validator('domain_version', mode='before')
    @classmethod
    def _require_integer_literal_kind(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError('recovery integer literal requires an integer')
        return value

class SignedRecoveryDeclassificationGrantV2(BaseModel):
    model_config = ConfigDict(extra='forbid')
    body: RecoverySignedGrantV2Body
    authority_key: constr(pattern='^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\\+mldsa65)$')
    algorithm: RecoverySignedGrantV2Algorithm
    signature: constr(pattern='^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+):[0-9a-f]{6618}:(ed25519|p256|p384)\\+mldsa65)$')

# Public compatibility aliases reference the actual current model classes.
Algorithm = RecoverySignedGrantV2Algorithm
Body = RecoverySignedGrantV2Body
RecoveryDigest32Item = RecoveryDigestOctet
RecoverySignedGrantV2OpaqueId = OpaqueId
RecoverySignedGrantV2RecoveryDigest32 = RecoveryDigest32
RecoverySignedGrantV2RecoveryDigestOctet = RecoveryDigestOctet
RecoverySignedGrantV2SafeInteger = SafeInteger
RecoverySignedGrantV2SignedRecoveryDeclassificationGrantV2 = SignedRecoveryDeclassificationGrantV2
Scope = RecoverySignedGrantV2DefinitionsScope
