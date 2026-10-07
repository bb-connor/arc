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
from typing import Literal
from pydantic import field_validator
from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr

class OpaqueId(RootModel[constr(pattern='^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$', min_length=1, max_length=128)]):
    root: constr(pattern='^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$', min_length=1, max_length=128)

class RecoveryDigestOctet(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255) = Field(..., title='Recovery digest octet')

class RecoveryDigest32(RootModel[list[RecoveryDigestOctet]]):
    root: list[RecoveryDigestOctet] = Field(..., max_length=32, min_length=32, title='Recovery digest32')

class SafeInteger(RootModel[conint(ge=0, le=9007199254740991)]):
    root: conint(ge=0, le=9007199254740991)

class RecoveryGrantBindingDefinitionsScope(BaseModel):
    model_config = ConfigDict(extra='forbid')
    authority_domain: OpaqueId
    tenant_id: OpaqueId
    process_id: OpaqueId

class RecoveryMandatoryGrantBindingV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    schema_: Literal['chio.recovery.grant-binding.v1'] = Field(..., alias='schema')
    version: Literal[1]
    authority_domain: OpaqueId
    workflow_id: OpaqueId
    step_id: OpaqueId
    continuation_id: OpaqueId
    process_id: OpaqueId
    request_id: OpaqueId
    isolation_lineage: OpaqueId
    approval_intent: OpaqueId
    challenge: OpaqueId
    request_namespace: RecoveryDigest32
    action_intent: RecoveryDigest32
    authorization_requirements: RecoveryDigest32
    selected_offer: RecoveryDigest32
    approved_plan: RecoveryDigest32
    policy_digest: RecoveryDigest32
    contract_digest: RecoveryDigest32
    authority_scope: RecoveryDigest32
    output_disposition: RecoveryDigest32
    coverage_digest: RecoveryDigest32
    isolation_epoch: conint(ge=1, le=9007199254740991)

    @field_validator('version', mode='before')
    @classmethod
    def _require_integer_literal_kind(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError('recovery integer literal requires an integer')
        return value

# Public compatibility aliases reference the actual current model classes.
RecoveryDigest32Item = RecoveryDigestOctet
RecoveryGrantBindingOpaqueId = OpaqueId
RecoveryGrantBindingRecoveryDigest32 = RecoveryDigest32
RecoveryGrantBindingRecoveryDigestOctet = RecoveryDigestOctet
RecoveryGrantBindingRecoveryMandatoryGrantBindingV1 = RecoveryMandatoryGrantBindingV1
RecoveryGrantBindingSafeInteger = SafeInteger
Scope = RecoveryGrantBindingDefinitionsScope
