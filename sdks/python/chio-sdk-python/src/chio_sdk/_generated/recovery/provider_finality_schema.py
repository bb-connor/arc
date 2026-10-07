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
from pydantic import field_validator as _facet_field_validator

class RecoveryProviderFinalityDisposition(Enum):
    succeeded = 'succeeded'
    partially_applied = 'partially_applied'
    failed_after_effect = 'failed_after_effect'

class OpaqueId(RootModel[constr(pattern='^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$', min_length=1, max_length=128)]):
    root: constr(pattern='^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$', min_length=1, max_length=128)

class RecoveryDigestOctet(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255) = Field(..., title='Recovery digest octet')

class RecoveryDigest32(RootModel[list[RecoveryDigestOctet]]):
    root: list[RecoveryDigestOctet] = Field(..., max_length=32, min_length=32, title='Recovery digest32')

class SafeInteger(RootModel[conint(ge=0, le=9007199254740991)]):
    root: conint(ge=0, le=9007199254740991)

class RecoveryProviderFinalityDefinitionsScope(BaseModel):
    model_config = ConfigDict(extra='forbid')
    authority_domain: OpaqueId
    tenant_id: OpaqueId
    process_id: OpaqueId

class RecoveryProviderPositiveFinalityV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    schema_: Literal['chio.recovery.provider-finality.v1'] = Field(..., alias='schema')
    version: Literal[1]
    workflow_id: OpaqueId
    continuation_id: OpaqueId
    operation_id: OpaqueId
    attempt_id: OpaqueId
    scope: RecoveryProviderFinalityDefinitionsScope
    native_admission_digest: RecoveryDigest32
    provider: constr(pattern='^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$', min_length=1, max_length=256)
    account: constr(pattern='^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$', min_length=1, max_length=256)
    resource_digest: RecoveryDigest32
    contract_digest: RecoveryDigest32
    observed_at_unix_ms: SafeInteger
    expires_at_unix_ms: SafeInteger
    disposition: RecoveryProviderFinalityDisposition
    applied_effects: Literal[1]

    @field_validator('version', 'applied_effects', mode='before')
    @classmethod
    def _require_integer_literal_kind(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError('recovery integer literal requires an integer')
        return value

    @_facet_field_validator('provider', mode='after')
    @classmethod
    def _require_provider_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if isinstance(value, str):
            _require_utf8_bound(value, 256)
        return value

    @_facet_field_validator('account', mode='after')
    @classmethod
    def _require_account_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if isinstance(value, str):
            _require_utf8_bound(value, 256)
        return value

# Public compatibility aliases reference the actual current model classes.
Disposition = RecoveryProviderFinalityDisposition
RecoveryDigest32Item = RecoveryDigestOctet
RecoveryProviderFinalityOpaqueId = OpaqueId
RecoveryProviderFinalityRecoveryDigest32 = RecoveryDigest32
RecoveryProviderFinalityRecoveryDigestOctet = RecoveryDigestOctet
RecoveryProviderFinalityRecoveryProviderPositiveFinalityV1 = RecoveryProviderPositiveFinalityV1
RecoveryProviderFinalitySafeInteger = SafeInteger
Scope = RecoveryProviderFinalityDefinitionsScope
