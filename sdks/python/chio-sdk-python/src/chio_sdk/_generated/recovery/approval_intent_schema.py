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
from pydantic import field_validator as _facet_field_validator

class RecoveryApprovalIntentObligationsItemsOwnerRelease(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['owner_release']
    owner: constr(pattern='^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$', min_length=1, max_length=256)

    @_facet_field_validator('owner', mode='after')
    @classmethod
    def _require_owner_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if isinstance(value, str):
            _require_utf8_bound(value, 256)
        return value

class RecoveryApprovalIntentObligationsItemsCompartmentRelease(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['compartment_release']
    compartment: constr(pattern='^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$', min_length=1, max_length=256)

    @_facet_field_validator('compartment', mode='after')
    @classmethod
    def _require_compartment_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if isinstance(value, str):
            _require_utf8_bound(value, 256)
        return value

class RecoveryApprovalIntentObligationsItemsUserAcceptance(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['user_acceptance']
    principal: constr(pattern='^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$', min_length=1, max_length=256)

    @_facet_field_validator('principal', mode='after')
    @classmethod
    def _require_principal_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if isinstance(value, str):
            _require_utf8_bound(value, 256)
        return value

class RecoveryApprovalIntentObligationsItemsIntegrityEndorsement(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['integrity_endorsement']
    principal: constr(pattern='^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$', min_length=1, max_length=256)

    @_facet_field_validator('principal', mode='after')
    @classmethod
    def _require_principal_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if isinstance(value, str):
            _require_utf8_bound(value, 256)
        return value

class OpaqueId(RootModel[constr(pattern='^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$', min_length=1, max_length=128)]):
    root: constr(pattern='^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$', min_length=1, max_length=128)

class RecoveryDigestOctet(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255) = Field(..., title='Recovery digest octet')

class RecoveryDigest32(RootModel[list[RecoveryDigestOctet]]):
    root: list[RecoveryDigestOctet] = Field(..., max_length=32, min_length=32, title='Recovery digest32')

class SafeInteger(RootModel[conint(ge=0, le=9007199254740991)]):
    root: conint(ge=0, le=9007199254740991)

class RecoveryApprovalIntentDefinitionsScope(BaseModel):
    model_config = ConfigDict(extra='forbid')
    authority_domain: OpaqueId
    tenant_id: OpaqueId
    process_id: OpaqueId

class RecoveryApprovalIntentV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    schema_: Literal['chio.recovery.approval-intent.v1'] = Field(..., alias='schema')
    version: Literal[1]
    approval_intent: OpaqueId
    challenge: OpaqueId
    scope: RecoveryApprovalIntentDefinitionsScope
    action_intent: RecoveryDigest32
    authorization_requirements: RecoveryDigest32
    offer: RecoveryDigest32
    plan: RecoveryDigest32
    preview: RecoveryDigest32
    recipient: constr(pattern='^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$', min_length=1, max_length=256)
    purpose: constr(pattern='^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$', min_length=1, max_length=256)
    reviewer: constr(pattern='^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$', min_length=1, max_length=256)
    obligations: list[RecoveryApprovalIntentObligationsItemsOwnerRelease | RecoveryApprovalIntentObligationsItemsCompartmentRelease | RecoveryApprovalIntentObligationsItemsUserAcceptance | RecoveryApprovalIntentObligationsItemsIntegrityEndorsement] = Field(..., max_length=64, min_length=1)
    issued_at_unix_ms: SafeInteger
    expires_at_unix_ms: SafeInteger

    @field_validator('version', mode='before')
    @classmethod
    def _require_integer_literal_kind(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError('recovery integer literal requires an integer')
        return value

    @_facet_field_validator('recipient', mode='after')
    @classmethod
    def _require_recipient_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if isinstance(value, str):
            _require_utf8_bound(value, 256)
        return value

    @_facet_field_validator('purpose', mode='after')
    @classmethod
    def _require_purpose_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if isinstance(value, str):
            _require_utf8_bound(value, 256)
        return value

    @_facet_field_validator('reviewer', mode='after')
    @classmethod
    def _require_reviewer_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if isinstance(value, str):
            _require_utf8_bound(value, 256)
        return value

# Public compatibility aliases reference the actual current model classes.
Obligations = RecoveryApprovalIntentObligationsItemsOwnerRelease
Obligations1 = RecoveryApprovalIntentObligationsItemsCompartmentRelease
Obligations2 = RecoveryApprovalIntentObligationsItemsUserAcceptance
Obligations3 = RecoveryApprovalIntentObligationsItemsIntegrityEndorsement
RecoveryApprovalIntentOpaqueId = OpaqueId
RecoveryApprovalIntentRecoveryDigest32 = RecoveryDigest32
RecoveryApprovalIntentRecoveryDigestOctet = RecoveryDigestOctet
RecoveryApprovalIntentSafeInteger = SafeInteger
RecoveryDigest32Item = RecoveryDigestOctet
Scope = RecoveryApprovalIntentDefinitionsScope
