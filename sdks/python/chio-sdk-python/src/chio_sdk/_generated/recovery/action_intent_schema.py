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
from typing import Any, Self
from pydantic import field_validator, model_serializer, SerializerFunctionWrapHandler
from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr
from . import authorization_requirements_schema, observation_schema
from pydantic import field_validator as _facet_field_validator

class OpaqueId(RootModel[constr(pattern='^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$', min_length=1, max_length=128)]):
    root: constr(pattern='^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$', min_length=1, max_length=128)

class RecoveryDigestOctet(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255) = Field(..., title='Recovery digest octet')

class RecoveryDigest32(RootModel[list[RecoveryDigestOctet]]):
    root: list[RecoveryDigestOctet] = Field(..., max_length=32, min_length=32, title='Recovery digest32')

class SafeInteger(RootModel[conint(ge=0, le=9007199254740991)]):
    root: conint(ge=0, le=9007199254740991)

class RecoveryActionIntentDefinitionsScope(BaseModel):
    model_config = ConfigDict(extra='forbid')
    authority_domain: OpaqueId
    tenant_id: OpaqueId
    process_id: OpaqueId

class RecoveryActionIntentOrigin(BaseModel):
    """
    Verified original effect-free denial. Historical actions may omit this field; fresh native recovery authorization requires it.
    """
    model_config = ConfigDict(extra='forbid')
    operation: observation_schema.RecoveryObservationDefinitionsOperation
    request_id: OpaqueId
    closure: OpaqueId

class RecoveryExactActionIntentV1(BaseModel):
    """Retained v1 action data with legacy and fresh native profiles.

    Legacy signed data omits origin. Fresh native authorization requires the
    complete original denial binding; this model cannot establish freshness.
    Explicit null is refused and an absent origin stays absent on serialization.
    """
    model_config = ConfigDict(extra='forbid')
    schema_: Literal['chio.recovery.action-intent.v1'] = Field(..., alias='schema')
    version: Literal[1]
    workflow_id: OpaqueId
    step_id: OpaqueId
    continuation_id: OpaqueId
    request_id: OpaqueId
    origin: RecoveryActionIntentOrigin | None = Field(None, description='Verified original effect-free denial. Historical actions may omit this field; fresh native recovery authorization requires it.')

    @classmethod
    def model_validate_json(cls, json_data: str | bytes | bytearray, *, strict: bool | None=None, extra: Literal['allow', 'ignore', 'forbid'] | None=None, context: Any | None=None, by_alias: bool | None=None, by_name: bool | None=None) -> Self:
        """Validate one immutable action wire before Pydantic member collapse."""
        from pydantic import ValidationError
        from ...recovery_wire import MAX_WIRE_BYTES, assert_foundation_wire
        invalid_wire = False
        try:
            if isinstance(json_data, str):
                if str.__len__(json_data) > MAX_WIRE_BYTES:
                    raise ValueError('recovery foundation byte bound')
                json_data = str.__str__(json_data)
                source = json_data
            elif isinstance(json_data, bytes):
                if bytes.__len__(json_data) > MAX_WIRE_BYTES:
                    raise ValueError('recovery foundation byte bound')
                json_data = bytes.__bytes__(json_data)
                source = json_data.decode('utf-8')
            elif isinstance(json_data, bytearray):
                snapshot = bytearray.__getitem__(json_data, slice(0, MAX_WIRE_BYTES + 1))
                if len(snapshot) > MAX_WIRE_BYTES:
                    raise ValueError('recovery foundation byte bound')
                json_data = bytes(snapshot)
                source = json_data.decode('utf-8')
            else:
                source = None
            if source is not None:
                assert_foundation_wire(source)
        except ValueError:
            invalid_wire = True
        if invalid_wire:
            raise ValidationError.from_exception_data(cls.__name__, [{'type': 'json_invalid', 'loc': (), 'input': None, 'ctx': {'error': 'recovery action JSON violates its foundation profile'}}], input_type='json', hide_input=True)
        validation_options: dict[str, Any] = {'strict': strict, 'context': context}
        if extra is not None:
            validation_options['extra'] = extra
        if by_alias is not None:
            validation_options['by_alias'] = by_alias
        if by_name is not None:
            validation_options['by_name'] = by_name
        return super().model_validate_json(json_data, **validation_options)

    @field_validator('origin', mode='before')
    @classmethod
    def _origin_must_not_be_null(cls, value: object) -> object:
        if value is None:
            raise ValueError('recovery origin must be omitted instead of null')
        return value

    @model_serializer(mode='wrap')
    def _omit_absent_legacy_origin(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        value = handler(self)
        if self.origin is None:
            value.pop('origin', None)
        return value
    isolation_lineage: OpaqueId
    scope: RecoveryActionIntentDefinitionsScope
    capability_id: constr(pattern='^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$', min_length=1, max_length=256)
    authorization_requirements: authorization_requirements_schema.RecoveryAuthorizationRequirementsV1
    request_namespace: RecoveryDigest32
    capability_body: RecoveryDigest32
    semantic_request: RecoveryDigest32
    policy_digest: RecoveryDigest32
    contract_digest: RecoveryDigest32
    authority_scope: RecoveryDigest32
    basis: RecoveryDigest32
    output_disposition: RecoveryDigest32
    source_generation: SafeInteger
    isolation_epoch: SafeInteger

    @field_validator('version', mode='before')
    @classmethod
    def _require_integer_literal_kind(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError('recovery integer literal requires an integer')
        return value

    @_facet_field_validator('capability_id', mode='after')
    @classmethod
    def _require_capability_id_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if isinstance(value, str):
            _require_utf8_bound(value, 256)
        return value

# Public compatibility aliases reference the actual current model classes.
Origin = RecoveryActionIntentOrigin
RecoveryActionIntentOpaqueId = OpaqueId
RecoveryActionIntentRecoveryDigest32 = RecoveryDigest32
RecoveryActionIntentRecoveryDigestOctet = RecoveryDigestOctet
RecoveryActionIntentRecoveryExactActionIntentV1 = RecoveryExactActionIntentV1
RecoveryActionIntentSafeInteger = SafeInteger
RecoveryDigest32Item = RecoveryDigestOctet
Scope = RecoveryActionIntentDefinitionsScope
