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
from pydantic import BaseModel, ConfigDict, RootModel, constr
from . import semantic_payload_schema
from pydantic import field_validator as _facet_field_validator

class OpaqueId(RootModel[constr(pattern='^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$', min_length=1, max_length=128)]):
    root: constr(pattern='^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$', min_length=1, max_length=128)

class SemanticProviderResponseV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    provider: OpaqueId
    account: OpaqueId
    resource: OpaqueId
    checked_provider_version: constr(min_length=1, max_length=128)
    operation: OpaqueId
    attempt: constr(min_length=1, max_length=128)
    payload: semantic_payload_schema.SemanticPayloadV1

    @_facet_field_validator('checked_provider_version', mode='after')
    @classmethod
    def _require_checked_provider_version_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if isinstance(value, str):
            _require_utf8_bound(value, 128)
        return value

    @_facet_field_validator('attempt', mode='after')
    @classmethod
    def _require_attempt_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if isinstance(value, str):
            _require_utf8_bound(value, 128)
        return value

# Public compatibility aliases reference the actual current model classes.
RecoverySemanticProviderResponseOpaqueId = OpaqueId
RecoverySemanticProviderResponseSemanticProviderResponseV1 = SemanticProviderResponseV1
