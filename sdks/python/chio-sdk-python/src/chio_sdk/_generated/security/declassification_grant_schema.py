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
from pydantic import field_validator as _facet_field_validator

class SecurityDeclassificationGrantAlgorithm(Enum):
    ed25519 = 'ed25519'
    p256 = 'p256'
    p384 = 'p384'
    hybrid = 'hybrid'

class FlowIdentifier(RootModel[constr(pattern='^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$', min_length=1, max_length=256)]):
    root: constr(pattern='^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$', min_length=1, max_length=256)

    @_facet_field_validator('root', mode='after')
    @classmethod
    def _require_root_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if isinstance(value, str):
            _require_utf8_bound(value, 256)
        return value

class Digest32Item(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255)

class Digest32(RootModel[list[Digest32Item]]):
    root: list[Digest32Item] = Field(..., max_length=32, min_length=32)
from .information_label_schema import SecurityInformationLabelKnown

class TargetLabel(SecurityInformationLabelKnown):
    kind: Literal['known']

class SecurityDeclassificationGrantBodyReferenced(BaseModel):
    model_config = ConfigDict(extra='forbid')
    domain_version: Literal[1]
    grant_id: FlowIdentifier
    capability_id: FlowIdentifier
    tenant_id: FlowIdentifier
    subject_id: FlowIdentifier
    agent_id: FlowIdentifier
    session_id: FlowIdentifier
    source_label_hash: Digest32
    target_label: TargetLabel
    destination_id: FlowIdentifier
    tool_name: FlowIdentifier
    purpose: FlowIdentifier
    request_hash: Digest32
    issued_at_unix_seconds: conint(ge=0)
    expires_at_unix_seconds: conint(ge=0)
    authority_key_id: FlowIdentifier

    @_facet_field_validator('grant_id', mode='after')
    @classmethod
    def _require_grant_id_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if value is not None:
            _require_utf8_bound(value.root, 256)
        return value

    @_facet_field_validator('capability_id', mode='after')
    @classmethod
    def _require_capability_id_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if value is not None:
            _require_utf8_bound(value.root, 256)
        return value

    @_facet_field_validator('tenant_id', mode='after')
    @classmethod
    def _require_tenant_id_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if value is not None:
            _require_utf8_bound(value.root, 256)
        return value

    @_facet_field_validator('subject_id', mode='after')
    @classmethod
    def _require_subject_id_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if value is not None:
            _require_utf8_bound(value.root, 256)
        return value

    @_facet_field_validator('agent_id', mode='after')
    @classmethod
    def _require_agent_id_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if value is not None:
            _require_utf8_bound(value.root, 256)
        return value

    @_facet_field_validator('session_id', mode='after')
    @classmethod
    def _require_session_id_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if value is not None:
            _require_utf8_bound(value.root, 256)
        return value

    @_facet_field_validator('destination_id', mode='after')
    @classmethod
    def _require_destination_id_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if value is not None:
            _require_utf8_bound(value.root, 256)
        return value

    @_facet_field_validator('tool_name', mode='after')
    @classmethod
    def _require_tool_name_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if value is not None:
            _require_utf8_bound(value.root, 256)
        return value

    @_facet_field_validator('purpose', mode='after')
    @classmethod
    def _require_purpose_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if value is not None:
            _require_utf8_bound(value.root, 256)
        return value

    @_facet_field_validator('authority_key_id', mode='after')
    @classmethod
    def _require_authority_key_id_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if value is not None:
            _require_utf8_bound(value.root, 256)
        return value

class SecurityDeclassificationGrantBody(BaseModel):
    model_config = ConfigDict(extra='forbid')
    domain_version: Literal[1]
    grant_id: FlowIdentifier
    capability_id: FlowIdentifier
    tenant_id: FlowIdentifier
    subject_id: FlowIdentifier
    agent_id: FlowIdentifier
    session_id: FlowIdentifier
    source_label_hash: Digest32
    target_label: TargetLabel
    destination_id: FlowIdentifier
    tool_name: FlowIdentifier
    purpose: FlowIdentifier
    request_hash: Digest32
    issued_at_unix_seconds: conint(ge=0)
    expires_at_unix_seconds: conint(ge=0)
    authority_key_id: FlowIdentifier

    @_facet_field_validator('grant_id', mode='after')
    @classmethod
    def _require_grant_id_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if value is not None:
            _require_utf8_bound(value.root, 256)
        return value

    @_facet_field_validator('capability_id', mode='after')
    @classmethod
    def _require_capability_id_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if value is not None:
            _require_utf8_bound(value.root, 256)
        return value

    @_facet_field_validator('tenant_id', mode='after')
    @classmethod
    def _require_tenant_id_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if value is not None:
            _require_utf8_bound(value.root, 256)
        return value

    @_facet_field_validator('subject_id', mode='after')
    @classmethod
    def _require_subject_id_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if value is not None:
            _require_utf8_bound(value.root, 256)
        return value

    @_facet_field_validator('agent_id', mode='after')
    @classmethod
    def _require_agent_id_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if value is not None:
            _require_utf8_bound(value.root, 256)
        return value

    @_facet_field_validator('session_id', mode='after')
    @classmethod
    def _require_session_id_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if value is not None:
            _require_utf8_bound(value.root, 256)
        return value

    @_facet_field_validator('destination_id', mode='after')
    @classmethod
    def _require_destination_id_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if value is not None:
            _require_utf8_bound(value.root, 256)
        return value

    @_facet_field_validator('tool_name', mode='after')
    @classmethod
    def _require_tool_name_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if value is not None:
            _require_utf8_bound(value.root, 256)
        return value

    @_facet_field_validator('purpose', mode='after')
    @classmethod
    def _require_purpose_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if value is not None:
            _require_utf8_bound(value.root, 256)
        return value

    @_facet_field_validator('authority_key_id', mode='after')
    @classmethod
    def _require_authority_key_id_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if value is not None:
            _require_utf8_bound(value.root, 256)
        return value

class SignedDeclassificationGrant(BaseModel):
    """
    One-shot, destination-bound authorization to lower the information label of one exact tool invocation.
    """
    model_config = ConfigDict(extra='forbid')
    body: SecurityDeclassificationGrantBody
    authority_key: constr(pattern='^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\\+mldsa65)$')
    algorithm: SecurityDeclassificationGrantAlgorithm
    signature: constr(pattern='^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+):[0-9a-f]{6618}:(ed25519|p256|p384)\\+mldsa65)$')

# Public compatibility aliases reference the actual current model classes.
Algorithm = SecurityDeclassificationGrantAlgorithm
Body = SecurityDeclassificationGrantBody
Body2 = SecurityDeclassificationGrantBody
SecurityDeclassificationGrantDigest32 = Digest32
SecurityDeclassificationGrantDigest32Item = Digest32Item
SecurityDeclassificationGrantFlowIdentifier = FlowIdentifier
SecurityDeclassificationGrantSignedDeclassificationGrant = SignedDeclassificationGrant
SecurityDeclassificationGrantTargetLabel = TargetLabel
