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
from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr
from ..security import information_label_schema
from pydantic import field_validator as _facet_field_validator

class RecoveryArtifactRecipientDefinitionsArtifactSinkAgent(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['agent']

class RecoveryArtifactRecipientDefinitionsArtifactSinkArchive(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['archive']

class OpaqueId(RootModel[constr(pattern='^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$', min_length=1, max_length=128)]):
    root: constr(pattern='^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$', min_length=1, max_length=128)

class RecoveryDigestOctet(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255) = Field(..., title='Recovery digest octet')

class RecoveryDigest32(RootModel[list[RecoveryDigestOctet]]):
    root: list[RecoveryDigestOctet] = Field(..., max_length=32, min_length=32, title='Recovery digest32')

class SafeInteger(RootModel[conint(ge=0, le=9007199254740991)]):
    root: conint(ge=0, le=9007199254740991)

class RecoveryArtifactRecipientDefinitionsScope(BaseModel):
    model_config = ConfigDict(extra='forbid')
    authority_domain: OpaqueId
    process_id: OpaqueId
    tenant_id: OpaqueId

class RecoveryArtifactRecipientDefinitionsArtifactReference(BaseModel):
    model_config = ConfigDict(extra='forbid')
    artifact: OpaqueId
    provenance: RecoveryDigest32
    scope: RecoveryArtifactRecipientDefinitionsScope
    version: OpaqueId

class RecoveryArtifactRecipientDefinitionsModelContext(BaseModel):
    model_config = ConfigDict(extra='forbid')
    account: OpaqueId
    cache: constr(min_length=1, max_length=128)
    context: OpaqueId
    contract: RecoveryDigest32
    conversation: constr(min_length=1, max_length=128)
    provider: OpaqueId
    side_files: list[RecoveryArtifactRecipientDefinitionsArtifactReference] = Field(..., max_length=8, min_length=0)

    @_facet_field_validator('cache', mode='after')
    @classmethod
    def _require_cache_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if isinstance(value, str):
            _require_utf8_bound(value, 128)
        return value

    @_facet_field_validator('conversation', mode='after')
    @classmethod
    def _require_conversation_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if isinstance(value, str):
            _require_utf8_bound(value, 128)
        return value

class RecoveryArtifactRecipientDefinitionsArtifactSinkModel(BaseModel):
    model_config = ConfigDict(extra='forbid')
    context: RecoveryArtifactRecipientDefinitionsModelContext
    kind: Literal['model']

class ArtifactSink(RootModel[RecoveryArtifactRecipientDefinitionsArtifactSinkAgent | RecoveryArtifactRecipientDefinitionsArtifactSinkModel | RecoveryArtifactRecipientDefinitionsArtifactSinkArchive]):
    root: RecoveryArtifactRecipientDefinitionsArtifactSinkAgent | RecoveryArtifactRecipientDefinitionsArtifactSinkModel | RecoveryArtifactRecipientDefinitionsArtifactSinkArchive

class ArtifactRecipientV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    clearance: information_label_schema.InformationLabel
    context_generation: SafeInteger
    isolation_epoch: constr(min_length=1, max_length=128)
    lineage: OpaqueId
    principal: constr(min_length=1, max_length=256)
    recipient: OpaqueId
    runtime: constr(min_length=1, max_length=128)
    scope: RecoveryArtifactRecipientDefinitionsScope
    sink: ArtifactSink

    @_facet_field_validator('isolation_epoch', mode='after')
    @classmethod
    def _require_isolation_epoch_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if isinstance(value, str):
            _require_utf8_bound(value, 128)
        return value

    @_facet_field_validator('principal', mode='after')
    @classmethod
    def _require_principal_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if isinstance(value, str):
            _require_utf8_bound(value, 256)
        return value

    @_facet_field_validator('runtime', mode='after')
    @classmethod
    def _require_runtime_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if isinstance(value, str):
            _require_utf8_bound(value, 128)
        return value

# Public compatibility aliases reference the actual current model classes.
ArtifactReference = RecoveryArtifactRecipientDefinitionsArtifactReference
ArtifactSink1 = RecoveryArtifactRecipientDefinitionsArtifactSinkAgent
ArtifactSink2 = RecoveryArtifactRecipientDefinitionsArtifactSinkModel
ArtifactSink3 = RecoveryArtifactRecipientDefinitionsArtifactSinkArchive
ModelContext = RecoveryArtifactRecipientDefinitionsModelContext
RecoveryArtifactRecipientArtifactRecipientV1 = ArtifactRecipientV1
RecoveryArtifactRecipientArtifactSink = ArtifactSink
RecoveryArtifactRecipientOpaqueId = OpaqueId
RecoveryArtifactRecipientRecoveryDigest32 = RecoveryDigest32
RecoveryArtifactRecipientRecoveryDigestOctet = RecoveryDigestOctet
RecoveryArtifactRecipientSafeInteger = SafeInteger
RecoveryDigest32Item = RecoveryDigestOctet
Scope = RecoveryArtifactRecipientDefinitionsScope
