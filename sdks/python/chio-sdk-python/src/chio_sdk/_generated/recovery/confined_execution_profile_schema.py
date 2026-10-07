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

class RecoveryConfinedExecutionProfileDefinitionsArtifactSinkAgent(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['agent']

class RecoveryConfinedExecutionProfileDefinitionsArtifactSinkArchive(BaseModel):
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

class RecoveryConfinedExecutionProfileDefinitionsScope(BaseModel):
    model_config = ConfigDict(extra='forbid')
    authority_domain: OpaqueId
    tenant_id: OpaqueId
    process_id: OpaqueId

class ConfinedExecutionProfileV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    manifest: RecoveryDigest32
    profile: RecoveryDigest32
    configuration: RecoveryDigest32
    helper: RecoveryDigest32
    image: RecoveryDigest32
    provider: Literal['disabled']

class RecoveryConfinedExecutionProfileDefinitionsArtifactInfluence(BaseModel):
    model_config = ConfigDict(extra='forbid')
    commitment: RecoveryDigest32
    externally_influenced: bool
    unknown: bool

class RecoveryConfinedExecutionProfileDefinitionsArtifactReference(BaseModel):
    model_config = ConfigDict(extra='forbid')
    scope: RecoveryConfinedExecutionProfileDefinitionsScope
    artifact: OpaqueId
    version: OpaqueId
    provenance: RecoveryDigest32

class RecoveryConfinedExecutionProfileDefinitionsModelContext(BaseModel):
    model_config = ConfigDict(extra='forbid')
    context: OpaqueId
    provider: OpaqueId
    account: OpaqueId
    conversation: constr(min_length=1, max_length=128)
    cache: constr(min_length=1, max_length=128)
    side_files: list[RecoveryConfinedExecutionProfileDefinitionsArtifactReference] = Field(..., max_length=8, min_length=0)
    contract: RecoveryDigest32

    @_facet_field_validator('conversation', mode='after')
    @classmethod
    def _require_conversation_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if isinstance(value, str):
            _require_utf8_bound(value, 128)
        return value

    @_facet_field_validator('cache', mode='after')
    @classmethod
    def _require_cache_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if isinstance(value, str):
            _require_utf8_bound(value, 128)
        return value

class RecoveryConfinedExecutionProfileDefinitionsArtifactSinkModel(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['model']
    context: RecoveryConfinedExecutionProfileDefinitionsModelContext

class ArtifactSink(RootModel[RecoveryConfinedExecutionProfileDefinitionsArtifactSinkAgent | RecoveryConfinedExecutionProfileDefinitionsArtifactSinkModel | RecoveryConfinedExecutionProfileDefinitionsArtifactSinkArchive]):
    root: RecoveryConfinedExecutionProfileDefinitionsArtifactSinkAgent | RecoveryConfinedExecutionProfileDefinitionsArtifactSinkModel | RecoveryConfinedExecutionProfileDefinitionsArtifactSinkArchive

class RecoveryConfinedExecutionProfileDefinitionsArtifactRecipient(BaseModel):
    model_config = ConfigDict(extra='forbid')
    recipient: OpaqueId
    scope: RecoveryConfinedExecutionProfileDefinitionsScope
    runtime: constr(min_length=1, max_length=128)
    principal: constr(min_length=1, max_length=256)
    lineage: OpaqueId
    isolation_epoch: constr(min_length=1, max_length=128)
    context_generation: SafeInteger
    clearance: information_label_schema.InformationLabel
    sink: ArtifactSink

    @_facet_field_validator('runtime', mode='after')
    @classmethod
    def _require_runtime_utf8_bytes(cls, value: object) -> object:
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

    @_facet_field_validator('isolation_epoch', mode='after')
    @classmethod
    def _require_isolation_epoch_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if isinstance(value, str):
            _require_utf8_bound(value, 128)
        return value

# Public compatibility aliases reference the actual current model classes.
ArtifactInfluence = RecoveryConfinedExecutionProfileDefinitionsArtifactInfluence
ArtifactRecipient = RecoveryConfinedExecutionProfileDefinitionsArtifactRecipient
ArtifactReference = RecoveryConfinedExecutionProfileDefinitionsArtifactReference
ArtifactSink7 = RecoveryConfinedExecutionProfileDefinitionsArtifactSinkAgent
ArtifactSink8 = RecoveryConfinedExecutionProfileDefinitionsArtifactSinkModel
ArtifactSink9 = RecoveryConfinedExecutionProfileDefinitionsArtifactSinkArchive
ModelContext = RecoveryConfinedExecutionProfileDefinitionsModelContext
RecoveryConfinedExecutionProfileArtifactSink = ArtifactSink
RecoveryConfinedExecutionProfileConfinedExecutionProfileV1 = ConfinedExecutionProfileV1
RecoveryConfinedExecutionProfileOpaqueId = OpaqueId
RecoveryConfinedExecutionProfileRecoveryDigest32 = RecoveryDigest32
RecoveryConfinedExecutionProfileRecoveryDigestOctet = RecoveryDigestOctet
RecoveryConfinedExecutionProfileSafeInteger = SafeInteger
RecoveryDigest32Item = RecoveryDigestOctet
Scope = RecoveryConfinedExecutionProfileDefinitionsScope
