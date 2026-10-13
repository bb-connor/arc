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
from ..security import information_label_schema
from pydantic import field_validator as _facet_field_validator

class RecoveryReturnContractDefinitionsArtifactSinkAgent(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['agent']

class RecoveryReturnContractDefinitionsArtifactSinkArchive(BaseModel):
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

class RecoveryReturnContractDefinitionsScope(BaseModel):
    model_config = ConfigDict(extra='forbid')
    authority_domain: OpaqueId
    tenant_id: OpaqueId
    process_id: OpaqueId

class RecoveryReturnContractDefinitionsArtifactInfluence(BaseModel):
    model_config = ConfigDict(extra='forbid')
    commitment: RecoveryDigest32
    externally_influenced: bool
    unknown: bool

class RecoveryReturnContractDefinitionsArtifactReference(BaseModel):
    model_config = ConfigDict(extra='forbid')
    scope: RecoveryReturnContractDefinitionsScope
    artifact: OpaqueId
    version: OpaqueId
    provenance: RecoveryDigest32

class RecoveryReturnContractDefinitionsModelContext(BaseModel):
    model_config = ConfigDict(extra='forbid')
    context: OpaqueId
    provider: OpaqueId
    account: OpaqueId
    conversation: constr(min_length=1, max_length=128)
    cache: constr(min_length=1, max_length=128)
    side_files: list[RecoveryReturnContractDefinitionsArtifactReference] = Field(..., max_length=8, min_length=0)
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

class RecoveryReturnContractDefinitionsArtifactSinkModel(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['model']
    context: RecoveryReturnContractDefinitionsModelContext

class ArtifactSink(RootModel[RecoveryReturnContractDefinitionsArtifactSinkAgent | RecoveryReturnContractDefinitionsArtifactSinkModel | RecoveryReturnContractDefinitionsArtifactSinkArchive]):
    root: RecoveryReturnContractDefinitionsArtifactSinkAgent | RecoveryReturnContractDefinitionsArtifactSinkModel | RecoveryReturnContractDefinitionsArtifactSinkArchive

class RecoveryReturnContractDefinitionsArtifactRecipient(BaseModel):
    model_config = ConfigDict(extra='forbid')
    recipient: OpaqueId
    scope: RecoveryReturnContractDefinitionsScope
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

class ReturnContractV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    domain_version: Literal[1]
    contract: RecoveryDigest32
    schema_: RecoveryDigest32 = Field(..., alias='schema')
    implementation: RecoveryDigest32
    field: constr(min_length=1, max_length=128)
    parent: RecoveryReturnContractDefinitionsArtifactRecipient
    source_ceiling: information_label_schema.InformationLabel
    target: information_label_schema.InformationLabel
    require_integrity: bool
    max_bytes: Literal[8]
    max_values: Literal[1]
    channels: list[str] = Field(..., max_length=1, min_length=1)
    expires_at_unix_ms: conint(ge=1, le=9007199254740991)
    policy: RecoveryDigest32

    @field_validator('domain_version', 'max_bytes', 'max_values', mode='before')
    @classmethod
    def _require_integer_literal_kind(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError('recovery integer literal requires an integer')
        return value

# Public compatibility aliases reference the actual current model classes.
ArtifactInfluence = RecoveryReturnContractDefinitionsArtifactInfluence
ArtifactRecipient = RecoveryReturnContractDefinitionsArtifactRecipient
ArtifactReference = RecoveryReturnContractDefinitionsArtifactReference
ArtifactSink22 = RecoveryReturnContractDefinitionsArtifactSinkAgent
ArtifactSink23 = RecoveryReturnContractDefinitionsArtifactSinkModel
ArtifactSink24 = RecoveryReturnContractDefinitionsArtifactSinkArchive
ModelContext = RecoveryReturnContractDefinitionsModelContext
RecoveryDigest32Item = RecoveryDigestOctet
RecoveryReturnContractArtifactSink = ArtifactSink
RecoveryReturnContractOpaqueId = OpaqueId
RecoveryReturnContractRecoveryDigest32 = RecoveryDigest32
RecoveryReturnContractRecoveryDigestOctet = RecoveryDigestOctet
RecoveryReturnContractReturnContractV1 = ReturnContractV1
RecoveryReturnContractSafeInteger = SafeInteger
Scope = RecoveryReturnContractDefinitionsScope
