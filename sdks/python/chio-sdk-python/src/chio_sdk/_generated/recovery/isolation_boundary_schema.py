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
from . import confined_execution_profile_schema, confined_limits_schema
from pydantic import field_validator as _facet_field_validator

class RecoveryIsolationBoundaryDefinitionsArtifactSinkAgent(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['agent']

class RecoveryIsolationBoundaryDefinitionsArtifactSinkArchive(BaseModel):
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

class RecoveryIsolationBoundaryDefinitionsScope(BaseModel):
    model_config = ConfigDict(extra='forbid')
    authority_domain: OpaqueId
    tenant_id: OpaqueId
    process_id: OpaqueId

class RecoveryIsolationBoundaryDefinitionsArtifactInfluence(BaseModel):
    model_config = ConfigDict(extra='forbid')
    commitment: RecoveryDigest32
    externally_influenced: bool
    unknown: bool

class RecoveryIsolationBoundaryDefinitionsArtifactReference(BaseModel):
    model_config = ConfigDict(extra='forbid')
    scope: RecoveryIsolationBoundaryDefinitionsScope
    artifact: OpaqueId
    version: OpaqueId
    provenance: RecoveryDigest32

class RecoveryIsolationBoundaryDefinitionsModelContext(BaseModel):
    model_config = ConfigDict(extra='forbid')
    context: OpaqueId
    provider: OpaqueId
    account: OpaqueId
    conversation: constr(min_length=1, max_length=128)
    cache: constr(min_length=1, max_length=128)
    side_files: list[RecoveryIsolationBoundaryDefinitionsArtifactReference] = Field(..., max_length=8, min_length=0)
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

class RecoveryIsolationBoundaryDefinitionsArtifactSinkModel(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['model']
    context: RecoveryIsolationBoundaryDefinitionsModelContext

class ArtifactSink(RootModel[RecoveryIsolationBoundaryDefinitionsArtifactSinkAgent | RecoveryIsolationBoundaryDefinitionsArtifactSinkModel | RecoveryIsolationBoundaryDefinitionsArtifactSinkArchive]):
    root: RecoveryIsolationBoundaryDefinitionsArtifactSinkAgent | RecoveryIsolationBoundaryDefinitionsArtifactSinkModel | RecoveryIsolationBoundaryDefinitionsArtifactSinkArchive

class RecoveryIsolationBoundaryDefinitionsArtifactRecipient(BaseModel):
    model_config = ConfigDict(extra='forbid')
    recipient: OpaqueId
    scope: RecoveryIsolationBoundaryDefinitionsScope
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

class IsolationBoundaryV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    domain_version: Literal[1]
    boundary: OpaqueId
    request: OpaqueId
    scope: RecoveryIsolationBoundaryDefinitionsScope
    parent_capability: RecoveryDigest32
    parent: RecoveryIsolationBoundaryDefinitionsArtifactRecipient
    child: OpaqueId
    child_principal: constr(min_length=1, max_length=128)
    child_capability: RecoveryDigest32
    ancestry: list[OpaqueId] = Field(..., max_length=8, min_length=1)
    lineage: OpaqueId
    isolation_epoch: constr(min_length=1, max_length=128)
    seed_artifacts: list[RecoveryIsolationBoundaryDefinitionsArtifactReference] = Field(..., max_length=8, min_length=0)
    observation: RecoveryIsolationBoundaryDefinitionsArtifactReference
    parent_control: RecoveryDigest32
    seed_label: information_label_schema.InformationLabel
    seed_influence: RecoveryIsolationBoundaryDefinitionsArtifactInfluence
    execution: confined_execution_profile_schema.ConfinedExecutionProfileV1
    return_contract: RecoveryDigest32
    limits: confined_limits_schema.ConfinedLimitsV1
    deadline_unix_ms: conint(ge=1, le=9007199254740991)
    policy: RecoveryDigest32

    @field_validator('domain_version', mode='before')
    @classmethod
    def _require_integer_literal_kind(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError('recovery integer literal requires an integer')
        return value

# Public compatibility aliases reference the actual current model classes.
ArtifactInfluence = RecoveryIsolationBoundaryDefinitionsArtifactInfluence
ArtifactRecipient = RecoveryIsolationBoundaryDefinitionsArtifactRecipient
ArtifactReference = RecoveryIsolationBoundaryDefinitionsArtifactReference
ArtifactSink16 = RecoveryIsolationBoundaryDefinitionsArtifactSinkAgent
ArtifactSink17 = RecoveryIsolationBoundaryDefinitionsArtifactSinkModel
ArtifactSink18 = RecoveryIsolationBoundaryDefinitionsArtifactSinkArchive
ModelContext = RecoveryIsolationBoundaryDefinitionsModelContext
RecoveryDigest32Item = RecoveryDigestOctet
RecoveryIsolationBoundaryArtifactSink = ArtifactSink
RecoveryIsolationBoundaryIsolationBoundaryV1 = IsolationBoundaryV1
RecoveryIsolationBoundaryOpaqueId = OpaqueId
RecoveryIsolationBoundaryRecoveryDigest32 = RecoveryDigest32
RecoveryIsolationBoundaryRecoveryDigestOctet = RecoveryDigestOctet
RecoveryIsolationBoundarySafeInteger = SafeInteger
Scope = RecoveryIsolationBoundaryDefinitionsScope
