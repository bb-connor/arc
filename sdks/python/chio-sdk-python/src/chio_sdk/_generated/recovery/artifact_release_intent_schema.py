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
from ..security import information_label_schema
from pydantic import field_validator as _facet_field_validator

class RecoveryArtifactReleaseIntentState(Enum):
    admitted = 'admitted'
    uncertain = 'uncertain'
    delivered = 'delivered'

class RecoveryArtifactReleaseIntentDefinitionsArtifactSinkAgent(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['agent']

class RecoveryArtifactReleaseIntentDefinitionsArtifactSinkArchive(BaseModel):
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

class RecoveryArtifactReleaseIntentDefinitionsScope(BaseModel):
    model_config = ConfigDict(extra='forbid')
    authority_domain: OpaqueId
    process_id: OpaqueId
    tenant_id: OpaqueId

class RecoveryArtifactReleaseIntentKindCapturedOutput(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['captured_output']
    operation: OpaqueId

class RecoveryArtifactReleaseIntentKindIndependentlyAdmitted(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['independently_admitted']
    request: OpaqueId

class RecoveryArtifactReleaseIntentDefinitionsArtifactInfluence(BaseModel):
    model_config = ConfigDict(extra='forbid')
    commitment: RecoveryDigest32
    externally_influenced: bool
    unknown: bool

class RecoveryArtifactReleaseIntentDefinitionsArtifactReference(BaseModel):
    model_config = ConfigDict(extra='forbid')
    artifact: OpaqueId
    provenance: RecoveryDigest32
    scope: RecoveryArtifactReleaseIntentDefinitionsScope
    version: OpaqueId

class RecoveryArtifactReleaseIntentDefinitionsModelContext(BaseModel):
    model_config = ConfigDict(extra='forbid')
    account: OpaqueId
    cache: constr(min_length=1, max_length=128)
    context: OpaqueId
    contract: RecoveryDigest32
    conversation: constr(min_length=1, max_length=128)
    provider: OpaqueId
    side_files: list[RecoveryArtifactReleaseIntentDefinitionsArtifactReference] = Field(..., max_length=8, min_length=0)

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

class RecoveryArtifactReleaseIntentDefinitionsArtifactSinkModel(BaseModel):
    model_config = ConfigDict(extra='forbid')
    context: RecoveryArtifactReleaseIntentDefinitionsModelContext
    kind: Literal['model']

class ArtifactSink(RootModel[RecoveryArtifactReleaseIntentDefinitionsArtifactSinkAgent | RecoveryArtifactReleaseIntentDefinitionsArtifactSinkModel | RecoveryArtifactReleaseIntentDefinitionsArtifactSinkArchive]):
    root: RecoveryArtifactReleaseIntentDefinitionsArtifactSinkAgent | RecoveryArtifactReleaseIntentDefinitionsArtifactSinkModel | RecoveryArtifactReleaseIntentDefinitionsArtifactSinkArchive

class RecoveryArtifactReleaseIntentDefinitionsArtifactRecipient(BaseModel):
    model_config = ConfigDict(extra='forbid')
    clearance: information_label_schema.InformationLabel
    context_generation: SafeInteger
    isolation_epoch: constr(min_length=1, max_length=128)
    lineage: OpaqueId
    principal: constr(min_length=1, max_length=256)
    recipient: OpaqueId
    runtime: constr(min_length=1, max_length=128)
    scope: RecoveryArtifactReleaseIntentDefinitionsScope
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

class ArtifactReleaseIntentV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    admitted_label: information_label_schema.InformationLabel
    artifact: RecoveryArtifactReleaseIntentDefinitionsArtifactReference
    authorization: RecoveryDigest32
    domain_version: Literal[1]
    influence: RecoveryArtifactReleaseIntentDefinitionsArtifactInfluence
    kind: RecoveryArtifactReleaseIntentKindCapturedOutput | RecoveryArtifactReleaseIntentKindIndependentlyAdmitted
    observation_generation: SafeInteger
    observation_transition: OpaqueId
    policy: RecoveryDigest32
    recipient: RecoveryArtifactReleaseIntentDefinitionsArtifactRecipient
    release: OpaqueId
    source_label: information_label_schema.InformationLabel
    state: RecoveryArtifactReleaseIntentState

    @field_validator('domain_version', mode='before')
    @classmethod
    def _require_integer_literal_kind(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError('recovery integer literal requires an integer')
        return value

# Public compatibility aliases reference the actual current model classes.
ArtifactInfluence = RecoveryArtifactReleaseIntentDefinitionsArtifactInfluence
ArtifactRecipient = RecoveryArtifactReleaseIntentDefinitionsArtifactRecipient
ArtifactReference = RecoveryArtifactReleaseIntentDefinitionsArtifactReference
ArtifactSink4 = RecoveryArtifactReleaseIntentDefinitionsArtifactSinkAgent
ArtifactSink5 = RecoveryArtifactReleaseIntentDefinitionsArtifactSinkModel
ArtifactSink6 = RecoveryArtifactReleaseIntentDefinitionsArtifactSinkArchive
Kind = RecoveryArtifactReleaseIntentKindCapturedOutput
Kind2 = RecoveryArtifactReleaseIntentKindIndependentlyAdmitted
ModelContext = RecoveryArtifactReleaseIntentDefinitionsModelContext
RecoveryArtifactReleaseIntentArtifactReleaseIntentV1 = ArtifactReleaseIntentV1
RecoveryArtifactReleaseIntentArtifactSink = ArtifactSink
RecoveryArtifactReleaseIntentOpaqueId = OpaqueId
RecoveryArtifactReleaseIntentRecoveryDigest32 = RecoveryDigest32
RecoveryArtifactReleaseIntentRecoveryDigestOctet = RecoveryDigestOctet
RecoveryArtifactReleaseIntentSafeInteger = SafeInteger
RecoveryDigest32Item = RecoveryDigestOctet
Scope = RecoveryArtifactReleaseIntentDefinitionsScope
State = RecoveryArtifactReleaseIntentState
