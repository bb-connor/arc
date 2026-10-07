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

class RecoveryArtifactVersionRetention(Enum):
    ephemeral = 'ephemeral'
    checkpoint = 'checkpoint'
    evidence = 'evidence'

class OpaqueId(RootModel[constr(pattern='^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$', min_length=1, max_length=128)]):
    root: constr(pattern='^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$', min_length=1, max_length=128)

class RecoveryDigestOctet(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255) = Field(..., title='Recovery digest octet')

class RecoveryDigest32(RootModel[list[RecoveryDigestOctet]]):
    root: list[RecoveryDigestOctet] = Field(..., max_length=32, min_length=32, title='Recovery digest32')

class RecoveryArtifactVersionDefinitionsScope(BaseModel):
    model_config = ConfigDict(extra='forbid')
    authority_domain: OpaqueId
    process_id: OpaqueId
    tenant_id: OpaqueId

class RecoveryArtifactVersionDefinitionsArtifactInfluence(BaseModel):
    model_config = ConfigDict(extra='forbid')
    commitment: RecoveryDigest32
    externally_influenced: bool
    unknown: bool

class RecoveryArtifactVersionDefinitionsArtifactProducerNativeOperation(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['native_operation']
    operation: OpaqueId

class RecoveryArtifactVersionDefinitionsArtifactProducerCheckpoint(BaseModel):
    model_config = ConfigDict(extra='forbid')
    checkpoint: OpaqueId
    kind: Literal['checkpoint']

class RecoveryArtifactVersionDefinitionsArtifactProducerDerivation(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['derivation']
    operation: OpaqueId

class RecoveryArtifactVersionDefinitionsArtifactProducerAdoption(BaseModel):
    model_config = ConfigDict(extra='forbid')
    evidence: OpaqueId
    kind: Literal['adoption']

class RecoveryArtifactVersionDefinitionsArtifactReference(BaseModel):
    model_config = ConfigDict(extra='forbid')
    artifact: OpaqueId
    provenance: RecoveryDigest32
    scope: RecoveryArtifactVersionDefinitionsScope
    version: OpaqueId

class RecoveryArtifactVersionDefinitionsArtifactProducerImport(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['import']
    manifest: RecoveryDigest32
    origin: RecoveryArtifactVersionDefinitionsArtifactReference

class ArtifactProducer(RootModel[RecoveryArtifactVersionDefinitionsArtifactProducerNativeOperation | RecoveryArtifactVersionDefinitionsArtifactProducerCheckpoint | RecoveryArtifactVersionDefinitionsArtifactProducerDerivation | RecoveryArtifactVersionDefinitionsArtifactProducerAdoption | RecoveryArtifactVersionDefinitionsArtifactProducerImport]):
    root: RecoveryArtifactVersionDefinitionsArtifactProducerNativeOperation | RecoveryArtifactVersionDefinitionsArtifactProducerCheckpoint | RecoveryArtifactVersionDefinitionsArtifactProducerDerivation | RecoveryArtifactVersionDefinitionsArtifactProducerAdoption | RecoveryArtifactVersionDefinitionsArtifactProducerImport

class ArtifactVersionV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    artifact: OpaqueId
    content: RecoveryDigest32
    contract: RecoveryDigest32
    creation_sequence: conint(ge=1, le=9007199254740991)
    dependencies: list[RecoveryArtifactVersionDefinitionsArtifactReference] = Field(..., max_length=16, min_length=0)
    domain_version: Literal[1]
    evidence: list[OpaqueId] = Field(..., max_length=8, min_length=0)
    influence: RecoveryArtifactVersionDefinitionsArtifactInfluence
    isolation_epoch: constr(min_length=1, max_length=128)
    label: information_label_schema.InformationLabel
    lineage: OpaqueId
    media_type: constr(min_length=1, max_length=128)
    policy: RecoveryDigest32
    producer: ArtifactProducer
    retention: RecoveryArtifactVersionRetention
    schema_: RecoveryDigest32 = Field(..., alias='schema')
    scope: RecoveryArtifactVersionDefinitionsScope
    size_bytes: conint(ge=0, le=1048576)
    version: OpaqueId

    @field_validator('domain_version', mode='before')
    @classmethod
    def _require_integer_literal_kind(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError('recovery integer literal requires an integer')
        return value

    @_facet_field_validator('isolation_epoch', mode='after')
    @classmethod
    def _require_isolation_epoch_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if isinstance(value, str):
            _require_utf8_bound(value, 128)
        return value

    @_facet_field_validator('media_type', mode='after')
    @classmethod
    def _require_media_type_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if isinstance(value, str):
            _require_utf8_bound(value, 128)
        return value

# Public compatibility aliases reference the actual current model classes.
ArtifactInfluence = RecoveryArtifactVersionDefinitionsArtifactInfluence
ArtifactProducer10 = RecoveryArtifactVersionDefinitionsArtifactProducerImport
ArtifactProducer6 = RecoveryArtifactVersionDefinitionsArtifactProducerNativeOperation
ArtifactProducer7 = RecoveryArtifactVersionDefinitionsArtifactProducerCheckpoint
ArtifactProducer8 = RecoveryArtifactVersionDefinitionsArtifactProducerDerivation
ArtifactProducer9 = RecoveryArtifactVersionDefinitionsArtifactProducerAdoption
ArtifactReference = RecoveryArtifactVersionDefinitionsArtifactReference
RecoveryArtifactVersionArtifactProducer = ArtifactProducer
RecoveryArtifactVersionArtifactVersionV1 = ArtifactVersionV1
RecoveryArtifactVersionOpaqueId = OpaqueId
RecoveryArtifactVersionRecoveryDigest32 = RecoveryDigest32
RecoveryArtifactVersionRecoveryDigestOctet = RecoveryDigestOctet
RecoveryDigest32Item = RecoveryDigestOctet
Retention = RecoveryArtifactVersionRetention
Scope = RecoveryArtifactVersionDefinitionsScope
