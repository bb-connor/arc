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

class RecoveryArtifactCertificateKind(Enum):
    classification = 'classification'
    projection = 'projection'

class OpaqueId(RootModel[constr(pattern='^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$', min_length=1, max_length=128)]):
    root: constr(pattern='^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$', min_length=1, max_length=128)

class RecoveryDigestOctet(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255) = Field(..., title='Recovery digest octet')

class RecoveryDigest32(RootModel[list[RecoveryDigestOctet]]):
    root: list[RecoveryDigestOctet] = Field(..., max_length=32, min_length=32, title='Recovery digest32')

class SafeInteger(RootModel[conint(ge=0, le=9007199254740991)]):
    root: conint(ge=0, le=9007199254740991)

class RecoveryArtifactCertificateDefinitionsScope(BaseModel):
    model_config = ConfigDict(extra='forbid')
    authority_domain: OpaqueId
    process_id: OpaqueId
    tenant_id: OpaqueId

class RecoveryArtifactCertificateDefinitionsArtifactInfluence(BaseModel):
    model_config = ConfigDict(extra='forbid')
    commitment: RecoveryDigest32
    externally_influenced: bool
    unknown: bool

class RecoveryArtifactCertificateDefinitionsArtifactProducerNativeOperation(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['native_operation']
    operation: OpaqueId

class RecoveryArtifactCertificateDefinitionsArtifactProducerCheckpoint(BaseModel):
    model_config = ConfigDict(extra='forbid')
    checkpoint: OpaqueId
    kind: Literal['checkpoint']

class RecoveryArtifactCertificateDefinitionsArtifactProducerDerivation(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['derivation']
    operation: OpaqueId

class RecoveryArtifactCertificateDefinitionsArtifactProducerAdoption(BaseModel):
    model_config = ConfigDict(extra='forbid')
    evidence: OpaqueId
    kind: Literal['adoption']

class RecoveryArtifactCertificateDefinitionsArtifactReference(BaseModel):
    model_config = ConfigDict(extra='forbid')
    artifact: OpaqueId
    provenance: RecoveryDigest32
    scope: RecoveryArtifactCertificateDefinitionsScope
    version: OpaqueId

class RecoveryArtifactCertificateDefinitionsArtifactProducerImport(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['import']
    manifest: RecoveryDigest32
    origin: RecoveryArtifactCertificateDefinitionsArtifactReference

class ArtifactProducer(RootModel[RecoveryArtifactCertificateDefinitionsArtifactProducerNativeOperation | RecoveryArtifactCertificateDefinitionsArtifactProducerCheckpoint | RecoveryArtifactCertificateDefinitionsArtifactProducerDerivation | RecoveryArtifactCertificateDefinitionsArtifactProducerAdoption | RecoveryArtifactCertificateDefinitionsArtifactProducerImport]):
    root: RecoveryArtifactCertificateDefinitionsArtifactProducerNativeOperation | RecoveryArtifactCertificateDefinitionsArtifactProducerCheckpoint | RecoveryArtifactCertificateDefinitionsArtifactProducerDerivation | RecoveryArtifactCertificateDefinitionsArtifactProducerAdoption | RecoveryArtifactCertificateDefinitionsArtifactProducerImport

class ArtifactCertificateV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    artifact: OpaqueId
    configuration: RecoveryDigest32
    content: RecoveryDigest32
    dependencies: list[RecoveryArtifactCertificateDefinitionsArtifactReference] = Field(..., max_length=16, min_length=0)
    domain_version: Literal[1]
    evidence: OpaqueId
    implementation: RecoveryDigest32
    influence: RecoveryArtifactCertificateDefinitionsArtifactInfluence
    issued_at_unix_ms: SafeInteger
    kind: RecoveryArtifactCertificateKind
    output_label: information_label_schema.InformationLabel
    producer: ArtifactProducer
    schema_: RecoveryDigest32 = Field(..., alias='schema')
    scope: RecoveryArtifactCertificateDefinitionsScope
    size_bytes: conint(ge=0, le=1048576)
    valid_until_unix_ms: SafeInteger
    version: OpaqueId

    @field_validator('domain_version', mode='before')
    @classmethod
    def _require_integer_literal_kind(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError('recovery integer literal requires an integer')
        return value

# Public compatibility aliases reference the actual current model classes.
ArtifactInfluence = RecoveryArtifactCertificateDefinitionsArtifactInfluence
ArtifactProducer1 = RecoveryArtifactCertificateDefinitionsArtifactProducerNativeOperation
ArtifactProducer2 = RecoveryArtifactCertificateDefinitionsArtifactProducerCheckpoint
ArtifactProducer3 = RecoveryArtifactCertificateDefinitionsArtifactProducerDerivation
ArtifactProducer4 = RecoveryArtifactCertificateDefinitionsArtifactProducerAdoption
ArtifactProducer5 = RecoveryArtifactCertificateDefinitionsArtifactProducerImport
ArtifactReference = RecoveryArtifactCertificateDefinitionsArtifactReference
Kind = RecoveryArtifactCertificateKind
RecoveryArtifactCertificateArtifactCertificateV1 = ArtifactCertificateV1
RecoveryArtifactCertificateArtifactProducer = ArtifactProducer
RecoveryArtifactCertificateOpaqueId = OpaqueId
RecoveryArtifactCertificateRecoveryDigest32 = RecoveryDigest32
RecoveryArtifactCertificateRecoveryDigestOctet = RecoveryDigestOctet
RecoveryArtifactCertificateSafeInteger = SafeInteger
RecoveryDigest32Item = RecoveryDigestOctet
Scope = RecoveryArtifactCertificateDefinitionsScope
