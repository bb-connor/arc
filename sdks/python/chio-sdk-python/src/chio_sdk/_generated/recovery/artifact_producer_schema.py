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

class OpaqueId(RootModel[constr(pattern='^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$', min_length=1, max_length=128)]):
    root: constr(pattern='^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$', min_length=1, max_length=128)

class RecoveryDigestOctet(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255) = Field(..., title='Recovery digest octet')

class RecoveryDigest32(RootModel[list[RecoveryDigestOctet]]):
    root: list[RecoveryDigestOctet] = Field(..., max_length=32, min_length=32, title='Recovery digest32')

class RecoveryArtifactProducerDefinitionsScope(BaseModel):
    model_config = ConfigDict(extra='forbid')
    authority_domain: OpaqueId
    tenant_id: OpaqueId
    process_id: OpaqueId

class RecoveryArtifactProducerNativeOperation(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['native_operation']
    operation: OpaqueId

class RecoveryArtifactProducerCheckpoint(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['checkpoint']
    checkpoint: OpaqueId

class RecoveryArtifactProducerDerivation(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['derivation']
    operation: OpaqueId

class RecoveryArtifactProducerAdoption(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['adoption']
    evidence: OpaqueId

class RecoveryArtifactProducerDefinitionsArtifactReference(BaseModel):
    model_config = ConfigDict(extra='forbid')
    scope: RecoveryArtifactProducerDefinitionsScope
    artifact: OpaqueId
    version: OpaqueId
    provenance: RecoveryDigest32

class RecoveryArtifactProducerImport(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['import']
    manifest: RecoveryDigest32
    origin: RecoveryArtifactProducerDefinitionsArtifactReference

class ArtifactProducerV1(RootModel[RecoveryArtifactProducerNativeOperation | RecoveryArtifactProducerCheckpoint | RecoveryArtifactProducerDerivation | RecoveryArtifactProducerAdoption | RecoveryArtifactProducerImport]):
    root: RecoveryArtifactProducerNativeOperation | RecoveryArtifactProducerCheckpoint | RecoveryArtifactProducerDerivation | RecoveryArtifactProducerAdoption | RecoveryArtifactProducerImport = Field(..., title='Artifact Producer V1')

# Public compatibility aliases reference the actual current model classes.
ArtifactProducerV11 = RecoveryArtifactProducerNativeOperation
ArtifactProducerV12 = RecoveryArtifactProducerCheckpoint
ArtifactProducerV13 = RecoveryArtifactProducerDerivation
ArtifactProducerV14 = RecoveryArtifactProducerAdoption
ArtifactProducerV15 = RecoveryArtifactProducerImport
ArtifactReference = RecoveryArtifactProducerDefinitionsArtifactReference
RecoveryArtifactProducerArtifactProducerV1 = ArtifactProducerV1
RecoveryArtifactProducerOpaqueId = OpaqueId
RecoveryArtifactProducerRecoveryDigest32 = RecoveryDigest32
RecoveryArtifactProducerRecoveryDigestOctet = RecoveryDigestOctet
RecoveryDigest32Item = RecoveryDigestOctet
Scope = RecoveryArtifactProducerDefinitionsScope
