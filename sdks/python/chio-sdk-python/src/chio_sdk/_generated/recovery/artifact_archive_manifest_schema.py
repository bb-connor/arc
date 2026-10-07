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
from . import artifact_version_schema

class OpaqueId(RootModel[constr(pattern='^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$', min_length=1, max_length=128)]):
    root: constr(pattern='^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$', min_length=1, max_length=128)

class RecoveryDigestOctet(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255) = Field(..., title='Recovery digest octet')

class RecoveryDigest32(RootModel[list[RecoveryDigestOctet]]):
    root: list[RecoveryDigestOctet] = Field(..., max_length=32, min_length=32, title='Recovery digest32')

class RecoveryArtifactArchiveManifestDefinitionsScope(BaseModel):
    model_config = ConfigDict(extra='forbid')
    authority_domain: OpaqueId
    tenant_id: OpaqueId
    process_id: OpaqueId

class RecoveryArtifactArchiveManifestDefinitionsArtifactReference(BaseModel):
    model_config = ConfigDict(extra='forbid')
    scope: RecoveryArtifactArchiveManifestDefinitionsScope
    artifact: OpaqueId
    version: OpaqueId
    provenance: RecoveryDigest32

class ArtifactArchiveManifestV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    domain_version: Literal[1]
    scope: RecoveryArtifactArchiveManifestDefinitionsScope
    root: RecoveryArtifactArchiveManifestDefinitionsArtifactReference
    versions: list[artifact_version_schema.ArtifactVersionV1] = Field(..., max_length=16, min_length=1)
    total_bytes: conint(ge=0, le=1048576)

    @field_validator('domain_version', mode='before')
    @classmethod
    def _require_integer_literal_kind(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError('recovery integer literal requires an integer')
        return value

# Public compatibility aliases reference the actual current model classes.
ArtifactReference = RecoveryArtifactArchiveManifestDefinitionsArtifactReference
RecoveryArtifactArchiveManifestArtifactArchiveManifestV1 = ArtifactArchiveManifestV1
RecoveryArtifactArchiveManifestOpaqueId = OpaqueId
RecoveryArtifactArchiveManifestRecoveryDigest32 = RecoveryDigest32
RecoveryArtifactArchiveManifestRecoveryDigestOctet = RecoveryDigestOctet
RecoveryDigest32Item = RecoveryDigestOctet
Scope = RecoveryArtifactArchiveManifestDefinitionsScope
