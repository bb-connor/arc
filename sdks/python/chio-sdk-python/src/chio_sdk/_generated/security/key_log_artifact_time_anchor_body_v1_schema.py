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

class Identifier(RootModel[constr(pattern='^[A-Za-z0-9._:/-]+$', min_length=1, max_length=128)]):
    root: constr(pattern='^[A-Za-z0-9._:/-]+$', min_length=1, max_length=128)

class Hash(RootModel[constr(pattern='^0x[0-9a-f]{64}$')]):
    root: constr(pattern='^0x[0-9a-f]{64}$')

class U64(RootModel[conint(ge=0, le=18446744073709551615)]):
    root: conint(ge=0, le=18446744073709551615)

class SecurityKeyLogArtifactTimeAnchorBodyV1DefinitionsCheckpointAnchorType(Enum):
    receipt_checkpoint = 'receipt_checkpoint'
    key_log_checkpoint = 'key_log_checkpoint'

class SecurityKeyLogArtifactTimeAnchorBodyV1DefinitionsCheckpointAnchor(BaseModel):
    model_config = ConfigDict(extra='forbid')
    type: SecurityKeyLogArtifactTimeAnchorBodyV1DefinitionsCheckpointAnchorType
    checkpoint_sequence: U64
    checkpoint_hash: Hash

class SecurityKeyLogArtifactTimeAnchorBodyV1DefinitionsExternalAnchor(BaseModel):
    model_config = ConfigDict(extra='forbid')
    type: Literal['external']
    commitment: Hash

class Anchor(RootModel[SecurityKeyLogArtifactTimeAnchorBodyV1DefinitionsCheckpointAnchor | SecurityKeyLogArtifactTimeAnchorBodyV1DefinitionsExternalAnchor]):
    root: SecurityKeyLogArtifactTimeAnchorBodyV1DefinitionsCheckpointAnchor | SecurityKeyLogArtifactTimeAnchorBodyV1DefinitionsExternalAnchor

class ChioKeyLogArtifactTimeAnchorBodyV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    schema_: Literal['chio.key-log.artifact-time-anchor.v1'] = Field(..., alias='schema')
    anchor_id: Identifier
    artifact_hash: Hash
    anchored_at: U64
    anchor: Anchor

# Public compatibility aliases reference the actual current model classes.
CheckpointAnchor = SecurityKeyLogArtifactTimeAnchorBodyV1DefinitionsCheckpointAnchor
ExternalAnchor = SecurityKeyLogArtifactTimeAnchorBodyV1DefinitionsExternalAnchor
SecurityKeyLogArtifactTimeAnchorBodyV1Anchor = Anchor
SecurityKeyLogArtifactTimeAnchorBodyV1ChioKeyLogArtifactTimeAnchorBodyV1 = ChioKeyLogArtifactTimeAnchorBodyV1
SecurityKeyLogArtifactTimeAnchorBodyV1Hash = Hash
SecurityKeyLogArtifactTimeAnchorBodyV1Identifier = Identifier
SecurityKeyLogArtifactTimeAnchorBodyV1U64 = U64
Type = SecurityKeyLogArtifactTimeAnchorBodyV1DefinitionsCheckpointAnchorType
