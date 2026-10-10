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

class OpaqueId(RootModel[constr(pattern='^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$', min_length=1, max_length=128)]):
    root: constr(pattern='^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$', min_length=1, max_length=128)

class RecoveryDigestOctet(RootModel[conint(ge=0, le=255)]):
    root: conint(ge=0, le=255) = Field(..., title='Recovery digest octet')

class RecoveryDigest32(RootModel[list[RecoveryDigestOctet]]):
    root: list[RecoveryDigestOctet] = Field(..., max_length=32, min_length=32, title='Recovery digest32')

class RecoveryLabeledCheckpointDefinitionsScope(BaseModel):
    model_config = ConfigDict(extra='forbid')
    authority_domain: OpaqueId
    process_id: OpaqueId
    tenant_id: OpaqueId

class RecoveryLabeledCheckpointDefinitionsArtifactInfluence(BaseModel):
    model_config = ConfigDict(extra='forbid')
    commitment: RecoveryDigest32
    externally_influenced: bool
    unknown: bool

class RecoveryLabeledCheckpointDefinitionsArtifactReference(BaseModel):
    model_config = ConfigDict(extra='forbid')
    artifact: OpaqueId
    provenance: RecoveryDigest32
    scope: RecoveryLabeledCheckpointDefinitionsScope
    version: OpaqueId

class RecoveryLabeledCheckpointDefinitionsModelContext(BaseModel):
    model_config = ConfigDict(extra='forbid')
    account: OpaqueId
    cache: constr(min_length=1, max_length=128)
    context: OpaqueId
    contract: RecoveryDigest32
    conversation: constr(min_length=1, max_length=128)
    provider: OpaqueId
    side_files: list[RecoveryLabeledCheckpointDefinitionsArtifactReference] = Field(..., max_length=8, min_length=0)

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

class LabeledCheckpointV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    artifacts: list[RecoveryLabeledCheckpointDefinitionsArtifactReference] = Field(..., max_length=8, min_length=1)
    checkpoint: OpaqueId
    domain_version: Literal[1]
    influence: RecoveryLabeledCheckpointDefinitionsArtifactInfluence
    isolation_epoch: constr(min_length=1, max_length=128)
    label: information_label_schema.InformationLabel
    lineage: OpaqueId
    model_contexts: list[RecoveryLabeledCheckpointDefinitionsModelContext] = Field(..., max_length=8, min_length=0)
    native_evidence_sequence: conint(ge=1, le=9007199254740991)
    policy: RecoveryDigest32
    revision: conint(ge=1, le=9007199254740991)
    runtime: constr(min_length=1, max_length=128)
    scope: RecoveryLabeledCheckpointDefinitionsScope

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

    @_facet_field_validator('runtime', mode='after')
    @classmethod
    def _require_runtime_utf8_bytes(cls, value: object) -> object:
        from ...recovery_wire import require_utf8_bound as _require_utf8_bound
        if isinstance(value, str):
            _require_utf8_bound(value, 128)
        return value

# Public compatibility aliases reference the actual current model classes.
ArtifactInfluence = RecoveryLabeledCheckpointDefinitionsArtifactInfluence
ArtifactReference = RecoveryLabeledCheckpointDefinitionsArtifactReference
ModelContext = RecoveryLabeledCheckpointDefinitionsModelContext
RecoveryDigest32Item = RecoveryDigestOctet
RecoveryLabeledCheckpointLabeledCheckpointV1 = LabeledCheckpointV1
RecoveryLabeledCheckpointOpaqueId = OpaqueId
RecoveryLabeledCheckpointRecoveryDigest32 = RecoveryDigest32
RecoveryLabeledCheckpointRecoveryDigestOctet = RecoveryDigestOctet
Scope = RecoveryLabeledCheckpointDefinitionsScope
