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
from ..security import information_label_schema
from . import confined_return_evidence_schema
from pydantic import field_validator as _facet_field_validator

class RecoverySignedConfinedEndorsementAlgorithm(Enum):
    ed25519 = 'ed25519'
    p256 = 'p256'
    p384 = 'p384'
    hybrid = 'hybrid'

class RecoverySignedConfinedEndorsementDefinitionsArtifactSinkAgent(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['agent']

class RecoverySignedConfinedEndorsementDefinitionsArtifactSinkArchive(BaseModel):
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

class RecoverySignedConfinedEndorsementDefinitionsScope(BaseModel):
    model_config = ConfigDict(extra='forbid')
    authority_domain: OpaqueId
    tenant_id: OpaqueId
    process_id: OpaqueId

class RecoverySignedConfinedEndorsementDefinitionsArtifactInfluence(BaseModel):
    model_config = ConfigDict(extra='forbid')
    commitment: RecoveryDigest32
    externally_influenced: bool
    unknown: bool

class RecoverySignedConfinedEndorsementDefinitionsArtifactReference(BaseModel):
    model_config = ConfigDict(extra='forbid')
    scope: RecoverySignedConfinedEndorsementDefinitionsScope
    artifact: OpaqueId
    version: OpaqueId
    provenance: RecoveryDigest32

class RecoverySignedConfinedEndorsementDefinitionsModelContext(BaseModel):
    model_config = ConfigDict(extra='forbid')
    context: OpaqueId
    provider: OpaqueId
    account: OpaqueId
    conversation: constr(min_length=1, max_length=128)
    cache: constr(min_length=1, max_length=128)
    side_files: list[RecoverySignedConfinedEndorsementDefinitionsArtifactReference] = Field(..., max_length=8, min_length=0)
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

class RecoverySignedConfinedEndorsementDefinitionsArtifactSinkModel(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['model']
    context: RecoverySignedConfinedEndorsementDefinitionsModelContext

class ArtifactSink(RootModel[RecoverySignedConfinedEndorsementDefinitionsArtifactSinkAgent | RecoverySignedConfinedEndorsementDefinitionsArtifactSinkModel | RecoverySignedConfinedEndorsementDefinitionsArtifactSinkArchive]):
    root: RecoverySignedConfinedEndorsementDefinitionsArtifactSinkAgent | RecoverySignedConfinedEndorsementDefinitionsArtifactSinkModel | RecoverySignedConfinedEndorsementDefinitionsArtifactSinkArchive

class RecoverySignedConfinedEndorsementDefinitionsArtifactRecipient(BaseModel):
    model_config = ConfigDict(extra='forbid')
    recipient: OpaqueId
    scope: RecoverySignedConfinedEndorsementDefinitionsScope
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

class SignedConfinedEndorsementV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    body: confined_return_evidence_schema.ConfinedReturnEvidenceV1
    authority_key: constr(pattern='^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\\+mldsa65)$')
    algorithm: RecoverySignedConfinedEndorsementAlgorithm
    signature: constr(pattern='^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+):[0-9a-f]{6618}:(ed25519|p256|p384)\\+mldsa65)$')

# Public compatibility aliases reference the actual current model classes.
Algorithm = RecoverySignedConfinedEndorsementAlgorithm
ArtifactInfluence = RecoverySignedConfinedEndorsementDefinitionsArtifactInfluence
ArtifactRecipient = RecoverySignedConfinedEndorsementDefinitionsArtifactRecipient
ArtifactReference = RecoverySignedConfinedEndorsementDefinitionsArtifactReference
ArtifactSink28 = RecoverySignedConfinedEndorsementDefinitionsArtifactSinkAgent
ArtifactSink29 = RecoverySignedConfinedEndorsementDefinitionsArtifactSinkModel
ArtifactSink30 = RecoverySignedConfinedEndorsementDefinitionsArtifactSinkArchive
ModelContext = RecoverySignedConfinedEndorsementDefinitionsModelContext
RecoveryDigest32Item = RecoveryDigestOctet
RecoverySignedConfinedEndorsementArtifactSink = ArtifactSink
RecoverySignedConfinedEndorsementOpaqueId = OpaqueId
RecoverySignedConfinedEndorsementRecoveryDigest32 = RecoveryDigest32
RecoverySignedConfinedEndorsementRecoveryDigestOctet = RecoveryDigestOctet
RecoverySignedConfinedEndorsementSafeInteger = SafeInteger
RecoverySignedConfinedEndorsementSignedConfinedEndorsementV1 = SignedConfinedEndorsementV1
Scope = RecoverySignedConfinedEndorsementDefinitionsScope
