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

class RecoverySignedConfinedDisclosureAlgorithm(Enum):
    ed25519 = 'ed25519'
    p256 = 'p256'
    p384 = 'p384'
    hybrid = 'hybrid'

class RecoverySignedConfinedDisclosureDefinitionsArtifactSinkAgent(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['agent']

class RecoverySignedConfinedDisclosureDefinitionsArtifactSinkArchive(BaseModel):
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

class RecoverySignedConfinedDisclosureDefinitionsScope(BaseModel):
    model_config = ConfigDict(extra='forbid')
    authority_domain: OpaqueId
    tenant_id: OpaqueId
    process_id: OpaqueId

class RecoverySignedConfinedDisclosureDefinitionsArtifactInfluence(BaseModel):
    model_config = ConfigDict(extra='forbid')
    commitment: RecoveryDigest32
    externally_influenced: bool
    unknown: bool

class RecoverySignedConfinedDisclosureDefinitionsArtifactReference(BaseModel):
    model_config = ConfigDict(extra='forbid')
    scope: RecoverySignedConfinedDisclosureDefinitionsScope
    artifact: OpaqueId
    version: OpaqueId
    provenance: RecoveryDigest32

class RecoverySignedConfinedDisclosureDefinitionsModelContext(BaseModel):
    model_config = ConfigDict(extra='forbid')
    context: OpaqueId
    provider: OpaqueId
    account: OpaqueId
    conversation: constr(min_length=1, max_length=128)
    cache: constr(min_length=1, max_length=128)
    side_files: list[RecoverySignedConfinedDisclosureDefinitionsArtifactReference] = Field(..., max_length=8, min_length=0)
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

class RecoverySignedConfinedDisclosureDefinitionsArtifactSinkModel(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['model']
    context: RecoverySignedConfinedDisclosureDefinitionsModelContext

class ArtifactSink(RootModel[RecoverySignedConfinedDisclosureDefinitionsArtifactSinkAgent | RecoverySignedConfinedDisclosureDefinitionsArtifactSinkModel | RecoverySignedConfinedDisclosureDefinitionsArtifactSinkArchive]):
    root: RecoverySignedConfinedDisclosureDefinitionsArtifactSinkAgent | RecoverySignedConfinedDisclosureDefinitionsArtifactSinkModel | RecoverySignedConfinedDisclosureDefinitionsArtifactSinkArchive

class RecoverySignedConfinedDisclosureDefinitionsArtifactRecipient(BaseModel):
    model_config = ConfigDict(extra='forbid')
    recipient: OpaqueId
    scope: RecoverySignedConfinedDisclosureDefinitionsScope
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

class SignedConfinedDisclosureV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    body: confined_return_evidence_schema.ConfinedReturnEvidenceV1
    authority_key: constr(pattern='^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\\+mldsa65)$')
    algorithm: RecoverySignedConfinedDisclosureAlgorithm
    signature: constr(pattern='^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+):[0-9a-f]{6618}:(ed25519|p256|p384)\\+mldsa65)$')

# Public compatibility aliases reference the actual current model classes.
Algorithm = RecoverySignedConfinedDisclosureAlgorithm
ArtifactInfluence = RecoverySignedConfinedDisclosureDefinitionsArtifactInfluence
ArtifactRecipient = RecoverySignedConfinedDisclosureDefinitionsArtifactRecipient
ArtifactReference = RecoverySignedConfinedDisclosureDefinitionsArtifactReference
ArtifactSink25 = RecoverySignedConfinedDisclosureDefinitionsArtifactSinkAgent
ArtifactSink26 = RecoverySignedConfinedDisclosureDefinitionsArtifactSinkModel
ArtifactSink27 = RecoverySignedConfinedDisclosureDefinitionsArtifactSinkArchive
ModelContext = RecoverySignedConfinedDisclosureDefinitionsModelContext
RecoveryDigest32Item = RecoveryDigestOctet
RecoverySignedConfinedDisclosureArtifactSink = ArtifactSink
RecoverySignedConfinedDisclosureOpaqueId = OpaqueId
RecoverySignedConfinedDisclosureRecoveryDigest32 = RecoveryDigest32
RecoverySignedConfinedDisclosureRecoveryDigestOctet = RecoveryDigestOctet
RecoverySignedConfinedDisclosureSafeInteger = SafeInteger
RecoverySignedConfinedDisclosureSignedConfinedDisclosureV1 = SignedConfinedDisclosureV1
Scope = RecoverySignedConfinedDisclosureDefinitionsScope
