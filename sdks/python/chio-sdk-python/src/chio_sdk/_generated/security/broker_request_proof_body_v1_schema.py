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
from . import broker_capability_body_v1_schema

class Identifier(RootModel[constr(min_length=1, max_length=512)]):
    root: constr(min_length=1, max_length=512)

class Digest(RootModel[constr(pattern='^[0-9a-f]{64}$')]):
    root: constr(pattern='^[0-9a-f]{64}$')

class PublicKey(RootModel[constr(pattern='^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\\+mldsa65)$')]):
    root: constr(pattern='^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\\+mldsa65)$')

class ChioBrokerRequestProofBodyV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    schema_: Literal['chio.broker-request-proof.v1'] = Field(..., alias='schema')
    brokerCapabilityId: Identifier
    parentCapabilityId: Identifier
    credential: broker_capability_body_v1_schema.SecurityBrokerCapabilityBodyV1DefinitionsCredentialRef
    capabilityExpiresAtUnixSeconds: conint(ge=1)
    destination: broker_capability_body_v1_schema.SecurityBrokerCapabilityBodyV1DefinitionsDestination
    bodySha256: Digest
    callerHeadersSha256: Digest
    callerOptionsSha256: Digest
    nonce: constr(pattern='^[A-Za-z0-9_-]+$', min_length=16, max_length=128)
    issuedAtUnixSeconds: conint(ge=0)
    authorityKey: PublicKey

# Public compatibility aliases reference the actual current model classes.
SecurityBrokerRequestProofBodyV1ChioBrokerRequestProofBodyV1 = ChioBrokerRequestProofBodyV1
SecurityBrokerRequestProofBodyV1Digest = Digest
SecurityBrokerRequestProofBodyV1Identifier = Identifier
SecurityBrokerRequestProofBodyV1PublicKey = PublicKey
