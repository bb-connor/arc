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

class Identifier(RootModel[constr(min_length=1, max_length=512)]):
    root: constr(min_length=1, max_length=512)

class Digest(RootModel[constr(pattern='^[0-9a-f]{64}$')]):
    root: constr(pattern='^[0-9a-f]{64}$')

class PublicKey(RootModel[constr(pattern='^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\\+mldsa65)$')]):
    root: constr(pattern='^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\\+mldsa65)$')

class SecurityBrokerCapabilityBodyV1DefinitionsCredentialRef(BaseModel):
    model_config = ConfigDict(extra='forbid')
    provider: Identifier
    credentialId: Identifier
    version: conint(ge=1)

class SecurityBrokerCapabilityBodyV1DefinitionsDestinationScheme(Enum):
    https = 'https'
    http = 'http'

class SecurityBrokerCapabilityBodyV1DefinitionsDestinationMethod(Enum):
    GET = 'GET'
    HEAD = 'HEAD'
    POST = 'POST'
    PUT = 'PUT'
    PATCH = 'PATCH'
    DELETE = 'DELETE'
    OPTIONS = 'OPTIONS'

class SecurityBrokerCapabilityBodyV1DefinitionsDestination(BaseModel):
    model_config = ConfigDict(extra='forbid')
    scheme: SecurityBrokerCapabilityBodyV1DefinitionsDestinationScheme
    normalizedHost: constr(pattern='^[^A-Z\\s/*]+$', min_length=1, max_length=253)
    explicitPort: conint(ge=1, le=65535)
    exactPathAndQuery: constr(pattern='^/[^#\\\\\\u0000-\\u0020\\u007f]*$', min_length=1, max_length=16384)
    method: SecurityBrokerCapabilityBodyV1DefinitionsDestinationMethod

class HeaderName(RootModel[constr(pattern='^[a-z0-9-]+$', min_length=1, max_length=128)]):
    root: constr(pattern='^[a-z0-9-]+$', min_length=1, max_length=128)

class HeaderNames(RootModel[list[HeaderName]]):
    root: list[HeaderName] = Field(..., max_length=64)

class SecurityBrokerCapabilityBodyV1DefinitionsProofBindingMode(Enum):
    public_key = 'public_key'
    loopback_bearer = 'loopback_bearer'

class SecurityBrokerCapabilityBodyV1DefinitionsProofBinding(BaseModel):
    model_config = ConfigDict(extra='forbid')
    mode: SecurityBrokerCapabilityBodyV1DefinitionsProofBindingMode
    callerPublicKey: PublicKey
    nonceTtlSeconds: conint(ge=1, le=300)

class SecurityBrokerCapabilityBodyV1DefinitionsRequestConstraints(BaseModel):
    model_config = ConfigDict(extra='forbid')
    allowedCallerHeaders: HeaderNames
    providerOwnedHeaders: HeaderNames
    maximumBodyBytes: conint(ge=0, le=524288)
    requiredBodySha256: Digest
    requiredPreviewSha256: Digest | None = None
    redirectPolicy: Literal['disabled']
    maximumResponseBytes: conint(ge=1, le=2097152)
    streamingAllowed: bool
    maximumTimeoutMs: conint(ge=1, le=120000)

class ChioBrokerCapabilityBodyV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    schema_: Literal['chio.broker-capability.v1'] = Field(..., alias='schema')
    issuer: PublicKey
    capabilityId: Identifier
    parentCapabilityId: Identifier
    subject: PublicKey
    audience: Identifier
    issuedAtUnixSeconds: conint(ge=0)
    notBeforeUnixSeconds: conint(ge=0)
    expiresAtUnixSeconds: conint(ge=1)
    credential: SecurityBrokerCapabilityBodyV1DefinitionsCredentialRef
    providerAdapterId: Identifier
    providerAdapterVersion: conint(ge=1, le=4294967295)
    destination: SecurityBrokerCapabilityBodyV1DefinitionsDestination
    constraints: SecurityBrokerCapabilityBodyV1DefinitionsRequestConstraints
    brokerQuotaKeyId: Identifier
    maximumExecutions: conint(ge=1, le=4294967295)
    consumption: Literal['capture_before_dispatch']
    revocationId: Identifier
    proof: SecurityBrokerCapabilityBodyV1DefinitionsProofBinding

# Public compatibility aliases reference the actual current model classes.
CredentialRef = SecurityBrokerCapabilityBodyV1DefinitionsCredentialRef
Destination = SecurityBrokerCapabilityBodyV1DefinitionsDestination
Method = SecurityBrokerCapabilityBodyV1DefinitionsDestinationMethod
Mode = SecurityBrokerCapabilityBodyV1DefinitionsProofBindingMode
ProofBinding = SecurityBrokerCapabilityBodyV1DefinitionsProofBinding
RequestConstraints = SecurityBrokerCapabilityBodyV1DefinitionsRequestConstraints
Scheme = SecurityBrokerCapabilityBodyV1DefinitionsDestinationScheme
SecurityBrokerCapabilityBodyV1ChioBrokerCapabilityBodyV1 = ChioBrokerCapabilityBodyV1
SecurityBrokerCapabilityBodyV1Digest = Digest
SecurityBrokerCapabilityBodyV1HeaderName = HeaderName
SecurityBrokerCapabilityBodyV1HeaderNames = HeaderNames
SecurityBrokerCapabilityBodyV1Identifier = Identifier
SecurityBrokerCapabilityBodyV1PublicKey = PublicKey
