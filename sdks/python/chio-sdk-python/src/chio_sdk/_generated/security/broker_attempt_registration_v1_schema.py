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
from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr

class Identifier(RootModel[constr(min_length=1, max_length=512)]):
    root: constr(min_length=1, max_length=512)

class Digest(RootModel[constr(pattern='^[0-9a-f]{64}$')]):
    root: constr(pattern='^[0-9a-f]{64}$')

class SecurityBrokerAttemptRegistrationV1DefinitionsAttemptIds(BaseModel):
    model_config = ConfigDict(extra='forbid')
    operationId: Identifier
    attemptId: Identifier
    holdId: Identifier
    authorizeEventId: Identifier
    reverseEventId: Identifier
    captureEventId: Identifier

class SecurityBrokerAttemptRegistrationV1DefinitionsQuota(BaseModel):
    model_config = ConfigDict(extra='forbid')
    keyId: Identifier
    maximumExecutions: conint(ge=1, le=4294967295)

class ChioBrokerAttemptRegistrationV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    ids: SecurityBrokerAttemptRegistrationV1DefinitionsAttemptIds
    invocationId: Identifier
    parentCapabilityId: Identifier
    brokerCapabilityId: Identifier
    requestDigest: Digest
    requestCanonicalDigest: Digest
    proofDigest: Digest
    proofKeyId: Identifier
    proofNonce: constr(pattern='^[A-Za-z0-9_-]+$', min_length=16, max_length=128)
    nonceExpiresAtUnixSeconds: conint(ge=1)
    quotas: list[SecurityBrokerAttemptRegistrationV1DefinitionsQuota] = Field(..., max_length=8, min_length=1)
    authorityMetadataDigest: Digest
    revocationAuthorityDomain: Identifier

# Public compatibility aliases reference the actual current model classes.
AttemptIds = SecurityBrokerAttemptRegistrationV1DefinitionsAttemptIds
Quota = SecurityBrokerAttemptRegistrationV1DefinitionsQuota
SecurityBrokerAttemptRegistrationV1ChioBrokerAttemptRegistrationV1 = ChioBrokerAttemptRegistrationV1
SecurityBrokerAttemptRegistrationV1Digest = Digest
SecurityBrokerAttemptRegistrationV1Identifier = Identifier
