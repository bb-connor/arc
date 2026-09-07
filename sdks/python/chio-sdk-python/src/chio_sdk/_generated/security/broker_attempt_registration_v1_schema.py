# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: c56ebd67862c888dd340e0ba3a14bf38d69abc45d8d02e706ed935cd512054ec
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr


class Identifier(RootModel[constr(min_length=1, max_length=512)]):
    root: constr(min_length=1, max_length=512)


class Digest(RootModel[constr(pattern=r"^[0-9a-f]{64}$")]):
    root: constr(pattern=r"^[0-9a-f]{64}$")


class AttemptIds(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    operationId: Identifier
    attemptId: Identifier
    holdId: Identifier
    authorizeEventId: Identifier
    reverseEventId: Identifier
    captureEventId: Identifier


class Quota(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    keyId: Identifier
    maximumExecutions: conint(ge=1, le=4294967295)


class ChioBrokerAttemptRegistrationV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    ids: AttemptIds
    invocationId: Identifier
    parentCapabilityId: Identifier
    brokerCapabilityId: Identifier
    requestDigest: Digest
    requestCanonicalDigest: Digest
    proofDigest: Digest
    proofKeyId: Identifier
    proofNonce: constr(pattern=r"^[A-Za-z0-9_-]+$", min_length=16, max_length=128)
    nonceExpiresAtUnixSeconds: conint(ge=1)
    quotas: list[Quota] = Field(..., max_length=8, min_length=1)
    authorityMetadataDigest: Digest
    revocationAuthorityDomain: Identifier
