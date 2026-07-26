# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 0a3a1765a96b67781f41c28a0d27ad221b6ab37620da7ca89acc92357927dee9
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, RootModel


class Digest(RootModel[str]):
    root: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]


class Identifier(RootModel[str]):
    root: Annotated[str, Field(max_length=512, min_length=1)]


class Quota(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    keyId: Identifier
    maximumExecutions: Annotated[int, Field(ge=1, le=4294967295)]


class AttemptIds(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    attemptId: Identifier
    authorizeEventId: Identifier
    captureEventId: Identifier
    holdId: Identifier
    operationId: Identifier
    reverseEventId: Identifier


class ChioBrokerAttemptRegistrationV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authorityMetadataDigest: Digest
    brokerCapabilityId: Identifier
    ids: AttemptIds
    invocationId: Identifier
    nonceExpiresAtUnixSeconds: Annotated[int, Field(ge=1)]
    parentCapabilityId: Identifier
    proofDigest: Digest
    proofKeyId: Identifier
    proofNonce: Annotated[
        str, Field(max_length=128, min_length=16, pattern="^[A-Za-z0-9_-]+$")
    ]
    quotas: Annotated[list[Quota], Field(max_length=8, min_length=1)]
    requestCanonicalDigest: Digest
    requestDigest: Digest
    revocationAuthorityDomain: Identifier
