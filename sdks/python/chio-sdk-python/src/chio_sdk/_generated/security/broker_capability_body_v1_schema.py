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

from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel


class Method(Enum):
    GET = "GET"
    HEAD = "HEAD"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    OPTIONS = "OPTIONS"


class Scheme(Enum):
    https = "https"
    http = "http"


class Destination(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    exactPathAndQuery: Annotated[
        str,
        Field(
            max_length=16384, min_length=1, pattern="^/[^#\\\\\\u0000-\\u0020\\u007f]*$"
        ),
    ]
    explicitPort: Annotated[int, Field(ge=1, le=65535)]
    method: Method
    normalizedHost: Annotated[
        str, Field(max_length=253, min_length=1, pattern="^[^A-Z\\s/*]+$")
    ]
    scheme: Scheme


class Digest(RootModel[str]):
    root: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]


class HeaderName(RootModel[str]):
    root: Annotated[str, Field(max_length=128, min_length=1, pattern="^[a-z0-9-]+$")]


class HeaderNames(RootModel[list[HeaderName]]):
    root: Annotated[list[HeaderName], Field(max_length=64)]


class Identifier(RootModel[str]):
    root: Annotated[str, Field(max_length=512, min_length=1)]


class Mode(Enum):
    public_key = "public_key"
    loopback_bearer = "loopback_bearer"


class PublicKey(RootModel[str]):
    root: Annotated[
        str,
        Field(
            pattern="^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\\+mldsa65)$"
        ),
    ]


class RequestConstraints(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    allowedCallerHeaders: HeaderNames
    maximumBodyBytes: Annotated[int, Field(ge=0, le=524288)]
    maximumResponseBytes: Annotated[int, Field(ge=1, le=2097152)]
    maximumTimeoutMs: Annotated[int, Field(ge=1, le=120000)]
    providerOwnedHeaders: HeaderNames
    redirectPolicy: Literal["disabled"]
    requiredBodySha256: Digest
    requiredPreviewSha256: Digest | None = None
    streamingAllowed: bool


class CredentialRef(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    credentialId: Identifier
    provider: Identifier
    version: Annotated[int, Field(ge=1)]


class ProofBinding(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    callerPublicKey: PublicKey
    mode: Mode
    nonceTtlSeconds: Annotated[int, Field(ge=1, le=300)]


class ChioBrokerCapabilityBodyV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    audience: Identifier
    brokerQuotaKeyId: Identifier
    capabilityId: Identifier
    constraints: RequestConstraints
    consumption: Literal["capture_before_dispatch"]
    credential: CredentialRef
    destination: Destination
    expiresAtUnixSeconds: Annotated[int, Field(ge=1)]
    issuedAtUnixSeconds: Annotated[int, Field(ge=0)]
    issuer: PublicKey
    maximumExecutions: Annotated[int, Field(ge=1, le=4294967295)]
    notBeforeUnixSeconds: Annotated[int, Field(ge=0)]
    parentCapabilityId: Identifier
    proof: ProofBinding
    providerAdapterId: Identifier
    providerAdapterVersion: Annotated[int, Field(ge=1, le=4294967295)]
    revocationId: Identifier
    schema_: Annotated[Literal["chio.broker-capability.v1"], Field(alias="schema")]
    subject: PublicKey
