# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 389bcf1b0204c491a4db719480c568ace486987ea9871d15adefdc3bb3a365cc
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


class Digest(RootModel[constr(pattern=r"^[0-9a-f]{64}$")]):
    root: constr(pattern=r"^[0-9a-f]{64}$")


class PublicKey(
    RootModel[
        constr(
            pattern=r"^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\+mldsa65)$"
        )
    ]
):
    root: constr(
        pattern=r"^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\+mldsa65)$"
    )


class CredentialRef(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    provider: Identifier
    credentialId: Identifier
    version: conint(ge=1)


class Scheme(Enum):
    https = "https"
    http = "http"


class Method(Enum):
    GET = "GET"
    HEAD = "HEAD"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    OPTIONS = "OPTIONS"


class Destination(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    scheme: Scheme
    normalizedHost: constr(pattern=r"^[^A-Z\s/*]+$", min_length=1, max_length=253)
    explicitPort: conint(ge=1, le=65535)
    exactPathAndQuery: constr(
        pattern=r"^/[^#\\\u0000-\u0020\u007f]*$", min_length=1, max_length=16384
    )
    method: Method


class HeaderName(
    RootModel[constr(pattern=r"^[a-z0-9-]+$", min_length=1, max_length=128)]
):
    root: constr(pattern=r"^[a-z0-9-]+$", min_length=1, max_length=128)


class HeaderNames(RootModel[list[HeaderName]]):
    root: list[HeaderName] = Field(..., max_length=64)


class Mode(Enum):
    public_key = "public_key"
    loopback_bearer = "loopback_bearer"


class ProofBinding(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    mode: Mode
    callerPublicKey: PublicKey
    nonceTtlSeconds: conint(ge=1, le=300)


class RequestConstraints(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    allowedCallerHeaders: HeaderNames
    providerOwnedHeaders: HeaderNames
    maximumBodyBytes: conint(ge=0, le=524288)
    requiredBodySha256: Digest
    requiredPreviewSha256: Digest | None = None
    redirectPolicy: Literal["disabled"]
    maximumResponseBytes: conint(ge=1, le=2097152)
    streamingAllowed: bool
    maximumTimeoutMs: conint(ge=1, le=120000)


class ChioBrokerCapabilityBodyV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.broker-capability.v1"] = Field(..., alias="schema")
    issuer: PublicKey
    capabilityId: Identifier
    parentCapabilityId: Identifier
    subject: PublicKey
    audience: Identifier
    issuedAtUnixSeconds: conint(ge=0)
    notBeforeUnixSeconds: conint(ge=0)
    expiresAtUnixSeconds: conint(ge=1)
    credential: CredentialRef
    providerAdapterId: Identifier
    providerAdapterVersion: conint(ge=1, le=4294967295)
    destination: Destination
    constraints: RequestConstraints
    brokerQuotaKeyId: Identifier
    maximumExecutions: conint(ge=1, le=4294967295)
    consumption: Literal["capture_before_dispatch"]
    revocationId: Identifier
    proof: ProofBinding
