# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: cff572cd647726251b5cdb39013d235e07916c80b9a46e5bc035b374e0fd7041
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Boundary(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    automaticTrustAdmission: bool
    explicitTrustActivationRequired: bool
    visibilityOnly: bool


class Compatibility(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    sourceArtifactId: str
    sourceArtifactSha256: str
    sourceSchema: str


class NamespaceOwnership(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    namespace: str
    ownerId: str
    ownerName: str | None = None
    registeredAt: int
    registryUrl: str
    signerPublicKey: str


class Subject(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    actorId: str
    actorKind: str
    displayName: str | None = None
    homepageUrl: str | None = None
    metadataUrl: str | None = None
    resolutionUrl: str | None = None


class ChioRegistryListingSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    boundary: Boundary
    compatibility: Compatibility
    expiresAt: int
    listingId: str
    namespace: str
    namespaceOwnership: NamespaceOwnership
    publishedAt: int
    schema_: Literal["chio.registry.listing.v1"] = Field(..., alias="schema")
    status: str
    subject: Subject
