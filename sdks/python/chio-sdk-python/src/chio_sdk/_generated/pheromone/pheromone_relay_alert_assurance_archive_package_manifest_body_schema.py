# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: f98e61fca1094fc6e2763340dae554e56c34e2d18e5720c6f3a7f9b589406726
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Bundle(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    artifactCount: int
    bundleId: str
    bundlePath: str
    exportManifestSha256: str
    exportReportSha256: str
    sourcePackageSha256: str


class Member(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    artifactRole: str
    bundleId: str
    byteCount: int
    kind: str
    path: str
    retentionClass: str
    schema_: str = Field(..., alias="schema")
    sha256: str


class ChioPheromoneRelayAlertAssuranceArchivePackageManifestV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    bundleCount: int
    bundles: list[Bundle]
    compressionFormat: str
    createdAtUnixMs: int
    localKernelId: str
    memberCount: int
    members: list[Member]
    packageGeneration: int
    packageId: str
    packagerId: str
    packagerKeyId: str
    safetyClaims: list[str]
    schema_: Literal[
        "chio.pheromone.relay-alert-assurance-archive-package-manifest.v1"
    ] = Field(..., alias="schema")
    sourceArchiveReportSha256: str
    sourceCloseoutReportSha256: str
    totalByteCount: int
