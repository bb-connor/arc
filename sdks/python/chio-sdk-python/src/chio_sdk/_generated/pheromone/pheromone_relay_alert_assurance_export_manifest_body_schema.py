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


class Artifact(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    byteCount: int
    path: str
    retentionClass: str
    role: str
    schema_: str = Field(..., alias="schema")
    sha256: str


class ChioPheromoneRelayAlertAssuranceExportManifestV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    artifacts: list[Artifact]
    bundleId: str
    exportedAtUnixMs: int
    exporterId: str
    exporterKeyId: str
    localKernelId: str
    safetyClaims: list[str]
    schema_: Literal["chio.pheromone.relay-alert-assurance-export-manifest.v1"] = Field(
        ..., alias="schema"
    )
    sourcePackageSha256: str
