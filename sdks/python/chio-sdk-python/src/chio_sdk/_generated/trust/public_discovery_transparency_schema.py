# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: b55a701e44e8cab56a79619656a773cbb3b9fd63c65594e997f7efc988bc178c
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Entry(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    discoveryId: str
    documentSha256: str
    expiresAt: int
    kind: str
    metadataUrl: str
    publishedAt: int


class ImportGuardrails(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    informationalOnly: bool
    requiresExplicitPolicyImport: bool
    requiresManualReview: bool


class ChioPublicDiscoveryTransparencySignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    entries: list[Entry]
    expiresAt: int
    importGuardrails: ImportGuardrails
    publishedAt: int
    publisher: str
    schema_: Literal["chio.public-discovery-transparency.v1"] = Field(
        ..., alias="schema"
    )
    signerPublicKey: str
    transparencyId: str
    version: int
