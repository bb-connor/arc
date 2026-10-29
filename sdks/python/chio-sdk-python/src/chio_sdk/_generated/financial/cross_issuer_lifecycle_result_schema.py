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


class SourceIndexLeaf(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    resultDigest: str
    sourcePassportId: str


class SourceIndexProof(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    audit_path: list[str]
    leaf_index: int
    tree_size: int


class ChioFinancialCrossIssuerLifecycleResultSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    effectiveAt: int
    issuerDid: str
    resolverIdentity: str
    resultDigest: str
    schema_: Literal["chio.financial.cross-issuer.lifecycle-result.v1"] = Field(
        ..., alias="schema"
    )
    signerKeyEpoch: int
    signerKeyId: str
    sourceIndexLeaf: SourceIndexLeaf
    sourceIndexProof: SourceIndexProof
    sourceManifestDigest: str
    sourcePassportId: str
    status: str
    statusVersion: int
    storeGeneration: int
    trustedClockHighWater: int
