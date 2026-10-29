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


class ChioRuntimeVerifierTrustBundleV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    expiresAtUnixMs: int
    issuedAtUnixMs: int
    keyId: str
    previousHashSha256: str | None = None
    revocationAuthorityRoots: list[str]
    revocationCheckpointSha256: str
    schema_: Literal["chio.runtime.verifier-trust-bundle.v1"] = Field(
        ..., alias="schema"
    )
    trustBundleSha256: str
    verificationContextSha256: str
    verifierId: str
    version: int
