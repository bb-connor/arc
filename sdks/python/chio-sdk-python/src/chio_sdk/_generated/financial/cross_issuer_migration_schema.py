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


class ChioFinancialCrossIssuerMigrationSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    attesterId: str
    continuityRef: str
    expiresAt: int
    fromIssuer: str
    fromSubject: str
    issuedAt: int
    migrationDigest: str
    migrationId: str
    priorSourcePassportIds: list[str]
    reason: str
    schema_: Literal["chio.financial.cross-issuer-migration.v1"] = Field(
        ..., alias="schema"
    )
    signerKeyEpoch: int
    signerKeyId: str
    toIssuer: str
    toSubject: str
