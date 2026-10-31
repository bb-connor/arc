# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: cdaf59925a71448dee294bc7dd11837a988bac5f39ad022834183bd6833707a0
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ChioRuntimeRevocationFreshnessProofSignatureSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    ancestorCapabilityDigest: str | None = None
    epochId: str
    epochRoot: str
    fetchedAt: str
    maxStalenessMs: int
    oracleId: str
    proofId: str
    revokedAncestorResult: bool | None = None
    revokedLeafResult: bool
    schema_: Literal["chio.runtime.revocation-freshness-proof-signature.v1"] = Field(
        ..., alias="schema"
    )
    sequence: int
    subjectCapabilityDigest: str | None = None
