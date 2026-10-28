# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 9040b11ea385ff84e98e4063d81426678eceeb5a4d55e2f86191e7f0064502af
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ChioRuntimeSandboxAttestationSignatureSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    attestationId: str
    attester: str
    egressPolicyDigest: str
    expiresAt: str
    sandboxProfileDigest: str
    schema_: Literal["chio.runtime.sandbox-attestation-signature.v1"] = Field(
        ..., alias="schema"
    )
    startedAt: str
    toolInstanceId: str
    toolManifestDigest: str
    toolServerId: str
