# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: e7734a10ce3d0e21e8497fad86bfb2a97e79c44ce827e678a869c592687f8837
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel


class Digest(RootModel[str]):
    root: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]


class Identifier(RootModel[str]):
    root: Annotated[str, Field(max_length=512, min_length=1)]


class ChioBrokerExecutionEvidenceV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    attemptId: Identifier
    authorityCommitIndex: Annotated[int, Field(ge=0)]
    budgetCommitIndex: Annotated[int, Field(ge=0)]
    capabilityDigest: Digest
    holdId: Identifier
    invocationId: Identifier
    leaderEpoch: Annotated[int, Field(ge=0)]
    requestDigest: Digest
    responseBodySha256: Digest
    revocationCommitIndex: Annotated[int, Field(ge=0)]
    revocationSetDigest: Digest
    schema_: Annotated[
        Literal["chio.broker-execution-evidence.v1"], Field(alias="schema")
    ]
    upstreamStatus: Annotated[int, Field(ge=100, le=599)]
