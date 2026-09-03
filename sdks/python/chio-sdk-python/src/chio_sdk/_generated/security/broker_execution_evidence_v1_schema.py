# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 6a4145266d2febc07a862fffbc565f800ff133c6f0adb06aac524c0ff01e4f34
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr


class Identifier(RootModel[constr(min_length=1, max_length=512)]):
    root: constr(min_length=1, max_length=512)


class Digest(RootModel[constr(pattern=r"^[0-9a-f]{64}$")]):
    root: constr(pattern=r"^[0-9a-f]{64}$")


class ChioBrokerExecutionEvidenceV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.broker-execution-evidence.v1"] = Field(..., alias="schema")
    attemptId: Identifier
    invocationId: Identifier
    holdId: Identifier
    requestDigest: Digest
    capabilityDigest: Digest
    revocationSetDigest: Digest
    budgetCommitIndex: conint(ge=0)
    revocationCommitIndex: conint(ge=0)
    authorityCommitIndex: conint(ge=0)
    leaderEpoch: conint(ge=0)
    upstreamStatus: conint(ge=100, le=599)
    responseBodySha256: Digest
