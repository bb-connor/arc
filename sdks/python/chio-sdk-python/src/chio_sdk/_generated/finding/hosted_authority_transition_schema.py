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


class ChioFindingHostedAuthorityTransitionSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    configurationRevision: str
    createdAt: int
    fromAuthority: str
    fromEpoch: int
    operation: str
    rollbackWindowEndsAt: int | None = None
    schema_: Literal["chio.finding.hosted-authority-transition.v1"] = Field(
        ..., alias="schema"
    )
    sourceCheckpointSha256: str
    targetCheckpointSha256: str
    tenantId: str
    throughSequence: int
    toAuthority: str
    toEpoch: int
