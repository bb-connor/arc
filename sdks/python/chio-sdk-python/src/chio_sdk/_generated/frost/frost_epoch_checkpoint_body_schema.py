# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: b6f1812f92935a14019f86d41be473435cc0ec402c6c70767457f18fc119ce8a
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ChioFrostEpochCheckpointV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    activationFence: int
    activeRosterDigest: str
    activeRosterId: str
    anchorId: str
    anchorKeyId: str
    checkpointSequence: int
    clockHighWater: int
    groupPublicKeyDigest: str
    keyEpoch: int
    predecessorDigest: str | None = None
    rotationAuthorizationDigest: str | None = None
    schema_: Literal["chio.frost.epoch-checkpoint.v1"] = Field(..., alias="schema")
    scopeId: str
