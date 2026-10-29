# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 7c51d7910f0345879134e0bf5bbb042abd7b8dbfdcd23700753b77f6814a0f36
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from . import observation_schema


class Expected(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    effect_count: observation_schema.SafeInteger
    consumed_authority: observation_schema.SafeInteger
    remaining_budget: observation_schema.SafeInteger
    knowledge_digest: observation_schema.RecoveryDigest32
    native_admission_digest: observation_schema.RecoveryDigest32
    process_request_digest: observation_schema.RecoveryDigest32


class Frame(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    observation: observation_schema.RecoveryObservationV1
    expected: Expected


class RecoveryTrajectoryV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.recovery.trajectory.v1"] = Field(..., alias="schema")
    version: Literal[1]
    source_digest: observation_schema.RecoveryDigest32
    contract_digest: observation_schema.RecoveryDigest32
    policy_digest: observation_schema.RecoveryDigest32
    profile_digest: observation_schema.RecoveryDigest32
    deterministic_time: observation_schema.SafeInteger
    frames: list[Frame] = Field(..., max_length=32, min_length=1)
