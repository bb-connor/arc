# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 35f8e30cf30553986a159b074ee485804a85db29547a8102522cd7bfa3080d2e
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.

from __future__ import annotations
from typing import Literal
from pydantic import field_validator
from pydantic import BaseModel, ConfigDict, Field
from . import observation_schema

class RecoveryTrajectoryFramesItemsExpected(BaseModel):
    model_config = ConfigDict(extra='forbid')
    effect_count: observation_schema.SafeInteger
    consumed_authority: observation_schema.SafeInteger
    remaining_budget: observation_schema.SafeInteger
    knowledge_digest: observation_schema.RecoveryDigest32
    native_admission_digest: observation_schema.RecoveryDigest32
    process_request_digest: observation_schema.RecoveryDigest32

class RecoveryTrajectoryFramesItems(BaseModel):
    model_config = ConfigDict(extra='forbid')
    observation: observation_schema.RecoveryObservationV1
    expected: RecoveryTrajectoryFramesItemsExpected

class RecoveryTrajectoryV1(BaseModel):
    model_config = ConfigDict(extra='forbid')
    schema_: Literal['chio.recovery.trajectory.v1'] = Field(..., alias='schema')
    version: Literal[1]
    source_digest: observation_schema.RecoveryDigest32
    contract_digest: observation_schema.RecoveryDigest32
    policy_digest: observation_schema.RecoveryDigest32
    profile_digest: observation_schema.RecoveryDigest32
    deterministic_time: observation_schema.SafeInteger
    frames: list[RecoveryTrajectoryFramesItems] = Field(..., max_length=32, min_length=1)

    @field_validator('version', mode='before')
    @classmethod
    def _require_integer_literal_kind(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError('recovery integer literal requires an integer')
        return value

# Public compatibility aliases reference the actual current model classes.
Expected = RecoveryTrajectoryFramesItemsExpected
Frame = RecoveryTrajectoryFramesItems
