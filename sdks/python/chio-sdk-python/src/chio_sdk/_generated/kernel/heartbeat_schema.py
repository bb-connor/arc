# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: addbe60437bb0258103fb68da7ee1ee5c1d4fade2ca6aab98f2d5ddc89f0b7e1
#
# Manual edits will be overwritten by the next regeneration; the
# M01.P3.T5 spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict


class ChioKernelmessageHeartbeat(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    type: Literal["heartbeat"]
