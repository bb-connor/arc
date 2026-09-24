# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: c31fc3d855f29edabccd629866ae3f328d7322f74f9c97ed7c5788c1adc8efbe
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict


class ChioKernelmessageHeartbeat(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    type: Literal["heartbeat"]
