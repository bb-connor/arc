# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: b261c2c851aa63df2638fe74c53b0a52d0dc0dc3799e18c6f4f14d84fc309598
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, conint, constr


class ChioToolcallresultIncomplete(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    status: Literal["incomplete"]
    reason: constr(min_length=1)
    chunks_received: conint(ge=0)
