# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 5b72d08cd719f3366c07810a157d7a31cc1aed2f664fddcf267f1f50a0a5ca0e
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, conint, constr


class ChioToolcallresultCancelled(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    status: Literal["cancelled"]
    reason: constr(min_length=1)
    chunks_received: conint(ge=0)
