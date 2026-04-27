# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 47c14e6bc7f276540f7ae14d78b3cfb7b2b67b0a023df6a65298a2fa4d2b38e5
#
# Manual edits will be overwritten by the next regeneration; the
# M01.P3.T5 spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, conint, constr


class ChioKernelmessageToolCallChunk(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    type: Literal["tool_call_chunk"]
    id: constr(min_length=1)
    chunk_index: conint(ge=0)
    data: Any
