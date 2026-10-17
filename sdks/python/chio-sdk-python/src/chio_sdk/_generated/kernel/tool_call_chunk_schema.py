# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 474bdbf3f47de4760cd26c431403a6dfec83325e15db307cb5fcbf132a6f05dd
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
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
