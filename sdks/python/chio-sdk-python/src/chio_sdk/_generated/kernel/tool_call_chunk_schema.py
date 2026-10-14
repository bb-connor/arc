# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: d2b29cbbc9a0070d3666a33fd5a06bbda07a8e70f6d54bf33c15ca8b74893ff9
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.

from __future__ import annotations
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, conint, constr

class ChioKernelMessageToolCallChunk(BaseModel):
    model_config = ConfigDict(extra='forbid')
    type: Literal['tool_call_chunk']
    id: constr(min_length=1)
    chunk_index: conint(ge=0)
    data: Any

# Public compatibility aliases reference the actual current model classes.
ChioKernelmessageToolCallChunk = ChioKernelMessageToolCallChunk
KernelToolCallChunkChioKernelMessageToolCallChunk = ChioKernelMessageToolCallChunk
