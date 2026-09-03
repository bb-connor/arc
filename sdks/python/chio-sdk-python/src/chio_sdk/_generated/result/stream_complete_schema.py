# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 4a7bc0b351ead69443b53d3554b3870bfe3db70714941f8a38c0d0f25511f1d7
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, conint


class ChioToolcallresultStreamComplete(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    status: Literal["stream_complete"]
    total_chunks: conint(ge=0)
