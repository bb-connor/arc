# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 44e2b5d0d537b81c385e782237c4b1d70e1b43804215a266d836346cbbe1448c
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field


class Detail(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    guard: Annotated[str, Field(min_length=1)]
    reason: Annotated[str, Field(min_length=1)]


class ChioToolcallerrorPolicyDenied(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    code: Literal["policy_denied"]
    detail: Detail
