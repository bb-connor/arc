# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 7bc9c9d39014b0d2234c7f929e827c2ab02e825f9cb23c608c135695ce3ed4d1
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from ..root_authority import delegation_context_schema
from . import token_schema


class ChioCapabilityPresentation(BaseModel):
    """
    `chio.capability-presentation.v1` (PROTOCOL 5.6.5), carried in MCP `_meta.chioCapability`. The envelope is unsigned; every member inside is verified independently.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.capability-presentation.v1"] = Field(..., alias="schema")
    leaf: token_schema.ChioCapabilitytoken
    ancestors: list[token_schema.ChioCapabilitytoken] = Field(
        ...,
        description="Signed ancestors ordered root to parent. A root presented alone has an empty list.",
    )
    delegation_context: delegation_context_schema.ChioDelegationContext | None = Field(
        None,
        description="Required when the presenter is not the session holder, so the verifier can recompute `context_digest`.",
    )
