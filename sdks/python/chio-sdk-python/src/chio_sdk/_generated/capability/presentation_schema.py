# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 06789f7cc8fb9ed55f9aba55aadcbf4ec7c60d519627433209cdf916fda34f0d
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
    `chio.capability-presentation.v1`, carried in MCP `_meta.chioCapability`: a leaf capability, its signed ancestors and, when the presenter is not the session holder, the delegation context. The envelope is unsigned; every member inside is verified independently. Decoding is strict.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.capability-presentation.v1"] = Field(..., alias="schema")
    leaf: token_schema.ChioCapabilitytoken
    ancestors: list[token_schema.ChioCapabilitytoken] = Field(
        ...,
        description="Signed ancestors ordered root to parent, at most 16. A root presented alone has an empty list.",
        max_length=16,
    )
    delegation_context: delegation_context_schema.ChioDelegationContext | None = Field(
        None,
        description="Required when the presenter is not the session holder, so the verifier can recompute `context_digest`.",
    )
