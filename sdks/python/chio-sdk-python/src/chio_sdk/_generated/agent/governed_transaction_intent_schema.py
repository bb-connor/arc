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

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from . import active_response_governed_intent_schema


class Body(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["tool_invocation"]


class Body4(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["active_response_plan"]
    value: active_response_governed_intent_schema.ChioGovernedActiveResponseIntentBody


class MaxAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: Annotated[str, Field(min_length=1)]
    units: Annotated[int, Field(ge=0)]


class ChioGovernedTransactionIntent(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    autonomy: dict[str, Any] | None = None
    body: Body | Body4 | None = None
    call_chain: dict[str, Any] | None = None
    commerce: dict[str, Any] | None = None
    context: Any | None = None
    id: Annotated[str, Field(min_length=1)]
    max_amount: MaxAmount | None = None
    metered_billing: dict[str, Any] | None = None
    purpose: str
    runtime_attestation: dict[str, Any] | None = None
    server_id: Annotated[str, Field(min_length=1)]
    tool_name: Annotated[str, Field(min_length=1)]
