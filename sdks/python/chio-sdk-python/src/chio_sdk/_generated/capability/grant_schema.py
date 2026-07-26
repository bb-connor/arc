# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 12f29b53e7b2b0f290d2f6e643bb969068e1777bf31ecf770aa23307b31bec09
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, RootModel


class Constraint(BaseModel):
    """
    Tagged enum mirroring `Constraint`. Encoded as `{ type, value }` (or `{ type }` for unit variants like `governed_intent_required`). The variant set is intentionally extensible per ADR-TYPE-EVOLUTION; this schema validates the discriminator only and lets downstream guards interpret the `value`.
    """

    type: Annotated[str, Field(min_length=1)]
    value: Any | None = None


class MonetaryAmount(BaseModel):
    """
    A monetary amount in the currency's smallest minor unit (e.g. cents for USD). Mirrors `MonetaryAmount`.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    currency: Annotated[str, Field(min_length=1)]
    units: Annotated[int, Field(ge=0)]


class Operation(Enum):
    invoke = "invoke"
    read_result = "read_result"
    read = "read"
    subscribe = "subscribe"
    get = "get"
    delegate = "delegate"


class PromptGrant(BaseModel):
    """
    Authorization for retrieving a prompt by name. Mirrors `PromptGrant`.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    operations: Annotated[list[Operation], Field(min_length=1)]
    prompt_name: Annotated[str, Field(min_length=1)]


class ResourceGrant(BaseModel):
    """
    Authorization for reading or subscribing to a resource. Mirrors `ResourceGrant`.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    operations: Annotated[list[Operation], Field(min_length=1)]
    uri_pattern: Annotated[str, Field(min_length=1)]


class ToolGrant(BaseModel):
    """
    Authorization to invoke a single tool. Mirrors `ToolGrant`.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    constraints: list[Constraint] | None = None
    dpop_required: Annotated[
        bool | None,
        Field(
            description="If true, the kernel requires a valid DPoP proof for every invocation under this grant."
        ),
    ] = None
    max_cost_per_invocation: MonetaryAmount | None = None
    max_invocations: Annotated[int | None, Field(ge=0)] = None
    max_total_cost: MonetaryAmount | None = None
    operations: Annotated[list[Operation], Field(min_length=1)]
    server_id: Annotated[
        str,
        Field(
            description="Tool server identifier from the manifest. Use `*` to match any server (only valid in parent grants for delegation).",
            min_length=1,
        ),
    ]
    tool_name: Annotated[
        str,
        Field(
            description="Tool name on the server. Use `*` to match any tool (only valid in parent grants for delegation).",
            min_length=1,
        ),
    ]


class ChioCapabilityGrant(RootModel[ToolGrant | ResourceGrant | PromptGrant]):
    root: Annotated[
        ToolGrant | ResourceGrant | PromptGrant,
        Field(
            description="A single grant carried inside a capability token's `scope`. Chio uses three distinct grant kinds (tool, resource, prompt) that share no common discriminator field; this schema accepts any one of them via `oneOf`. Mirrors `ToolGrant`, `ResourceGrant`, and `PromptGrant` in `crates/core/chio-core-types/src/capability/scope.rs`. The wrapper `ChioScope` partitions grants into three named arrays (`grants`, `resource_grants`, `prompt_grants`); validators that consume a token can dispatch to the appropriate `$defs/*` shape directly without relying on `oneOf` matching.",
            title="Chio Capability Grant",
        ),
    ]
