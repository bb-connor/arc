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

from pydantic import BaseModel, ConfigDict, Field, RootModel


class Id(RootModel[str]):
    root: Annotated[
        str,
        Field(
            description="Request correlation id. Chio adapters originate monotonic integer ids; relayed peer ids may be strings. Null is permitted per JSON-RPC 2.0 but discouraged for new requests because it is indistinguishable from a server-side parse failure response.",
            min_length=1,
        ),
    ]


class ChioJsonRpc20Request(BaseModel):
    """
    JSON-RPC 2.0 request envelope used by Chio for MCP and A2A wire framing. Mirrors the inline serde shape constructed by `send_request` in `crates/protocol/chio-mcp-adapter` and the typed `A2aJsonRpcRequest<T>` in `crates/protocol/chio-a2a-adapter`. The `id` may be an integer, a string, or null; null is permitted on the wire because Chio relays peers that originate ids upstream and forward them verbatim. `params` is optional per JSON-RPC 2.0 (notifications and parameterless calls omit it), but most Chio call sites supply at least an empty object.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    id: Annotated[
        int | Id | None,
        Field(
            description="Request correlation id. Chio adapters originate monotonic integer ids; relayed peer ids may be strings. Null is permitted per JSON-RPC 2.0 but discouraged for new requests because it is indistinguishable from a server-side parse failure response."
        ),
    ] = None
    jsonrpc: Annotated[
        Literal["2.0"],
        Field(description="Protocol version literal. Always the string '2.0'."),
    ]
    method: Annotated[
        str,
        Field(
            description="RPC method name (for example 'tools/call', 'initialize', 'sampling/createMessage').",
            min_length=1,
        ),
    ]
    params: Annotated[
        dict[str, Any] | list | None,
        Field(
            description="Method parameters. JSON-RPC 2.0 allows omission for parameterless methods; structured params are typically an object, occasionally an array."
        ),
    ] = None
