# chio-mcp-adapter-integration

Distribution integration for Chio's registry-listed MCP server. This crate
extends the `chio-mcp-edge` transport contract with the Streamable HTTP,
OAuth 2.1 + PKCE, and RFC 9728 Protected Resource Metadata surfaces used by
the MCP marketplace listing lane. The crate does not produce or verify Chio
receipts, and its tests run over an in-memory transport, not against AWS.

It is the packaging layer that turns the Chio MCP edge into a deployable,
marketplace-distributable MCP server. The core MCP edge transport itself lives
in `crates/protocol/chio-mcp-edge`.
