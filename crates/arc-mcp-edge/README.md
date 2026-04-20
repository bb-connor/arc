# arc-mcp-edge

`arc-mcp-edge` exposes ARC-governed tools over MCP transports and holds the
shared protocol/runtime contracts used by ARC's MCP-facing surfaces.

Use this crate when you need to present an ARC-governed runtime as an MCP
server instead of wrapping an existing MCP server with `arc-mcp-adapter`.
