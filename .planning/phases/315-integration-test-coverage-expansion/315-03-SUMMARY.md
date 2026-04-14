# Summary 315-03

`arc-a2a-adapter`, `arc-mcp-adapter`, and `arc-mcp-edge` now exercise real
protocol exchanges in integration tests instead of only constructing structs.
The phase verifies A2A discovery and send-message JSON-RPC traffic, MCP
adapter mediation through a loopback `ArcMcpEdge`, and direct MCP edge
`initialize` -> `tools/list` -> `tools/call` envelopes.
