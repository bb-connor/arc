# JavaScript Peer

This directory now contains the first executable JavaScript peer adapter.

Current shipped slice:

- Streamable HTTP client against a live `pact mcp serve-http` edge
- machine-readable `ScenarioResult` JSON output
- transcript emission for debugging failed runs

Current Wave 1 coverage:

- initialize
- tools/list
- tools/call simple text
- resources/list
- prompts/list

Current Wave 2 and Wave 3 additions:

- remote HTTP task lifecycle scenarios
- remote HTTP auth-family scenarios using local OAuth discovery, auth-code + PKCE, token exchange, and protected-resource challenge handling
- remote HTTP notification and subscription scenarios for wrapped resource updates and catalog `list_changed` delivery

Deferred:

- JS server peer
- stdio peer mode
- broader nested-flow families beyond the current remote HTTP slices
