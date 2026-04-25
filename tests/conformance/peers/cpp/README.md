# Chio C++ Conformance Peer

This peer exercises the hosted MCP surface through `packages/sdk/chio-cpp` and a
small command-backed curl transport used only by the peer. It currently covers
the package-backed C++ surface: session initialization, tools, resources,
prompts, task request helpers, and catalog notification forwarding. OAuth
discovery, streaming subscriptions, and nested callbacks are reported as
unsupported until the C++ SDK grows those flows.

Build:

```bash
cmake -S tests/conformance/peers/cpp -B target/chio-cpp-peer
cmake --build target/chio-cpp-peer
```

Run against a live Chio MCP edge:

```bash
target/chio-cpp-peer/chio_cpp_conformance_peer \
  --base-url http://127.0.0.1:8080 \
  --auth-token conformance-token \
  --scenarios-dir tests/conformance/scenarios/mcp_core \
  --results-output tests/conformance/results/generated/cpp-remote-http.json \
  --artifacts-dir tests/conformance/results/generated/artifacts/cpp
```

The peer writes Chio conformance JSON using `peer: "cpp"` so the shared report
generator can ingest it.
