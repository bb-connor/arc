# hello-mcp

Minimal MCP example using [`crates/arc-mcp-edge`](../../crates/arc-mcp-edge/).

## What It Demonstrates

- `initialize` and `tools/list` over stdio JSON-RPC
- authoritative `tools/call` execution through the embedded ARC kernel
- a companion bridge call that exposes the underlying ARC receipt id

## Files

```text
README.md
Cargo.toml
src/main.rs
run-edge.sh
smoke.sh
```

## Run

Start the stdio edge:

```bash
./run-edge.sh serve
```

Run the smoke flow:

```bash
./smoke.sh
```
