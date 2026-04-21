# hello-acp

Minimal ACP example using [`crates/chio-acp-edge`](../../crates/chio-acp-edge/).

## What It Demonstrates

- `session/list_capabilities`
- authoritative `tool/invoke`
- deferred `tool/stream` followed by `tool/resume`
- receipt-bearing metadata on terminal results

## Files

```text
README.md
Cargo.toml
src/main.rs
run-edge.sh
smoke.sh
```

## Run

Start the line-based JSON-RPC edge:

```bash
./run-edge.sh serve
```

Run the smoke flow:

```bash
./smoke.sh
```
