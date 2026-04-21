# hello-a2a

Minimal A2A example using [`crates/chio-a2a-edge`](../../crates/chio-a2a-edge/).

## What It Demonstrates

- discovery through the generated agent card
- authoritative `message/send`
- deferred `message/stream` followed by `task/get`
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

Print the agent card:

```bash
./run-edge.sh agent-card
```

Start the line-based JSON-RPC edge:

```bash
./run-edge.sh serve
```

Run the smoke flow:

```bash
./smoke.sh
```
