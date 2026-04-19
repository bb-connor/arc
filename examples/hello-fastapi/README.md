# hello-fastapi

Minimal FastAPI example using the shipped Python HTTP surfaces:

- [`arc-asgi`](../../sdks/python/arc-asgi/) for request interception
- [`arc-fastapi`](../../sdks/python/arc-fastapi/) for FastAPI-native receipt access

This is the recommended second web-backend example. Do
[`hello-openapi-sidecar/`](../hello-openapi-sidecar/README.md) first, then use
this example when you want framework-native Python integration on top of the
same local sidecar model.

## What It Demonstrates

- `GET /hello` is allowed and returns a receipt header
- `POST /echo` is denied without a capability token
- `POST /echo` succeeds with a trust-issued capability token and a receipt header
- the app talks to a real local ARC sidecar over `/arc/evaluate`
- the smoke flow lists persisted receipts from the sidecar SQLite store

## Files

```text
README.md
pyproject.toml
app.py
openapi.yaml
policy.yaml
run.sh
smoke.sh
```

## Run

Start the app only:

```bash
./run.sh
```

Run the full end-to-end smoke flow:

```bash
./smoke.sh
```

Keep the same verification contract as the sidecar-first path: safe route
allows, governed route denies without a capability, governed route allows with
a capability, and the smoke flow lists persisted receipts.

Like `hello-openapi-sidecar`, this is a direct HTTP app example rather than an
MCP hosted-session example. It does not exercise `initialize`,
`notifications/initialized`, or `GET /mcp` replay semantics.
