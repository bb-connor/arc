# hello-fastapi

Minimal FastAPI example using the shipped Python HTTP surfaces:

- [`arc-asgi`](../../sdks/python/arc-asgi/) for request interception
- [`arc-fastapi`](../../sdks/python/arc-fastapi/) for FastAPI-native receipt access

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
