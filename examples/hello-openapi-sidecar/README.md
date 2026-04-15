# hello-openapi-sidecar

Minimal spec-driven HTTP example using `arc api protect` directly in front of a plain upstream app.

The upstream app has no ARC framework SDK or middleware. All governance, deny behavior, and receipt capture happen in the OpenAPI sidecar.

## What It Demonstrates

- `GET /hello` is allowed through the sidecar and returns an ARC receipt header
- `POST /echo` is denied by the sidecar without a capability token
- `POST /echo` succeeds with a trust-issued capability token
- the app itself is a plain Python HTTP server with no ARC coupling
- the smoke flow lists persisted sidecar receipts from SQLite

## Files

```text
README.md
app.py
openapi.yaml
run.sh
smoke.sh
```

## Run

Start the upstream app only:

```bash
./run.sh
```

Run the full trust + sidecar smoke flow:

```bash
./smoke.sh
```
