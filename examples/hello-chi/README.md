# hello-chi

Minimal Go `chi` example using [`chio-go-http`](../../sdks/go/chio-go-http/).

## What It Demonstrates

- `GET /hello` is allowed through Chio middleware
- `POST /echo` is denied without a capability token
- `POST /echo` succeeds with a trust-issued capability token
- receipt ids are visible in response headers
- the smoke flow lists persisted sidecar receipts

## Files

```text
README.md
go.mod
main.go
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
