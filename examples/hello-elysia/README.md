# hello-elysia

Minimal Elysia example using [`sdks/typescript/packages/elysia`](../../sdks/typescript/packages/elysia/).

## What It Demonstrates

- `GET /hello` is allowed and emits a receipt header
- `POST /echo` is denied without a capability token
- `POST /echo` succeeds with a trust-issued capability token
- the Elysia plugin stays truthful to its header-first receipt contract

## Files

```text
README.md
package.json
server.mjs
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
