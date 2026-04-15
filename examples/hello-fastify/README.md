# hello-fastify

Minimal Fastify example using [`@arc-protocol/fastify`](../../sdks/typescript/packages/fastify/).

## What It Demonstrates

- `GET /hello` is allowed and returns the attached ARC receipt id
- `POST /echo` is denied without a capability token
- `POST /echo` succeeds with a trust-issued capability token
- Fastify request bodies remain available after ARC interception
- the smoke flow lists persisted sidecar receipts

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
