# hello-express

Minimal Express example using [`sdks/typescript/packages/express`](../../sdks/typescript/packages/express/).

## What It Demonstrates

- `GET /hello` is allowed and returns a receipt id in the response body
- `POST /echo` is denied without a capability token
- `POST /echo` succeeds with a trust-issued capability token
- parsed JSON bodies remain available downstream after ARC buffering
- the smoke flow persists sidecar receipts and captures request/response artifacts

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
