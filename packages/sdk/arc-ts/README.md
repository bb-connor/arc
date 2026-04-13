# `@arc-protocol/sdk`

Stable TypeScript SDK for ARC hosted MCP sessions, receipt queries, and
invariant verification.

## Installation

```bash
npm install @arc-protocol/sdk
```

Requirements: Node.js `>=22`. The package ships as ESM and includes `.d.ts`
types in the published artifact.

## Quickstart

```ts
import { ArcClient, ReceiptQueryClient } from "@arc-protocol/sdk";

const client = ArcClient.withStaticBearer("http://127.0.0.1:8931", "demo-token");
const session = await client.initialize();

try {
  const tools = await session.listTools();
  console.log(tools);

  const receipts = await new ReceiptQueryClient(
    "http://127.0.0.1:8940",
    "demo-token",
  ).query({ toolServer: "wrapped-http-mock", limit: 5 });
  console.log(receipts.totalCount);
} finally {
  await session.close();
}
```

## API Reference

- `ArcClient` and `ArcSession` cover ARC hosted MCP HTTP sessions.
- `ReceiptQueryClient` wraps `GET /v1/receipts/query`.
- `signDpopProof` signs DPoP proofs for governed invocations.
- `@arc-protocol/sdk/invariants` exposes canonical JSON, hashing, signing,
  receipt, capability, and manifest helpers.

The full public reference lives in [docs/SDK_TYPESCRIPT_REFERENCE.md](../../../docs/SDK_TYPESCRIPT_REFERENCE.md).

## Official Example

The package-local governed example expects a running ARC hosted edge and trust
service:

```bash
ARC_BASE_URL=http://127.0.0.1:8931 \
ARC_CONTROL_URL=http://127.0.0.1:8940 \
ARC_AUTH_TOKEN=demo-token \
node --experimental-strip-types packages/sdk/arc-ts/examples/governed_hello.ts
```

For a repo-local end-to-end verification run that boots those services
automatically, use:

```bash
./scripts/check-sdk-publication-examples.sh
```

## Release Checks

```bash
npm --prefix packages/sdk/arc-ts test
./scripts/check-arc-ts-release.sh
```
