# `@chio-protocol/sdk`

TypeScript SDK for Chio hosted MCP sessions, receipt queries, and
invariant verification.

This checkout retains workspace version `0.1.0`. That version alone does not
identify the current content-addressed receipt format and trusted-signer
verification changes, or establish six-host acceptance. For integration
qualification, install the explicitly supplied tarball after independently
verifying its SHA-256 against the selected source artifact. A previously
published package with the same version is not interchangeable:

```bash
npm install --save-exact ./chio-protocol-sdk-0.1.0.tgz
```

Use `verifyReceiptWithTrustedSigners` with keys selected by the operator.
Trusting the key returned inside the receipt only establishes self-consistency.
Callers must also bind the verified receipt to their expected caller, tool,
parameters, operation identity, and any claimed output. A policy evaluation
receipt is not proof that an effect was prevented or committed.

## Installation

Use the selected tarball above for this source. Registry installation follows
the separate release qualification and version-selection step.

Requirements: Node.js `>=22`. The package ships as ESM and includes `.d.ts`
types in the published artifact.

## Quickstart

```ts
import { ChioClient, ReceiptQueryClient } from "@chio-protocol/sdk";

const client = ChioClient.withStaticBearer("http://127.0.0.1:8931", "demo-token");
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

- `ChioClient` and `ChioSession` cover Chio hosted MCP HTTP sessions.
- `ReceiptQueryClient` wraps `GET /v1/receipts/query`.
- `signDpopProof` signs DPoP proofs for governed invocations.
- `signAuthorityDpopProof` signs the explicit v2 durable proof domain, including
  its independently configured destination, generation and freshness policy.
  Legacy v1 verifiers reject this profile. Signing is not proof of activation,
  a replay reservation or permission to execute.
- `@chio-protocol/sdk/invariants` exposes canonical JSON, hashing, signing,
  receipt, capability, and manifest helpers.

The full public reference lives in [docs/reference/SDK_TYPESCRIPT_REFERENCE.md](../../../docs/reference/SDK_TYPESCRIPT_REFERENCE.md).

## Official Example

The package-local governed example expects a running Chio hosted edge and trust
service:

```bash
CHIO_BASE_URL=http://127.0.0.1:8931 \
CHIO_CONTROL_URL=http://127.0.0.1:8940 \
CHIO_AUTH_TOKEN=demo-token \
CHIO_ADMIN_TOKEN=demo-admin-token \
CHIO_CONTROL_TOKEN=demo-control-token \
node --experimental-strip-types sdks/typescript/chio-ts/examples/governed_hello.ts
```

For a repo-local end-to-end verification run that boots those services
automatically, use:

```bash
./scripts/check-sdk-publication-examples.sh
```

## Canonical Example Links

- `../../../docs/guides/WEB_BACKEND_QUICKSTART.md`
- `../../../examples/hello-openapi-sidecar/README.md`
- `../../../examples/hello-fastapi/README.md`

## Release Checks

```bash
npm --prefix sdks/typescript/chio-ts test
./scripts/check-chio-ts-release.sh
```
