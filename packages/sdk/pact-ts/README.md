# `@pact-protocol/sdk`

Production-candidate TypeScript SDK for the current PACT hosted-edge and
invariant surface.

Current scope:

- pure TypeScript invariant helpers
- published package-backed remote-edge SDK for the current conformance waves
- low-level TypeScript transport and session helpers
- root-level `PactClient` and `PactSession` APIs
- stable package-level invariant error codes
- shared vector-fixture verification against `tests/bindings/vectors`
- no native addons
- no stable high-level ergonomic SDK client yet

Current release posture:

- package name: `@pact-protocol/sdk`
- release-qualified for clean build, pack, and consumer-install smoke tests
- aligned to the `v2.3` production-candidate contract in `spec/PROTOCOL.md`
- still intentionally narrow and Node-first rather than a broad browser SDK

Current invariant coverage:

- canonical JSON
- SHA-256 helpers
- Ed25519 signing and verification over UTF-8 and canonical JSON
- receipt verification
- capability verification
- signed manifest verification

Current transport coverage:

- JSON-RPC response parsing for plain JSON and `text/event-stream`
- request header helpers for bearer auth, session id, and protocol version
- low-level `postRpc`, `postNotification`, `initializeSession`, and `deleteSession`
- root-package reuse by the JS conformance peer across live Waves 1 through 5

Current root API coverage:

- `PactClient.withStaticBearer(...).initialize()`
- `PactSession` request and notification primitives
- convenience methods for tools, resources, prompts, completion, logging, and tasks
- conformance-backed coverage for initialize/session, tools/resources/prompts, notifications, tasks, auth, and nested callbacks

Current limitations:

- no first-class OAuth helper surface yet
- no browser-target packaging work yet
- nested callback ergonomics are still low-level and conformance-driven
- browser-target packaging remains intentionally narrow and Node-first

Minimal example:

```ts
import { PactClient } from "@pact/sdk";

const client = PactClient.withStaticBearer("http://127.0.0.1:8080/mcp", "token");
const session = await client.initialize();
const tools = await session.listTools();

console.log(tools);
await session.close();
```

Run the current checks with:

```sh
npm --prefix packages/sdk/pact-ts test
```

Run the release-artifact qualification with:

```sh
./scripts/check-pact-ts-release.sh
```
