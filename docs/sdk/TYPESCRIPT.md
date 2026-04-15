# ARC TypeScript SDK Reference

This document covers all five ARC TypeScript packages. Each package communicates with the ARC Rust kernel via a localhost HTTP sidecar. All packages are ESM-first and work with Node.js 18+ and Bun.

## Quick Start

```bash
# Core HTTP substrate (required by framework packages)
npm install @arc-protocol/node-http

# Pick your framework integration
npm install @arc-protocol/express    # Express.js
npm install @arc-protocol/fastify    # Fastify
npm install @arc-protocol/elysia     # Elysia (Bun)

# Testing and conformance utilities
npm install @arc-protocol/conformance --save-dev
```

Minimal Express example:

```ts
import express from "express";
import { arc } from "@arc-protocol/express";

const app = express();
app.use(arc({ config: "arc.yaml" }));
app.use(express.json());

app.get("/pets", (_req, res) => {
  res.json([{ name: "Fido" }]);
});

app.listen(3000);
```

## Sidecar Communication Model

All ARC TypeScript SDKs communicate with the ARC Rust kernel through localhost HTTP. The kernel runs as a sidecar process alongside your application.

- **Default URL**: `http://127.0.0.1:9090`
- **Configurable via**: `ARC_SIDECAR_URL` environment variable or the `sidecarUrl` config option
- **No native compilation or FFI**: pure TypeScript/JavaScript over HTTP (uses `fetch`)
- **Fail-closed by default**: when the sidecar is unreachable, requests receive a 502 response. Set `onSidecarError: "allow"` to forward the request without synthesizing an ARC receipt.

---

## 1. @arc-protocol/node-http

The core HTTP substrate. Provides types, identity extraction, the sidecar client, and request interceptors. All framework packages depend on this.

### Installation

```bash
npm install @arc-protocol/node-http
```

### Types

All types mirror the Rust `arc-http-core` crate.

**HttpMethod**

```ts
type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS";

isMethodSafe(method: HttpMethod): boolean  // true for GET, HEAD, OPTIONS
```

**AuthMethod** (tagged union)

```ts
type AuthMethod =
  | { method: "bearer"; token_hash: string }
  | { method: "api_key"; key_name: string; key_hash: string }
  | { method: "cookie"; cookie_name: string; cookie_hash: string }
  | { method: "mtls_certificate"; subject_dn: string; fingerprint: string }
  | { method: "anonymous" };
```

**CallerIdentity**

```ts
interface CallerIdentity {
  subject: string;
  auth_method: AuthMethod;
  verified: boolean;
  tenant?: string;
  agent_id?: string;
}
```

**Verdict** (tagged union)

```ts
type Verdict =
  | { verdict: "allow" }
  | { verdict: "deny"; reason: string; guard: string; http_status: number }
  | { verdict: "cancel"; reason: string }
  | { verdict: "incomplete"; reason: string };

isAllowed(verdict: Verdict): boolean
isDenied(verdict: Verdict): boolean
```

**HttpReceipt**

```ts
interface HttpReceipt {
  id: string;
  request_id: string;
  route_pattern: string;
  method: HttpMethod;
  caller_identity_hash: string;
  session_id?: string;
  verdict: Verdict;
  evidence: GuardEvidence[];
  response_status: number; // ARC evaluation-time HTTP status, not guaranteed downstream response evidence for allow-path receipts
  timestamp: number;
  content_hash: string;
  policy_hash: string;
  capability_id?: string;
  metadata?: unknown;
  kernel_key: string;
  signature: string;
}
```

**GuardEvidence**

```ts
interface GuardEvidence {
  guard_name: string;
  verdict: boolean;
  details?: string;
}
```

**ArcHttpRequest** (sent to sidecar for evaluation)

```ts
interface ArcHttpRequest {
  request_id: string;
  method: HttpMethod;
  route_pattern: string;
  path: string;
  query: Record<string, string>;
  headers: Record<string, string>;
  caller: CallerIdentity;
  body_hash?: string;
  body_length: number;
  session_id?: string;
  capability_id?: string;
  timestamp: number;
}
```

**EvaluateResponse**

```ts
interface EvaluateResponse {
  verdict: Verdict;
  receipt: HttpReceipt;
  evidence: GuardEvidence[];
}
```

**ArcConfig**

```ts
interface ArcConfig {
  sidecarUrl?: string;             // Default: ARC_SIDECAR_URL env or "http://127.0.0.1:9090"
  config?: string;                 // Path to arc.yaml config file
  identityExtractor?: IdentityExtractor;
  routePatternResolver?: RoutePatternResolver;
  onSidecarError?: "deny" | "allow";  // Default: "deny" (fail-closed)
  timeoutMs?: number;              // Default: 5000
  forwardHeaders?: string[];       // Default: ["content-type", "content-length"]
}
```

**Error codes**

```ts
const ARC_ERROR_CODES = {
  ACCESS_DENIED: "arc_access_denied",
  SIDECAR_UNREACHABLE: "arc_sidecar_unreachable",
  EVALUATION_FAILED: "arc_evaluation_failed",
  INVALID_RECEIPT: "arc_invalid_receipt",
  TIMEOUT: "arc_timeout",
} as const;
```

### ArcSidecarClient

HTTP client for the ARC sidecar. Uses the Fetch API internally.

```ts
import { ArcSidecarClient } from "@arc-protocol/node-http";

const client = new ArcSidecarClient({
  sidecarUrl: "http://127.0.0.1:9090",
  timeoutMs: 5000,
});

// Evaluate an HTTP request
const result: EvaluateResponse = await client.evaluate(arcHttpRequest);

// Verify a receipt signature
const valid: boolean = await client.verifyReceipt(receipt);

// Health check
const healthy: boolean = await client.healthCheck();
```

**SidecarError**

Thrown when the sidecar is unreachable or returns an error:

```ts
class SidecarError extends Error {
  readonly code: string;        // e.g., "arc_sidecar_unreachable", "arc_timeout"
  readonly statusCode: number | undefined;
}
```

### Identity Extraction

The default identity extractor checks headers in this order:

1. `Authorization: Bearer <token>` -- hashes the token with SHA-256
2. `X-API-Key` header -- hashes the key value
3. `Cookie` header -- hashes the first cookie value
4. Falls back to anonymous

```ts
import { defaultIdentityExtractor, sha256Hex } from "@arc-protocol/node-http";

// Use directly
const identity = defaultIdentityExtractor(request.headers);

// Provide a custom extractor via config
const config: ArcConfig = {
  identityExtractor: (headers) => ({
    subject: "custom-subject",
    auth_method: { method: "bearer", token_hash: sha256Hex("my-token") },
    verified: true,
  }),
};
```

### Interceptors

Two interceptor patterns are provided for direct use (the framework packages use these internally):

**Node.js `(req, res)` pattern:**

```ts
import { interceptNodeRequest, resolveConfig } from "@arc-protocol/node-http";

const resolved = resolveConfig({ config: "arc.yaml" });

const outcome = await interceptNodeRequest(req, res, resolved);
if (!outcome.responseSent) {
  if (outcome.result) {
    // Request allowed with a real ARC receipt.
  }
  if (outcome.passthrough) {
    // Fail-open passthrough. No ARC receipt exists for this request.
  }
}
```

**Web API `Request -> Response` pattern:**

```ts
import { interceptWebRequest, resolveConfig } from "@arc-protocol/node-http";

const resolved = resolveConfig({ config: "arc.yaml" });

const { response, result, passthrough } = await interceptWebRequest(request, resolved);
if (result != null) {
  // Allowed with a real ARC receipt. The original Request body remains readable.
} else if (passthrough != null) {
  // Fail-open passthrough. No ARC receipt exists for this request.
} else {
  // Denied -- return the error response
  return response;
}
```

### Helper Functions

```ts
import { buildArcHttpRequest, resolveConfig } from "@arc-protocol/node-http";

// Build an ArcHttpRequest from parts
const arcReq = buildArcHttpRequest({
  method: "POST",
  path: "/api/deploy",
  query: {},
  headers: { "content-type": "application/json" },
  caller: { subject: "user-1", auth_method: { method: "anonymous" }, verified: false },
  bodyHash: "sha256...",
  bodyLength: 42,
  routePattern: "/api/deploy",
  capabilityId: "cap-123",
});
```

---

## 2. @arc-protocol/express

Express.js middleware for ARC protocol evaluation.

### Installation

```bash
npm install @arc-protocol/express
```

### Basic Usage

```ts
import express from "express";
import { arc, arcErrorHandler } from "@arc-protocol/express";

const app = express();

// Evaluate every request against ARC
app.use(arc({ config: "arc.yaml" }));

// Routes
app.get("/pets", (req, res) => {
  res.json([{ name: "Fido" }]);
});

// Optional: structured error handler for ARC errors
app.use(arcErrorHandler);

app.listen(3000);
```

### Configuration

`ArcExpressConfig` extends `ArcConfig` with:

| Option | Type | Description |
|--------|------|-------------|
| `skip` | `Array<string \| RegExp>` | Paths to bypass ARC evaluation |

```ts
app.use(arc({
  config: "arc.yaml",
  sidecarUrl: "http://127.0.0.1:9090",
  onSidecarError: "deny",
  timeoutMs: 5000,
  skip: ["/health", "/ready", /^\/public\//],
}));
```

### Accessing Results

The evaluation result is attached to the request when ARC evaluation succeeds:

```ts
import type { ArcRequest } from "@arc-protocol/express";

app.get("/pets", (req, res) => {
  const arcReq = req as ArcRequest;
  if (arcReq.arcResult) {
    console.log("Receipt ID:", arcReq.arcResult.receipt.id);
  }
  if (arcReq.arcPassthrough) {
    console.log("ARC passthrough mode:", arcReq.arcPassthrough.mode);
  }
  res.json([]);
});
```

### Error Handler

`arcErrorHandler` is an Express error middleware that formats ARC-related errors as structured JSON:

```ts
app.use(arcErrorHandler);
// Errors with an `arc_*` code are returned as { error: "arc_...", message: "..." }
// Other errors pass through to the next error handler
```

---

## 3. @arc-protocol/fastify

Fastify plugin for ARC protocol evaluation.

### Installation

```bash
npm install @arc-protocol/fastify
```

### Basic Usage

```ts
import Fastify from "fastify";
import { arc } from "@arc-protocol/fastify";

const fastify = Fastify();

// Register the ARC plugin
await fastify.register(arc, { config: "arc.yaml" });

fastify.get("/pets", async (request, reply) => {
  return [{ name: "Fido" }];
});

await fastify.listen({ port: 3000 });
```

### Configuration

`ArcFastifyConfig` extends `ArcConfig` with:

| Option | Type | Description |
|--------|------|-------------|
| `skip` | `Array<string \| RegExp>` | Paths to bypass ARC evaluation |

```ts
await fastify.register(arc, {
  config: "arc.yaml",
  sidecarUrl: "http://127.0.0.1:9090",
  onSidecarError: "deny",
  timeoutMs: 5000,
  skip: ["/health", /^\/public\//],
});
```

### Accessing Results

The ARC evaluation result is available on the Fastify request object when ARC evaluation succeeds:

```ts
fastify.get("/pets", async (request, reply) => {
  if (request.arcResult) {
    console.log("Receipt ID:", request.arcResult.receipt.id);
  }
  return [{ name: "Fido" }];
});
```

### Route Pattern Resolution

The plugin automatically uses Fastify's `routeOptions.url` for route pattern resolution. For example, a request to `/pets/42` matched by route `/pets/:petId` will evaluate against the pattern `/pets/:petId`.

### Plugin Details

The plugin is wrapped with `fastify-plugin` to skip Fastify encapsulation, so hooks apply to all routes in the instance. Requires Fastify 4.0.0 or later.

---

## 4. @arc-protocol/elysia

Elysia lifecycle hook for ARC protocol evaluation. Designed for Bun.

### Installation

```bash
npm install @arc-protocol/elysia
# or
bun add @arc-protocol/elysia
```

### Basic Usage

```ts
import { Elysia } from "elysia";
import { arc } from "@arc-protocol/elysia";

const app = new Elysia()
  .use(arc({ config: "arc.yaml" }))
  .get("/pets", () => [{ name: "Fido" }])
  .listen(3000);
```

### Configuration

`ArcElysiaConfig` extends `ArcConfig` with:

| Option | Type | Description |
|--------|------|-------------|
| `skip` | `Array<string \| RegExp>` | Paths to bypass ARC evaluation |

```ts
const app = new Elysia()
  .use(arc({
    config: "arc.yaml",
    sidecarUrl: "http://127.0.0.1:9090",
    onSidecarError: "deny",
    skip: ["/health"],
  }))
  .get("/pets", () => [{ name: "Fido" }]);
```

### How It Works

The plugin hooks into Elysia's `onBeforeHandle` lifecycle. For each request it:

1. Checks skip patterns
2. Extracts caller identity from headers
3. Computes a SHA-256 body hash
4. Sends an evaluation request to the ARC sidecar
5. Returns a structured error response on deny, or allows the request to proceed
6. Attaches `X-Arc-Receipt-Id` to the response

---

## 5. @arc-protocol/conformance

Test utilities for verifying that TypeScript SDK behavior matches the Rust kernel. Intended for use in integration and conformance test suites.

### Installation

```bash
npm install @arc-protocol/conformance --save-dev
```

### Canonical JSON (RFC 8785)

ARC requires canonical JSON for all signed payloads. These functions produce byte-identical output to the Rust kernel.

```ts
import { canonicalJsonString, canonicalJsonBytes } from "@arc-protocol/conformance";

// Returns a string with sorted keys, no extra whitespace
const json = canonicalJsonString({ b: 2, a: 1 });
// '{"a":1,"b":2}'

// Returns UTF-8 bytes
const bytes = canonicalJsonBytes({ b: 2, a: 1 });
```

RFC 8785 rules enforced:
- Object keys sorted lexicographically
- No whitespace between tokens
- Numbers as shortest representation
- `undefined` values are skipped (matching Rust `skip_serializing_if`)
- Non-finite numbers throw an error

### Receipt Structure Validation

```ts
import { validateReceiptStructure } from "@arc-protocol/conformance";

const errors: string[] = validateReceiptStructure(receipt);
if (errors.length > 0) {
  console.error("Invalid receipt:", errors);
}
```

Validates:
- All required fields are present and correctly typed
- `id` and `request_id` are non-empty strings
- `method` is a valid HTTP method
- `caller_identity_hash` is a 64-character hex string
- `verdict` has valid structure
- `evidence` entries have `guard_name` (string) and `verdict` (boolean)
- `response_status` is a valid HTTP status code (100-599)
- `timestamp` is a positive number
- `content_hash` is a 64-character hex string
- `kernel_key` and `signature` are non-empty strings

### Content Hash Verification

Verify that a receipt's content hash matches the expected request content binding:

```ts
import { verifyContentHash } from "@arc-protocol/conformance";

const matches = verifyContentHash(
  receipt,
  "POST",          // method
  "/pets/{petId}", // route pattern
  "/pets/42",      // actual path
  { limit: "10" }, // query parameters
  "sha256hex...",  // body hash (or null)
);
```

### Verdict Assertion

```ts
import { assertVerdictMatch } from "@arc-protocol/conformance";

const errors = assertVerdictMatch(receipt.verdict, {
  verdict: "deny",
  reason: "rate limit exceeded",
  guard: "velocity-guard",
  http_status: 429,
});
// Returns string[] of mismatches, empty on success
```

### E2E Test Helpers

The conformance package includes end-to-end test examples for Express and Fastify in `test/e2e/`. These demonstrate how to spin up a test server with ARC middleware and validate receipt production.
