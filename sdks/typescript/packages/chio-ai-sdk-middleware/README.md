# @chio-protocol/ai-sdk-middleware

Vercel AI SDK 7 language-model middleware for Chio verdict gating. Supports
AI SDK 7 only (`ai@>=7 <8`).

```ts
import { wrapWithChio } from "@chio-protocol/ai-sdk-middleware";

const model = wrapWithChio(baseModel, {
  provider: "openai",
  modelId: "gpt-4.1",
});
```

`wrapWithChio` calls the AI SDK's `wrapLanguageModel` with the middleware from
`createChioMiddleware`, so the wrapped model keeps its provider, model id and
supported URLs. To compose with other middleware, pass the middleware
yourself:

```ts
import { wrapLanguageModel } from "ai";
import { createChioMiddleware } from "@chio-protocol/ai-sdk-middleware";

const model = wrapLanguageModel({
  model: baseModel,
  middleware: [createChioMiddleware({ provider: "openai", modelId: "gpt-4.1" })],
});
```

## Ordering

Chio must be the innermost middleware, so that it sees the tools after every
other middleware has run `transformParams`. `wrapLanguageModel` applies an
array so that the first entry runs first and the last entry sits directly
around the model; put `createChioMiddleware` last. A middleware placed after Chio in the array, or `wrapWithChio` applied to a
model that other middleware already wraps, puts Chio outside that middleware,
so tools it adds after the check are not evaluated. `wrapWithChio(baseModel)` on
the raw provider model, with any other middleware wrapped around the result, is
also correct. Tests cover both correct placements denying a tool added by a
middleware outside Chio.

## What is evaluated

The middleware runs in `wrapGenerate` (used by `generateText`) and
`wrapStream` (used by `streamText`). Before delegating to the model it
evaluates every tool declared in the call's `tools` option, function and
provider tools alike, in name order. Each evaluation carries the tool `name`,
its `type` (`"function"` or `"provider"`) and, for provider tools, the provider
`id`, so policy can tell a provider `bash` tool from a function named `bash`.
A declaration with an unknown type, an empty name, or a provider tool without
an id is denied. This gates whether the model may be
called with those tools offered. It does not inspect the arguments of the
tool calls the model later emits, and it does not wrap tool execution. Use
`@chio-protocol/ai-sdk` (`chioTool`) to evaluate each tool invocation with
its arguments.

A call that declares no tools is not evaluated. Denials throw
`ChioMiddlewareDeniedError` with the denial reason and optional receipt id,
and the underlying model is never invoked. Allowed streams are returned
untouched.

The default Edge path consumes `@chio-protocol/edge` dynamically. Node uses
`fetch` against `/chio/evaluate`. Tests can inject `evaluate` directly.

## Runtime selection

The runtime path is selected as follows:

- `runtime: "edge"` (or detected `EdgeRuntime` global) - dynamic `import`
  of `@chio-protocol/edge` evaluates the wasm artifact in-process.
- `runtime: "node"` (default outside Edge) - HTTP POST to a Chio sidecar at
  `sidecarUrl` (default `http://127.0.0.1:9090/chio/evaluate`).
- `runtime: "auto"` (the default) - picks Edge when `EdgeRuntime` is set,
  Node otherwise.

A custom `evaluate` callback short-circuits both paths and is the
recommended seam for unit tests.

## Receipt verification

An allow verdict authorizes the call only after the receipt passes
verification. The middleware uses `verifyReceipt` when supplied and otherwise
POSTs the receipt to the sidecar's `/chio/verify` route. On the Edge runtime
there is no fetch fallback, so a `verifyReceipt` is required; without one the
call is denied.
