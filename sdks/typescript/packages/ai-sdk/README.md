# @arc-protocol/ai-sdk

Streaming-safe wrapper around the [Vercel AI SDK](https://sdk.vercel.ai/)
`tool()` helper that routes every tool invocation through the ARC sidecar
for capability-based policy evaluation.

- Gates tool calls at the `execute` entry point before any side effects.
- Preserves `ReadableStream` / async-generator return values without
  buffering, so `streamText` / `streamObject` / SSE keep working.
- Keeps full TypeScript generic inference from the underlying `tool()`.
- Fails closed by default; opt-in fail-open for degraded-mode operation.

## Install

```bash
npm install @arc-protocol/ai-sdk
```

Requires the ARC sidecar running locally (default
`http://127.0.0.1:9090`). Peer dependencies: `ai@>=3.4 <6`,
`zod@>=3.23 <4`.

## Quickstart

```ts
import { streamText } from "ai";
import { openai } from "@ai-sdk/openai";
import { z } from "zod";
import { arcTool } from "@arc-protocol/ai-sdk";

const searchTool = arcTool({
  description: "Search the web",
  parameters: z.object({
    query: z.string().describe("search query"),
  }),
  execute: async ({ query }) => {
    return await fetchSearchResults(query);
  },
  scope: {
    toolServer: "web-tools",
    toolName: "search",
    capabilityId: "cap-agent-001",
  },
});

const result = streamText({
  model: openai("gpt-4o"),
  tools: { search: searchTool },
  prompt: "Research quantum computing advances",
});

for await (const chunk of result.textStream) {
  process.stdout.write(chunk);
}
```

If the sidecar denies the call, `execute` throws `ArcToolError`. The
Vercel AI SDK surfaces the error through its standard `onError` /
`result.error` channels.

## Streaming example

`arcTool` never buffers the value returned from the underlying
`execute`. You can return a `ReadableStream` or an async generator and
the caller (or the Vercel AI SDK streaming pipeline) receives the exact
same object reference.

```ts
const streamingTool = arcTool({
  description: "Stream rows from a warehouse query",
  parameters: z.object({ sql: z.string() }),
  execute: async ({ sql }) => {
    // Returning a ReadableStream -- passed through unchanged.
    return runQueryAsStream(sql);
  },
  scope: { toolServer: "warehouse", toolName: "query" },
});
```

```ts
const progressiveTool = arcTool({
  description: "Yield partial results as they arrive",
  parameters: z.object({ topic: z.string() }),
  execute: async function* ({ topic }) {
    // Async generators are also forwarded unchanged.
    for await (const item of researchIterator(topic)) {
      yield item;
    }
  },
  scope: { toolServer: "research", toolName: "deep-dive" },
});
```

## API

### `arcTool(options)`

| Option            | Type                                  | Description                                                             |
| ----------------- | ------------------------------------- | ----------------------------------------------------------------------- |
| `description`     | `string`                              | Forwarded to the Vercel AI SDK tool.                                    |
| `parameters`      | `ZodSchema`                           | Input schema (AI SDK v3/v4 shape).                                      |
| `inputSchema`     | `ZodSchema`                           | Input schema (AI SDK v5 shape).                                         |
| `execute`         | `(params, options?) => T`             | Underlying tool implementation; called when ARC allows the call.        |
| `scope`           | `ArcToolScope`                        | ARC evaluation binding (`toolServer`, `toolName`, `capabilityId`, ...). |
| `client`          | `ArcClient`                           | Optional shared client.                                                 |
| `clientOptions`   | `ArcClientOptions`                    | Inline client options (`sidecarUrl`, `timeoutMs`, `fetch`, `debug`).    |
| `onSidecarError`  | `"deny"` \| `"allow"`                 | Default `"deny"` -- throw on transport failure.                         |
| `debug`           | `(message, data?) => void`            | Optional debug hook; the wrapper never writes to stdout.                |

Returns a tool object with the same structural shape as the input so it
drops directly into `streamText({ tools: { ... } })`.

### `ArcToolError`

Thrown when the sidecar denies a tool call or the transport fails in
fail-closed mode. Fields: `verdict`, `guard`, `reason`, `receiptId`.

### `ArcClient`

Minimal HTTP client for `POST /arc/evaluate`. Can be shared across many
`arcTool()` instances to amortize construction cost. The client builds an
`ArcHttpRequest`-compatible payload for tool calls, accepts the sidecar's
canonical `EvaluateResponse { verdict, receipt, evidence }` shape, and
still normalizes the Lambda evaluator's legacy `{ receipt_id, decision }`
wire contract into the same `ArcReceipt` API.

## License

MIT
