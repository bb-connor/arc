# @chio-protocol/ai-sdk

Streaming-safe wrapper around the [Vercel AI SDK](https://ai-sdk.dev/) 7
`tool()` definition that routes every tool invocation through the Chio
sidecar for capability-based policy evaluation.

- Gates tool calls at the `execute` entry point before any side effects.
- Async generator tools keep streaming preliminary results.
- Keeps TypeScript inference of input, output and `context` from the
  `tool()` definition.
- Fails closed when the sidecar is unreachable, and refuses to wrap tools
  that have no `execute` function.

Supports AI SDK 7 only.

## Install

```bash
npm install @chio-protocol/ai-sdk
```

Requires the Chio sidecar running locally (default
`http://127.0.0.1:9090`). Peer dependencies: `ai@>=7 <8`,
`zod@^3.25.76 || ^4.1.8`.

## Quickstart

```ts
import { streamText } from "ai";
import { openai } from "@ai-sdk/openai";
import { z } from "zod";
import { chioTool } from "@chio-protocol/ai-sdk";

const searchTool = chioTool({
  description: "Search the web",
  inputSchema: z.object({
    query: z.string().describe("search query"),
  }),
  execute: async ({ query }) => {
    return await fetchSearchResults(query);
  },
  scope: {
    toolServer: "web-tools",
    toolName: "search",
    capabilityToken: process.env.CHIO_CAPABILITY_TOKEN!,
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

If the sidecar denies the call, `execute` throws `ChioToolError`. The
Vercel AI SDK surfaces the error through its standard `onError` /
`result.error` channels.

## Streaming

AI SDK 7 calls `execute` synchronously and streams the result as
preliminary outputs when it is an async iterable. `chioTool` keeps that
behavior for async generator functions: the wrapper is itself an async
generator that authorizes with Chio on its first `next()` and then
delegates with `yield*`, without buffering.

```ts
const progressiveTool = chioTool({
  description: "Yield partial results as they arrive",
  inputSchema: z.object({ topic: z.string() }),
  execute: async function* ({ topic }) {
    for await (const item of researchIterator(topic)) {
      yield item;
    }
  },
  scope: { toolServer: "research", toolName: "deep-dive" },
});
```

Any other `execute` is awaited and its result returned untouched, so a
`ReadableStream` resolved from an async function reaches the AI SDK by
reference as the final output. A plain function that synchronously returns an
async iterable (for example a `ReadableStream`) is rejected with
`ChioToolError`, because the asynchronous Chio check would turn the stream
into a final output; declare such tools as async generator functions.

## Approvals

`toolApproval` (and the deprecated tool-level `needsApproval`) are applied by
the AI SDK before it calls `execute`, so Chio authorization runs inside
`execute` after any approval step and does not replace it. A call that is
waiting for user approval is not sent to the sidecar. An approved call is
still evaluated by Chio, and a Chio deny surfaces as a tool error. Approval
fields on the tool definition pass through the wrapper unchanged.

`chioTool` throws `ChioToolError` at construction for a tool without an
`execute` function, such as a client-side tool or a provider-executed tool,
because Chio cannot mediate execution that happens outside this process.

## API

### `chioTool(options)`

| Option            | Type                                  | Description                                                             |
| ----------------- | ------------------------------------- | ----------------------------------------------------------------------- |
| `description`     | `string`                              | Forwarded to the Vercel AI SDK tool.                                    |
| `inputSchema`     | `FlexibleSchema`                      | Input schema (zod or any AI SDK schema).                                |
| `execute`         | `(input, options) => T`               | Required. Underlying tool implementation; called when Chio allows the call. |
| `scope`           | `ChioToolScope`                        | Chio evaluation binding (`toolServer`, `toolName`, `capabilityToken`, ...). |
| `client`          | `ChioClient`                           | Optional shared client.                                                 |
| `clientOptions`   | `ChioClientOptions`                    | Inline client options (`sidecarUrl`, `timeoutMs`, `fetch`, `debug`).    |
| `debug`           | `(message, data?) => void`            | Optional debug hook; the wrapper never writes to stdout.                |
| `resolveCapabilityToken` | `(capabilityId) => token`       | Optional resolver when `scope.capabilityId` is only an indirection key. |
| `verifyReceipt`   | `(receipt) => ChioReceiptAuthority`   | Optional receipt verifier; defaults to the sidecar `/chio/verify` route. |

Every other `tool()` field (`contextSchema`, `needsApproval`, `toModelOutput`,
...) is forwarded unchanged.

Returns the tool without the Chio fields so it drops directly into
`streamText({ tools: { ... } })`.

`scope.capabilityId` is only a request hint. Chio deny-by-default sidecar
evaluation still requires a signed capability token to be presented via
`scope.capabilityToken` or `resolveCapabilityToken`.

### `ChioToolError`

Thrown when the sidecar denies a tool call or the transport fails in
fail-closed mode. Fields: `verdict`, `guard`, `reason`, `receiptId`.

### `ChioClient`

Minimal HTTP client for `POST /chio/evaluate`. Can be shared across many
`chioTool()` instances to amortize construction cost. The client builds an
`ChioHttpRequest`-compatible payload for tool calls, accepts the sidecar's
canonical `EvaluateResponse { verdict, receipt, evidence }` shape, and
still normalizes the Lambda evaluator's `{ receipt_id, decision }` wire
contract into the same `ChioReceipt` API.

## License

MIT
