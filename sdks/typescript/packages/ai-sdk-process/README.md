# @chio-protocol/ai-sdk-process

Run AI SDK tools through Chio's native process kernel. The host executes the
selected tools, records their outcomes, and replays a saved call after worker
or host failure. The adapter supplies AI SDK tool definitions and awaits the
guarded result. Requires Node 22+, AI SDK 6 or 7, and the native Linux process
host. This package is experimental; registry publication is a separate step.

## Install into an existing AI SDK application

Install the local package tarballs alongside your application's AI SDK:

```sh
npm install /path/to/chio-protocol-process-0.1.0.tgz \
  /path/to/chio-protocol-ai-sdk-process-0.1.0.tgz
```

## Resume an ordinary model loop

`ChioProcessAgent` saves complete provider responses in the native process
checkpoint before the SDK can execute their tool calls. Resume with the original
application input and the same turn identity; the journal restores saved model
responses, including generated tool-call IDs. The caller does not need to write
a provider-response journal.

```typescript
import { generateText, stepCountIs } from "ai";
import { ProcessClient } from "@chio-protocol/process";
import { ChioProcessAgent } from "@chio-protocol/ai-sdk-process";

// existingModel is your configured AI SDK provider model. bootstrap is the
// native runner's private input; its application fields persist across attempts.
const connection = bootstrap.connection;
const agent = new ChioProcessAgent({
  client: new ProcessClient(connection.socket_path, connection.credential),
  model: existingModel,
  tools: connection.tools,
  namespace: "repository-review",
  threadId: bootstrap.input.threadId,
  turnId: bootstrap.input.turnId,
  modelKey: "review-model-and-application-v1",
});
const result = await agent.run(bindings => generateText({
  ...bindings,
  prompt: bootstrap.input.prompt,
  stopWhen: stepCountIs(8),
}));
```

`agent.run` also accepts a callback that consumes `streamText`. Text streams
until the first tool event; that event and the remaining response wait for the
durable checkpoint before release. Keep the native checkpoint and the original
turn input. A provider call without a complete saved response remains unknown
and is not retried automatically. The journal uses native immutable response blobs when supported and keeps small
references in the 1 MiB checkpoint. Older hosts retain the inline profile.
Changed model requests reject before dispatch. See
[MODEL_JOURNAL.md](MODEL_JOURNAL.md) for the contract, limits and HTTP recovery
qualification.

## Use tools with application-owned model persistence

The [native runner](../../../../crates/products/chio-cli/PROCESS_RUNNER.md)
delivers a private bootstrap on standard input with `connection.socket_path`,
`connection.credential`, and `connection.tools`. Configure the worker's tool
scope and executable in the host plan. The model receives only the advertised
tool schemas and guarded outputs; keep the bootstrap outside prompts and logs.

```typescript
import { generateText, stepCountIs } from "ai";
import { ProcessClient } from "@chio-protocol/process";
import { ChioProcessTools } from "@chio-protocol/ai-sdk-process";

// bootstrap is the native runner's private input. The application supplies
// model and savedTurn. See the persistence requirement below before retrying.
const connection = bootstrap.connection;
const processTools = new ChioProcessTools({
  client: new ProcessClient(connection.socket_path, connection.credential),
  tools: connection.tools,
  namespace: "repository-review",
  threadId: savedTurn.threadId,
  turnId: savedTurn.id,
  maxConcurrency: 4,
  onReceipt: event => receiptStore.record(event.operationKey, event.result.receipt_json),
});

const result = await processTools.run(bindings => generateText({
  model,
  ...bindings,
  prompt: savedTurn.prompt,
  stopWhen: stepCountIs(8),
}));
```

`model`, `savedTurn`, and `receiptStore` are application dependencies. The
lower-level tool bridge does not supply model persistence or a receipt database. `onReceipt`
is optional; when supplied, it is awaited before a result becomes model-visible.
Preserve the original `receipt_json` string. Signatures are unverified by this
JavaScript package; use a Chio verifier with the operator's pinned kernel key.

For streaming, consume the stream **inside** `run`:

```typescript
import { streamText, stepCountIs } from "ai";

await processTools.run(async bindings => {
  const result = streamText({
    model,
    ...bindings,
    prompt: savedTurn.prompt,
    stopWhen: stepCountIs(8),
  });
  for await (const text of result.textStream) {
    await applicationOutput.write(text);
  }
  await result.text;
});
```

Each `ChioProcessTools` instance runs once. Create a fresh instance when resuming
a saved run. Returning a live stream from the callback closes admissions before
its later tool calls. Model text may already have reached the consumer when a
later failure rejects `run`; wait for `run` before reporting application success.

## Persistence contract for ChioProcessTools

The logical operation key hashes the tuple `(namespace, threadId, turnId,
toolCallId)`. Save all four identities and the exact model-selected tool name
and JSON arguments **before** the SDK executes the call. Restore the same plan
when a worker resumes. Model responses with fresh tool-call IDs create fresh
operations even if they describe the same action. Saving only `turnId` does
not make a regenerated model response safe to retry.

When using `ChioProcessTools`, the caller owns this model-response journal or
equivalent durable workflow. `ChioProcessAgent` supplies the checkpoint journal
described above.
AI SDK's `onStepFinish` runs after tool execution, so that callback is too late
to establish this prerequisite. The lower-level qualification worker demonstrates the
ordering with a saved provider response and a scripted model interface. It
does not implement a live provider response journal for your application.

Arguments, routes, credentials, and OS attempt numbers are excluded from the
logical key. Replaying a key with different arguments or a different route
fails with `conflict`. Keep the original key when recovering an uncertain
outcome. The adapter and process client perform no automatic invocation retry.

## Failure and concurrency

AI SDK can represent an execution exception as a tool error and continue its
model loop. This bridge also records the first failure, aborts the SDK signal,
rejects queued work, and makes the outer `run` reject. Denials, incomplete
outcomes, transport failures, MCP error results, and receipt-store failures
therefore cannot become successful bridge runs.

Concurrency defaults to four active calls and 64 total active or queued calls.
`maxConcurrency` accepts 1 through 32; `maxPending` must be at least the
concurrency and at most 128. Calls already sent to the host are awaited on exit,
including their receipt callbacks. Other admitted calls may still commit after
one fails. Aborting the SDK does not undo effects or cancel the native process
subtree, and a client timeout can finish before the host's effect does. The
application must cooperate with the supplied abort signal and own its deadlines.

Only completed, allowed results reach the model. Value results retain their
guarded JSON shape, including MCP content wrappers. Host stream results become
`{ chunks: [...] }` after completion; this does not stream live tool output.
The SDK's model text streaming remains available. See
[ARCHITECTURE.md](ARCHITECTURE.md) for the trust and persistence boundaries.

## Build and qualify

From the repository root, with Python 3.11+, Node 22+, and a built `chio` binary:

```sh
npm ci --prefix sdks/typescript --ignore-scripts
npm run build --prefix sdks/typescript --workspace @chio-protocol/ai-sdk-process
npm test --prefix sdks/typescript --workspace @chio-protocol/ai-sdk-process
python3 sdks/typescript/packages/ai-sdk-process/qualification/qualify.py \
  --chio target/debug/chio --output /path/to/new-evidence-directory
```

The harness packs both Chio packages, installs them outside the checkout,
typechecks a consumer against pinned AI SDK **6.0.277** and **7.0.93**, and runs
both real SDK execution loops against the native host and a non-idempotent
SQLite publication tool. Dependency installation initially needs registry
access or a populated npm cache. Installing the Chio tarballs uses offline mode.

| Profile, repeated for both SDK versions | Publications | Final run |
| --- | ---: | --- |
| Local callback, restart after committed publication | 2 | Completed |
| Native worker restart after known result | 1 | Completed with identical original receipt |
| Native host death after known result | 1 | Completed with identical original receipt |
| Tool outside the worker's capability | 0 | Failed |
| Tool exits after commit, before returning output | 1 | Failed, no redispatch |
| Saved call ID replayed with changed arguments | 1 | Failed with conflict |

Worker restart uses `generateText`; host death and denial use `streamText`.
The harness deletes the first-result oracle before recovery, verifies receipt
signatures against the initialization key, and confirms a completed native run
does not respawn the worker. Evidence includes package and binary hashes, SDK
versions, source checkout status, saved plans, and original receipt text.
The binary hash identifies the supplied binary; it is not a build attestation.

These tests establish the specified recovery behavior using scripted provider
responses. They do not establish live model quality, independent adoption,
distributed transactions, or general exactly-once application execution.

AI SDK reference: [tools and tool calling](https://ai-sdk.dev/docs/ai-sdk-core/tools-and-tool-calling)
and [tool execution options](https://ai-sdk.dev/docs/reference/ai-sdk-core/tool).
