# Run model-selected child work

`cooperativeChildren: true` lets an ordinary AI SDK loop join native child
processes without occupying a worker slot while they run. The model chooses
from the host's advertised spawn templates and calls `wait_children` with the
returned child IDs. Chio retains those model responses before tool execution.
A restart restores the same spawn calls, tasks and child identities.

Use this option under Linux `chio process run` with configured adaptive
[spawn templates](../../../../crates/products/chio-cli/PROCESS_RUNNER.md#adaptive-child-work).
The host selects executable commands, configuration, grants, budgets, worker
slots and attempt ceilings. Models cannot supply executable commands or choose
a parent identity. A child receives only the template's narrowed routes; the
caller must already hold those routes with delegation authority.

## Worker integration

Keep the application's provider setup and original turn input. Each new OS
attempt creates a fresh agent instance with the same identity and model key:

```typescript
import { generateText, stepCountIs } from "ai";
import { ChioProcessAgent, ProcessSuspendedError } from "@chio-protocol/ai-sdk-process";

try {
  const result = await new ChioProcessAgent({
    client,
    model,
    tools: bootstrap.connection.tools,
    namespace: "research",
    threadId: savedTask.threadId,
    turnId: savedTask.turnId,
    modelKey: "research-model-and-application-v1",
    cooperativeChildren: true,
    onReceipt: event => receiptStore.save(event.operationKey, event.result.receipt_json),
  }).run(bindings => generateText({
    ...bindings,
    messages: savedTask.originalMessages,
    maxRetries: 0,
    stopWhen: stepCountIs(32),
  }));
  await applicationOutput.save(result.text);
} catch (error) {
  if (error instanceof ProcessSuspendedError) process.exitCode = error.exitCode; // 75
  else throw error;
}
```

This integration also supports `streamText`; consume the stream inside `run`
and await it before handling suspension. `run` drains all admitted tool calls
and receipt callbacks before throwing `ProcessSuspendedError`. It aborts the
SDK loop and rejects queued calls. A genuine failure from an already admitted
sibling takes precedence over suspension. Suspension does not cancel the Chio
process or undo any admitted effect.

Exit 75 lets the native runner release this worker's slot. It relaunches the
parent after the recorded children complete, even with `max_parallel: 1`.
Return from the worker entrypoint and let Node exit; background application
handles must be closed. Do not catch suspension and immediately invoke the
model again in the same OS attempt. A successful logical join is required for
the runner to recognize exit 75. Child failure, cancellation, or exhausted
attempt budgets remain terminal under the existing native runner contract.
Every launch, including a cooperative resumption, consumes a lifetime attempt.

`ChioProcessTools` supports the same option for applications that own their
model-response journal. Its client must provide `invoke`, `inspect`, and
`checkpoint`. Without the option, tool outputs retain their existing behavior,
including native pending join results. This option adds no native RPC and does
not require blob storage; larger model histories benefit from the native blob
extension described in [MODEL_JOURNAL.md](MODEL_JOURNAL.md).

## Durable observations

A native join is an observation. Replaying its operation key returns its
original pending or completed result. Observing later completion therefore
requires a distinct poll key. The adapter performs this transition explicitly:

1. Bind the logical join's original operation key and exact arguments in the
   native checkpoint before its first invocation.
2. Preserve the original signed receipt through `onReceipt`.
3. If the join is pending, advance its poll ordinal with checkpoint CAS, then
   stop the model loop and throw `ProcessSuspendedError`.
4. On resumption, replay the original model turn. Spawn keys stay unchanged.
   The same generated join tool-call ID uses its checkpointed next poll key.
   Only a completed join is returned to the model.

Poll keys derive from the original logical key and durable poll ordinal.
Credentials, OS attempts and time do not enter their identity. A lost
acknowledgement of an advancement that committed recovers the next poll. If
advancement did not commit, the original pending result replays before the
adapter advances and suspends again. That recovery can require another OS
attempt. An unknown native invocation never authorizes a replacement poll.

The adapter reserves `CHILD_WAITS_SLOT` (`chio.ai-sdk.child-waits.v1`) alongside
`MODEL_JOURNAL_SLOT` in the process checkpoint. Preserve both when updating
application state. Changing child sets under an existing logical join, corrupt
state, or a checkpoint conflict stops the run. Local concurrent joins serialize
their checkpoint mutations; concurrent external writers still use CAS. The
slot permits at most 1024 logical joins and 128 poll advances per join, subject
to the native 1 MiB checkpoint, process-call quota and worker attempt ceiling.
There is no automatic history eviction or checkpoint migration.

A join can produce multiple receipts under one SDK tool-call ID. Store receipts
by `event.operationKey`, not only by `event.toolCallId`. Each native observation
keeps its own original signed receipt. The adapter does not verify signatures;
use a Chio verifier. The host's worker completion status is not proof that a
model's work is correct, and mailbox payloads do not acquire sender attestation.

## Installed qualification

The package qualification runs a scripted HTTP planner through real AI SDK
provider parsers and the native runner. The coordinator selects two children,
joins them, receives their mailbox reviews, publishes one report, and
acknowledges the handoffs. Each child can only read fixture files and send to
the results mailbox. The fixture reads real 8 KiB files. No application-owned
model plan or child-ID file drives recovery.

The baseline uses the same model loop with cooperative joins disabled. It
replays pending joins and exhausts four coordinator attempts without publishing.
The cooperative profiles finish with two reads, two child identities and one
publication at one worker slot or with concurrent children. Other profiles kill
the host after durable suspension or kill the coordinator after its publication
receipt. The harness verifies narrowed child grants, overlapping child provider
calls, original receipts, provider request counts, checkpointed join ordinals,
and that completed workers do not respawn. These checks establish execution
behavior; live model quality and independent adoption remain unverified.
