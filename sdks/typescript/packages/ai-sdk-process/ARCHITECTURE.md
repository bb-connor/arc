# AI SDK process execution boundary

The adapter connects an application-owned AI SDK loop to the native Chio
process service. The application provides model planning, durable model-turn
identities, its receipt sink, and user-visible progress. The native host owns
process capabilities, guards, tool execution, the durable operation journal,
and receipt signing.

## Execution

1. The host supplies selected tool definitions in its private worker bootstrap.
2. The application restores or saves the model response before effects, including
   tool-call IDs, names and exact JSON arguments.
3. AI SDK invokes a bound tool with `toolCallId`. The adapter snapshots its input
   and hashes the saved identity tuple into a process operation key.
4. A bounded queue admits the call through `ProcessClient.invoke`. The native
   host validates the credential and process scope, runs guards, and executes
   or replays the operation.
5. The adapter snapshots the result and awaits `onReceipt`, if configured, with
   the unchanged receipt string. Only an allowed, completed tool output returns
   to the model. A failure aborts the current bridge run.
6. `run` drains outstanding client calls and receipt callbacks before returning
   or throwing. An instance cannot admit calls after its callback has returned.

The same logical key with changed input or route is a conflict. Distinct keys
consume distinct native admissions. Completed outcomes replay from the host's
journal. An effect committed before a lost server response can remain unknown;
the host does not repeat that effect to manufacture a result. Native durability
details are defined in the [process worker protocol](../../../../crates/kernel/chio-process/WORKER_PROTOCOL.md).

## Authority and errors

Tool definitions advertise schemas. They do not grant capabilities or provide
complete JSON Schema validation in this adapter. The native process credential
fixes authority. Advertising an extra tool cannot grant it to a worker. The
adapter has no local execution callback; `execute` calls the selected host.

The bridge accepts plain JSON, rejects unsupported JavaScript coercions, and
copies definitions, arguments and results across asynchronous boundaries.
Inputs cannot contain unsafe integers, incomplete Unicode, getters, cycles,
class instances, or sparse arrays. This preserves the client's JSON contract;
it is not isolation from malicious JavaScript running in the same process.

Model-visible errors use fixed public codes. Detailed receipt data goes to the
application callback. A thrown callback stops the run even after a completed
effect. Replaying the saved operation can recover that result, but the caller
must also make its receipt sink safe to repeat.

Kernel denials, transport exceptions and incomplete outcomes set a permanent
failure on this instance. This prevents AI SDK's tool-error handling from
silently converting the failure into application success. Already admitted
effects remain possible; neither abort nor failure is a rollback mechanism.
The bridge abort signal does not invoke native subtree cancellation.

## Persistence and trust limits

The operation journal resides in the native host's private state. It does not
persist provider requests, model responses, SDK transcripts, or arbitrary
application checkpoints. Restoring a saved model plan is a caller prerequisite.
The adapter cannot infer that a new model call means the same external action.
Changing a call ID to evade an unknown outcome defeats recovery protection.

The local worker trusts its private socket and host. Receipts are preserved but
not verified in the JavaScript client. Verification needs the operator's trusted
key. A receipt signature covers its defined signed payload; it is not a
signature over arbitrary tool outputs, application files, or the whole model
transcript. The qualification harness verifies the original receipt bytes and
separately checks the fixture's committed effects.

The process host and this adapter do not place a same-user Node worker in an OS
sandbox. A worker can use its own ambient network and filesystem permissions,
including model-provider access outside Chio. Deployment isolation and provider
transport mediation remain separate operator concerns. See the
[host boundary](../../../../crates/products/chio-cli/PROCESS_HOST.md).
