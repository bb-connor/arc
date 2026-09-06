# Recover an AI SDK model loop

`ChioProcessAgent` combines the native tool bridge with a model-response journal.
It wraps an existing provider model through AI SDK's
[language model middleware](https://ai-sdk.dev/docs/ai-sdk-core/middleware).
The application supplies its model and original turn input. A worker restart
replays recorded responses through the same SDK loop, recovers native tool
results, and requests the next unrecorded model response.

## Application contract

Construct a fresh `ChioProcessAgent` for each OS attempt and call `run` once.
Use the same `namespace`, `threadId`, `turnId`, and `modelKey` when resuming that
turn. Supply the **original** prompt or messages for the turn, not a partially
reconstructed SDK transcript. The model-response cursor starts at zero and
advances through the saved calls. The SDK rebuilds its own tool messages using
the recorded model responses and native operation results.

`modelKey` versions your provider configuration and application behavior. The
journal also binds the provider name, model ID, provider specification version,
generation API, and model-call parameters. Changes to prompts, tool schemas,
sampling, headers, provider options, or the declared `modelKey` reject a replay
before another provider call. Abort signals are transient and excluded from
request identity. A provider endpoint or other configuration hidden inside a
model closure cannot be inspected automatically; version it in `modelKey`.
URL identity binds the URL string, not mutable remotely hosted content.

Use the returned `model`, `tools`, and `abortSignal` in the SDK call. The supplied
tools execute through the native host. Provider-defined tools are rejected
before the provider request. Native capability enforcement still lives in the
host. The application must not add local effectful callbacks and assume the
journal protects them. Model-provider traffic, billing, SDK callbacks, UI output,
and same-user ambient permissions remain outside the native tool guarantee.

The journal supports one sequential model loop per instance. Concurrent model
calls on that instance fail; native tool calls retain their separate concurrency
bound. Use separate process/turn identities for independent model workers.
SDK provider auto-retry cannot bypass a journal failure. A pending provider
reservation is an unknown result, not permission to generate a new plan.

## Durable ordering

For a new model call, the adapter first reserves its ordinal and request hash
in the native process checkpoint with compare-and-swap. It then calls the
provider, snapshots the complete response, stores immutable response chunks when
supported, and commits their checkpoint references before
returning it to AI SDK. A checkpoint conflict, oversize response, malformed
value, or provider failure stops the run before any of that response's native
tool calls can execute.

A completed entry replays the original content, generated tool-call IDs,
metadata and usage without contacting the provider. Changed request parameters
or duplicate tool-call IDs fail. The native tool journal then recovers any
known tool result under its original logical key. A lost acknowledgement of a
completed model checkpoint can recover on the next attempt because the durable
response is already present.

A provider request that was reserved but has no completed checkpoint remains
unknown on restart. The adapter does not automatically resend it. This includes
provider failure, interrupted streams, response serialization failure, and a
worker dying before response persistence. A complete provider response is the
recovery boundary; general resumable inference is not implemented. New turns
are distinct work and must not be used to blindly repeat an uncertain native
tool effect.

For `streamText`, the adapter passes text and reasoning through until the first
tool event. That event and the remainder of the response are held until a
complete, valid stream has been recorded. The terminal finish event is always
held. This preserves early model text while preventing a tool from executing
before its complete model response is durable. It delays tool execution until
the model finishes that response. Truncated streams, error events, and unknown
finish reasons fail without releasing the held tool calls.

Consume streams inside `agent.run` and await its completion before declaring
application success. Returning a live stream from the callback is unsupported.
Text already delivered to a UI can repeat when the whole turn replays; the
application owns UI reconciliation. Aborting does not undo admitted effects.
Providers must cooperate with abort signals or have their own timeouts.

## Checkpoint ownership and limits

The native checkpoint value must be `null` or a JSON object. The journal reserves
the property exported as `MODEL_JOURNAL_SLOT`, currently
`chio.ai-sdk.journal.v1`. It preserves other object properties. Application
checkpoint writers must preserve this property when updating their own state.
Deleting or replacing it discards the model history and invalidates recovery
assumptions. With cooperative children, also preserve the reserved child-wait slot described
in [COOPERATIVE_SWARMS.md](COOPERATIVE_SWARMS.md). Concurrent writes use native compare-and-swap; conflicts stop the
run instead of overwriting another writer's data.

| Option or limit | Default | Bound |
| --- | ---: | --- |
| `maxModelCalls` per saved turn | 64 | 1 through 128 |
| `maxCheckpointBytes`, including other application state | 1 MiB | 4 KiB through 1 MiB |
| `maxResponseBytes` per encoded response | 8 MiB | 4 KiB through 64 MiB |
| `responseStorage` | `auto` | `auto`, `checkpoint`, or `blobs` |
| Saved turns in one checkpoint | 128 maximum | No automatic history eviction |
| Supported model-value nesting | 64 codec levels | Native JSON nesting and frame limits also apply |

`auto` stores responses in native immutable blobs when `inspect.storage` advertises
`chio.process.blobs.v1` and the client supplies blob methods. Otherwise it keeps
the existing inline checkpoint profile. `blobs` requires native support before
a provider call. `checkpoint` explicitly retains inline storage. Existing inline
entries remain replayable after upgrading; entries with blob references never
fall back to regenerating missing responses.

Responses retain all supported provider fields, including growing request bodies.
Each is encoded once into chunks of at most 1 MiB. The checkpoint binds the full
byte count, full SHA-256, ordered chunk hashes and sizes, and original tool IDs.
Reads verify chunks and the full payload before decoding. The small reference is
committed only after every chunk is durable. Failure or a lost acknowledgement
before that checkpoint leaves the model reservation unknown and can leave charged
orphan chunks. The default native root quota is 64 MiB / 4096 blobs, configurable
by the host up to 1 GiB / 16384 blobs. Both bytes and record counts are shared by
siblings; there is no per-child fairness or automatic history collection.

The checkpoint still has its 1 MiB bound. Large numbers of entries/turns can
exhaust it. A response can exhaust its own byte bound or the native tree quota.
None of these failures release that response's held tool calls. Native blobs
are private local state, with no external object service or migration API.

The codec preserves ordinary objects, arrays, undefined values, dates, URLs,
byte arrays, array buffers and finite safe numeric values. It rejects getters,
cycles, unsupported class instances and invalid Unicode. Tagged values avoid
collisions with ordinary provider JSON. Integrity hashes detect accidental
record corruption; they are not signatures or proof of provider authenticity.
Model history is application-owned checkpoint data on the trusted local host.
Native tool receipts retain their separate signature verification requirements.

## Installed HTTP qualification

The standard package qualification command in [README.md](README.md) includes
the model journal. It installs package tarballs outside the checkout and uses
the real `@ai-sdk/openai-compatible` provider against a local scripted HTTP
service. AI SDK 6.0.277 uses provider 2.0.74; AI SDK 7.0.93 uses provider 3.0.44.
The service generates fresh response and tool-call IDs, records requests, and
decides whether to publish or finish from the SDK's tool-result messages.
The application does not create a saved model-plan file.

| Profile, repeated for both SDK versions | Provider requests | Publications | Outcome |
| --- | ---: | ---: | --- |
| Callback baseline restarted after publication | 3 | 2 | Completed with a fresh tool-call ID |
| Worker death after known publication | 2 | 1 | Completed with original receipt |
| Host death after known publication during `streamText` | 2 | 1 | Completed with original receipt |
| Worker death after model checkpoint, before tool execution | 2 | 1 | Completed |
| HTTP provider closes before returning its response | 1 | 0 | Failed, pending model reservation |
| SSE stream ends before its terminal event | 1 | 0 | Failed, pending model reservation |
| Original prompt changed on retry after publication | 1 | 1 | Failed before another provider call |

The harness also checks generated IDs in native checkpoint entries, installed
module paths, absence of credentials and receipts in provider prompts, terminal
native attempt counts, original receipt signatures, and that a completed native
run does not respawn its worker or contact the provider. Package unit tests
exercise full replay without provider calls, genuine early streaming, concurrent
claimants, checkpoint conflicts, lost acknowledgements, input drift, corruption,
and metadata serialization.

The HTTP service follows scripted decisions. These tests qualify the adapter's
real request/response and streaming paths, not model reasoning quality, live
hosted inference, or independent application adoption.

## Longer native workloads

The same installed qualification adds 32 sequential reads returning 8 KiB per
file, retaining the HTTP provider's growing request bodies. It compares inline
checkpoint exhaustion with immutable storage, kills the worker after read 16,
kills the host during streaming, and exhausts a one-byte tree quota. Successful
recovery must finish with 32 distinct native reads, 33 provider requests and 32
verified original receipts. It checks every persisted chunk hash, byte usage,
checkpoint writes and size, retained provider metadata, and completed-run replay.
Quota and inline failures must keep the final provider reservation unknown.
The workload is scripted and establishes storage/recovery behavior only.
