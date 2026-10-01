# Execution review: protocol ingress and authority boundaries, October 1, 2026

Scope: commits `53858afa39`, `68fb96f436`, `150f7bea8e`, `93fbf2eb4d`
(protocol half), `cbd78cd8b1`, `cacaf69fc9` (remote lifecycle and ACP half) and
`55e7439da3` (ACP errors and OpenAPI half), reviewed at tip `a2630c20a1` against
base `07e963e8f5`. Plans: `2026-09-29-protocol-authority-boundaries.md`,
`2026-09-29-enforced-native-protocol-boundaries.md`,
`2026-09-29-remote-lifecycle-acp-native-ci.md` and
`2026-09-29-native-consumers-acp-errors-openapi.md`, with their matching
`docs/reviews/2026-09-29-*-execution.md` records and evidence directories under
`docs/reviews/artifacts/`. Native launch, consumers, policy clocks and source
gates are owned by other reviewers and are covered here only where they touch a
protocol boundary. Method: diff reading, then reading the resulting code at the
tip and tracing each candidate through its callers and composition; record
claims were checked against the archived logs. No cargo was run: every finding
below rests on a step-by-step source trace, and the High finding is also backed
by an existing passing unit test that asserts its first link.

**Judgment: The slice delivers real boundary work. Frame readers stop at the
bound without reinterpreting the tail. The ACP and A2A compatibility
passthroughs and the uncaged provisioning-discovery path are gone, with
negative controls. A2A OAuth cache custody and ACP signer clock custody are
correct, and the ACP signer consumes authorization only after time checks.
The most important defect is a regression in `cacaf69fc9`: a remote MCP
service that crashes while holding a Ready session cannot restart once that
session's persisted idle deadline passes (PB1). In two more places fail-closed
was applied at the wrong granularity. Unsigned peer and operator documents are
decoded under signed-record numeric spelling rules (PB2), and a transient clock
fault now ends every MCP edge session rather than refusing one time-dependent
effect (PB3). The records are numerically accurate but describe unit behavior
where the composition fails. The security closures were worth doing; PB1 to PB3
should be repaired before this work is called qualified.**

## Plan conformance

| Plan item | Recorded status | Verified status | Evidence |
| --- | --- | --- | --- |
| Protocol authority 1: bounded original bytes, duplicate rejection, typed causes for MCP edge/adapter, A2A, OpenAI | Complete | Done with a defect | Bounds and duplicate rejection present at every listed reader; wrong numeric contract for unsigned documents (PB2); limit tests absent for the A2A edge and adapter 16 MiB bounds. |
| Protocol authority 2: A2A OAuth and lifecycle clocks, bounded registry reads | Complete | Done with a defect | OAuth cache verified clean; registry read bounded but write unbounded (PB5). |
| Protocol authority 3: MCP task/dispatch time, nested expiry and capacity, writer deadlines | Complete | Done with a defect | Fenced deadlines, checked counters, retention to TTL verified; clock fault ends the session (PB3); nested-flow client waits have no deadline (PB4). |
| Protocol authority 4: census, clock gates, evidence | Complete | Done | 22 reader owners match `qualification.json`; counts not independently recounted (gate reviewer's slice). |
| Enforced native 1 (protocol part): remove A2A edge compatibility passthrough | Complete | Done | Feature, wrapper and direct path absent; only xtask calibration fixtures mention it. |
| Enforced native 2: remote MCP and A2A edge ingress, typed local sources, redacted external errors | Complete | Partial | Bounds and duplicates done; A2A and remote still send peer and internal text outward (PB7); A2A envelope rejections keep no local cause (PB8). |
| Enforced native review repair: uncaged provisioning discovery | Complete | Done | Two independent gates (`provision.rs:393`, `discovery/launch.rs:18`) and an end-to-end negative control. |
| Remote lifecycle 1: shared fenced clock for remote owners | Complete | Done with a High regression | Ambient reads removed, propose-persist-publish verified; restore of an expired Ready session refuses startup (PB1). |
| Remote lifecycle 2: remove ACP direct invocation | Complete | Done | Verified clean; no-bypass gate test rejects reintroduction. |
| Remote lifecycle 3: ACP original-byte ingress | Complete | Done | Proxy reader bounds before extend, poisons on error, never resyncs. |
| Native consumers 2: ACP clock owner | Complete | Done | Signer validates time before consuming authorization; tests drive the real signer. |
| Native consumers 3: domain errors for remote MCP/ACP | Complete for these owners | Partial and overbroad | Remote covers OAuth and sender constraint only (PB7); ACP compliance and OpenAPI operator diagnostics erased (PB6). |
| Native consumers 4: OpenAPI original bytes | Complete | Done with defects | Bridge, fuzz and conformance callers migrated; `chio-api-protect` discovery not (PB9); JSON path uses signed numeric rules (PB2). |

## PB1. High: a remote MCP service that crashes with a Ready session cannot restart after that session's persisted idle deadline passes

`cacaf69fc9` made `RemoteSession::new` rebuild an `AuthorityDeadline` for a
restored Ready snapshot
(`crates/protocol/chio-mcp-remote/src/remote_mcp/session_core/session.rs:17-24`).
`AuthorityDeadline::new` (`chio-security-types/src/clock.rs:239-262`) returns
`Expired` when `idle_expires_at <= now` and `NotYetValid` when
`now < last_seen_at`. Restore reaches that constructor with no earlier expiry
filter. `load_active_session_records` (`session_store.rs:712-789`) checks
terminal fences and HMAC integrity only. `validate_resume_record_integrity_with_keyring`
(`session_resume.rs:809-837`) checks key validity and the tag. `restore_session`
(`session_core/factory.rs:454-647`) checks fingerprints, then launches the
upstream, spawns the edge thread and calls `RemoteSession::new(..)?` at
`:623`. `restore_persisted_sessions` (`http_service.rs:204-236`) turns any
restore error into `return Err(error)`, keeping the row, and the serve entry
propagates it (`http_service.rs:79-82`) before `cleanup_due_sessions` at `:84`
ever runs.

Scenario: the service is killed (OOM, host reboot, `SIGKILL`) while any session
is Ready. Graceful shutdown terminalizes rows, so only an unclean stop
triggers it. On restart, if the clock has passed that row's persisted
`idle_expires_at`, startup fails with `urn:chio:error:kernel:clock-expired`.
The row is retained, so every later restart fails the same way until an
operator deletes it by hand. Persisted expiry is refreshed only every few
seconds, so it trails the in-memory value. A busy service is therefore likely
to hold at least one such row after any restart gap. A host whose clock comes
back behind a row's `last_seen_at` fails the same way with `NotYetValid`.

At the base, `new` built no deadline and `cleanup_due_sessions` expired these
sessions after restore. The unit test
`restored_session_rebuilds_deadline_without_reviving_expired_or_future_state`
(`tests/clock_custody.rs:180-204`) asserts the first link,
`RemoteSession::new` returning `Expired`. The recovery tests in
`session_recovery.rs` stub the restore closure. Nothing composes a persisted
expired row with startup. The record's claim "session state is persisted before
live authority is published" (`remote-lifecycle-acp-native-ci-execution.md:17`)
is true and does not cover restart.

Fix: in `restore_persisted_sessions`, treat `Expired` from restore as proof of
expiry. Write the terminal fence and tombstone (or delete the row) and
continue. Keep refusing startup for outages and for `NotYetValid`, which
indicates a clock fault rather than an expired session. Also filter expired
rows before the upstream launch in `restore_session`, so expiry does not spawn
a process that is then dropped. Add a startup test that seeds an expired Ready
row.

**Confidence:** Confirmed. The first link is asserted by a passing unit test; the composition is an unambiguous trace from `restore_session` to the serve entry's `?`.

**Independent verification:** Confirmed, High. The loader (`session_store.rs:704-788`) and
`validate_resume_record_integrity_with_keyring` (`session_resume.rs:809`) do not check idle
expiry, and serve calls the restore with `.await?` (`http_service.rs:78-81`), so startup aborts
before `cleanup_due_sessions()` runs. Only crashes leave Ready rows, because graceful shutdown
closes them (`ledger.rs:147`); a backward wall-clock step fails the same way with `NotYetValid`.
The fallible constructor came from `cacaf69fc9`; the fatal-on-error restore predates the range
(`7e54c14a60`). No existing test restarts after expiry.

## PB2. Medium: unsigned peer and operator documents are decoded with the signed-record numeric contract, so valid JSON from ordinary serializers is rejected

The batch moved protocol readers onto `UntrustedJsonText`, and most chose
`decode_signed`. That contract
(`crates/core/chio-core-types/src/canonical/untrusted.rs:66-71`) is
"lossless native signed JSON, before the owner's signature and authorization
checks". Besides rejecting duplicate keys it runs `validate_number_tokens`
(`canonical/signed_json.rs:108-150`). That function rejects any number token
whose spelling differs from both serde_json's ryu rendering and the JCS
rendering of the parsed value. The workspace does not enable
`arbitrary_precision` (`Cargo.toml:394`), so the check is live.

It is applied to documents that are neither signed nor authoritative:

- provider SSE data frames, shared by every provider adapter
  (`crates/protocol/chio-provider-adapter-core/src/sse.rs:220-226`);
- OpenAI chat-completion responses, Responses envelopes and kernel `ToolResult`
  payloads (`crates/protocol/chio-openai-adapter/src/input.rs:10-12`, reached
  from `adapter.rs` `parse_payload`, `response_body`, `parse_tool_result` and
  `transport.rs:193`);
- JSON OpenAPI specifications (`crates/protocol/chio-openapi/src/input.rs:21-26`);
- MCP client and upstream frames
  (`chio-mcp-edge/src/runtime/framing.rs:25-31`,
  `chio-mcp-adapter/src/framing.rs:29-35`) and remote MCP POST bodies
  (`chio-mcp-remote/src/input.rs:15-19`, used at `http_service.rs:311`).

Each scenario below is traced through `validate_number_tokens`. An operator's
JSON OpenAPI spec containing `"example": 10.00` is refused: the value renders
as `10.0` under ryu and `10` under JCS, so the original spelling matches
neither, and the error is `urn:chio:error:attest:signed-json-invalid-input`.
The same spec written as YAML is accepted, because the YAML path
(`input.rs:81-85`) takes any finite float.

A Python tool or provider that emits `json.dumps(1e-05)` (`1e-05`, where ryu
and JCS both give `0.00001`) fails the entire SSE stream, tool result or MCP
request. So does `-6.704273e-07` (both give `-6.704273e-7`). A remote MCP
client sending `2.50` receives -32700. Whether a particular hosted provider
emits these spellings is the one link not traced; the parser behavior is not
in doubt.

The repository already has the right contract. `decode_document`
(`untrusted.rs:55-64`) rejects original duplicate keys, keeps full-width
integers through the same `StoredValue` visitor, and applies ordinary float
coercion. The plan required "provider arguments must be I-JSON objects; signed
native envelopes retain u64 values". It did not ask for signed-record spelling
rules on provider responses, tool results, OpenAPI documents or JSON-RPC
frames. No test feeds a non-canonical float to any of these readers.

A related narrowing is not recorded. OpenAI tool arguments now go through the
strict I-JSON entry point (`chio-openai-adapter/src/input.rs:14-20`), which
also refuses integer-valued float tokens such as `0.0` and `5.0`
(`canonical.rs:150-160`). That is stricter than I-JSON and denies model
outputs that were accepted before. It may be intended for signing safety, but
`protocol-authority-boundaries-execution.md:16-17` does not mention it.

Fix: use `decode_document` for unsigned peer, provider and operator documents,
and keep `decode_signed` for records whose signature is verified downstream.
Add one non-canonical-float case per reader.

**Confidence:** Confirmed. Unambiguous source trace through `validate_number_tokens`; only provider emission frequency is unverified.

**Independent verification:** Confirmed, Medium. The `decode_signed` sites are `sse.rs:219-226`
(used by the anthropic, openai, cohere and gemini streams; previously `serde_json::from_str`),
`chio-openai-adapter/src/input.rs:10-12`, `chio-openapi/src/input.rs:21-27` (JSON only; the YAML
path is lenient), and the MCP frame readers `chio-mcp-adapter/src/framing.rs:29-33`,
`chio-mcp-edge/src/runtime/framing.rs:25-29` and `chio-mcp-remote/src/input.rs:15-19`. Measured
with a probe: `decode_signed` rejects `10.00`, `0.50`, `1e-05` and `1e-5`. The same verification
confirmed the sibling finding PR1 in the product, CLI and provider readers review, where
`canonicalize` rejects the complementary spellings `21.0` and `0.0`.

## PB3. Medium: any clock fault, including a wall-clock step backward, ends every live MCP edge session at its next idle poll

`ChioMcpEdge::serve_inbound_loop`
(`crates/protocol/chio-mcp-edge/src/runtime.rs:420-482`) calls
`service_background_runtime_with_channel(...)?` after every message and on
every 25 ms idle timeout (`runtime.rs:92`, `:472-475`). That calls
`process_background_tasks_with_channel`, whose loop reads the clock through
`prune_expired_tasks()?` before checking whether any task is pending
(`runtime/tasks.rs:608-614`). The `ClockError` converts to
`AdapterError::Clock` (`chio-mcp-edge/src/lib.rs:159`), and the `?` chain
returns from the serve loop.

Scenario: the host wall clock steps back one second (NTP step, VM resume).
`SystemClock` (`chio-security-types/src/clock/system.rs:13-29`) and the kernel
fence (`chio-kernel/src/kernel/clock.rs:38-49`) both return
`WallClockRegression` until wall time passes the old high-water mark. Within
25 ms every stdio edge returns `Err`, and so does every remote session's edge
thread (one `serve_message_channels` per session,
`session_core/factory.rs:406`, `:605`). Sessions with no task at all end too.
Before `53858afa39`, pruning was infallible.

The record says "clock faults preserve pending work without dispatching it"
(`protocol-authority-boundaries-execution.md:37`). The unit test
`protocol_boundary_clock_fault_keeps_pending_work_unexecuted`
(`runtime_tests/protocol_boundaries.rs:94-113`) shows the function returns
`Err` without dispatching. It never drives the serve loop, which then discards
that pending work along with the session. Refusing a time-dependent effect on a
clock fault is correct. Ending the session on an idle tick is not required by
any authority rule.

Fix: in the background service path, treat a clock fault as "dispatch nothing
this tick" and keep serving. Fail only requests that need a time decision.
Skip the clock read when nothing is pending. Add a serve-loop test with a
faulting clock.

**Confidence:** Confirmed. Step-by-step trace from the idle-timeout arm to the loop's return.

## PB4. Medium: per-session remote MCP input is unbounded in aggregate, and nested-flow waits on the client have no deadline

The batch bounded each frame and body but not what a session can accumulate.
Remote POSTs are capped at 8 MiB each. Notifications bypass the per-session
request lock: `try_lock_owned().ok()` and then `session.send(message)`
regardless (`chio-mcp-remote/src/remote_mcp/http_service.rs:405-406`).
`send` writes to an unbounded std `mpsc` (`session.rs:57-61`; channels
created at `factory.rs:406` and `:605`). The edge pump moves them into a
second unbounded channel (`chio-mcp-edge/src/runtime/protocol/messaging.rs:131-150`).

While the edge thread is in a nested flow, `next_client_message` blocks in
`client_rx.recv()` with no timeout (`messaging.rs:74`). Every method-bearing
message is pushed onto an unbounded `deferred_client_messages` vector
(`runtime/nested_flow.rs:246`, `runtime_flow.rs:272`).

Scenario: an authenticated client starts a tool call that issues a sampling or
elicitation request, or simply a slow tool. It never answers the nested
request, and it posts 8 MiB notifications. The only limit is 600 requests per
60 s per source IP (`rate_limit.rs:16-17`), so one address can queue up to
about 4.8 GiB of request bodies per minute in the shared server, more once
parsed. The blocked edge thread cannot expire anything. Idle expiry in the
reaper (`session_core/ledger.rs:98-145`) removes the ledger entry, but
`input_tx` lives inside `RemoteSession`. Open POST or GET streams hold
`Arc<RemoteSession>`, the blocked writer co-owns the broadcast sender those
streams wait on, and `request_timeout` is `None` (`http_service.rs:156`).
Whether that cycle survives every client behavior was not executed.

The unbounded channels predate the batch, but the plans claim bounded ingress
and finite dispatch deadlines for exactly these owners. Fix: give each session
a bounded inbound queue with rejection on overflow, and bound the deferred
vector. Put the nested-flow wait under the request's or task's deadline.

**Confidence:** Confirmed for unbounded queueing and the missing deadline (source trace); the memory figure is computed, not executed.

## PB5. Medium: the A2A task registry bounds its reads but not its writes, so growth past 16 MiB stops the adapter from starting

`53858afa39` changed `A2aTaskRegistry::load` to read at most 16 MiB plus one byte
and reject larger files
(`crates/protocol/chio-a2a-adapter/src/task_registry.rs:98-107`). `save`
(`:134-158`) writes pretty JSON with `fs::write`, with no size check and no
atomic rename. Every peer-reported task ID gets a record, stored twice as map
key and `taskId` field (`:261-276`). Task IDs are checked only for being
non-empty (`discovery.rs:461-518`). There is no eviction or TTL.

Scenario: a partner returns long task IDs, or ordinary use accumulates tens of
thousands of tasks. The file passes 16 MiB, and every subsequent `load` fails
with `TooLarge`. That breaks `validate_follow_up` and `record_task_activity`,
and `A2aAdapter::discover` too, since it opens the registry (`invoke.rs:93-97`).
It stays broken until someone deletes the file. A crash during `fs::write` can
also truncate the file into an undecodable state.

Neither A2A crate has a production consumer in this workspace (tests,
conformance and examples only), which bounds the impact. Fix: cap task-ID
length on observation, refuse to save beyond the read bound, evict by
`last_seen_at`, and write through a temporary file and rename.

**Confidence:** Confirmed. Source trace of read bound, unbounded write and absent eviction.

## PB6. Medium: redaction meant for peers was applied to operator-local diagnostics, so errors are erased or misdirected

`55e7439da3` gave every `ComplianceCertificateError` variant the display
`urn:chio:error:attest:receipt-signing-failed`
(`crates/protocol/chio-acp-proxy/src/compliance.rs:41-160`). That includes
`EmptySession`, `BudgetExceeded`, `ScopeViolation`, `GuardBypass`,
`ChainDiscontinuity`, `TenantMismatch` and `UntrustedKernelKey`. `chio cert
generate` wraps it under the same code (`crates/products/chio-cli/src/cert.rs:44-55`).
`write_cli_error` (`cli/dispatch/output.rs:3-29`) prints only the registry
summary and suggested fix.

So an operator whose session exceeded its budget is told to "repair the signing
key, key store, or canonical payload". The same commit made `OpenApiError`
display one generic code for every variant and set `Debug` equal to `Display`
(`crates/protocol/chio-openapi/src/lib.rs:26-68`). `MissingField`,
`UnresolvedRef`, `UnsupportedVersion` and `InvalidSpec` carry their detail as
plain `String`s with no `source`, so no log or debug surface can show which
field or `$ref` in an operator's spec is wrong.

These are local operator surfaces over operator-owned data. The plan limited
redaction to public errors ("local errors retain native sources while public
errors omit input and filesystem secrets"). Tests match on variants and never
on what the operator sees. Fix: register distinct codes, or give each
compliance violation a static public message. Keep the OpenAPI detail in a
retained source or a redacted-by-default diagnostic that local callers can
print.

**Confidence:** Confirmed. Direct reading of the error definitions and the CLI print path.

## PB7. Low: peer-facing errors still carry peer input and internal text on A2A, remote MCP and ACP

The enforced-native plan, task 2, requires "redacted external errors".
`A2aEdge::jsonrpc_error_response` (`crates/protocol/chio-a2a-edge/src/edge.rs:297-311`)
reduces only `UntrustedInput`, `TaskCapacity` and `Clock` to codes.
`ToolNotFound` and `InvalidRequest` go out verbatim, which echoes the
peer-supplied skill ID and the list of qualified IDs at `:287-294`. All other
variants go out as `other.to_string()`, including kernel and bridge errors.

Remote MCP returns `spawn_session` error text, including policy and
native-launch detail, to the peer (`http_service.rs:580`). It also returns
negotiation detail (`:571`) and the body-read error (`:1064`). ACP sends kernel
deny reasons to the agent verbatim (`chio-acp-proxy/src/interceptor.rs:765-780`).
The remote-lifecycle record's "wire responses stay redacted" (line 19) holds
only for parser, transport and checker causes. Fix: map these to registered
codes and keep the text as a local source.

**Confidence:** Confirmed. Direct reading of each mapping.

## PB8. Low: A2A envelope-stage rejections keep no local cause, and invalid notifications vanish

Rejections for bad envelopes, non-object params and unknown methods are built
at `chio-a2a-edge/src/jsonrpc.rs:11-42` and `edge.rs:640-668` without the
local error sidecar. A batch array, or a message with no `id` whose `jsonrpc`
or `method` is invalid, produces no wire response and no local error. The
record's "A2A notifications retain their local failure sidecar"
(`enforced-native-protocol-boundaries-execution.md:15`) is true only for
errors raised during dispatch. Fix: attach the sidecar at the envelope stage.

**Confidence:** Confirmed. Source trace of the envelope paths.

## PB9. Low: the one production network caller of the OpenAPI parser was not migrated to the byte boundary

`chio-api-protect` discovers specs from the upstream (`spec_discovery.rs:55-83`).
It buffers up to the egress contract's 64 MiB (`:12`), converts to `String`,
and passes `&str` to `OpenApiSpec::parse` (`proxy/state.rs:478`), which
applies the 8 MiB bound only after that allocation. The record claims the
bridge, fuzz and "actual conformance callers" use the new boundary
(`native-consumers-acp-errors-openapi-execution.md:48-50`). This caller is
none of those, and the plan named only those. Fix: set the discovery contract's
`max_response_bytes` to `MAX_OPENAPI_BYTES` and pass bytes.

**Confidence:** Confirmed. Source trace.

## PB10. Low: the ACP capability-check error path does not clear the request's capability context

Before `cacaf69fc9` a capability-check error produced a Block response, and the
Block arm calls `clear_request_capability_context`. Now `CapabilityGate::Error`
returns `Err` without clearing (`chio-acp-proxy/src/interceptor.rs:319`,
`:372`, `:425`, `:542`). A later request for the same `toolCallId` that
carries a malformed token could find an earlier live context still in place.
Whether the caller tears down the connection on that `Err` was not traced.

**Confidence:** Plausible. The asymmetry is in source; the downstream consequence is not traced.

## PB11. Low: stale documentation and dead dependencies left by removed paths

- `crates/protocol/chio-mcp-edge/ARCHITECTURE.md:102` still says "a full task
  table prunes terminal tasks before rejecting new ones". `68fb96f436` removed
  that pruning.
- `chio-cross-protocol/Cargo.toml:18` (`futures`) and `:22` (`tokio`) are
  unused after `sync_bridge_shared.rs` was deleted.
- `chio-cross-protocol/ARCHITECTURE.md:74-77` still documents
  `block_on_tool_server_invoke`.
- `docs/security/consumer-support.md:137` (row P04) still says "Compatibility
  passthrough is separately feature-gated".

**Confidence:** Confirmed.

## PB12. Low: process vocabulary in test names

Six tests are named `review_regression_*`. They are at
`chio-a2a-adapter/src/tests/oauth_cache_review.rs:57,91`,
`chio-mcp-adapter/src/transport/nested_flow_tests.rs:131`,
`stdio_writer_tests.rs:47`, and
`chio-mcp-edge/src/runtime/runtime_tests/protocol_boundaries.rs:131,155`. The
module `oauth_cache_review` (`chio-a2a-adapter/src/tests.rs:37-38`) has the
same problem. The house rule forbids review and process vocabulary in code.
Rename each test for the property it proves.

**Confidence:** Confirmed.

## PB13. Low: A2A adapter types derive `Debug` over secrets (pre-existing, left in place)

`A2aAdapter` (`chio-a2a-adapter/src/invoke.rs:1-2`) and the credential types in
`config.rs` derive `Debug`. They print `client_secret`, cached `access_token`
values and `private_key_pem` (`config.rs:21-38`). `53858afa39` hand-wrote a
redacting `Debug` for `AdapterError` and edited both files without fixing
these. No logging of these values was found; the risk is the next `{:?}`.

**Confidence:** Confirmed for the derive; no current leak site found.

## PB14. Low: a failed A2A deferred task is dispatched again on the next `task/get` (pre-existing)

At `chio-a2a-edge/src/edge.rs:797-809`, an orchestrator error leaves the task
`Working`, so the next `task/get` (`:751-753`) runs the stored request again
under the same request ID. The ACP sibling was changed to mark the task
`Failed` without redispatching (`chio-acp-edge/src/edge.rs:846-862`). The open
question is whether the kernel can fail after the effect without deduplicating
the retry.

**Confidence:** Plausible.

## Notes

- Counter exhaustion is reported as `ClockError::Overflow` in the MCP edge
  (`tasks.rs:168-174`), the MCP adapter (`nested_flow.rs:227-233`) and the A2A
  adapter (`discovery.rs:558`). A counter is not a clock. A dedicated error
  would keep the clock-fault code meaningful.
- The A2A SSE stream total is clamped twice (`chio-a2a-adapter/src/transport.rs:31`,
  `:39`). The effective cap is 1 MiB, not the 16 MiB the record states for
  A2A streams (`protocol-authority-boundaries-execution.md:19`). That is
  stricter, not looser.
- The shared provider SSE parser retains each frame's raw bytes and parsed
  `Value` together. A 16 MiB stream of small-element arrays can expand to
  roughly 16 times that in memory. This is bounded, and below the threshold
  for action.
- `chio-acp-edge`'s kernel-less permission preview (`edge.rs:347`) and the
  default `MessageInterceptor`/`chio cert` constructors read `SystemClock` rather
  than an injected clock. `SystemClock` is the fenced adapter, so this is
  acceptable, but those paths cannot be time-tested.
- The remote rate limiter now scans all 4,096 windows on every request
  (`rate_limit.rs:51-57`). The local OAuth approval endpoint is unauthenticated
  and outside the limiter; its new 4,096-code cap (`local_server.rs:224`) turns
  growth into lockout. That surface is development-only.

## Execution-record claims checked

| Claim (record:line) | Verdict | Evidence |
| --- | --- | --- |
| Final campaign passed 889 tests across 58 targets in 13 packages (protocol-authority:55-56) | True | `review-suite.log.gz`: 58 `test result` lines summing to 889 passed, 0 failed, 0 ignored. |
| All six review regressions failed before repair (protocol-authority:92-93) | True | `review-red.log.gz` shows exactly six `FAILED` tests across the A2A, MCP adapter and MCP edge targets, each at the asserted property. |
| Twenty-two reader-file owners have named contracts (protocol-authority:43) | True | `qualification.json` lists 22 owners. |
| A2A/provider documents and streams capped at 16 MiB (protocol-authority:19-20) | Imprecise | A2A SSE streams are capped at 1 MiB (Notes). |
| Clock faults preserve pending work without dispatching it (protocol-authority:37) | True at unit level, false in composition | The serve loop ends on the fault and drops the work (PB3). |
| Concurrent OAuth regression forces reversed order without sleeping (protocol-authority:95) | True | Channel-ordered test drives the production cache methods; red log shows `WallClockRegression` at `oauth_cache_review.rs:80`. |
| Writer regression proves a healthy command after an expired one still writes (protocol-authority:96) | True | `stdio_writer_tests.rs:46-72` calls the production `run_stdio_writer`; it would fail with the pre-repair `break`. |
| Shadow live discovery rejects before target launch (enforced-native:14) | True | `reference_runtime_provision.rs` `shadow_discovery_refuses_before_executing_the_target` runs the CLI binary and asserts the target's marker file was never written. |
| A2A notifications retain their local failure sidecar (enforced-native:15) | Partly true | Only for dispatch-stage errors (PB8). |
| Remote: five ambient readers moved to a shared fenced clock; state persisted before publish (remote-lifecycle:17) | True, incomplete | Verified at `session.rs:309-391`; restart composition fails (PB1). |
| Ready/touch repair has regressions (remote-lifecycle:41-46) | True | `clock_custody.rs:208`, `:257` drive the real session with SQLite and assert `idle_expires_at` unchanged after overflow. |
| ACP edge 96, ACP proxy 201, remote 98 (remote-lifecycle:64) | True | Matches `owning-tests-5.log`. |
| Wire responses stay redacted (remote-lifecycle:19) | Partly true | Kernel deny reasons and remote spawn errors still reach peers (PB7). |
| Signing validates time before consuming authorization (native-consumers:23-24) | True | `kernel_signer.rs:442-449`; `attestation_clock.rs:30-110` drives the real signer and would fail if the old `SystemTime::now` fallback returned. |
| 513 tests = 98 + 205 + 99 + 59 + 52 (native-consumers:105) | True as recorded, stale for the final source | Matches the log; remote had 101 tests after the later verifier refactor and only 7 focused tests were rerun. The record lists both. |
| Bridge, fuzz and conformance callers use the OpenAPI boundary (native-consumers:48-50) | True for those callers | `chio-api-protect` discovery not migrated (PB9). |

## Verified clean

- **Frame readers do not reinterpret a rejected tail.** The MCP edge and
  adapter readers (edge `framing.rs:35-85`, adapter `framing.rs:39-89`) check the bound before extending
  the buffer and return `TooLarge` without draining. The edge pump stops after
  `TooLarge` (`messaging.rs:98-111`), and the serve loop then sees disconnect.
  The ACP proxy reader poisons on any error and never resyncs.
- **The shared provider SSE parser bounds per-frame bytes before extending**
  (`sse.rs:120-127`), caps frame count, and is fed by a transport that bounds
  total bytes chunk by chunk with a whole-request timeout
  (`provider-adapter-core/src/http.rs:604-627`).
- **A2A OAuth cache.** The key covers scheme, endpoint and sorted scopes, and the
  cache is owned by a single adapter, partner, credential set and tenant, so
  no cross-audience serving is possible. The clock is sampled under the cache
  lock and no lock is held across the network call. Tokens with no or short
  expiry are never cached. Advertised expiry is rechecked at the final
  observation, and arithmetic is checked.
- **MCP edge task custody.** Owner checks run on get, result and cancel. A
  cancelled task never executes, and outcomes are recorded only if the task is
  still non-terminal. Uncollected results are retained to TTL, the TTL is
  capped at 60 minutes, and counters and pagination cannot wrap.
- **Writer deadlines.** An expired queued command no longer disconnects
  healthy commands. The record acknowledges the residual window in which a
  write in progress outlives the caller's deadline.
- **The discovery bypass is closed** in both provisioning entry points, with
  two independent gates. No sibling tool-listing path spawns a target uncaged.
  The remaining `Command::new` sites in protocol crates are test-only or spawn
  the ACP agent, which is not a tool.
- **Compatibility passthroughs** are fully removed from the A2A and ACP
  edges. The no-bypass gate tests reintroduction.
- **Remote principals.** POST, GET and DELETE check the session auth context
  before `touch` or any effect, including for terminal records. Approval,
  credential and admin routes require the admin token, compared in constant
  time. The authorization code is consumed only after PKCE, sender checks and
  signing succeed. The DPoP nonce is recorded last, after the signature check.
- **ACP clock and signer custody.** `AcpClock` clones share one fence. The
  signer validates the clock and event time before verifying or consuming
  authorization, and consumption is in the same store operation as the
  receipt append.
- **House rules.** No em dashes were added in any of the seven commits. No
  `unwrap`/`expect` was added to production code in the slice.

## Recommendations for the remaining plan

1. Repair PB1 before any remote MCP deployment claim: classify expiry on restore
   as expiry, and add a seeded-row startup test.
2. Replace `decode_signed` with `decode_document` at every unsigned reader named
   in PB2. Add the contract choice to the reader census, so the inventory
   records which numeric rule each owner applies, not only that it uses
   `UntrustedJsonText`.
3. Make background clock faults non-terminal in the MCP edge (PB3). Bound
   per-session inbound queues and nested-flow waits (PB4) in the same change,
   because both live in the serve loop.
4. Split operator-local error rendering from peer rendering (PB6, PB7). One
   registered code per refusal class, a local source chain that the CLI can
   print, and a peer mapping that never uses `to_string()`.
5. Treat composition tests as the acceptance bar for custody claims. PB1 and
   PB3 each had a correct unit test whose property did not survive the caller.
   For every "fails closed" claim, add one test that drives the outer loop or
   startup path.
