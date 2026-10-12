# chio-guards architecture

## Responsibility and boundary

The public surface supplies concrete `Guard` implementations, `GuardPipeline`,
`RuntimeGuardProfile`, sanitizers, advisory types, and async external adapters.
A guard receives a borrowed `GuardContext` and returns a `GuardDecision` or
`KernelError`. Guard configuration and internal state belong to each guard.
The kernel owns capability validation, dispatch, approval adjudication, receipt
signing, and durable stores.

Constructing a guard does not install it. Callers select the request guards and
post-invocation pipeline for their runtime. Session-aware guards require the
journal supplied through the context; finding governance uses supplied lineage
and authenticated status resolvers.

## Structure

`lib.rs` exports the guard types and builds default runtime material.
`pipeline.rs` composes request guards and forwards dispatch revalidation and
output-release validation to children.
`action.rs` and `action/extractor.rs` decode tool arguments into `ToolAction`;
`path_normalization.rs` supplies lexical and filesystem-aware path matching.

Filesystem, shell, egress, MCP, secret, and patch modules implement individual
request checks. `velocity.rs` and `agent_velocity.rs` own bounded token buckets.
`data_flow.rs` and `behavioral_sequence.rs` consume session history.
Computer-use, remote-desktop, browser, code-execution, content-review, and
memory-governance modules inspect their corresponding action classes.
Detection and advisory modules supply signals and configurable promotion.

`response_sanitization/` separates detection, validators, overlap handling,
formatting, strategies, and token storage. `post_invocation.rs` supplies
`SanitizerHook` and reexports the kernel's post-invocation pipeline types.
`external/` separates adapter orchestration, retry, cache, token bucket, and
circuit breaker state.

## Data and control flow

`GuardPipeline::evaluate` visits guards in insertion order and appends evidence.
Allow continues. Pending approval is sticky and continues evaluation. Deny or
error returns immediately with accumulated evidence and a denial record.
An empty pipeline allows. `Default` constructs that empty pipeline.

`default_pipeline()` constructs exactly seven guards: forbidden path, shell
command, egress allowlist, path allowlist, MCP tool, secret leak, patch integrity.
The runtime profile is assembled separately: internal network with rebinding
checks enabled, agent velocity, advisory pipeline, and an output sanitizer hook.
Default agent/session rate thresholds are unset; default advisory detectors are
empty. Installing those defaults alone does not activate every exported guard.

The sanitizer traverses JSON values, redacts detected strings, and preserves
JSON structure. Hook evidence summarizes detector counts. External adapters
consult circuit, rate limit, and cache state around async evaluation and retry;
service errors yield deny after retry handling.

## Trust and invariants

Pipeline errors become explicit deny decisions. Dispatch and release callbacks
propagate errors to the kernel. Conflicting required finding-status feed IDs
produce `KernelError::GuardDenied`.
Rate-limit tables retain live consumed state; full buckets can be pruned, while
capacity exhaustion with live state denies new keys.
External circuit-open and rate-limited verdicts default to deny and expose
explicit allow configuration. Advisory promotion also depends on caller policy.

The runtime profile identity hashes canonical JSON containing ordered guards,
configuration, component versions, and sanitizer identity.
`SanitizerHook::durable_identity` refuses tokenization strategies.
This crate emits evidence; the kernel signs the enclosing enforcement receipt.

Input-file custody checks regular-file metadata and bounds bytes before and
after reading. Unix adds `O_NOFOLLOW | O_NONBLOCK`; other platforms lack those
open flags. Filesystem-aware path normalization resolves existing targets or
parents where possible and otherwise falls back to lexical normalization.
Tool servers remain responsible for filesystem operations and isolation.

## Dependencies

`chio-kernel` provides guard and hook contracts; `chio-core` supplies evidence
and canonical hashing. `chio-security-types` supplies shared security types;
`chio-http-session` supports session-related behavior.
Regex and glob handle configured matching. Serde handles structured inputs;
SHA-256, base64, and random values support hashes and sanitizer strategies.
Tokio and async-trait support async adapters, LRU supports bounded caching, and
libc supplies Unix input-open flags.

## Verification

`pipeline.rs` unit tests exercise error denial, empty allowance, child
revalidation, and output validation forwarding.
`tests/integration.rs` exercises registered guards through a native kernel.
Other integration suites cover code execution, browser automation, content
review, memory governance, prompt injection, jailbreak, and output sanitization.
`tests/external_guard_adapter.rs` exercises adapter behavior; clock tests live
under `external/clock_tests.rs`.

```bash
cargo test -p chio-guards
cargo test -p chio-guards --test integration
```

These commands exercise local guard behavior. Runtime operators choose policy,
context providers, response hooks, and service fallback settings.
