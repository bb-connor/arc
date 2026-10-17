# chio-external-guards architecture

## Responsibility and boundary

Concrete `ExternalGuard` implementations translate Chio call contexts into
provider requests and provider responses into `Verdict`. Public adapters cover
Bedrock guardrails, Azure Content Safety, Vertex safety, VirusTotal, Safe
Browsing, and Snyk. Provider configuration holds credentials and thresholds.
Evidence helpers create provider-specific decision records for callers.

The crate owns HTTP request/response translation and `ScopedAsyncGuard`, the
synchronous kernel bridge. `chio-guards` owns the generic async adapter, cache,
retry, circuit breaker, and token bucket. The kernel owns authorization,
pipeline composition, dispatch, and receipt signing.

## Structure

`external/mod.rs` reexports infrastructure and concrete adapters.
`bedrock`, `azure_content_safety`, and `vertex_safety` implement cloud checks.
`threat_intel` contains `virustotal`, `safe_browsing`, and `snyk` modules.
`endpoint_security` validates configured URLs and DNS results. `http_egress`
constructs an egress contract, creates its client, and dispatches requests.
`input` centralizes bounded original-JSON readers. `src/lib.rs` contains the
kernel bridge and wildcard matcher.

## Data and control flow

`AsyncGuardAdapter::evaluate` checks the circuit first, then cache, then token
bucket. A cached verdict avoids a provider call and token consumption. An open
circuit returns its configured verdict before checking cache. Rate exhaustion
returns its configured verdict without recording a provider failure.

Provider calls run through the retry helper. Retryable errors can be retried;
permanent errors end that loop immediately. Successful verdicts, including
Denies, record circuit success and are cached when a key exists. Errors record
circuit failure and return Deny. Threat-intelligence adapters return no cache key for invalid argument JSON.
Cloud adapters hash the original argument text and submit it as content.

Cloud adapters evaluate configured severity, action, or probability fields.
Unknown required verdict values and absent required fields reject evaluation.
Safe Browsing accepts an empty matches document as its no-threat response.
VirusTotal compares malicious plus suspicious counts against its threshold;
Snyk evaluates configured severity and upgrade policy.

A VirusTotal 404 with a bounded parsed `NotFoundError` body becomes the
configured unseen verdict. The default is Deny. This is a successful policy
outcome, so it can be cached without increasing the failure circuit. Other
404 shapes, malformed responses, and missing analysis fields remain failures.
Unseen Allow can hide later changes until the configured cache TTL expires.

`ScopedAsyncGuard` copies tool, agent, server, and serialized arguments into a
call context. It blocks on Tokio, using `block_in_place` on multithread runtimes
and a scoped fallback runtime thread for current-thread runtimes. Dispatch
revalidation preserves the admission verdict without consuming adapter state
again. Tool patterns outside the selected scope return Allow.

## Trust and invariants

Threat-intelligence arguments use the bounded signed-JSON reader; all provider
responses use the external-JSON reader. These readers enforce a 1 MiB limit
and duplicate-aware parsing before typed projection. Cloud adapters submit
argument text as content without using the argument reader. These readers validate JSON shape; they do not sign provider data.
Credentials use secret wrappers, and status errors omit provider body text.

Endpoint validation requires HTTPS except explicit loopback HTTP endpoints.
DNS validation rejects disallowed resolved addresses. The shared transport
pins DNS and enforces a contract with one allowed authority, a redirect-chain
ceiling of four, and a response ceiling of 1 MiB. The contract allows loopback
only for a loopback-configured endpoint. Each guard owns a `ContractClient`
built from that contract; no constructor accepts a caller-supplied client.

HTTP 429 and server-error statuses are classified Transient; other unsuccessful
statuses are Permanent, subject to VirusTotal's unseen exception. Contract
send errors, including transport failures returned by the shared helper, map
to Permanent here. URL DNS resolution errors are Transient. Callers must retain
these distinctions when selecting retry and failure handling policies.

## Dependencies

`chio-egress-contract` owns contract-bound reqwest dispatch. `reqwest`, Tokio,
URL parsing, and `async-trait` support transport and async interfaces.
`chio-core-types` supplies original JSON validation and evidence types.
SHA-256 and base64 derive lookup keys and URL identifiers. `secrecy` and
`zeroize` support credential handling; tracing records adapter outcomes.

## Verification

`cloud_guardrails.rs` checks local mocked cloud verdicts and evidence.
`threat_intel.rs` checks mocked lookup outcomes, redirects, and cache reuse.
`reader_boundaries.rs` checks duplicate responses, invalid arguments, unknown
verdicts, and body-safe status errors. `threat_intel/virustotal_outcomes.rs`
checks unseen policies, caching, and circuit behavior. Bridge unit tests cover
current-thread fallback, blank scopes, and non-consuming revalidation.

Run `cargo test -p chio-external-guards`. These are local HTTP mock and unit
tests. Operational upstream compatibility and credential acceptance require
separate verification against the configured services.
