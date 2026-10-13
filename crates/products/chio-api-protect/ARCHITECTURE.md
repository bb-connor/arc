# chio-api-protect architecture

## Responsibility and boundary

The public surface exports `ProtectProxy`, `ProtectConfig`, `RequestEvaluator`,
`RouteEntry`, `EvaluationResult`, approval and retention configuration, spec
loaders, and `ProtectError`. `ProtectProxy` owns startup, the Axum router, shared
state, maintenance tasks, and upstream dispatch. `RequestEvaluator` maps a
method/path to an `HttpAuthorityPolicy` and evaluates it through `HttpAuthority`.
Its ephemeral constructors explicitly select in-memory receipt and revocation
state. Durable constructors require supplied stores unless their explicit
`allow_ephemeral` argument permits memory-backed state.

The upstream API remains responsible for its application behavior. Sidecar
control authority belongs to the operator or trusted tool server. Capability
subjects retain their signing keys. Caller execution needs a separately pinned
executor; installing an ordinary approval configuration also installs that
identity. Budget and receipt custody are local deployment resources.

## Structure

- `lib.rs` re-exports the supported library entrypoints; `error.rs` defines errors.
- `evaluator.rs` wraps HTTP authority. `evaluator/route_matching.rs` selects local
  routes and rejects ambiguous encoding; `diagnostics.rs` records parse categories.
- `spec_discovery.rs` provides public text acquisition and upstream egress policy.
- `proxy/state.rs` builds stores, kernels, transport, and task ownership.
  `proxy/config.rs` declares operator settings; `spec_authority.rs` binds policy
  to document bytes, local pin status, anonymous-read policy, and guard profile.
- `proxy/router.rs` mounts helper endpoints and the catch-all upstream handler.
  `sidecar.rs`, `control.rs`, `input.rs`, `http.rs`, and `receipts.rs` implement
  helper routes, credential gates, bounded decoding, HTTP projection, and signing.
- `proxy/mediated.rs` builds the retained pre-execution kernel; its `authenticated`
  module handles trusted caller start/report and `budget_configuration` chooses
  available budget authority. `approval.rs` and `approval_authority.rs` handle
  execution-bound approval workflows. `attenuation.rs` refuses server-side delegation.
- `proxy/evidence.rs` writes the shared receipt sink; `retention.rs` owns explicit
  archive maintenance. Admission maintenance under `proxy/state/` reaps abandoned
  reservations and reports worker health.

## Startup and policy flow

`run_with_observer` prepares listener transport, validates mutually exclusive spec
sources and any SHA-256 pin, checks control-token syntax, and rejects absent or
in-memory receipt stores unless explicitly permitted. Durable signing requires
an existing custody file; an inline seed conflicts with that file and is accepted
only for ephemeral embedding. Durable admission opens a sibling authority DB
under `<receipt-path>.authority-locks`, with a private lock directory. The serving
owner gate requires Unix support for file identity and locking. Signing custody
is loaded separately through the control-plane existing-key loader.

Startup reads a local spec through a byte-bounded loader or discovers it through
four upstream probes. It parses routes and `x-chio-*` extensions before binding
the listener. Policy-relaxing side-effect overrides require a local exact-byte
pin. `routes_from_spec` always uses unpinned policy. The public
`load_spec_from_file` helper uses `read_to_string` directly; parsing and bounds
are supplied by its caller. Auto-discovery collects at most `MAX_OPENAPI_BYTES`
through the HTTP egress contract and returns unparsed text.

The HTTP evaluator independently matches method and path, including when a
sidecar caller supplies a route pattern. Anonymous reads require local opt-in on
matched `SessionAllow` routes. Unmatched paths deny. Route specificity favors
exact segments; equally specific overlaps favor restrictive policy. Encoded and
decoded paths must select the same route, with separators, nested escapes,
controls, and dot segments rejected.

## Requests, execution, and evidence

The upstream handler first scans original headers for the reserved control
credential. It rejects duplicate decoded query keys and bounds request bodies
at 10 MiB. It projects caller credentials and a presented capability, consults
revocation state, then evaluates. Only `Verdict::is_allowed` enters dispatch.
The authority contract pins the upstream scheme and authority, bounds redirects
at four and responses at 64 MiB, and applies address restrictions with pinned DNS.
Loopback upstreams require an explicitly loopback upstream host.

The upstream client has a configurable full-hop timeout, defaulting to 20
seconds, with no application retry. Successful responses and upstream failures
finalize signed HTTP status and record evidence before returning. Early invalid
input and authentication failures can terminate before receipt creation.
The shared receipt sink converts HTTP receipts into signed `ChioReceipt` records
with a 5-second append budget. Store failure produces an error response.

`POST /chio/evaluate` evaluates HTTP authority without forwarding upstream.
`POST /v1/evaluate` uses one retained kernel with default runtime guards, approval
and DPoP replay state, strict execution nonces, and budget holds. It requires
durable local admission, a configured control credential, and an operator-pinned
executor. Reservation returns a non-executable acknowledgement without dispatch
or payment-rail operations. External budget authorities are rejected at startup
so reservations share the local authority transaction.

Control-gated `/v1/caller/start` commits the original durable reservation and
returns a signed authorization bound to the pinned executor. The executor
independently verifies that authorization and claims the original operation in
its durable execution ledger before an effect. `/v1/caller/report` authenticates
the exact original commitment and signed executor report, restores the retained
request and caller context, and resumes finalization without admission or
dispatch. Only kernel guard-evaluated output and the resulting signed receipt
return to the caller. Conflicting reports fail closed; duplicate reports reuse
the original completion.

Durable approved retries may present their operation-bound nonce. Ordinary
approvals pin an already activated replay source and approver roster. Loading
configuration activates no source. Threshold collection requires an operator
context resolver; direct threshold tokens and proposals remain rejected on
`/v1/evaluate`, as does supplemental authorization without a verifier. Prepayment
requires a configured payment adapter and authenticated caller start.

## Trust and lifecycle invariants

Control credentials authenticate capability lifecycle, approval workflows,
receipt submission, caller start/report, and metrics independently of peer address.
Nonempty configured credentials use RFC 6750 token syntax with a 512-byte limit.
The proxy's 64 KiB aggregate header scan rejects control-token bytes before
mediation and egress. Public liveness, verification, and independently authorized
evaluation routes do not acquire operator authority.

Capability issuers and receipt signers use separate trust sets. Token validation
checks trusted issuer, signature, validity window, revocation of the token and
chain ancestors, and optional subject matching; concrete-call policy and scope
checks happen at mediation. Receipt verification pins the local signer and checks
signed receipt semantics. Advisory evaluation checks revocation and parameter
hashes, then emits an observation with `TrustLevel::Advisory` and
`authorization: false`. Attenuation returns 403 because the subject signer is absent.

A configured additional revocation DB is read at startup; external changes to
that loaded set require restart or an in-process release channel. Readiness
consults durable receipt-writer health while liveness reports process health.
Shutdown drains for the upstream timeout plus 5 seconds, stops owned maintenance,
and flushes accepted receipt writes. Retention is disabled unless configured;
its validator requires a durable live DB, positive days, a 1-to-86400-second
interval, and a distinct archive destination.

## Dependencies and verification

`chio-openapi` parses documents and classifies routes; `chio-http-core` supplies
HTTP authority, receipts, and contracted egress; `chio-kernel` supplies admission,
guards, replay, budgets, and caller delivery. `chio-store-sqlite` persists receipt,
approval, revocation, and admission state. `chio-control-plane` and
`chio-http-serve` supply custody loading, listener transport, hygiene, and drain.
Axum, Tokio, and reqwest provide routing, task ownership, and upstream I/O.

`cargo test -p chio-api-protect` exercises the crate's tests.
`tests/openapi_extension_policy.rs` checks restrictive classification, invalid
extensions, and rejection before listener activation. Proxy test modules cover
control credentials and containment, encoded routes, signer trust, receipt
redelivery, readiness, upstream errors/timeouts, and producer numbers. Mediated
tests cover authorization, approvals, authenticated caller delivery, finalization,
and default guards. These tests exercise local authority and loopback fixtures;
production composition needs deployed custody, TLS, persistent stores, and an
independently configured execution site.
