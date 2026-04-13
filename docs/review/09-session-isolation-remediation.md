# Hole 09 Remediation Memo: Session Isolation, Shared Hosting, and Multi-Client Runtime Claims

## Problem

ARC currently has a useful hosted MCP runtime, but its strongest multiple-client
and isolation claims are ahead of the implementation.

The core mismatch is this:

- the hosted edge and kernel are mostly session-scoped
- the optional `shared_hosted_owner` mode reuses one upstream subprocess across
  sessions
- session reuse checks continuity too weakly
- the runtime does not yet define one complete non-interference contract for
  pooled upstreams, privilege drift, or cross-session concurrency

That matters because "multiple clients," "session isolation," and
"hosted runtime ownership broader than one subprocess per session" are not just
feature statements. They are security and semantics statements. To make them
true in a defensible way, ARC must be able to say exactly what is isolated,
what is pooled, when authority may continue, and which concurrency behaviors
are forbidden.

Today ARC can honestly claim:

- one hosted edge can manage multiple ARC sessions
- each ARC session gets its own edge worker, auth context, and capability set
- the default conservative mode remains one wrapped subprocess per session
- there is an opt-in shared-owner path with some regression coverage

Today ARC cannot yet honestly claim, without qualification:

- generic process-deep isolation under shared hosting
- robust session reuse across privilege drift or shrink
- non-interference between sessions sharing one opaque upstream subprocess
- fully specified cross-session concurrency boundaries for pooled upstreams

## Current Evidence

The repo already contains meaningful isolation primitives.

- `crates/arc-cli/src/remote_mcp.rs` creates a fresh `RemoteSession` with its
  own `SessionAuthContext`, per-session capability issuance, per-session event
  bus, per-session lifecycle state, and per-session request-stream lease.
- `RemoteSessionFactory::spawn_session` builds a distinct kernel and edge for
  each session even when the upstream owner is shared.
- `validate_session_auth_context` requires transport continuity and rejects
  obvious principal mismatches on reuse.
- `crates/arc-hosted-mcp/tests/session_isolation.rs` proves cross-tenant and
  cross-subject session reuse denial and shows receipt attribution stays
  separated across sessions.
- `crates/arc-cli/tests/mcp_serve_http.rs` includes a shared-owner regression
  showing one upstream subprocess can be reused while basic task ownership and
  cross-session cancel boundaries still hold.
- `RemoteSession` already tracks request-stream exclusivity and notification
  attachment, and the remote lifecycle surface exposes that ownership state.
- `docs/epics/E10-remote-runtime-hardening.md` and
  `docs/epics/E11-cross-transport-concurrency-semantics.md` already identify
  broader hosted ownership and one coherent ownership model as architectural
  goals, not finished invariants.

The same code also shows the exact gap:

- `SharedUpstreamOwner::new` starts one wrapped stdio subprocess and shares the
  resulting `AdaptedMcpServer` across sessions.
- `notification_tap` fans out one shared notification stream into per-session
  queues, but there is no proof that upstream notifications are session-safe or
  even meaningfully attributable when the upstream is opaque and stateful.
- `validate_session_auth_context` accepts OAuth session reuse when
  `principal`, `issuer`, `subject`, and `audience` match, while ignoring
  `scopes`, `client_id`, `tenant_id`, `organization_id`, `groups`, `roles`,
  and the richer `enterpriseIdentity` payload already stored in
  `SessionAuthContext`.
- `derive_session_agent_keypair` falls back to a fresh random key unless
  identity federation seed configuration is present, which weakens stable
  continuity semantics.
- the current tests do not prove absence of state bleed through a shared
  stateful upstream, do not prove privilege-shrink denial for same-principal
  token refresh, and do not establish a complete concurrency contract for
  pooled upstream ownership.

In other words: ARC already has session-scoped control-plane state, but not yet
an end-to-end hosted isolation model.

## Why Claims Overreach

### 1. Shared subprocess reuse is not the same thing as shared-hosting isolation

`shared_hosted_owner` currently means "reuse one upstream subprocess." That is
an optimization and ownership choice, not a proof of safe multitenancy.

For a generic wrapped stdio MCP server, ARC cannot infer:

- whether tool-server memory is partitioned by session
- whether cached state, globals, background tasks, or environment mutations can
  leak across sessions
- whether notifications are attributable to one logical session
- whether one session's cancellation, timeout, or backpressure can perturb
  another session's execution

Without either process isolation or a strong session-virtualization contract,
shared subprocess ownership cannot justify strong isolation claims.

### 2. Session reuse currently checks identity continuity, not authorization continuity

The current reuse check is intentionally narrow. That keeps obvious cross-user
reuse out, but it does not prove that the resumed session still matches the
security context under which the session was created.

The missing comparisons are the ones that matter for privilege drift:

- scopes
- client identity
- tenant and organization context
- groups and roles
- subject-key continuity
- token family or sender-constraint continuity
- policy epoch or capability-issuance epoch

This means a same-principal token with narrower or otherwise changed authority
can still look "continuous enough" to reuse an already-privileged session.

### 3. Current isolation is wrapper-deep, not provider-deep

ARC's per-session kernel and eventing layers are meaningful, but if two
sessions share the same opaque upstream process then the strongest security
property is still determined by the upstream process boundary.

This is the key systems point:

- ARC can isolate what it owns
- ARC cannot claim non-interference for state it cannot namespace, reset, or
  verify

That makes the current shared-owner story a bounded multiplexing feature, not a
general hosted-isolation theorem.

### 4. Concurrency semantics are only partly frozen

Per-session request-stream ownership exists. Cross-session task lookup denial
exists. GET/SSE attachment rules exist. But the current design still lacks one
complete answer to these questions in shared-host mode:

- can two sessions drive concurrent upstream calls safely if the upstream is
  not itself session-aware?
- what upstream messages are session-owned, globally owned, or broadcast by
  design?
- what happens when one session stalls the shared subprocess?
- what is the fairness or starvation contract across sessions?
- when are cross-session interleavings forbidden rather than best effort?

Until those boundaries are frozen, the runtime should not talk as if broader
hosted ownership is already a finished hard security property.

### 5. "Multiple clients" is too broad unless the isolation profile is named

There are at least three materially different runtime shapes:

- one session per subprocess
- multiple ARC sessions over one shared but truly session-virtualized upstream
- multiple ARC sessions over one legacy opaque subprocess

Those do not support the same claim language. Today the docs often treat them
as if they do.

## Target End-State

ARC should target an explicit hosted-isolation model with named deployment
profiles and claim discipline tied to those profiles.

### Security goal

For any two live sessions `S1` and `S2`, ARC should be able to argue:

- authority continuity for `S1` depends only on `S1`'s current authenticated
  security snapshot and ARC-issued continuation state
- operations in `S1` cannot mutate, observe, cancel, or inherit `S2`'s session
  state except through an explicitly shared, declared, externally visible
  resource
- pooled-host execution does not create hidden cross-session channels beyond
  the declared isolation contract

This is a non-interference target, not just a feature checklist.

### Required deployment profiles

ARC should define three explicit hosted profiles.

#### Profile A: Dedicated Session Runtime

- one upstream process or one isolated runtime instance per ARC session
- strong session-isolation claims allowed
- default for generic wrapped stdio servers

#### Profile B: Verified Multi-Session Runtime

- multiple ARC sessions may share one host process
- only allowed when the upstream implements ARC's session-virtualization and
  concurrency contract
- strong multi-client isolation claims allowed only for this profile

#### Profile C: Legacy Shared Owner Compatibility

- current `shared_hosted_owner` shape
- allowed only as a compatibility/performance mode
- docs must not attach strong isolation language to it

If ARC wants the broader claim to become true, it must move serious deployments
from Profile C to either A or B.

### Required session-continuity model

Session reuse must become a cryptographic or policy-backed continuity contract,
not a heuristic principal match.

The end-state should require:

- immutable session security snapshots
- explicit auth/context epochs
- exact-match reuse by default
- explicit rebinding or successor-session handoff when privileges change
- capability re-issuance on any material security drift

### Required concurrency model

ARC needs one documented statement of:

- which entity owns work
- which entity owns result streams
- which entity owns notification streams
- which operations may run concurrently inside one upstream
- how fairness, backpressure, and cancellation behave in pooled mode
- which upstreams are ineligible for pooling

Without that, "broader hosted ownership" remains an operational aspiration, not
an honest platform guarantee.

## Required Hosting/Session Changes

### 1. Introduce explicit hosted isolation profiles

Replace the current binary `shared_hosted_owner` story with an explicit runtime
policy such as:

```rust
enum HostedIsolationProfile {
    DedicatedPerSession,
    VerifiedMultiSession,
    LegacySharedOwner,
}
```

Then bind behavior and docs to that profile:

- `DedicatedPerSession`: strongest claims allowed
- `VerifiedMultiSession`: strong shared-host claims allowed if the provider
  contract is satisfied
- `LegacySharedOwner`: compatibility only; no strong isolation claims

This is the first step because it prevents future docs from collapsing
incompatible security models into one sentence.

### 2. Make dedicated isolation the required default for generic wrapped stdio servers

For opaque wrapped stdio MCP servers, ARC should assume the upstream is not
safe to pool.

That means:

- generic wrapped stdio remains one process per session
- `LegacySharedOwner` stays opt-in and heavily caveated
- strong multiple-client isolation wording must point to
  `DedicatedPerSession`, not to generic shared hosting

This is not a retreat. It is the only defensible claim boundary unless the
upstream participates in virtualization.

### 3. Define a verified multi-session upstream contract

If ARC wants true shared-host scalability without losing isolation, it needs a
new upstream contract. For pooled hosting, the provider must become
session-aware.

Minimum contract requirements:

- every stateful upstream operation is namespaced by a logical upstream session
  id
- every notification/event is attributable to exactly one session or explicitly
  declared as global
- upstream caches, roots, prompt/resource state, task state, and cancellation
  domains are session-scoped
- the provider can prove reset or teardown of session-local state
- the provider declares whether it is stateless, session-virtualized, or not
  poolable
- the provider declares concurrency support and blocking behavior

ARC should reject `VerifiedMultiSession` for providers that do not advertise and
pass this contract.

### 4. Add a session security snapshot and continuity hash

At session creation, freeze a `SessionSecuritySnapshot` containing at least:

- transport
- auth method kind
- normalized principal
- issuer, subject, audience
- scopes
- token fingerprint or token family id
- sender-constraint binding material
- `client_id`
- tenant id
- organization id
- groups and roles
- enterprise `subject_key`
- origin
- policy digest
- capability issuance epoch
- hosted isolation profile

Persist a canonical hash of this snapshot. Every session reuse attempt must
either:

- reproduce the same snapshot exactly, or
- present an ARC-issued continuation assertion authorizing a controlled
  transition

This turns reuse into a verifiable continuity check instead of a narrow identity
comparison.

### 5. Fail closed on privilege shrink or drift

Privilege shrink is the important adversarial case:

- same user
- same issuer/subject/audience
- different scopes, groups, roles, client id, tenant, or org

Current behavior is too permissive for this case. The fix is:

- deny reuse if the security snapshot differs
- mark the old session draining or successor-required
- force new capability issuance under the new snapshot
- optionally provide a controlled "session successor" flow that migrates safe
  state while revoking the old authority surface

Do not silently reuse a session minted under a stronger authorization context.

### 6. Bind capabilities to session-security epochs

A hosted session capability should not outlive the auth context that justified
it.

Add:

- `session_security_epoch`
- `session_id` or `session_anchor_id`
- `hosted_isolation_profile`

to the relevant hosted/session-issued capability metadata, or otherwise bind
them through a signed session anchor.

The kernel or hosted edge should reject use when:

- the capability was issued under an older security epoch
- the session has been rebound
- the session successor flow revoked the old epoch

This closes the privilege-shrink hole at the capability layer, not just the
HTTP reuse layer.

### 7. Replace `shared_hosted_owner` with a session-virtualizing host manager

If ARC wants one process to host multiple sessions safely, the pool manager must
own session virtualization explicitly.

That manager should provide:

- per-session upstream handles
- per-session notification routing
- per-session cancellation namespaces
- per-session teardown/reset hooks
- concurrency admission control
- fairness and backpressure accounting
- observability per session and per host process

For legacy stdio adapters that cannot provide this, ARC must fall back to
`DedicatedPerSession`.

### 8. Freeze concurrency boundaries as protocol/runtime rules

Document and enforce:

- whether one session may have more than one concurrent in-flight upstream call
- whether pooled sessions may execute concurrently on one provider
- whether specific tools/providers require serialization
- what ownership transfer means for request streams, session notifications, and
  task status streams
- how cancellation is scoped and what cross-session errors are mandatory
- how late events are attributed after reconnect or successor-session handoff

This should become a machine-tested runtime contract, not just a prose note in
epic docs.

### 9. Add provider-declared isolation metadata

The upstream manifest should declare something like:

- `isolation_model: dedicated_only | stateless_poolable | session_virtualized`
- `concurrency_model: serialized | bounded_parallel | fully_parallel`
- `notification_model: session_scoped | global_broadcast | mixed`
- `reset_semantics: explicit | none`

ARC can then refuse dangerous pooling combinations instead of guessing from
transport shape alone.

### 10. Separate honest claim language by profile

Examples of defensible language:

- `DedicatedPerSession`: "each hosted session executes against an isolated
  upstream runtime instance"
- `VerifiedMultiSession`: "multiple sessions may share a host process while
  preserving session-scoped upstream state under the verified virtualization
  contract"
- `LegacySharedOwner`: "multiple sessions may reuse one upstream subprocess,
  but this mode is a compatibility/performance optimization rather than a strong
  isolation profile"

This claim split is mandatory. Otherwise implementation progress will keep
outpacing documentation discipline.

## Validation Plan

ARC needs evidence for both security continuity and non-interference.

### 1. Session-reuse and privilege-drift tests

Add regression coverage for:

- same principal, narrower scopes => reuse denied
- same principal, changed client id => reuse denied
- same principal, changed tenant/org => reuse denied
- same principal, changed groups/roles => reuse denied
- same principal, changed sender-constraint key => reuse denied
- exact-match refreshed token => reuse allowed only if policy says token-family
  continuity is sufficient
- successor-session handoff => old session capabilities invalidated

### 2. Shared-owner state-bleed tests

Build a deliberately stateful test upstream that:

- stores mutable global variables
- caches last caller/session data
- emits late notifications
- supports overlapping slow tasks
- exposes whether one session can observe another's hidden state

Use it to prove:

- `LegacySharedOwner` is not eligible for strong isolation claims
- `VerifiedMultiSession` blocks or properly virtualizes every bleed path

### 3. Concurrency and fairness tests

Add tests for:

- overlapping calls from two sessions on one pooled provider
- starvation and head-of-line blocking behavior
- cancellation races across pooled sessions
- notification routing under concurrent long-running tasks
- reconnect during in-flight pooled work

### 4. Reset and teardown tests

For providers claiming `session_virtualized`, require:

- session teardown clears local state
- successor-session handoff does not inherit revoked authority
- no retained background tasks survive teardown unless explicitly owned by the
  session successor contract

### 5. Fault-injection and adversarial harnesses

Add hostile scenarios:

- pooled upstream emits unscoped notifications
- pooled upstream returns mixed-session task ids
- pooled upstream leaks cached state after session deletion
- auth context changes mid-session
- policy epoch changes while a session is still live

The runtime should fail closed, not guess.

### 6. Claim-gating validation

The release lane should require:

- profile-specific docs
- green tests for the enabled profile
- no strong isolation wording when only `LegacySharedOwner` is active or
  shipped as the demonstrated path

## Milestones

### M1: Claim containment and profile split

- define hosted isolation profiles
- update docs so strong language applies only to the right profile
- mark `shared_hosted_owner` as legacy compatibility unless and until stronger
  guarantees land

### M2: Session continuity hardening

- add `SessionSecuritySnapshot`
- enforce exact-match reuse
- add privilege-drift denial tests
- bind hosted capabilities to session-security epochs

### M3: Dedicated isolation completion

- ensure strong hosted-session claims are true in `DedicatedPerSession`
- add explicit docs and operational guidance making this the secure default for
  generic wrapped servers

### M4: Verified multi-session contract

- add provider isolation metadata
- implement session-virtualizing host manager
- gate pooling on provider contract satisfaction

### M5: Concurrency semantics completion

- freeze pooled concurrency rules
- add fairness, cancellation, and notification-routing coverage
- expose the active isolation/concurrency profile in diagnostics

### M6: Qualification and claim restoration

- qualify `VerifiedMultiSession` against the hostile state-bleed harness
- restore stronger multiple-client/shared-hosting claim language only after the
  evidence exists

## Acceptance Criteria

ARC can make strong hosted-MCP isolation claims only when all of the following
are true:

- session reuse is denied on any material security-snapshot drift unless a
  signed continuation/successor flow authorizes it
- privilege shrink cannot continue using capabilities issued under a stronger
  session-security epoch
- generic wrapped stdio servers default to dedicated per-session isolation
- pooled hosting is allowed only for providers that declare and pass the
  verified multi-session contract
- cross-session task, cancellation, notification, and state routing remain
  isolated under concurrency stress
- hostile state-bleed tests are green for the profile that claims shared-host
  isolation
- admin diagnostics expose the active isolation profile, concurrency model, and
  session-security epoch
- docs clearly distinguish `DedicatedPerSession`, `VerifiedMultiSession`, and
  `LegacySharedOwner`

## Risks/Non-Goals

### Risks

- Exact-match session reuse will make token refresh flows stricter until a
  proper continuation model exists.
- Dedicated per-session isolation is operationally heavier than pooling.
- Building a true session-virtualizing host manager may require upstream API
  changes and manifest extensions.
- Some third-party or legacy MCP servers may never qualify for pooled strong
  isolation.

### Non-goals

- proving global distributed trust-plane properties; this memo is about hosted
  runtime/session isolation
- claiming process-internal non-interference for opaque providers without
  either process isolation or a verified virtualization contract
- preserving backward compatibility for insecure reuse or pooling modes when
  those modes block strong claims

## Bottom Line

The path to making ARC's multiple-client and hosted-isolation claims true is
not "add a few more session checks."

It is:

- split hosting profiles honestly
- make reuse depend on full security continuity
- treat privilege drift as a new authority epoch
- stop pooling opaque upstreams by default
- require a real session-virtualization contract before shared-host isolation
  claims come back

Until then, ARC has session-scoped hosted control logic and a useful shared
owner optimization, but not yet a defensible general shared-host isolation
theory.
