# Chio operator projection design

Status: **PROPOSED OWNER PROJECTION DESIGN**, 2026-10-07. `chio.operator.v1` is
the reserved design name, not an implemented endpoint or frozen wire ABI.
Confidence: high in the verified ownership map; moderate in integration design;
platform and runtime qualification remains unestablished by this document.
The [program map](../docs/architecture/PROGRAM-MAP.md) and
[desktop ADR](../docs/adr/ADR-0038-desktop-operator-program.md) govern sequencing.
Normative MUST/REJECT statements below are acceptance obligations for the named
owners, not claims that their proposed interfaces have shipped.

## 1. Placement and authority

Chio is a modern Rust kernel for agentic operating systems. Its operator surface
lets a person inspect, approve and control work through the existing authorities.
The workbench is the first client; Omarchy QML, macOS menu bar and CLI are later
clients of the same controller. Proposed implementation homes are
`crates/products/chio-operator` and `tests/integration/operator`.

Under S1 the controller is C-layer, outside the TCB, in a separate process from
the gateway and process host. Neither controller nor UI holds authority signing
keys, issues capabilities, signs approvals/receipts, asserts trusted facts, or
maintains a competing task, recovery, budget or authority ledger. It may retain
bounded disposable presentation data and original owner references. Their loss
cannot renew authority, erase an effect, free capacity or manufacture a result.
Owner services authenticate requests, verify signed artifacts and decide effects.
The desktop user and installed client remain trusted within the desktop profile;
same-user IPC access alone is not proof of a particular application's identity.

## 2. Owner contracts and function mapping

Names in the first column describe product functions, not approved RPC spellings.
Wire schemas MUST import the landed closed owner types and generated bindings.
No desktop `WorkPhase`, replacement `WorkHandleV1`, recovery enum, retry enum,
approval format, event log or stop state machine is permitted.

| Operator function | Exact owning operation or query | Projection responsibility |
| --- | --- | --- |
| Choose work terms | W1 `WorkQueryV1::Catalog { catalog_ref, cursor }`, then `Profile { profile_ref }` | Render the authorized immutable source-generation basis; no arbitrary discovery URL or issuer selection. |
| Prepare and start sealed work | W1 `WorkClient::prepare`, `submit`, `query`; `WorkPreparationV1` and `WorkCommandV1` | The host-generic single-owner recipe uses the owner's preparation, selection, sealing and `WorkActionV1::Submit { commitment }` sequence; no direct agent launch or desktop signer. |
| Inspect work | W1 `WorkQueryV1::Work { handle }` | Render `WorkViewV1`; `Applied` means command processing, not successful work. |
| Recover lost preparation/command reply | W1 `Preparation { preparation_ref }` or `Command { command_ref }` | Query the original ID even if no work handle was returned; follow the retained owner operation. |
| Reconcile historical work | W1 `WorkActionV1::Reconcile { handle }` | Historical settlement/evidence only; cannot execute or release result bytes. |
| Cancel work intent | W1 `WorkActionV1::Cancel { handle }`; linked recovery `CancelWorkflow` where applicable | Preserve each owner's supported transition, revision and retained operation; no implied refund or no-effect guarantee. |
| Select a recovery offer | Recovery `SelectOffer { workflow_id, expected_revision, offer_id }` | Select only an owner-returned offer bound to the current workflow/revision; retain original command identity across a lost reply and reject stale/substituted offers before approval or resume. |
| Resume recovery | Existing `WorkRecoveryLinkV1` and recovery `ResumeWorkflow { workflow_id, expected_revision }` | Drive the original continuation/reconciliation; never clear cancellation or resubmit an unknown original. |
| Inspect recovery | Recovery `InspectWorkflow` for explicit command semantics; non-persisting `ChioKernel::read_recovery_workflow` for refresh | The latter must be exposed by the owner through an authenticated bounded read adapter; the controller never opens the store. |
| Open review / submit decision | Recovery `/v1/recovery/review` and `SubmitApproval { workflow_id, expected_revision, approval }` via `/v1/recovery/commands` | Native review custody and verified endorsement; no desktop-generated grant or decision credential. |
| Read result / export evidence | W1 design anchors `ArtifactReleasePort` / `ConfinedReturnPort`; landed disclosure API must be reconciled before use | These are planned ports, not present recovery implementation symbols. Query/reconcile is not a release grant. Export stays unavailable until its owner API binds destination, disclosure checks and original effect identity. |
| Close one task's authority | S4 `POST /admin/authority-spaces/close`, read `GET /admin/authority-spaces/{closure_id}` | Resolve the task's owned authority spaces and render `AuthoritySpaceClosureV1`; exact coverage is an owner obligation. |
| Emergency stop / restrict / resume / status | S8 S30 routes or process-host control socket, same owner DTOs | Preserve owner result and scope; no task-to-global-stop alias. |
| Subscribe / acknowledge changes | S5 Part B `chio/events/subscribe`, `unsubscribe`, `ack`, `list`; `notifications/chio/event` | Consume the shared negotiated hints; no independent desktop event protocol. |

W1 currently specifies no work-list query. A work-list owner/index with authorized
enumeration, consistent pagination and original-reference recovery MUST be
specified upstream before that function freezes. Health, enrolled-scope views,
trusted review locators and export adapters likewise need concrete owner bindings;
this document does not invent them. Missing bindings disable that function.

`WorkViewV1` keeps six independent observations: execution, acceptance,
result-reference, recovery, settlement and bilateral delivery. Preserve native
`NotApplicable`, `Pending`, `Available` and `Unavailable` observations and their
source, per-authority revision and observation time. A view is not a globally
atomic snapshot. Native `UnknownEffect`, successful execution with refused
acceptance, withheld result, unpaid obligation and incomplete delivery must remain
distinguishable. A reference is not proof, a permit, funding or release authority. `WorkAcceptanceV1` derives from the original configured evaluator and evidence contract, never a caller acceptance boolean. Human patch-application approval is separate from work acceptance.

## 3. IPC, negotiation and correlation

Linux MUST reuse `chio-secure-ipc` listener custody, peer authentication and
bounded framing. Its pinned implementation checks the configured PID/UID/GID,
socket identity and lifecycle, and refuses non-Linux platforms. The multi-client
operator authentication profile needs an owner-approved adaptation, not weaker
ad hoc UID checks. Darwin MUST add and qualify its peer-credential/custody path
in that same crate; the choice of Darwin mechanism is still a design gate.
No unauthenticated local fallback, separate XPC authority or in-guest operator
endpoint is allowed. Platform annexes define path/launch/session custody.

Each connection negotiates the exact operator version and required owner profiles
before other requests. Reconnect always renegotiates. Unsupported or inconsistent
versions close the connection with a bounded non-authorizing diagnostic and zero
native dispatch; never strip required fields or fall back to an older profile.
S5 Part B and its kernel-owned generated wire schemas MUST land before operator
wire freeze. The workbench is the second consuming surface that triggers Part B.

Freeze requires strict raw-byte decoding, closed method/result variants, duplicate
member rejection, Unicode/numeric checks and explicit aggregate byte/depth/count
bounds compatible with each embedded owner type. Do not coerce opaque owner IDs
to UUIDs, truncate them, rewrite signed bytes, or round-trip lossless owner values
through floating-point JSON. Controller labels and display digests confer no trust.

Every response, including errors, MUST correlate to the exact request ID, function,
selected protocol, authenticated owner namespace and intended resource/reference.
Validation matches the complete semantic request binding or its owner-retained
digest, including decision and pagination parameters, not only a partial tuple.
Clients reject unsolicited, cross-method, cross-owner, cross-session or stale
generation results. Request IDs are connection-scoped correlation only. Stable
command/preparation identities belong to owners and survive reconnect; rotating
tokens and transport nonces are not new intent. Owner revision is distinct from
connection generation, login/boot identity, catalog generation and subscription ID.
No counter from one scope may stand in for another.

Pagination MUST bind the authenticated audience, full query/filter/order/limit
parameters, owner namespace, snapshot/generation and continuation position. Owner
mutation during enumeration cannot silently mix pages; expiry, retention gaps or
generation changes require explicit refresh. Bound encoded bytes as well as row
count, return fewer whole rows when possible, and refuse indivisible overflow
without truncating identifiers, evidence or decision bindings.

## 4. Full intent, retries and error outcomes

An owner-retained mutation binds the authenticated stable principal/tenant scope,
command kind, original ID and **all semantic parameters**: exact input/prompt,
profile/project/source basis, target work or workflow, native operation/proposal,
decision, expected revision, policy/authority generation and applicable destination.
Canonical owner rules define that binding; a same-intent claim is valid only for
the same full parameters. Same ID with changed body conflicts before any effect.
An operator label, subset digest or matching task ID is insufficient.

Owners retain original intent before observable issuance/dispatch. Exact retained
lookup precedes new-admission capacity and stale expected-revision rejection;
current read/audience checks still apply. New mutations compare the reviewed basis
and expected revision atomically at the owning transition, and recheck mutable
authority at native commitment. There is no transaction across owners. A missing
controller/index row is never proof of no native operation.

Consume S9 M20 `IdentityDisposition` and the owner's separate retry guidance.
`Reusable`, `Retained` and `Terminal` are not desktop classifications. In
particular, `Reusable` plus `retry: Never` does not promise durable terminal replay;
`Retained` requires original-operation resolution. Preserve owner retention and
tombstone lifetimes regardless of client cache expiry or admission pressure.
Replaying a committed command cannot renew consent, quota, budgets or clocks.

| Error situation | Required correlation and permitted action |
| --- | --- |
| Validation, negotiation or definite pre-dispatch refusal | Exact request context; no fabricated operation reference. A known existing context must not imply this rejected request was submitted. |
| Body/identity conflict or changed revision | Return the owner's typed conflict; disclose existing references only if authorized. Refresh/review deliberately; no automatic new key. |
| Lost reply, timeout, storage/rendering failure after possible dispatch | Preserve original command/preparation and known owner operation references; report unknown outcome and perform owner lookup. Never relabel as harmless refusal or silently resubmit. |
| Known terminal result | Render owner result and current authorized disclosure; no fresh invocation under the old intent. |
| Retention gap, stale cursor or unrepresentable result | Explicit bounded refresh/unavailable result; never empty success, altered identity or unbounded fallback. |

The wire error codes and retry fields are frozen only with their owners. Error
messages contain bounded safe diagnostics, not raw native bodies or parser input.
Admission exhaustion must preserve bounded lookup/reconciliation capacity.

## 5. Review, health and honest limits

Review MUST bind the exact owner, original operation, proposal/review/decision IDs,
decision value, intended subject/action/recipient, native revision and expiry.
The native owner verifies that the returned endorsement covers exactly that basis.
A deny must never retain an approved credential. Missing, mismatched, expired,
replaced or revoked bindings refuse; stale UI consent cannot approve a new basis.
OS consent, a Chio grant and exact endorsement remain separate facts.

An attributable approval UI requires S8 S28's principal/roster foundation and the
recovery approval owner's production verifier and credential custody. S28 is not
itself the approval protocol. Until attribution is implemented, shared-credential
records remain `SharedCredential`; never label a sidecar signature as the person's
signature. The installed approval utility must pass deny and mismatch regressions.

Successful operator health responses MUST contain a nonempty set of explicitly
named supported profiles, with required prerequisites and component identities.
An empty set cannot masquerade as readiness. Each relevant observation binds its
owner, boot/login/session identity, observed time, maximum age and validity basis.
Unknown, expired, future/clock-inconsistent or wrong-session evidence cannot enable
a sensitive view or mutation. Disconnect marks data stale. The owner rechecks
session ownership/lock state and authority at admission independently of UI age.

Reviewed scope MUST resolve typed principal, authority/trust root, project and
selection, policy, host/provider/account/credential reference, verification recipe,
network, budget and publication bindings. Labels do not replace these bindings.
Changes invalidate the review; source staging has its own immutable generation.
Profile responses separate configured, observed and qualified enforcement and
carry ADR-0011 `boundary_class` and `planning_status` per boundary, not one badge
for a mixed profile. Display `receipt_kind` with `boundary_class`.

Budget views reject duplicate dimensions even when values or states differ.
Each dimension names its unit, accounting scope, owner, observation revision and
enforcement status. An enforced ceiling is explicit, finite and checked; zero is
zero allowance. Measured-only or unavailable is never enforced or unbounded.
Absent dimensions are unclaimed. Reuse the owner's numeric domain and accounting;
no controller conversion or summary can expand an allowance.

## 6. Stop and event consistency

Task closure requires S4 phases 1 and 2 and live process-host cancel/revoke.
Render fence, drain, process exit, remote abort request and unresolved obligations
from their respective owners; a retained cancel command or exited process alone
does not prove stopped admissions, absence of remote effects or settled money.
S8 emergency control is separate: phase 1 provides `Kernel` scope and S30 reach;
S28 identity is phase 3, `Tenant` scope phase 4 and `Recovery` scope phase 5.
Advertise only qualified scopes. Preserve S30 `stop_durable`, `stop_not_durable`
and `stop_outcome_unknown`; resume/restrict obey the owner's epoch and authority.
Task recovery resume cannot undo S4's terminal closure or silently clear S8 stop.

S5 hints are unsigned operational notifications, never receipts, trusted state or
authorization. Refresh `WorkQueryV1::Work` or the authorized non-persisting recovery
read after a hint. No busy `InspectWorkflow` command polling: commands can consume
permanent quota/settlement reserve and reused IDs can return stale cached results.
Use the owner's coalescing, rate bounds, subscribe-then-check, audience revalidation,
retention/restore, terminal delivery and stable subscription acknowledgement rules.
Gap, stale session or dropped stream forces authoritative refresh, not invented
state transitions. Bounded slow-consumer disconnect is preferable to silent loss.
Heartbeat/link liveness never extends a grant or the freshness of an owner fact.

## 7. Protocol-freeze acceptance and evidence

Owners add executable coverage beside their implementation; operator integration
tests exercise composition. Reuse native vectors and test harnesses. The retired
desktop fixture corpora are review history, not a second conformance authority.

| Acceptance case | Responsible owner and decisive evidence |
| --- | --- |
| Wrong peer, replaced/symlinked socket, guest access, Darwin unsupported path; reconnect/version mismatch | IPC owner plus operator: real process probes, bounded transcripts and zero unauthorized dispatch. |
| Duplicate keys, invalid numeric/Unicode tokens, maximal escaping, one-over aggregate size; wrong method/request/session result | Owner decoders plus operator: original-byte rejection and dispatch counters; no truncated identity. |
| Same ID with each semantic field changed; exact replay after restart, revision advance and full capacity | Work/recovery/native owners: retained full-body binding and one effect; current audience rejection still works. |
| Crash before dispatch, after native effect and before response/index persistence | Owning mutation services: independent effect marker, original-ID lookup before handle, no second invocation. |
| Six work axes disagree; result exists but release is refused; payment remains unresolved | W1/recovery/payment owners: faithful separate observations and no unauthorized result bytes. |
| Changed catalog/snapshot between pages; snapshot expiry; lag, restore, missed terminal and lost ack | Enumeration owner and S5: either consistent authoritative reconstruction or explicit gap; bounded queues and idempotent scoped ack. |
| Empty readiness profile, stale/wrong-login/future health, absent typed scope, duplicate budgets, unavailable limit | Profile/health owners plus operator: actions remain disabled; native admission independently refuses stale basis. |
| SelectOffer uses stale workflow revision, substituted offer or lost reply | Recovery owner: reject a stale/substituted selection; reconcile the original selection command before approval/resume, with no second effect. |
| Deny retaining approve material; changed proposal, recipient, decision ID or revision; revoked approver | Approval owner: installed verifier rejects each mismatch with zero protected effect. |
| Per-task closure races dispatch/release; kernel stop reply lost; unsupported tenant/recovery scope | S4/S8/process owners: exact closure coverage, independent exit evidence, retained unknown outcome and no scope escalation. |
| Long-lived idle/active workbench with recovery hints and redacted errors | S5/recovery/operator: no command-poll quota drain, bounded refresh cost, no secrets in argv, logs, events, crash data or caches. |

Agent text, filenames, tool output, URLs and labels are untrusted presentation.
Render inertly; trusted controls/review origins are distinct. Native helpers use
literal argv and bounded stdin, never shell interpolation. Credentials and decision
tokens stay in native custody; redact before logging/caching, and recheck audience
on every fetch/export. Artifacts are evidence only after native verification.

## 8. Verified source anchors and remaining gates

These are internal source snapshots, inspected with `git show <pin>:<path>`;
they establish exact proposed contracts/code locations, not release qualification.

| Source | Pin and exact path |
| --- | --- |
| W1 work surface (#1173) | `a0447e36ae55014a59aad2ae0c489ab4551f6389`: `docs/superpowers/specs/2026-10-03-work-runtime-design.md`; `2026-10-03-work-developer-surface-design.md` in the same directory. |
| North-star owners (#1174) | `8dffff3da53dfb56da8e60019af5e3ae896f7f5b`, `docs/superpowers/specs/`: S1 `2026-10-04-closed-kernel-abi-design.md`; S3 `2026-10-04-typed-reservations-design.md`; S4 `2026-10-04-authority-space-teardown-design.md`; S5 `2026-10-04-unified-event-queue-design.md`; S8 `2026-10-04-durable-stop-epoch-design.md`; S9 M20 `2026-10-04-pure-admission-machine-design.md`. |
| Recovery | `59138e12edac6d4d039bfd91e4a14a491ceda227`: `docs/architecture/recoverable-agent-runtime/08-protocol-operations.md`; `crates/security/chio-security-types/src/recovery/commands.rs`; `crates/platform/chio-control-plane/src/recovery/{runtime,transport}.rs`; `crates/kernel/chio-kernel/src/kernel/admission_coordinator/recovery_runtime.rs`. |
| Foundation IPC | `1267f9bf31d81947eee5cad838b1e3b4332ab4ab`: `crates/security/chio-secure-ipc/src/lib.rs`. |
| Review basis | [Architecture review revision 2](../docs/superpowers/specs/2026-10-07-omarchy-integration/reviews/2026-10-07-architecture-review.md); [ADR-0011](../docs/adr/ADR-0011-boundary-taxonomy-product-wording.md). |

Before freeze, owners must land the required work/recovery/stop/closure contracts,
S3 phase 1 receipts, S5 Parts A/B, M20 dispositions, production approval identity,
live process control, enumeration/read/health/scope adapters, Darwin IPC design and
generated schema/transport bounds. Review acceptance does not establish Linux or
macOS qualification. The program map records the current dependency evidence.
