# Chio operator projection design

Status: **PROPOSED OWNER PROJECTION DESIGN**, 2026-10-07. `chio.operator.v1` is
the reserved design name, not an implemented endpoint or frozen wire ABI.
Confidence: high in the verified ownership map; moderate in integration design;
platform and runtime qualification remains unestablished by this document.
The [program map](../../../architecture/PROGRAM-MAP.md) and
[desktop ADR](../../../adr/ADR-0038-desktop-operator-program.md) govern sequencing.
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
| Observe receipts and receipt analytics | Trust-control `GET /v1/receipts/query`, `GET /v1/receipts/analytics`, `GET /v1/receipts/tools`, `GET /v1/receipts/children`; `receipt_handlers.rs` | Project the stored owner receipts and query/analytics results with their native filters and read authority. Analytics and receipt-ID point loads require admin read authority at the inspected source; a receipt is not proof of unobserved host effects. |
| Inspect capability lineage | Trust-control `GET /v1/lineage/{capability_id}` and `GET /v1/lineage/{capability_id}/chain`; `handle_get_lineage` / `handle_get_delegation_chain` | Render the owner snapshot and root-first chain. Preserve capability identity and current disclosure authorization; no desktop reconstruction of grant authority. |
| Observe budget usage and revocation status | Trust-control `GET /v1/budgets` and `GET /v1/revocations`; `handle_list_budgets` / `handle_list_revocations` | Preserve capability/grant-index usage, exposure versus realized spend, and the owner's revocation result. Usage is not a complete limit contract; no missing-value-to-unlimited inference. |
| Observe hook-session activity and provenance | Host plugin owns the session bond and hook record; inspected Claude owner: `src/state/store.ts`, `hooks/pretooluse.mjs`, `hooks/posttooluse.mjs`. Bridge `src/receipts.ts` reads trust-control receipts | Bind the host session/tool-use identity to its exact recorded capability and separately verified receipt. Post-tool success remains `host-reported-success-unverified` and `detect_only`; trust-control receipt reads do not establish a host session inventory, liveness or completeness. A bounded authenticated host observation adapter is required before this function ships. |
| Choose work terms | W1 `WorkQueryV1::Catalog { catalog_ref, cursor }`, then `Profile { profile_ref }` | Render the authorized immutable source-generation basis; no arbitrary discovery URL or issuer selection. |
| Prepare and start sealed work | W1 `WorkClient::prepare`, `submit`, `query`; `WorkPreparationV1` and `WorkCommandV1` | The host-generic single-owner recipe uses the owner's preparation, selection, sealing and `WorkActionV1::Submit { commitment }` sequence; no direct agent launch or desktop signer. |
| Inspect work | W1 `WorkQueryV1::Work { handle }` | Render `WorkViewV1`; `Applied` means command processing, not successful work. |
| Recover lost preparation/command reply | W1 `Preparation { preparation_ref }` or `Command { command_ref }` | Query the original ID even if no work handle was returned; follow the retained owner operation. |
| Reconcile historical work | W1 `WorkActionV1::Reconcile { handle }` | Historical settlement/evidence only; cannot execute or release result bytes. |
| Cancel work intent | W1 `WorkActionV1::Cancel { handle }`; linked recovery `CancelWorkflow` where applicable | Preserve each owner's supported transition, revision and retained operation; no implied refund or no-effect guarantee. |
| Select a recovery offer | Recovery `SelectOffer { workflow_id, expected_revision, offer_id }` | Select only an owner-returned offer bound to the current workflow/revision; retain original command identity across a lost reply and reject stale/substituted offers before approval or resume. |
| Resume recovery | Planned W1 `WorkRecoveryLinkV1`, reconciled to the landed recovery reference; implemented recovery `ResumeWorkflow { workflow_id, expected_revision }` | The link is a W1 design type, not an exported implementation symbol at W or R. Drive the original continuation/reconciliation; never clear cancellation or resubmit an unknown original. |
| Inspect recovery | Recovery `InspectWorkflow` for explicit command semantics; non-persisting `ChioKernel::read_recovery_workflow` for refresh | The latter must be exposed by the owner through an authenticated bounded read adapter; the controller never opens the store. |
| Open review / submit decision | Recovery `/v1/recovery/review` and `SubmitApproval { workflow_id, expected_revision, approval }` via `/v1/recovery/commands` | Native review custody and verified endorsement; no desktop-generated grant or decision credential. |
| Read result / export evidence | W1 design anchors `ArtifactReleasePort` / `ConfinedReturnPort`; R:`crates/kernel/chio-kernel/src/knowledge.rs` implements `ArtifactReleaseSink` | The ports are planned, not present recovery implementation symbols. `ArtifactReleaseSink` is a reconciliation analogue with `recipient` / `deliver`, not an equivalent or completed W1 binding. Query/reconcile is not a release grant. Export stays unavailable until its owner API binds destination, disclosure checks and original effect identity. |
| Close one task's authority | S4 `POST /admin/authority-spaces/close`, read `GET /admin/authority-spaces/{closure_id}` | Resolve the task's owned authority spaces and render `AuthoritySpaceClosureV1`; exact coverage is an owner obligation. |
| Emergency stop / restrict / resume / status | S8 S30 routes or process-host control socket, same owner DTOs | Preserve owner result and scope; no task-to-global-stop alias. |
| Subscribe / acknowledge changes | S5 Part B `chio/events/subscribe`, `unsubscribe`, `ack`, `list`; `notifications/chio/event` | Consume the shared negotiated hints; no independent desktop event protocol. |

The Observe allowlist is method-specific. Trust-control mounts mutation handlers
on some of the same paths: `POST /v1/receipts/tools`, `POST /v1/receipts/children`
and `POST /v1/revocations` are not observation functions. Budget mutation,
capability issuance, lineage recording and evidence export/import are also outside
Observe. The existing dashboard consumes the receipt query/analytics and lineage
GETs; the bridge is a client, not their source of authority. Its current receipt
stream polls and does not implement S5 Part B. Preserve the native read-principal
rules; add any required audience-restricted adapter at the owner rather than
forwarding broad service credentials into a desktop client. Source pins and
mounted-handler evidence are recorded in section 8 and the program map.

Basic receipt/hook observation requires the Observe lane, not W1 or M20. Work
views and recovery capabilities remain optional, independently gated additions.
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

An evaluator that imports, builds or runs candidate-controlled code MUST use a
separately qualified bounded execution boundary at the existing runner/work
owner. Immutable oracle fixtures alone do not confine the code they evaluate.
That execution receives only captured candidate input, pinned dependencies and
declared fixtures, without ambient host data, credentials, egress, unrelated
process control or acceptance/signing authority. Trusted result validation and
W1 acceptance commit remain outside candidate execution; raw stdout/exit status
cannot impersonate them. Pin and test this evaluator boundary independently of
the agent/recipe boundary. Missing confinement, failed/unknown evaluation or
unproven result separation leaves sealed acceptance unavailable. This is an
execution-profile obligation, not a prerequisite for basic observation.

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
authorization. Refresh through the subject's authorized read owner: trust-control
GET or host observation adapter for basic Observe, `WorkQueryV1::Work` for enabled
W1 views, or the non-persisting recovery read for enabled recovery views.
No busy `InspectWorkflow` command polling: commands can consume
permanent quota/settlement reserve and reused IDs can return stale cached results.
Use the owner's coalescing, rate bounds, subscribe-then-check, audience revalidation,
retention/restore, terminal delivery and stable subscription acknowledgement rules.
Approval invalidation must resolve the native owner, original operation and
proposal/review identity, not task ID plus an owner-local proposal ID alone.
If a shared hint lacks that precision, invalidate the affected cached actions
conservatively and re-read their exact owner bindings before re-enabling them;
never guess which matching review remains valid.
Gap, stale session or dropped stream forces authoritative refresh, not invented
state transitions. Bounded slow-consumer disconnect is preferable to silent loss.
Heartbeat/link liveness never extends a grant or the freshness of an owner fact.

## 7. Protocol-freeze acceptance and evidence

Owners add executable coverage beside their implementation; operator integration
tests exercise composition. Reuse native vectors and test harnesses. The retired
desktop fixture corpora are review history, not a second conformance authority.
Apply the matrix to the exact exposed capabilities, with the mandatory Observe
cases and conditional W1/recovery cases in QUALIFICATION. Unexposed mutation
cases remain owner obligations for later capabilities; they do not block a
read-only freeze or become accepted by that freeze.

| Acceptance case | Responsible owner and decisive evidence |
| --- | --- |
| Wrong peer, replaced/symlinked socket, guest access, Darwin unsupported path; reconnect/version mismatch | IPC owner plus operator: real process probes, bounded transcripts and zero unauthorized dispatch. |
| Duplicate keys, invalid numeric/Unicode tokens, maximal escaping, one-over aggregate size; wrong method/request/session result | Owner decoders plus operator: original-byte rejection and dispatch counters; no truncated identity. |
| Same ID with each semantic field changed; exact replay after restart, revision advance and full capacity | Work/recovery/native owners: retained full-body binding and one effect; current audience rejection still works. |
| Crash before dispatch, after native effect and before response/index persistence | Owning mutation services: independent effect marker, original-ID lookup before handle, no second invocation. |
| Six work axes disagree; result exists but release is refused; payment remains unresolved | W1/recovery/payment owners: faithful separate observations and no unauthorized result bytes. |
| Changed catalog/snapshot between pages; snapshot expiry; lag, restore, missed terminal and lost ack | Enumeration owner and S5: either consistent authoritative reconstruction or explicit gap; bounded queues and idempotent scoped ack. |
| Empty readiness profile, stale/wrong-login/future health, absent typed scope, duplicate budgets, unavailable limit | Profile/health owners plus operator: actions remain disabled; native admission independently refuses stale basis. |
| Two owners reuse a proposal ID and one review is invalidated | S5/approval owner plus operator: resolve the exact operation or disable affected actions pending authoritative refresh; no wrong-review invalidation or stale approval. |
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
| Existing trust-control observation and dashboard | `6573b8980a1e5331028b7e688169f033a39d0384`: under `crates/platform/chio-control-plane/src/trust_control/`, `service_types/paths.rs`, `service_runtime/router.rs` (mounted GETs versus POSTs), `receipt_handlers.rs`, `budget_handlers.rs`, `authority_handlers.rs`; `crates/products/chio-cli/dashboard/src/api.ts` (`fetchReceipts`, `fetchReceiptAnalytics`, `fetchLineage`, `fetchDelegationChain`). |
| Host-session provenance and bridge client | Claude plugin `65ac8390c57a5292c055fba50caa1aafbd915848`: `src/state/store.ts`, `src/state/bridge.ts`, `hooks/{pretooluse,posttooluse,_receipt}.mjs`. Bridge local inspected source `f0f21945484b3e2a9ed79a5b2063bda98754ac80`: `src/receipts.ts` (`listReceipts`, polling `streamReceipts`). These are separate source pins, not a qualified installed combination. |
| W1 work surface (#1173) | `a0447e36ae55014a59aad2ae0c489ab4551f6389`: `docs/superpowers/specs/2026-10-03-work-runtime-design.md`; `2026-10-03-work-developer-surface-design.md` in the same directory. |
| North-star owners (#1174) | `8dffff3da53dfb56da8e60019af5e3ae896f7f5b`, `docs/superpowers/specs/`: S1 `2026-10-04-closed-kernel-abi-design.md`; S3 `2026-10-04-typed-reservations-design.md`; S4 `2026-10-04-authority-space-teardown-design.md`; S5 `2026-10-04-unified-event-queue-design.md`; S8 `2026-10-04-durable-stop-epoch-design.md`; S9 M20 `2026-10-04-pure-admission-machine-design.md`. |
| Recovery | `59138e12edac6d4d039bfd91e4a14a491ceda227`: `docs/architecture/recoverable-agent-runtime/08-protocol-operations.md`; `crates/security/chio-security-types/src/recovery/commands.rs`; `crates/platform/chio-control-plane/src/recovery/{runtime,transport}.rs`; `crates/kernel/chio-kernel/src/kernel/admission_coordinator/recovery_runtime.rs`; `crates/kernel/chio-kernel/src/knowledge.rs:203-213` (`ArtifactReleaseSink`). |
| Foundation IPC | `1267f9bf31d81947eee5cad838b1e3b4332ab4ab`: `crates/security/chio-secure-ipc/src/lib.rs`. |
| Review basis | [Architecture review revision 2](../2026-10-07-omarchy-integration/reviews/2026-10-07-architecture-review.md); [ADR-0011](../../../adr/ADR-0011-boundary-taxonomy-product-wording.md). |

An Observe-only candidate can proceed after S5 Parts A/B, authenticated bounded
non-persisting reads, truthful hook attribution, the selected trust-control read
bindings, platform IPC and generated schema/transport bounds qualify. Recovery
hints additionally require their landed recovery source and read adapter; W1 views
require their landed W1 query. Optional capabilities negotiate explicitly and
remain unavailable when their predecessors are absent. Selected mutations add
their own S3/M20, work/recovery, stop/closure, production approval identity and live
process-control gates. Final freeze requires the implemented-client acceptance
for the exposed profile. Review acceptance does not establish Linux or macOS
qualification. The program map records the current dependency evidence.
