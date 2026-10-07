# Local operator protocol

Status: Proposed ABI, not an implemented endpoint. Confidence: moderate until
the native adapter contract is qualified. Dependencies: [controller ownership](04-controller-architecture.md),
[authority](06-authority-approvals.md), [data model](14-state-evidence-data.md).
Machine shapes live in [contracts](contracts/README.md). Prose semantic checks
are mandatory in addition to structural schema validation.

## Transport and trust

Use an AF_UNIX stream socket at `$XDG_RUNTIME_DIR/chio-desktop/operator.sock`.
The parent directory is operator-owned 0700; the socket is 0600. Creation and
connection validate owner, type, parent identity and no symlink traversal.
The service checks peer credentials against its enrolled desktop principal.
This authenticates a user identity, not a particular same-user plugin. The guest
namespace excludes this socket and its ancestors. Root remains trusted.

The QML plugin starts an installed, pinned `chio-desktop-client` with literal
argv, sends JSON on stdin and parses stdout as a bounded stream. Stderr contains
redacted diagnostics only. The client handles socket/protocol details; QML must
not spawn a shell, concatenate user content into commands or read the authority
store. A shim protocol violation closes that connection without a mutation.

Wire encoding is UTF-8 newline-delimited JSON. One frame is at most 65,536 bytes
including its terminating LF. A literal LF within a string must be JSON escaped.
Reject invalid UTF-8, duplicate keys, unpaired surrogates, NaN/infinity, unknown
fields/methods and nesting beyond 16 before dispatch. The first Hello version
candidate is parsed as specified below before deciding ABI compatibility. Integers
are nonnegative and at most 9,007,199,254,740,991 unless a field is more bounded.
RFC 8785 canonicalization is used for semantic request digests; ordinary compact
JSON serialization is sufficient for transport. Sorting JSON keys is not a
substitute for JCS. [Canonicalization specification](https://www.rfc-editor.org/rfc/rfc8785)

Only one selected ABI `chio.omarchy.operator.v1` is supported initially. A first
`hello` request carries an envelope `protocol` and `params.protocol`, each a
bounded ASCII identifier matching `[A-Za-z][A-Za-z0-9._-]{0,63}`. These Hello fields
are candidates, so a well-formed unsupported ABI survives structural parsing.
The two identifiers must match exactly before compatibility is considered:
mismatch returns typed `invalid_request` with retry `never` and closes the
connection. Matching identifiers other than the selected ABI return typed
`unsupported_version` with retry `after_operator_repair` and close the connection.
Both errors have a null operation reference and cause no native dispatch.

Matching `chio.omarchy.operator.v1` identifiers select that exact ABI and return
the current journal epoch, release profile identifiers, backend component build
identities and feature availability. Every server reply, including a failed
Hello reply before negotiation succeeds, uses the server's supported v1 response
envelope, never the unselected candidate. All non-Hello request and event schemas
retain the exact selected v1 constant; they require a successfully negotiated
connection. Every reconnect renegotiates.

`scope.get` limits marked `enforced` require an explicit safe-integer ceiling
from 0 through 9,007,199,254,740,991. Null is allowed only for `measured_only` or
`unavailable`, and is never presented as an enforced ceiling. Zero denotes a
zero allowance, not an unlimited budget. The controller validates the shape
before projecting or committing the reviewed scope.

## Method inventory

Desktop task, owner, project, enrollment and control IDs are opaque UUIDs.
A native `operation_ref` contains enrolled `owner_id` and exact `native_id`; the
selected owner validates its original format, including resource SHA-256 IDs.
Native proposal, review and decision IDs are bounded original strings, not
converted to desktop UUIDs. Unrepresentable native identifiers block the adapter
profile instead of being truncated or replaced. Project/profile IDs refer to
operator-enrolled records; the API never accepts a command, executable, shell
string, arbitrary destination URL or absolute project path as a substitute.
Evidence in `task.get`, `tasks.list`, `task_changed` and operation responses uses
the same `evidence_ref` definition: enrolled `owner_id`, bounded native identifier,
nullable SHA-256 digest and explicit verification state. A native ID alone cannot
select its owner. Projecting a reference does not verify the underlying evidence.

| Method | Params | Result and authority |
| --- | --- | --- |
| `hello` | `client_version`, bounded `protocol` candidate matching the envelope | select exact supported ABI or typed refusal; server epoch, profiles, features, limits; no execution |
| `health.get` | empty object | runtime availability, named prerequisite failures and bounded timestamped health observations |
| `scope.get` | project/profile IDs | exact enrolled scope revision, digest, provider/governance/limit/recipe summary |
| `tasks.list` | bounded `limit`, nullable cursor | task summaries plus snapshot watermark and next cursor |
| `task.get` | task ID | current task projection and revision |
| `events.subscribe` | nullable cursor (unfiltered global journal) | ordered events or `cursor_expired`; dedicated stream |
| `operation.get` | task and native operation reference | bound native outcome projection, evidence refs |
| `task.create` | profile/project IDs, prompt, scope revision, reviewed scope digest, idempotency key | retained task reservation, not successful execution |
| `task.cancel` | task ID, expected revision, idempotency key | retained control command, separate admission/process/effect status |
| `task.resume` | same control fields | reconcile original bindings; native authorization still checked |
| `review.open` | task and native operation reference | trusted review locator, no approval |
| `approval.submit` | task/native operation reference/proposal ID, expected revision, idempotency key, opaque decision handle | native validated decision result or explicit unavailable |
| `receipts.export` | task ID, expected revision, idempotency key, exact enrolled export profile | bounded bundle descriptor; content export is audited and filtered |

`receipts.export` is not assumed side-effect-free: creating/exporting a bundle
has a retained export operation and native disclosure rules. P1 permits inspection
of receipt references only. The method refuses until its export profile is
qualified; no unrestricted filesystem destination is accepted.

The schema splits requests by method. Response success envelopes carry a typed
`kind` and bounded `value`; per-method result kinds are fixed in the schema's
method/result catalog. Arbitrary objects are not an extension mechanism. Events
use a separate envelope. Errors contain a stable code, safe message, retry class
and nullable original-operation reference; never raw native request bodies.

Health observations carry observation time, boot/session identity, freshness,
protocol/package compatibility, configured/observed/qualified enforcement state,
storage headroom, credentials, desktop lock/ownership, native recovery and state
store health. Every uncertain dimension is explicit `unknown` or `unavailable`.
These remain observations, not native attestations. Client connectivity derives
from its heartbeat/link state. Unknown/stale session ownership disables sensitive
views and mutations; the backend independently rechecks native session policy
at admission. A stale UI cannot authorize an unlocked-state assumption.

## Reviewed scope and cancellation projection

`scope.get` reads the exact operator-enrolled project/profile configuration. Its
successful result includes these required, closed fields in addition to the
project/profile IDs, enrollment epoch, scope revision and reviewed digest:

| Typed field | Reviewed binding |
| --- | --- |
| `operator_binding`, `authority_binding`, `trust_root_sha256` | Enrolled principal, issuing authority and pinned trust root. |
| `project_binding`, `selection_rules` | Enrolled project resource and explicit include/exclude, untracked, ignored, nested-repository and symlink rules. |
| `policy_binding` | Exact selected native policy identity, revision and digest. |
| `agent_binding`, `provider_binding`, `account_binding`, `credential_binding` | Selected host/agent configuration, provider route, account requirement and opaque enrolled credential reference. No credential bytes are exposed. |
| `verification_plan` | Pinned plan plus a bounded UUID-keyed map of required recipes, recipe/runtime digests, literal argument vectors, staged-project/private-scratch working directories and timeouts. These are inspected as data; QML never executes them. |
| `governance_mode`, `limits`, `network_scope` | Selected disclosure mode, unambiguous resource bounds and no-network/provider-only/exact enrolled-destination behavior. |
| `publication_scope` | Explicitly disabled publication or the exact private local review destination, pinned destination binding/path and pre-admitted versus exact native approval requirement. No remote, checkout, Git or deployment destination is supported. |

Each `enrolled_scope_binding` contains an owner-scoped native `reference`, safe
integer `revision`, SHA-256 digest and bounded label. Its reference uses the same
owner/native-ID wire shape as an operation reference but names an enrolled record,
not an executed operation or a grant. Display fields `project_label`,
`provider_label` and `selection_summary` are supplemental; they cannot replace
the typed fields. A missing, null or unavailable required binding cannot produce
a successful scope response. Return `prerequisite_unavailable`, keep Start
disabled and use health/diagnostics to explain the missing prerequisite.

The reviewed digest is the RFC 8785 digest of the complete successful scope
`value` with only `reviewed_scope_digest` omitted. This commits the typed fields
and their displayed labels together. The task instruction remains the separate
`task.create.prompt` binding and is included in the retained mutation digest.
The recipe map has one entry per recipe ID; duplicate JSON keys fail strict
decoding. Selection exclusions take precedence over includes. `project-v1`
requires pre-admitted local review delivery, and `reviewed-publish-v1` requires
the same destination kind with an exact native approval. Neither profile accepts
disabled review delivery or an external publication target.
Native adapters must resolve each reference under the enrolled trust root and
check its current identity, configuration and readiness before returning a scope
eligible for Start, then repeat those checks at admission. In particular, an
account/credential reference describes the enrolled requirement; checking the
actual credential's account remains private to its native owner after acquisition
and before provider egress. Schema-valid refs, digests and synthetic fixture labels
do not prove native identity, credential readiness or profile qualification.

Each limit dimension occurs at most once, even if two entries would have
different values or enforcement states. Absent dimensions are unclaimed, never
inferred from another dimension. `enforced` requires a non-null safe integer;
measured-only or unavailable entries cannot be presented as enforced bounds.
The UI displays the typed scope before Start. `task.create`
requires the returned `scope_revision` and `reviewed_scope_digest`; compare them
atomically with reservation and revalidate before provisioning. Any intervening
change refuses with `revision_conflict` and requires refreshed explicit consent.
Imported source bytes receive their own immutable generation after consistent
staging; no enrollment digest pretends to commit an unsnapshotted live checkout.

Every task projection carries `stop_status`: `admissions_stopped`,
`guest_exit_observed`, `provider_abort_requested`, and
`outcome_reconciliation_required`. Unknown is explicit. Only native evidence
confirms admission stop; only outside process observation confirms guest exit.
Provider abort is a request, never a guarantee of no remote effect or charge.
These fields persist into task.get/list and task_changed events after reconnect;
a retained cancel command alone does not set confirmed stop.

## Mutation identity and concurrency

`request_id` correlates a transport response and is not an effect identifier.
`idempotency_key` identifies a logical operator mutation across connections.
Every mutating method also requires `enrollment_epoch`, which must match the
trusted principal epoch returned by hello and is included in the retained binding.
After explicit epoch retirement, old-epoch mutations are refused, even after
a new handshake; the caller cannot relabel them as replay in the new epoch.
Epoch rollover closes existing connections and requires renewed enrollment.
For create, bind it to principal, profile, project and prompt digest. For existing
tasks also bind task ID, expected revision, method and canonical params. A same-key
replay with a changed binding returns `idempotency_conflict` before any effect.

Lookup a retained idempotency record before applying current admission capacity
or a stale-revision check. An exact replay must still resolve its original result
when the task has since advanced or new work is refused. Disclosure still requires
current operator authentication. A new key with a stale revision returns
`revision_conflict`; the UI refreshes and requires a new user action.

In one durable transaction reserve the mutation and its resulting task revision.
Perform native owner calls only after that intent is durable. Native request IDs
are persisted before submission. A crash between external effect and local result
publication leads to original-operation reconciliation, not another submission
with fresh authority. `task.resume` cannot reset limits, clocks, grants or outcomes.

P2 has one task launch slot. The initial controller bounds are 1,024 retained
tasks, 4,096 retained mutation records, 16 clients and 32 queued operator commands.
These are proposed admission defaults. Capacity refusal applies to new work;
inspection and original-operation recovery remain available above the limits.
Records are not silently evicted to make a new action possible.

## Event consistency and backpressure

Cursor = server journal epoch UUID plus a monotonically increasing safe-integer
sequence. The epoch persists with the journal across ordinary restarts and changes
only during a qualified replacement/import. Subscriptions are unfiltered in v1;
clients filter rendered tasks locally, so every committed global change remains
visible to gap detection. An event and the task projection it
describes commit atomically. The sequence orders presentation changes; it is not
the native authority's operation counter.

`tasks.list` takes one consistent snapshot and returns watermark W. Subscribe
from W and apply only events with sequence greater than W. Paginated pages use a
snapshot cursor tied to the same watermark; the snapshot expires after 60 seconds,
at which point the client discards all pages and restarts the snapshot. A restart
with a retained journal resumes from cursor; epoch mismatch or pruned history
returns `cursor_expired`, never an apparently empty successful stream.

Keep up to 10,000 events and 16 MiB of projection history, trimming only events
older than the current snapshot floor. If an active snapshot prevents trimming
at either hard bound, atomically invalidate the oldest blocking snapshots early
and return `cursor_expired` to those readers before trimming; the 60-second TTL
is an upper bound, not a guaranteed lease. Never discard unresolved native
records with presentation events. Heartbeats reuse the current watermark and
do not advance the journal sequence. Per-client queued output is at most 256 KiB. A slow
consumer receives a disconnect requiring snapshot recovery rather than silent
event loss. Heartbeat every 5 seconds; 15 seconds without a valid heartbeat marks
the view stale. This is an availability signal, never a grant extension.

UI coalesces rendering to at most 10 updates/second and retains at most 500 event
rows/1 MiB. Terminal outcome changes, pending-decision invalidations and denial
states are never coalesced away. Reconnect delays: 1, 2, 4, 8, 16, then 30 seconds
with bounded 20% jitter. Stop reconnect on protocol incompatibility until the
configuration or installed tuple changes. A task list page holds at most 200 rows, further reduced to fit the encoded
response envelope plus LF within 65,536 bytes. Count encoded UTF-8 bytes including
escaping before emission; return fewer rows with a cursor for the same snapshot.
If one row or any non-page result cannot fit, return bounded `response_too_large`
without truncating IDs, approval bindings or evidence. No partial frame is sent.
Large artifacts remain external sealed descriptors through qualified native
review/export paths; no arbitrary file reader is added to bypass the limit.

## Error semantics

| Code | Meaning and permitted next action | Exact `retry` | `operation_ref` |
| --- | --- | --- | --- |
| `invalid_request` | Failed validation before submission; correct input. | `never` | null |
| `unsupported_version` | No compatible selected ABI; install qualified tuple. | `after_operator_repair` | null |
| `prerequisite_unavailable` | Required native contract/binding absent; repair without execution fallback. | `after_operator_repair` | null or known context |
| `revision_conflict` | View no longer names current state; refresh and review again. | `refresh` | null or known context |
| `idempotency_conflict` | Key reused for a different mutation; investigate without generating another key. | `never` | null or known context |
| `capacity` | New admission bound reached; recover/archive eligible work while retained lookups continue. | `after_operator_repair` | null |
| `authority_denied` | Native authority refused; show the reason without automatic widening. | `never` | null or known context |
| `outcome_unknown` | Dispatch may have occurred without retained completion; reconcile the original operation. | `reconcile_original` | required original reference |
| `cursor_expired` | Event history cannot satisfy cursor; obtain a full consistent snapshot. | `refresh` | null |
| `storage_unavailable` | Durability unavailable before this request's submission; stop new mutations and repair. | `after_operator_repair` | null |
| `response_too_large` | Complete result exceeds the frame bound; select a qualified bounded view/export, without silently truncating the result. | `never` | null or known context |

The schema binds these three fields as a unit. `never` prohibits automatically
repeating that same request; an explicit corrected request or bounded inspection
route remains possible after the stated action. An optional known-context
reference identifies an existing original record whose status is known; it does
not assert submission of the rejected request and never authorizes replay.
Only `outcome_unknown` carries `reconcile_original`, and its owner-bound original
reference is mandatory. If a storage, transport or rendering failure leaves a
possibly dispatched effect unresolved, return `outcome_unknown` with that
reference instead of describing it as a pre-submission refusal. No error permits
replacing an uncertain original operation with a fresh effect identity.

## Normative requirements

| ID | Requirement | Proposed acceptance |
| --- | --- | --- |
| OM-API-001 | Peers and socket paths MUST be validated, and operator transport MUST be absent from the guest. | AT-API-001 |
| OM-API-002 | Wire limits and closed schemas MUST be enforced before dispatch. | AT-API-002 |
| OM-API-003 | ABI negotiation MUST precede every connection's other requests and distinguish mismatched Hello identifiers from a matching unsupported ABI. | AT-API-003 |
| OM-API-004 | Idempotency lookup MUST preserve original mutations, including above capacity and after revision changes. | AT-API-004 |
| OM-API-005 | Mutations MUST bind exact semantic params and enforce revision comparison on new requests. | AT-API-005 |
| OM-API-006 | Snapshot and event cursors MUST prevent missing or duplicating projection changes across reconnect. | AT-API-006 |
| OM-API-007 | Slow consumers MUST cause bounded disconnect and resnapshot rather than unbounded buffering or silent loss. | AT-API-007 |
| OM-API-008 | Error responses MUST distinguish pre-dispatch failure from uncertain original outcomes. | AT-API-008 |
| OM-API-009 | Client bridge invocation MUST use literal argv/stdin and keep secrets out of process metadata. | AT-API-009 |
| OM-API-010 | Export MUST use an enrolled disclosure profile and retained effect identity. | AT-API-010 |
| OM-API-011 | Task creation MUST atomically bind the exact scope revision and digest reviewed by the operator. | AT-API-011 |
| OM-API-012 | Reconnected projections MUST expose independent admission, guest, provider-abort and reconciliation stop dimensions. | AT-API-012 |

## Proposed acceptance

### AT-API-001: Peer and socket boundary
Trigger: wrong UID, symlinked socket parent, guest raw connection attempt and valid
operator connection. Expected: only enrolled operator succeeds. Oracle: socket
audit and independent guest probe. Artifact: `operator-socket-boundary.json`.

### AT-API-002: Invalid frame corpus
Trigger: unknown fields, duplicate keys, oversized LF frame, bad UTF-8, excessive
depth, invalid safe integer and valid boundary-sized request. Expected: exact
refusal classes, zero mutation on invalid frames. Oracle: native dispatch counter.
Artifact: `operator-frame-corpus.json` including corpus digests. Include 200
maximal-evidence rows and maximally escaped labels: pagination preserves one
snapshot, and indivisible overflow emits only the bounded typed refusal.

### AT-API-003: Negotiation failure
Trigger: request before Hello, matching supported identifiers, matching bounded
unsupported identifiers, mismatched identifiers, malformed/overlong identifiers,
non-Hello wrong protocol and reconnect with changed backend. Expected: only the
matching supported Hello selects an ABI; matching unsupported candidates return
`unsupported_version`, mismatches return `invalid_request`, and both typed errors
use the v1 response envelope and close the connection without native dispatch.
Malformed identifiers fail structural validation; a valid Hello never admits a
later request with a different ABI. Oracle: protocol transcript and native count.
Artifact: `operator-negotiation.json`. Synthetic catalog `valid` records structural
schema validity; `hello_outcome` separately records `selected`, `invalid_request`
or `unsupported_version`. Static fixture checks do not execute these session rules.

### AT-API-004: Durable replay above capacity
Trigger: replay completed and uncertain keys after restart, revision advance and
full admission capacity. Expected: original lookup remains available with no new
effect. Oracle: mutation and resource ledgers. Artifact: `operator-replay.json`.

### AT-API-005: Mutation substitution
Trigger: alter prompt, resource, native operation or expected revision under an
old key; race two new controls against one revision. Expected: conflict or one
linearized control. Oracle: persisted request binding. Artifact: `operator-cas.json`.

### AT-API-006: Snapshot-stream race
Trigger: commit task changes between paginated snapshot reads and subscription,
then expire the cursor and restore an older journal epoch. Expected: complete
single view or explicit restart, never false empty success. Oracle: snapshot at
known watermark and event sequence. Artifact: `operator-event-consistency.json`. Interleave updates for two tasks
and flood beyond 10,000 events/16 MiB within an active snapshot: unfiltered
sequences remain continuous, pressure invalidates blocking cursors explicitly,
and no memory/history bound is exceeded.

### AT-API-007: Slow consumer
Trigger: stop reading while producing more than 256 KiB of events. Expected:
bounded queue, explicit connection loss, complete state after resnapshot. Oracle:
external RSS/queue observer and state comparison. Artifact: `operator-backpressure.json`.

### AT-API-008: Error classification at cutpoints
Trigger: failure before native submission and response loss after dispatch.
Expected: different codes and recovery actions, original identity retained.
Oracle: independent dispatch marker. Artifact: `operator-error-cutpoints.json`.
Include a valid positive for each error-code row, all forbidden retry substitutions,
null `outcome_unknown` references and invented references on pre-submission
refusals. Schema refusal verifies only the projection contract; the independent
runtime marker must establish whether the claimed submission classification is true.

### AT-API-009: Shell metacharacters remain data
Trigger: prompt contains quotes, newlines, backticks and command substitutions.
Expected: literal prompt, absent execution sentinel, no secrets in argv/env.
Oracle: process metadata observer and sentinel hash. Artifact: `client-invocation.json`.

### AT-API-010: Receipt export disclosure
Trigger: export private receipt data to an unknown profile and approved redacted
profile; interrupt after bundle creation. Expected: unknown profile refusal,
exact filtered bundle, original export recovery. Oracle: read-only bundle scanner
and export ledger. Artifact: `receipt-export.json`.

### AT-API-011: Enrollment changed after review
Trigger: independently change principal, authority/trust root, project selection,
policy, host/provider/account/credential reference, verification plan, limits,
network or local review destination after scope.get and before reservation/provisioning.
Include duplicate limit dimensions, omitted/null typed bindings and display-label
substitution fixtures. Expected: malformed scope never enables Start; stale creation
refuses with no guest or model/tool effect; refreshed consent displays the exact
new typed values and digest. Oracle: native
launch/effect counter and enrollment transaction log. Artifact: `reviewed-scope-race.json`.

### AT-API-012: Lost cancellation result
Trigger: stop guest, lose native admission-stop response and reconnect the UI.
Expected: guest exit confirmed, admission stop unknown, reconciliation required;
no false cancelled/safe badge. Oracle: outside process observer and native owner
query. Artifact: `cancellation-projection.json`.
