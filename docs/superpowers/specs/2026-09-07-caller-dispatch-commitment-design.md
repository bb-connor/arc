# Caller dispatch commitment and delivery recovery

Status: private storage framing, typed frozen return-component capture and
readback, retained federation evidence, and opt-in operation-owned runtime
custody with explicit activation are implemented. The complete durable kernel
snapshot, credential/security-hook custody and external handshake remain
required. Composed runtime and bounded process-loss tests provide evidence,
not full profile qualification. This document preserves
the full security roadmap and resolves a missing caller-execution boundary.
It is not a release qualification or a new exception to admission ordering.

## Reproduced contract failure

The sidecar and Python SDK describe reserve, external execution, then report.
The current kernel reserves the operation-owned nonce in `ReadyToDispatch` and
captures invocation quota only while reconciling the report. Startup recovery
can compensate an expired Ready reservation without knowing whether the external
executor has already acted.

The real-kernel SQLite contract test
`external_delivery::an_external_effect_with_a_lost_report_cannot_be_refunded_at_nonce_expiry`
reproduces that interval. It checks the authority's retained nonce, creates and
syncs a file outside the kernel's registered tool server, closes the authority
without reporting, advances beyond nonce expiry, and reopens it. The file still
exists, but the grant has zero reserved and zero captured invocations. The test
also obtains an allowed reservation for a second operation under the same
one-invocation capability. It requires one captured invocation, denial of that
second call and an outcome-unknown dispatch terminal for the first operation.

This is a trusted-caller contract counterexample, not a qualified external
transport, process-kill test or demonstrated remote exploit. The fixture reads
nonce provenance from the authority directly. Its explicit ignore names the
missing dispatch-start handshake; running it with `--ignored` currently fails
at the intended quota/admission assertion: `((0, 0), Allow)` instead of
`((0, 1), Deny)`. It must become an executed passing gate after
the complete handshake replaces reservation-only external execution.

## Required lifecycle

```text
prepare/reserve -> ReadyToDispatch -> authenticated start -> DispatchCommitted
                         |                                      |
                 unused expiry cleanup                  external execution
                                                                |
                                               authenticated delivery report
                                                                |
                                                      existing finalization
```

Reservation alone is preparation, never permission to execute externally. A
distinct start operation reuses the retained operation ID, provider attempt,
executable hold and operation-owned nonce. It runs current admission checks,
commits required credentials and atomically captures the existing invocation
claims before a durable dispatch commitment can authorize the external effect.
No new request ID, independent quota counter or process-local owner map may
substitute for those participants.

The executor must authenticate the kernel's dispatch authorization against its
configured trust root and expected executor identity, request and operation.
It must claim the exact operation in its own durable execution ledger before
performing an effect. A received authorization is not an exactly-once proof:
lost replies and duplicate delivery require the executor's durable claim and
the downstream operation's stated idempotency contract. The kernel must never
blindly redeliver an executable authorization after losing its acknowledgement.

The dispatch authorization must bind the operation and request digests,
capability and action parameters, exact provider attempt and key epoch, nonce
identity, captured hold and dispatch commit, validity interval, and frozen
admission-context digest. It must have an explicit signed-message domain. The
reservation nonce's signature is not evidence that dispatch was committed.
Self-asserted transport identity or a deserialized DTO is not qualification.

Before publishing that authorization, retain the complete context required to
finish the same invocation: selected grant, original request, post-return plan,
pre-invocation guard evidence, receipt and federation snapshots, payment and
delivery bindings, stream limits, and security/runtime participant custody.
Derive those values from the admitted operation, never from a later report or
fresh default configuration. Required participant retention must be atomic with
or provably ordered before authorization publication. An unsupported backend
must fail closed before any external effect is authorized.
Keep retained context private to the authority. The public authorization binds
its digest, not raw credentials, internal policy evidence or protected input.
Persist one-shot credential disposition and binding through the existing
participants instead of copying reusable secrets into a new context artifact.

Reconciliation accepts the report only against that committed attempt and its
retained context. It enters the existing durable tool-return and post-return
pipeline; it must not repeat pre-dispatch admission, acquire another hold, or
invoke a tool server again. Completion is persisted before release, and exact
receipt replay remains distinct from a second execution. Authenticated reports
may complete the original operation after the execution permission has expired;
they do not extend permission for new effects. Report bytes, cost and terminal
evidence require exact authenticated binding and bounded canonical decoding.
Caller-supplied output must not be relabeled provider-attested evidence.
Accepting historical execution evidence for accounting must not bypass the
required output guards, revocation checks or release policy for returning data.

## Recovery and negative controls

| Boundary | Required result |
| --- | --- |
| Before start, including expired unused Ready reservation | Idempotent compensation of only the original owner's participants |
| Start denied by revocation, expiry, approval, guard or budget checks | No dispatch authorization and no external effect |
| Capture succeeds but dispatch commitment is unacknowledged | Query the same operation and capture; no new hold or send |
| Dispatch commitment succeeds but authorization delivery is lost | Captured quota and required custody retained; no blind resend |
| Authorization delivered twice or two executors race | One durable execution claim, or a documented fail-closed result; never two effects |
| External effect starts, report is lost, authority restarts or nonce expires | No refund and no fresh execution; retained unknown outcome/evidence |
| Report is duplicated, modified, misbound or signed by another executor | Exact completion replay or denial without another mutation |
| Report arrives after permission expiry | Historical committed context can finalize, but cannot authorize execution |
| Partial return/finalization persistence, key rotation or owner fencing | Existing durable recovery and signature/fence checks preserve the original operation |

Each relevant cutpoint needs a real-kernel/provider/store test. Retain the
current failed contract as a calibration: omitting start or releasing a
committed unknown outcome must reproduce the intended failure. Include
ordinary and delegated calls, same-child overlap, pending sibling admission,
cumulative approval, payment/monetary custody, revocation, security/runtime
leases, provider key/attempt substitution, and multi-process crash recovery.
Do not count abstract model checks or mocked status DTOs as these executions.

## Integration order and acceptance

The implementation must account for these existing boundaries:

- `kernel/evaluation/caller_execution.rs` uses `CallerReportServer` as a
  stand-in for already-performed execution. It is not an authenticated provider
  adapter. Its transport epoch currently derives from coordinator ownership,
  not an independently pinned external executor signing key.
- `kernel/admission_coordinator.rs` does not resume tool admission from
  `DispatchCommitted`. Merely adding that state to its replay match would send
  an already-executed call back through pre-dispatch authority acquisition.
  Reports need a distinct committed-context entry to terminal finalization.
- `kernel/admission_coordinator/execution_nonce.rs` applies live-nonce checks
  during current admission. Historical report verification needs independently
  authenticated dispatch time and exact committed nonce provenance; it must
  not weaken those live checks for new executions.
- `kernel/admission_coordinator/return_context.rs` now freezes receipt and
  purchase/recovery metadata, selected grant, pre-invocation guard evidence,
  stream limits and security invocation identity before the shared ordinary and
  nested dispatch commit. Terminal recording consumes that in-memory component.
  Memory-read provenance, actual output, cost and elapsed time remain return
  observations. Federation now contributes a bounded private encoding of its
  original signed treaty evidence, local accepted report binding, participant
  pins and admission time. That component is frozen before dispatch and retained
  with the returned outcome, not yet with a caller start commitment. The complete
  durable snapshot still needs credential/security/runtime participant custody
  and its joined producer and decoder before an external start can use it.
- `kernel/evaluation/async_evaluation_core.rs` currently enters `CapturePending`
  before payment authorization, the finding-pool claim and the final security
  dispatch hook. A context framed at that point cannot claim those later results
  already exist. The typed snapshot must distinguish frozen admission decisions
  from exact operation-owned participant references, then establish required
  durable custody before publishing authorization. Do not move a financial
  side effect ahead of its existing durable intent just to populate the frame.
- `admission_operation_store/execution_nonce/lifecycle.rs` keeps its exact
  empty-attachment capture-preparation command. The dedicated caller-context
  capture port instead commits the digest and physical row with actual quota
  capture, the nonce commitment and `DispatchCommitted` in the existing anchored
  transaction. Generic attachment paths remain denied.

The kernel paths above are relative to `crates/kernel/chio-kernel/src/`; the
store path is relative to `crates/platform/chio-store-sqlite/src/`.

Migration cannot reinterpret an older caller reservation as proof that no
external effect occurred. A populated authority with such reservations needs
explicit authoritative reconciliation or fail-closed migration refusal. Do not
backfill a dispatch authorization, synthesize capture history, or refund an
ambiguous legacy effect merely to obtain a schema version upgrade. Schema 18
refuses nonterminal caller records and caller compensation, not-accepted and
denied-after-delivery terminals from older or unversioned authorities. A legacy
refund is not proof of external nonexecution. Successful migration preserves
ordinary nonce history and does not invent a context for it.

### Implemented storage boundary

`AdmissionCallerDispatchContextV1` provides bounded, exact canonical framing for
the kernel's private context. It binds the immutable request and original-request
digest, CapturePending version, caller provider attempt, reserved nonce and executable
hold. The frame's digest is an immutable operation attachment. It is not an
execution permit or a verified kernel snapshot: the owning kernel's typed
payload producer and decoder are still required. A canonical JSON object alone
cannot prove guard, federation, credential or runtime custody.

SQLite's `capture_caller_invocation_and_commit_dispatch` retains the frame
atomically with actual invocation capture and the nonce `DispatchCommitted`
transition. Capture preparation remains a separate, earlier durable intent.
No external permit is produced by this storage port. Exact capture replay and
restart preserve the original commitment. Direct reads, replay, recovery scans and startup verify physical
context ownership and the committed digest against the retained original.
Oversized, missing, modified and unowned rows fail closed. Other store
implementations reject the new ports by default.

The caller-report capture path now uses this port for the typed frozen return
component described below. This extends the storage framing portion of step 1,
not the complete admission snapshot or any external transport qualification.
No authenticated kernel start producer, sidecar start route or SDK start client
exists yet. The
reproduced external-effect contract remains explicitly ignored and failing when
run until steps 1 through 6 are integrated and verified.

### Retained federation evidence for returned invocations

`kernel/admission_coordinator/federation_context.rs` captures the original DSSE
envelope and local accepted treaty report binding, not just derived receipt
metadata. Before dispatch, the kernel validates those materials against the
admitted peer, local identity, request and original admission time. The bounded
canonical component becomes part of the content-addressed raw outcome under
`chio.raw-invocation-outcome-with-federation-context.v1` after the tool returns.
Legacy outcome schemas retain their existing bytes and cannot carry the new
field. This is a private persistence format, not a provider report or public
receipt metadata field.

Recovery first validates the configured qualified outcome authority's exact raw
blob against the operation's dispatch binding. It then checks the retained
component's request and operation binding, local identity and time bounds, and
re-verifies the original DSSE using the retained peer pin at admission time.
The accepted local report binding is trusted through that durable provenance,
not by pretending the peer signed it. Deserialization never constructs
`VerifiedFederationTreatyMaterial` directly. Missing or malformed evidence in the
new schema denies; old outcomes remain distinguishable and use their existing
legacy recovery behavior without fabricated history.

Already returned outcomes can finish a missing bilateral projection without
running fresh runtime admission. Internal historical recovery need not acquire
a new peer pin, but public request replay still enforces its current registered
target, capability, revocation and peer gates. Local signing-key rotation fails
closed; no historical key-custody fallback is invented. This does not implement
an authenticated historical report entry point, external execution authority or
the complete caller dispatch snapshot.

Each startup finalization receives its own evaluation scope. Concurrent
operations may share a caller request ID without sharing retained treaty
authority, and nested scopes restore their enclosing recovery context. Raw
outcome diagnostics omit private evidence, request credentials and tool output.

Local context-validation errors are distinguished from unconfirmed store
commits. The former use original pre-dispatch compensation and roll back only
reversible credentials; payment-authorizing credentials stay retained. The
latter keep participant custody for authoritative recovery. Payment unwind
uses the same immutable operation reference as authorization and restart
recovery, not the caller's request ID. These properties do not establish
durable runtime or security participant custody for an external start.

### Credential preparation and required durable ownership

The shared credential path now separates non-consuming preparation from
reservation. `PreparedDispatchCredentials` borrows its originating kernel and
immutable request/capability inputs. It validates the applicable DPoP, legacy
execution nonce and governed-approval inputs before replay writes, and captures the legacy
nonce backend's reservation mode through a contained, read-only capability
query. It cannot be serialized or cloned into purported custody evidence.
Dropping it neither spends nor releases a credential.

Consumption revalidates the same artifacts with fresh time, without accepting
replacement inputs, stores or another kernel. A changed reservation mode or a
panicking capability query denies before any marker is acquired. The existing
owned reservation path still controls partial rollback, payment retention and
legacy nonce consumption at the first effect boundary. Caller authorization
shares this path without pretending to present the nonce it has not minted.
Preparation is not reservation: a competing reservation can still win and an
already-consumed approval can still reject during actual acquisition.

Preparation alone is the pre-mutation boundary, not durable credential custody.
The legacy DPoP path uses its process-local nonce store, and legacy governed
approval reservations are not admission-operation owner fences. The opt-in
operation-owned paths below instead acquire anchored exact-episode references
under the current admission lease. The operation-owned nonce
already has qualified custody and must not also be consumed in a legacy store.
The new authority path must retain a complete validated credential plan and
claim the actual replay identities under the existing operation authority,
including owner-qualified release, commit, readback and restart recovery.
It must not copy reusable signed credentials into a return-context artifact
or infer durable ownership from the prepared value.

The security pre-dispatch hook separately returns a request-lifecycle permit
and an optional outcome recorder. Their live handles can own an admitted
request or consumed declassification, but cannot survive process loss by
serialization. External start needs durable operation-bound security
participants with verifiable consumption, terminal disposition and current
release policy, including when no declassification outcome handle is returned.
Credential/security integration must preserve every existing consumer or
reject an unsupported profile. Mixed legacy writers, migration of ambiguous
historical consumption and lost acknowledgements remain qualification gates.

The current two-call caller API now refuses credential-bearing requests and
installed security-hook or enforced-security profiles before admission mutation.
This closes a misleading reserving Allow: the later report rebuilds a request
without those credentials and cannot recover their custody. Rejection preserves
any already-issued nonce and leaves ordinary kernel dispatch available. It is a
temporary fail-closed boundary, not completion of the snapshot/start contract.

The live security hook now validates its returned outcome owner against the
current request and canonical commitment. Shared callback and disposal containment
protects ordinary and nested execution, including outcome-recorder cleanup during
unwind. Post-effect errors use the non-redispatchable recovery error, not an
extension-supplied guard rejection. Request lifecycle release shares one checked
response boundary. None of these live handles certifies recoverable security
ownership after process loss. A consuming lifecycle callback and its own nested
destructors still belong to trusted native code; unwind containment is not an
abort or sandbox boundary.
The final-release failure/replay counterexample now has a physical SQLite
checkpoint implementation. A release requirement is frozen before dispatch and
retained in the new raw-outcome schema. Callback success produces an opaque
acknowledged-owner value; the fenced outcome store persists its exact request,
dispatch commitment, resolved outcome and evaluation before terminal publication.
The checkpoint is separate from output evaluation and monetary settlement.
Replay verifies the retained checkpoint without consuming another owner. Missing
acknowledgement or a crash before checkpoint persistence leaves the operation
unresolved and quota captured. A checkpoint write whose acknowledgement was lost
is recoverable by exact readback. Unsupported stores reject before dispatch, and
legacy security-context returns without a qualified requirement cannot infer one.
This closes the reproduced output bypass, not the full security participant
requirement: recovering a pending native owner, joined flow/declassification
custody, current release policy and authenticated caller start/report still need
their actual operation-owned authority. Decoding the checkpoint is never that
authority, and a successful historical release is not a fresh execution permit.

### Prepared production flow dispatch

The persistent flow resolver now separates non-consuming preparation from its
actual dispatch commit. `PreparedFlowDispatch` owns the validated flow plan and
borrows the originating resolver, whose manifest registry and policy remain
immutable. Preparation classifies once and retains the verified grant bindings,
original flow snapshot, request identity and dispatch commitment. It does not
consume declassification, join taint, acquire a fence or emit receipt evidence.
Dropping it does not perform those mutations. The existing production
`FlowPreDispatchPort` commit uses this same path, not a parallel implementation.

Commit accepts no replacement request or backend. After read-only evidence
lookups it rechecks the exact live flow snapshot and samples the original
authority's clock. A changed snapshot, backward clock, expired grant or expired
original fence plan rejects before participant writes. Preparation cannot renew
permission. Successful consumption records the fresh commit time and follows
the existing immutable consumption/outcome evidence and sink-readback path.
Verified prior consumption remains a replay refusal, not newly acquired custody.

This supplies the production validation boundary needed before operation-owned
security participants can be joined to caller admission. It is not that joined
custody: flow, declassification and receipt transactions remain separate,
concurrent changes after validation still rely on the existing fence and replay
checks, and no native owner can be recovered by deserializing this plan. Source
retirement, operation fencing, durable participant references, current release
policy and authenticated external start/report remain required.

### Flow and declassification source retirement

`security_state::SqliteSecurityParticipantSource` is a migration-only boundary
for an existing, quiesced SQLite security source. It never creates, migrates,
prunes or stamps that source. Opening requires the exact current critical-table
catalog, canonical application/schema identity, WAL with synchronous FULL, and
the audited SQLite VFS identity of one regular, single-link main file. Unsupported
VFSes, source substitution, partial seals and unqualified predecessors fail
closed without repair. The normal security-store opener and already-open typed
handles refuse service when retirement evidence exists.

An operator must independently retain the exact preview before calling
`seal_exact`. The preview fingerprints all fourteen flow, isolation, membership,
generation, egress-fence, declassification and shared-transition tables. It
preserves pending consumptions, retained receipt/outbox state and compacted replay
tombstones. Cells carry explicit SQL type tags; integers use decimal strings,
blobs use hex and text must be UTF-8. Sorted canonical row streams have
domain-separated, length-framed SHA-256 digests. Fingerprints include table row
counts, encoded byte counts, the qualified sealed catalog and physical device/
inode identity. This is not an importable row frame: complete rows remain in the
source. Operator-selected source, authority and destination labels are bindings,
not evidence that any destination or admission authority exists.

The exact source must fit 16,384 critical rows and 64 MiB of encoded row data,
with individual cells bounded at 1 MiB and raw rows at 2 MiB. Catalog observation
is bounded at 192 objects and 256 KiB; the canonical fingerprint is at most
64 KiB. Oversized data fails closed before domain decoding rather than being
pruned or truncated. Existing flow-label/context and declassification-evidence
integrity checks run after inventory bounds are enforced. These checks are not
a historical proof that every retained row came from a legitimate operation.

One immediate transaction compares the entire source before its first write,
inserts the canonical seal and installs 48 permanent SQL barriers. Those barriers
cover INSERT/UPDATE/DELETE on fourteen critical tables and seal evidence, plus
the security schema-version row, including replacement writes. Exact readback
is required before acknowledging success. Pre-commit failure rolls back the
whole retirement; commit acknowledgement loss is resolved by exact live readback.
A sealed retry verifies and never repairs. Existing older SQL connections cannot
mutate these tables, including with recursive triggers disabled. This retirement
seal is distinct from `live_dispatch_sealed`, which historically enables ordinary
declassification dispatch rather than retiring its writers.

This is source retirement only. It requires quiescence of the whole legacy
security service because shared transition history is frozen and normal typed
handles stop serving. Unrelated active-defense tables are not claimed frozen or
transferred. The boundary cannot retract already admitted in-memory work or
protect against a privileged actor rewriting the database/DDL or rolling back
the filesystem. A decoded fingerprint or observed seal is neither recoverable
security custody nor fresh permission. The destination boundary below retains
the exact pin and inactive inventory. Activation, all affected consumer
migrations, actual operation fencing and claim/release/recovery remain required
before this can be used in a serving configuration. No actual operator database
is retired by the implementation or tests.

### Inactive flow and declassification destination import

Admission schema v27 adds an immutable migration archive, not a serving flow
projection. `expect_security_participant_source` validates the independently
held destination serving-owner fence, obtains the real destination UUID from
that fence, and previews the source outside the destination lock. An immediate
destination transaction revalidates the owner, rejects its own physical main
file as source, and retains the exact canonical fingerprint with a deterministic
generation ID and globally anchored expectation event. Different source labels
cannot pin the same device/inode twice. Exact retries read the existing pin;
they do not rediscover or replace a now-retired source.

`import_security_participant_source` serializes source-mutating migrations,
loads that exact anchored generation, and seals and reads the physical source
outside the destination mutex and transaction. The source reader requires the
live exact seal, complete bounded inventory and unchanged file identity. It
exports actual canonical rows through a crate-private, non-deserializable value.
One destination transaction rechecks the current owner, copies every row, verifies
the row streams against every pinned table fingerprint, and appends the inactive
import event and global commit. Commit, independent-anchor synchronization and
exact readback precede acknowledgement.

The archive includes pending and terminal declassification uses, receipt outbox
entries, permanent replay tombstones, flow generations and shared transitions.
No expiry pruning or historical ownership inference occurs. Reads rehash actual
row bytes; contiguous indexes, complete table counts, canonical fingerprints,
historical owner leases, event order/digests and one-to-one global references
are checked. Schema v27 only adds empty tables to exact qualified predecessors;
partial, alternate-case and future migration namespaces are not adopted or
repaired. The global catalog upgrade preserves historical row and chain bytes.

The destination admits at most sixteen sources, 65,536 total retained rows and
64 MiB of canonical row data. Pending pins reserve their full declared inventory
against those limits before retirement. Source-specific bounds still apply.
Catalog, cell types, text/blob sizes, counts and aggregate byte bounds are
validated before allocation or source decoding. Nine persistent triggers forbid
update, deletion and replacement of the archive, including late row insertion
after import and conflict-ignore/replace operations with recursive triggers off.

The only phases are `Expected` and `ImportedInactive`. The archive does not
hydrate mutable legacy tables, activate a security authority, resume pending
dispatch, recreate a live admission owner or return an execution permit. An
import retry after acknowledgement still requires a live exact source seal and
never repairs it; archive lookup can survive source loss but confers no authority.
Operators must still quiesce every old security consumer. Activation must qualify
all affected consumers, preserve spent grants and unresolved fences, and seed
real operation-fenced mutable state under an explicit authority transition.
These later transitions and their recovery/rollback rules remain unimplemented.

Admission schema v28 adds a separate native hydration step, without changing
the v27 archive, its two phases or the source v1 fingerprint bytes.
`hydrate_security_participant_state` accepts exactly an imported authority and
expectation under the current destination serving fence. Every native primary,
unique and foreign key includes `security_authority_id`; tenant/grant/transition
identifiers from different sources remain independent. Fourteen relational
tables retain original SQL cell types. Hydration streams the verified archive,
stages pending uses and consumption evidence before retained terminal uses and
outcome evidence, and compares the actual native row streams with every pinned
source fingerprint. Staging is confined to the new unexposed transaction; no
committed source or archive history is rewound or pruned.

The same outer transaction inserts an immutable initialization bound to the
source generation, native catalog digest, independently observed time and
historical owner lease, then appends its exact global reference. SQLite commit,
independent-anchor synchronization and fenced readback precede acknowledgement.
Exact retries return the same history, including after owner rotation or loss of
the retired source file. They cannot manufacture a fresh source or authority.
Current owner/clock checks still apply. Readback validates bounded metadata,
canonical catalog, native row bytes and one-to-one global coverage.

Forty-two native-row barriers and three initialization-history barriers prevent
late insert, update, delete, conflict-ignore and replacement after initialization,
including with recursive triggers disabled. Three scoped dependency triggers
also protect use/evidence/predecessor and permanent spent-grant relationships
during hydration. A v27 upgrade adds only empty native tables and preserves all
import/global history; partial, future or alternate-case native namespaces and
missing current barriers reject without repair. Native initialization is still
inactive. It exposes no `FlowStateStore`, live declassification writer or
operation claim/release/commit API. Activation must first integrate qualified
mutable custody, every affected legacy consumer and the remaining recovery and
current-policy contracts above.

Later activation must preserve the historical v28 initialization and catalog
digests. Once rows legitimately change, their current projection must be checked
against qualified, anchored mutation history rooted in that initialized inventory.
An activation flag cannot simply disable fingerprint verification, change the
meaning of an existing initialization digest or manufacture operation ownership.

The existing security store's deadline checks have been hardened before engine
reuse. Trusted time is sampled only inside a transaction after the SQLite
snapshot is acquired, including for deferred read validation. Waiting for the
connection or database lock cannot preserve an earlier lease/fence timestamp.
Exact committed egress replay remains historical evidence and does not require
a live deadline or available clock. The native lock-contention regressions do
not establish operation ownership, an external execution permit or activation.

The internal `SecurityStateWriteTransaction` now owns the actual SQLite write
transaction across flow and declassification evidence mutations. Success returns
the owner for additional participant work; errors or cancellation roll back the
whole uncommitted transaction. Each legacy public method still performs its own
outer commit. This is the composition prerequisite, not an activated native
projection: production writes still target legacy tables and have no
admission-operation or recovery-claim binding. Future compensation must preserve committed taint,
spent grants and historical evidence rather than reverse them.

The flow engine now shares its domain semantics across a closed legacy/native
query catalog. Native SQL explicitly scopes all reads, mutations, conflict keys,
generation fallback branches and isolation-history source selection by authority.
Dense numbered bindings put the authority before the unchanged domain parameters.
The reader cannot construct a mutation view, and neither view exposes raw SQL,
an underlying connection or an independent commit. Production mutation views
remain borrowed from the legacy affine owner. Native mutation construction is
test-only, with speculative writes rolled back against the actual v28 catalog;
initialized barriers remain unchanged. Hydration additionally exercises scoped
flow readers once, after byte-exact fingerprint validation. Repeated inactive
readback relies on those exact fingerprints, without decoding shared labels once
per retained context on every owner check.

The declassification engine now uses the same checked binder with thirty-six
explicit legacy/native query pairs. Consumption, outcome, lifecycle, permanent
identity, acknowledgement/retry, pending/stranded selection and compaction all
keep the selected authority in their keys, joins and correlated queries.
Hydration additionally checks the scoped lifecycle and relational evidence once.
Legacy readiness and compaction candidate reads acquire one deferred snapshot
before their schema and data queries. Mutations retain the outer rollback-owning
transaction; no nested commit or raw connection escapes from the data engine.
Compaction checks the complete receipt-pair binding, chronological ordering and
both permanent identity records before deleting live evidence. Readiness cursors
are not authority to erase an inconsistent pair.

Native mutation construction remains test-only and every speculative mutation
is rolled back. Initialized write barriers and v28 initialization/catalog/source
digests are unchanged. Pure exact-history results do not activate a writer or
grant serving permission. These engines do not introduce anchored current-state
mutation history, activate an authority or mint an operation owner. Production
native mutation custody and migration of every affected legacy consumer remain
required.

Preserved fence and transition identifiers are not globally unique across
security authorities. Future operation custody and the retained caller snapshot
must bind the selected authority alongside those existing identifiers. A matching
fence DTO alone cannot establish that authority; changing the old identifier
derivation would also invalidate the retained source history.

Fresh declassification consumption additionally checks the independent store
clock inside that transaction. Exact consumption/outcome replay remains retained
history. Isolation verification is an external durable-evidence check over the
complete transition; no database lock spans that callback, and the mutation
rechecks current state after it returns. No deserialized migration record is
accepted as verification evidence or mutable transaction ownership.

Retained row decoding now preserves the exact v1 SQLite cell representation and
checks it against the compiled predecessor layout before insertion and on
destination readback. Complete retained egress records share the live decoder:
request-derived fence identity, paired commitment fields and historical time
bounds must hold independently of the pinned hash. Source inventory also checks
that a retained fence has a present, non-regressed flow context. Stale and expired
records remain retained history, never new execution permission.

Disposable projection tests establish lossless row decoding with live schema
triggers enabled, not production hydration. In particular, declassification
consumption, terminal use and outcome must be staged in dependency order inside
the single, unexposed initialization transaction. The final archive row order
cannot be applied directly through the live state-binding triggers. Real native
hydration must still bind this initialization to the selected authority, complete
migration generation, serving fence and operation-owned recovery contract.

### Governed approval legacy source retirement

The durable approval store exposes an explicit preview, exact-expected seal,
load and live verification boundary. It freezes all physically retained replay
markers, including committed and independently reserved markers, their expiry,
the persisted clock high-water and prune horizon, and capacity. The migrated
legacy unscoped-subject sentinel remains a wildcard blocker across subjects;
it must never become an ordinary subject during import. Historical reservation
identifiers are inventory data, not admission-operation release authority.

Sealing compares the complete candidate before its first write in the same
immediate SQLite transaction that installs the inventory and twelve persistent
insert/update/delete barriers on entries, clock, limits and seal evidence.
WAL with synchronous FULL and exact post-commit SQLite readback are required.
Typed legacy writers reject even no-op mutations once any seal evidence exists;
the SQL barriers also block actual writes from already-open older connections.
Sealed reopen verifies the complete source before migration, pruning, clock
advancement or capacity reconfiguration. Requested capacity is ignored for a
sealed read-only source. Missing or substituted evidence is never repaired.

The inventory uses bounded canonical JSON with domain-separated hashing and
decimal strings for full-range integers. Limits are 16,384 markers, 512 UTF-8
bytes per identifier and 8 MiB of encoded data. Oversized or malformed retained
data rejects rather than being truncated, pruned or reinterpreted. Sealing
accepts the exact current legacy catalog only; unqualified historical ALTER
variants reject without schema normalization. It binds the actual open SQLite
main-file descriptor and configured path to one regular, single-link file.
Unsupported VFSes, in-memory sources, copied files and changed path identities
cannot supply a source seal. Operator-selected source/authority labels and a
decoded snapshot are not authenticated authority or proof of live sealing.

The qualified admission store now independently pins one source generation to
its actual destination UUID and configured approval authority. After exact
live sealing and verification, it atomically imports the complete inventory as
unresolved tombstones with a local migration event and global anchored commit.
Source callbacks run outside the destination database mutex and transaction;
source-mutating workflows share the serving owner's nonblocking migration guard
with runtime replay migration. Exact recorded import retry only verifies the
source and reads history; it never discovers or reconstructs a missing seal.
Partial SQL writes roll back, and a lost seal acknowledgement leaves the
original pin intact for exact retry. Pending pins reserve complete inventory
capacity before sealing. Duplicate physical sources and source/destination
file identity collisions reject.

Use `SqliteGovernedApprovalReplaySource::open` for migration, including restart
between pinning and sealing. It opens an existing canonical source without file
creation, schema or application-ID adoption, clock advancement, pruning or
capacity changes, and exposes no legacy reservation writer. The normal legacy
opener is inappropriate for resuming a pending pin because it may advance the
clock and prune retained rows. Operators must quiesce all legacy consumers
before preview; independently open old writers can still change an unsealed
source, in which case the pinned import refuses without repinning or repair.

Import alone leaves the profile inactive. Admission schema v23 adds explicit
activation of the exact imported generation, operation-fenced approval claims
and exact pre-dispatch release. Activation requires the authority's actual clock
to have reached the imported high-water and prune horizon; a caller timestamp
ahead within tolerated skew cannot satisfy that requirement. The canonical
legacy inventory remains unchanged. Historical reservation IDs remain
provenance, never operation ownership. No migration revokes previously admitted
work or provides independent antirollback protection. An ambiguous seal commit
requires authoritative readback, never resumption of legacy writes.

Claims retain bounded, non-executable commitments to the token, issuer, subject,
request, intent, selected grant and validity interval. A claim requires the
original retained request, active authority generation and current exact-version
operation lease. A distinct permanent operation ledger binds at most 128
episodes with one live owner; each acquisition and release has canonical
physical evidence and a named admission/global commit. Old release references
cannot release a successor, and generic compare-and-swap cannot fabricate
ownership. Imported scoped and wildcard markers remain permanent blockers,
including expired rows. Expiry frees live capacity for different identities but
does not erase spent evidence or release an operation's claim.

New authorization and capture validate live approval authority. Historical
dispatch is checked at its retained commit observation, so current expiry cannot
turn committed work into reversible pre-dispatch ownership. Kernel startup
compensation and nonce issuance release only exact pre-dispatch claim history;
cleanup does not need the original signature or an unexpired token. Dispatch
commitment permanently prohibits release, including recovery after a lost report.

Normal acquisition can now be explicitly configured with
`set_operation_owned_governed_approval_source`. This installs only an already
activated generation and verifies the actual sealed backend; it neither imports
history nor activates a user source. Complete non-consuming credential
preparation precedes the selected grant's replay mutations. Approval claims are
acquired before budget authorization, and later credential reservation verifies
the exact original request, grant and token commitment without consuming the
legacy replay store. Source verification runs outside the coordinator sequencer
and is repeated after delivery readiness. Exact readback retains confirmed
operation updates across failed claim callbacks so cleanup cannot unknowingly
use the preceding version. RAII release names one exact episode and cannot
release its successor. Threshold approval proposals and sets are not replaced by
single-token custody; a malformed retained proposal is not an absent proposal.
Constructing or decoding claim intent data establishes neither signer trust nor
dispatch permission. Full caller security custody and authenticated external
start remain open; no user database has been activated. Combined runtime and
credential interruption qualification remains part of the full roadmap.
DPoP remains a separate volatile-history problem: a restarted empty nonce cache
does not establish that previously valid proofs were never consumed. Its
qualified transition must preserve that history or explicitly refuse/rekey the
old authority. Approval source retirement does not resolve that requirement.

### DPoP volatile source retirement boundary

The actual configured `DpopNonceStore` now implements explicit preview, exact
seal and live verification through `DpopReplaySourcePort`. Each cache receives
an internal instance identity at construction. The snapshot binds that instance,
operator-selected authority/destination labels, creation time, mutation revision,
clock high-water, pruning history, capacities, fallback TTL and every physically
retained marker. Historical reservations remain blockers, not transferable
release or operation authority. Preview does not prune or advance the clocks.
An insert/rollback cycle invalidates a preview even when the final inventory is
empty. Sealing compares and freezes under the same mutex as all legacy writes;
afterwards insertions, reservations and rollbacks reject. Exact retries verify
the frozen data without repair. Kernel credential preparation and final DPoP
revalidation reject the retired source before accepting further proofs.

Canonical data is not a live seal. A replacement cache cannot verify the pinned
predecessor even if the predecessor was empty. This is process-instance identity,
not proof that an operator namespace never served in an earlier process or via
another writer. Import must pin that identity before retirement and require
actual source verification. No source reconstruction from JSON is provided.
Before committed activation, source loss remains refusal or a separately
authenticated rekey/authority transition; choosing a fresh cache or a new label
cannot discharge that gate. After explicit v2 activation is committed, exact
anchored readback and retry no longer require the retired volatile source. This
does not turn an inactive import into activation or restore unknown history.

Retention preserves signed absolute and monotonic deadlines separately, including
indefinite overflow, and distinguishes local-only TTL markers. Offsets are relative
to the live instance's monotonic origin; destination code must not invent a new
origin after restart, expire on the wall deadline alone, or infer signed validity
from a local TTL. Clock anomalies, oversized inventories and stale previews refuse
without resetting history. Durable expected-source registration and atomic
inactive import are implemented. Explicit v2 activation is locally verified:
it binds the destination, actual generation and immutable freshness policy in
the signed proof and global history, while excluding legacy proofs. This is a
new proof domain, not restoration of unknown volatile history. Schema v26 adds
operation-owned DPoP storage claims and exact recovery, described below. Explicit
kernel domain selection now connects acquisition, serving and recovery without
recreating the retired source. Complete composed credential qualification
remains open. This source boundary does not enable external start
or make the legacy kernel configuration API restart-safe.

The v26 participant retains bounded, canonical, signature-redacted credential
commitments. An invocation digest binds the proof's capability ID, subject,
server, tool and action hash to the retained original request. Claim intent also
binds the activated authority, operation request digest, selected grant, phase
and unique episode. Decoding this data is not signature verification, a configured
authority or an operation lease. The trusted kernel must verify the capability,
policy and proof before supplying intent; storage independently enforces its
physical ownership, exact activation and retained-request commitments.

`set_operation_owned_dpop_authority` requires an already activated exact domain
from the qualified durable runtime. It cannot import, activate or replace a
previously configured domain. Every DPoP-required matching grant forces retained
structured admission even for read-only tools. Origin-bound preparation verifies
all applicable credentials before acquisition; DPoP and approval claims each
use the updated operation version and their own exact-version recovery lease.
Normal, nested and strict-nonce preflight paths share this acquisition. Exact
readback recovers a committed claim after acknowledgement loss or callback panic;
if both acknowledgement and readback fail, admission denies and only later
authoritative recovery can establish the current version. RAII names the exact
episode, and startup cleanup uses retained history without a fresh proof or
legacy source handle. No prepared value is a caller or executor start permit.

Claims, resource projections and releases share the admission transaction and
global commit chain. First custody advances the operation version and requires
a renewed exact-version lease for later work. A lost acknowledgement reads the
committed version and reference; it does not reacquire a nonce. Released episodes
cannot be reused, and an old release cannot release a successor. New budget
authorization, nonce preflight, capture and dispatch require a fresh live claim.
Preflight claims must be released before nonce issuance. A committed dispatch
retains replay custody permanently, even after expiry or source loss. Historical
retries validate the anchored commit time instead of granting fresh authority.

The distinct v2 domain uses the source's pinned count, per-capability and logical
identity-byte limits. Legacy markers remain permanent old-domain evidence rather
than v2 live occupancy. Expiry or explicit release frees live capacity; expiry
does not free an unreleased replay identity. Canonical ownership/release records
are bounded to 65,536 bytes, operation snapshots to 262,144 bytes and claim
episodes to 128 per operation. These are not whole-database retention limits.
Unknown pre-v26 custody or damaged predecessor catalogs refuse migration;
upgrades preserve existing activation, admission and global commit digests.

The source also binds count and identity-byte limits and the exact conservative
byte charge derived from its retained markers. New cache writes and rollback
requests reject identity parts over 4,096 UTF-8 bytes before allocation or replay
mutation. Non-consuming DPoP proof validation shares this shape check. A separate
16 MiB default identity budget is enforced under the mutation mutex; live markers
cannot be evicted to admit another proof. Exact release and safe expiry return
their charge. Physically retained over-bound history still refuses export without
truncation or reset. The remote MCP sender verifier now shares bounded identity
validation and retains signed proofs through their inclusive signed horizon,
rather than using the cache's local fallback TTL.

### Runtime participant ownership boundary

Runtime admission currently verifies and consumes through
`chio-runtime-core`. Its SQLite store persists destructive leases and treaty
and swarm continuations by resource ID and admission ID. That independent
database does not enforce the qualified admission store's owner fence, request
binding or commit chain. Scheduler-run lease fencing is not invocation fencing.
Receipt metadata and an in-memory release handle cannot establish recoverable
operation ownership, and copied fence values do not make an independent store
an enforcing participant.

The existing runtime hook now uses a non-consuming prepared plan derived from
the same verified bundle, request, treaty, swarm and policy inputs. The bundle
is loaded once, checked against its lookup ID and optional hash pin, and passed
to both treaty and core verification. The private owned core plan is neither
cloneable nor serializable; the hook plan is bound to its originating hook.
Standalone admission shares the same core preparation and commit path.
Preparation never consumes a continuation or lease, writes a trust floor or
emits reserved-resource metadata. Trust-floor validation and update remain at
commit, including concurrent advance and mutate-then-error/panic behavior.

This is a local validation boundary, not durable runtime participant custody.
Before the first lease or continuation consumption in the qualified profile,
the qualified admission transaction must
claim the complete participant set and retain its immutable plan binding under
the supported pre-dispatch phase's authority. It must validate the current
operation version,
selected grant, request digest and active owner fence in that transaction, not
accept a caller-asserted owner string. A partial conflict rolls back the entire
set. The prepared plan alone is not authority to execute.

Integration must account for the current coordinator ordering. Nonce preflight
reaches the runtime hook with a Prepared operation; ordinary dispatch normally
registers its broker attempt first. The hook context does not yet carry qualified
operation authority. A Prepared-only claim therefore does not cover ordinary
dispatch, and ordinary operations may not have retained original request bytes.
Do not backfill provenance or silently redefine the broker transition to bypass
those boundaries. The existing nonce-preflight transaction is a useful atomic
attachment pattern, but its verifier and issuance cleanup permit exact attachment
sets that must be updated together with any real runtime participant addition.
Qualified commitment must replace legacy replay consumption, not precede a second
consume or use a success-only adapter to suppress it.

Legacy completed federation recovery can also re-enter the runtime hook when
retained federation evidence is absent. That existing recovery path must not
become a fresh qualified participant claim on a terminal operation. Qualified
integration needs an explicit read-only treaty-recovery path or a fail-closed
legacy boundary; this is an integration constraint, not evidence of a current
ownership bypass.

Each replay identity includes the pinned runtime authority, participant kind
and resource ID. Exact claim records also bind the operation, request, plan,
grant, phase or attempt and owner generation. Preflight and dispatch must not
resurrect a released claim or allow an earlier release to erase a successor.
Dispatch commitment requires the exact reserved participants and retains them;
compensation releases only the original pre-dispatch owner. Lost acknowledgements
query the same claim, and expiry does not refund committed unknown execution.
The kernel retains authority-produced references for ordinary and nested
dispatch, Drop and recovery. Metadata can describe custody but cannot release it.

An upgraded profile must use one replay backend for all participant mutations.
Evidence storage may remain separate. It cannot activate new admission-ledger
claims while legacy consumers can consume or delete the same signed resources
in runtime-core's old tables. A populated migration must durably seal legacy
mutation paths, including older binaries, retain a verifiable source inventory,
and import replay-blocking markers as unresolved legacy claims before activation.
Such imports do not establish original invocation ownership. Interrupted
seal/import/activation remains closed and resumable. Ambiguous historical
consumption requires authoritative reconciliation or activation refusal, not
fabricated ownership or an optimistic refund. An ordinary profile flag without
storage enforcement is insufficient.

The SQLite source-sealing prerequisite is now implemented as an explicit store
and facade operation. One IMMEDIATE/FULL-WAL transaction freezes all three
legacy replay tables and its singleton evidence row with persistent mutation
barriers. Canonical evidence binds the complete bounded inventory, exact barrier
catalog, operator-selected source/runtime/destination labels and actual open
file identity. Load, verification and exact retry reconstruct that evidence;
partial or damaged seals reject before legacy schema initialization. This does
not create destination claims or enable the qualified runtime profile. Historical
admission IDs remain unresolved provenance, not operation owners. The barrier
does not defend against privileged schema changes, disabled triggers or complete
filesystem rollback, and it cannot retract effects admitted before sealing.
Operator quiescence remains necessary; sealing cannot prove that an already
admitted legacy invocation has stopped or completed safely.

The qualified destination expectation and imported-inactive stages are now
implemented. `expect_runtime_replay_source` validates the current destination
owner fence and migration clock before consulting the configured source. It
pins the complete candidate inventory and actual destination store UUID through
the existing SQLite write/commit/anchor path. Preview does not retire legacy
writers and rejects sources already carrying seal evidence. The immutable
expectation ID and digest identify this exact source generation; exact pin retry
returns retained history without rediscovering the source or substituting new
inventory.

`RuntimeReplaySourceSnapshotV1` is bounded canonical data, not a source seal or
authority token. `RuntimeReplaySourcePort` is trusted operator-configured I/O.
Its SQLite implementation observes the actual open source and checks the entire
inventory and physical identity before barrier installation in the same
IMMEDIATE transaction. A caller-created snapshot, source label or arbitrary
public trait implementation does not establish a qualified source profile.

`import_runtime_replay_source` first loads the exact anchored expectation. For a
pending import it seals and verifies that source before atomically retaining
every marker as an unresolved legacy tombstone and recording the second event.
The expectation, both immutable events and complete tombstone set participate
in global projection reference and coverage verification; no fake invocation
operation is created. Per-source limits remain 16,384 markers and 8 MiB of
canonical evidence. Destination limits are 128 expectations, 64 MiB of source
evidence and 65,536 total markers; pending expectations reserve that complete
inventory capacity before a source is sealed. Truncation is never success.

The import workflow uses a nonblocking RAII guard shared by all adapters of the
same serving owner. Concurrent or reentrant imports reject without another
source mutation. Source callbacks run outside destination database locks and
transactions, and the destination fence and clock are checked again before
commit. Migration events retain their historical owner bindings and a verified
migration-wide time high-water. This does not manufacture an admission-operation
commit or claim a new cross-domain clock guarantee.

An uncertain first seal retains the pending expectation for exact retry. Once
the destination records import, retry only verifies the live source; it cannot
recreate missing barriers and conceal damaged source history. Damaged local
records, missing or mismatched global references, and conflicting generations
reject without backfill. Schema v19 introduces this history; older-version
databases containing any of the new migration objects cannot be silently
restamped or repaired as a historical migration.

Tombstone uniqueness is runtime-authority/kind/original-resource identity.
Inventory digests bind equality, not another replay namespace. Source labels,
artifact digests and historical admission IDs cannot establish a second spend
or authenticated operation ownership. An imported-inactive record is not an
activation permit, a dispatch authorization or an expiry-based refund. The
destination anchor does not add an independent source-filesystem antirollback
mechanism or revoke effects already admitted by legacy consumers.

At the migration-only checkpoint, atomic participant claims, phase-aware
attachment, preflight-to-dispatch ownership, owner-qualified cleanup, restart
recovery and interruption-safe activation remained open. The custody and kernel
recovery sections below record subsequent progress. Activation must replace every
legacy replay mutation path with the qualified participant lifecycle, never run
both as active authorities. The full caller snapshot, credential/security
custody, authenticated external start and independent executor authority are
unchanged requirements.

Local verification: all 17 destination migration regressions pass within the
complete SQLite library suite (1,257 passed, three existing ignored entries).
Runtime-core passes 251 tests and the facade passes 15 tests, with no ignored
tests. Real-source tests cover exact migration, owner rotation, lost seal
acknowledgement, concurrent/reentrant imports and interruption-boundary restart.
Seven SQL fault cutpoints verify atomic destination rollback and complete retry.
The launch-plan checkpoint records the remaining verification results and the
limits of this evidence. These results do not qualify activation, external
execution, a launch profile or a new theorem.

Qualification must cover concurrent processes racing one resource, stale owner
and stale release, same admission ID with different requests, partial conflicts,
lost claim acknowledgement, restart on both sides of dispatch commitment,
missing or modified rows, trust-floor denial, preflight-to-dispatch ownership,
ordinary/nested parity, legacy writes after sealing and interrupted migration.
This design boundary is not implemented by the retained federation component
and does not relax the remaining credential, security or external-start work.

### Operation-owned custody primitive

Schema v20 adds atomic claim episodes, resource projections and append-only
releases to the existing SQLite operation authority. The immutable operation
ledger root identifies one runtime authority and imported source generation;
named `runtime_participant_claim` and `runtime_participant_release` commits bind
each exact canonical episode and operation snapshot. Missing physical history
is corruption, not legacy absence or permission to reconstruct ownership.

Claims require the retained original request, exact request-binding hash and
matching grant, phase-compatible operation state, current owner fence and
exact-version recovery lease. First attachment advances the operation version;
the coordinator must renew its lease before subsequent work. Later episodes
preserve the same ledger and source. Only one episode may be live, and released
episode IDs cannot be reused. Resource identity excludes artifact digests and
episode IDs. Release after dispatch commitment is forbidden; stale episode
release can acknowledge only its own historical release. Readback returns
untrusted history and disposition data, never an executable or release permit.

This primitive does not activate a profile. Runtime artifact verification and
the complete prepared-plan digest must come from the configured verifier, not
caller metadata. At this primitive checkpoint, runtime hook ports, actual
ordinary/nested/preflight wiring, exact live-path cleanup and Drop phase parity
were unfinished. Nonce budget/issuance allowlists still rejected the
unintegrated ledger. The live-acquisition section below records subsequent work. Store-state
fixtures do not qualify budget settlement, concurrency between processes,
power-loss behavior or end-to-end runtime dispatch. The launch-plan checkpoint
records current verification separately from the earlier migration milestone.

### Kernel recovery of runtime custody

The existing admission-operation port now exposes atomic claim, exact release
and fenced history readback. Unsupported implementations reject explicitly.
The qualified SQLite implementation forwards to its physical custody store;
there is no separately injected replay backend or metadata-based release token.

The shared kernel pre-dispatch compensator now releases runtime custody under
its current operation lease and mutation sequencer. Within this compensator,
release precedes no-effect assertions and monetary unwind. It requires the exact
current operation snapshot, complete bounded history, one source generation and
at most one live episode. A release acknowledgement must be followed by fenced readback showing
the same references and intents with only the live episode marked released.
Missing history, inconsistent ownership, unavailable storage and an unknown
release outcome leave compensation incomplete. Retry acknowledges an already
durable release without issuing another release. Committed dispatch recovery
retains custody and does not call the pre-dispatch release path.

Real SQLite close/reopen tests exercise both preflight and dispatch claims,
released predecessors, imported tombstones, committed unknown outcomes and SQL
cutpoints before release and terminal projection. Kernel fault doubles exercise
missing and substituted readback, no-op success and lost acknowledgement. These
tests prove the shared recovery path, not activation, live hook acquisition,
ordinary/nested grant fallback, nonce issuance, Drop phase parity, real budget
settlement or process-crash qualification. No runtime profile was activated at
that checkpoint.

### Live operation-scoped acquisition and explicit activation

The opt-in runtime hook now receives a kernel-constructed, call-scoped claim
authority. Request metadata cannot construct it or choose its operation,
original request binding, grant, phase, source generation or episode. Allow
requires exactly one confirmed claim and final fenced ownership readback. An
ignored claim error or a second attempt still denies. A lost acknowledgement
does not imply success; any recovered operation version is retained for cleanup.
Participant callback panics are contained before they can poison the sequencer.

Preparation binds the complete core inputs, decision, trust-floor update,
treaty evidence, swarm evidence and exact resource set into the plan digest.
Treaty loaders recompute hashes from returned payloads rather than trusting a
store's advertised digest. The runtime performs the real trust-floor CAS after
claiming, with no legacy replay adapter. Its metadata records historical
references and evidence digests, never release authority. Revalidation checks
the actual sealed backend and freshly verified artifact material.

Schema v21 adds an immutable third migration event for explicit activation.
Pinning and importing remain insufficient for the live hook. Activation verifies
the existing source seal without repairing or rediscovering it; operators must
quiesce legacy invocations first. The migration preserves earlier local/global
events, claim episodes, resource rows, releases and anchors without rewriting
historical digests. Unsupported or unrelated backends and fixed-clock overrides
cannot satisfy the live profile.

Ordinary and nested grant fallback release the previous episode before preparing
the next grant. Budget authorization and capture check the live claim's grant
and phase inside their transaction. Nonce preflight releases custody before
issuance, and execution acquires a distinct dispatch episode. Issuance history
preserves the ledger without admitting arbitrary attachments. Pre-dispatch
denial and Drop cleanup use operation ownership; committed dispatch and terminal
replay retain custody and do not redispatch.

Real SQLite tests cover these live paths with a destructive resource, real
budget transitions and real trust-floor writes. Separate destination tests
cover atomic multi-resource custody and activation cutpoints. This is not yet
the full live destructive/treaty/swarm, concurrent-process, lost-acknowledgement
and process-crash qualification matrix. Full caller dispatch context,
credential/security custody and independent executor authority remain open.
No production source or profile was activated by this implementation work.

The following composed-custody checkpoint now exercises all three resources
together through ordinary kernel dispatch, authenticated federation and bilateral
co-signing. It covers nonce preflight and presentation, pre/post-dispatch Drop,
tool errors, imported collisions of each kind, exact completed replay, new-owner
reopen and controlled overlapping invocation ownership. The latter rejects a
competitor without releasing the parked owner, then permits a fresh owner after
cancellation. These are real SQLite and runtime tests, not a multi-process crash
campaign or a complete nested/subset qualification matrix. The launch ledger
records the exact executed inventory and remaining boundaries.

### Stable security identity prerequisite

The live coordinator now includes a typed stable security binding in the
original durable request hash before begin and recovery. It binds trusted tenant,
session, principal, isolation epoch, lineage root and context generation, plus
the configured hook-presence and enforcement requirements. Both ordinary and
nested dispatch use this binding. A changed or removed context cannot recover
an operation's previous output. The pre-dispatch freeze and private caller
decoder check the same identity; individually valid context data is insufficient.

The private retained request codec uses v2 only when security binding is present;
unbound v1 bytes and hash preimages remain unchanged. The v2 immutable hash binds
the v1 request digest and the complete typed security binding under its own schema.
The enclosing canonical decoder rejects version downgrade, absent/unknown
security fields and invalid generations. Original-request retention remains
conditional on the existing participant requirements, so large ordinary requests
do not inherit the caller artifact limit. No public protocol token or database
catalog version changes.

Flow generation remains a mutable observation, not stable operation identity.
Its current value belongs in the participant's live claim and dispatch checks
and the complete frozen snapshot. Retained identity and raw-return context are
historical data for collection/finalization, never authority for new execution.
Changes to hook presence or enforcement fail closed during recovered evaluation;
hook presence alone does not bind its implementation or underlying source.
Older security-context operations that lack the new admission binding are not
silently translated into v2. Native dispatch custody, explicit activation and the
complete caller snapshot remain open. The first native monotone mutation is
described below; it is not a complete dispatch participant.

### Operation-owned native monotone joins

Admission schema v29 adds a bounded append-only mutation journal to the native
projection. Existing v28 initialization bytes, original catalog digests and
global commits are retained unchanged. Current rows verify against the original
archived inventory plus the journal's exact before/after row images. Historical
domain commands are not re-executed, and historical lease observations are never
decoded into fresh mutation authority.

`join_security_participant_flow` requires the actual stored operation and current
recovery lease in `BrokerAttemptRegistered`, before budget capture or dispatch.
The retained original request must bind the supplied stable security identity
with enforcement and hook presence enabled. The trusted host independently
selects an opaque initialization; agent metadata cannot select the source.
Fresh joins check current flow generation, and no operation may replace its
first authority or command or acquire an imported/other-owned transition.

Only that verified transaction can construct the affine internal join
authorization. Persistent before-write barriers reject unauthorized attempts,
including ignored inserts; after-write callbacks capture every affected row,
including sibling context invalidations. Callbacks are disabled and private
temporary row images released on every exit. The domain mutation, original lease
evidence, result and authority-wide commit share one outer transaction. Bounded
capture or journal exhaustion rolls it back without pruning retained evidence.
Expiry uses the later caller/authority time and is rechecked immediately before
enabling writes. The journal retains both the caller's decision time and the
actual authority observation. The decision cannot precede its own operation's
lease commit; authority observations impose global chronological order. An
independent operation with an earlier decision time is not a clock regression.

Exact join retries and `load_security_participant_flow_join` return historical
data, not a fresh generation observation or permission to dispatch. Readback
does not require the original lease to remain unexpired. Lost commitment or
anchor acknowledgements retain the existing outcome-unknown owner boundary.
Monotone taint is not undone when an operation later stops before dispatch.

Authority and table scoping alone do not prove monotonicity. Live row capture
and journal readback now share bounded semantic checks on every before/after
image: the original tenant and affected principal/lineage cohort, immutable row
identity and evidence, nonregressing positive generations, canonical label
hashes, and labels at least as restrictive as their predecessors and requested
joins. A nested effect that lowers a label or changes an identity aborts the
outer transaction. The computed return snapshot must match the actual resulting
rows before commit. Invalid historical changes are rejected, never repaired or
re-executed as commands. This does not grant any egress or declassification
mutation permission or relax the existing no-delete contract.

This is not destination serving activation. Dispatch-ledger attachment, native
egress and declassification custody, all affected legacy consumers and the
complete caller start/delivery contract remain required. No live adapter is
selected by this storage API, and imported pending fences, grants and evidence
are not released.

### Original native authority selection

The trusted security hook now supplies a non-consuming, data-only
`NativeSecurityAuthorityBindingV1` before durable admission. The selection binds
the destination UUID, security authority identifier and original initialization
digest, never agent metadata or the current owner epoch. Its presence requires
trusted invocation context and enforced security. Errors and unwinds deny before
begin. Retained request v3 and immutable request hash v3 bind the selection;
identity-only v2 and unbound v1 keep their original bytes and hash domains.
Ordinary native-bound admissions also retain the bounded original request.

Every new native join compares this original selection with the independently
verified initialization inside the actual operation/recovery transaction. An
otherwise valid authority cannot substitute for the selected authority, even
before the first join. Context-only operations cannot acquire a native selection
retroactively. Native history verifies a retained v3 selection when present;
older context-only history remains data, not permission for a new mutation. The
physical v29 schema and historical initialization records are not rewritten.

Normal and nested admission, dispatch-context freezing, terminal recovery,
caller-context decoding and approval collection compare the configured selection
with the original binding. Historical context does not authenticate a new host
invocation. Serving-owner rotation preserves the original selection. This closes
one field of the complete original profile, not the full runtime/approval/DPoP
and security snapshot or native dispatch lifecycle.

### Native dispatch preparation boundary

The last-moment security hook cannot acquire an operation's first native
join. Normal and nested evaluation reach that hook after `CapturePending`, while
the native join deliberately requires `BrokerAttemptRegistered`. Native serving
integration requires non-consuming preparation and operation-owned acquisition
before budget authorization, then carrying the resulting custody to the final
dispatch commitment. Do not widen the join's phase check or treat historical
join readback as a new observation to bridge these stages.

The separate `prepare_native_admission` callback now receives a kernel-created
`NativeSecurityFlowJoinAuthority` before runtime claims and dispatch budget
capture. Its one-shot API accepts only labels and a transition identifier;
the kernel supplies the operation, selected initialization, trusted identity and
recovery lease. The store checks the original v4 request and live observation
inside its existing transaction. The kernel checks exact original request
material before calling the verifier and compares the acknowledgement with
independent complete-history readback both at the write and callback completion.
Skipping a join, suppressing an error, repeating a join or panicking denies.
Mandatory readback still runs after a write failure, but its missing-history
error cannot obscure the original physical write denial. Lost acknowledgement
after a committed write remains a denial, even when durable history is present.
Monotone history remains committed after denial, not released or reclassified
as current authority. The dispatch-only journal and its SQL whitelist are
unchanged. Native nonce preflight has no dedicated custody yet and fails closed
before budget or issuance rather than borrowing the dispatch phase.

The final pre-dispatch gate now rejects native selections before any legacy
lifecycle acquisition or commit callback. The immutable original admission
selection is checked before the live hook, context and optional-policy
fallbacks. A hook reporting no current selection cannot erase the original
operation's native requirement. Both ordinary and nested evaluation carry that
original admission to the gate. The real SQLite regression first demonstrated
that a successful join plus a permissive legacy callback could otherwise invoke
the connector. Closing that path is an unsupported-lifecycle denial, not
activation; only actual typed, operation-owned native custody may replace it.

Fresh native observation is now a separate fenced admission-store read. It may
precede the original admission and first join and requires an independently
initialized selected authority, not an existing operation or join. SQLite
checks owner, trusted time, anchor and complete native coverage, then reads
effective flow labels and exact context-row presence in the same transaction.
An unjoined session can inherit principal/lineage labels with an effective
generation but no stored context generation. Native admission uses the latter's
`Option<u64>`, never a substituted effective generation. Absence of an isolation
epoch is not proof that a later join will inherit public labels. The returned
data creates no write lease or activation; each writer rechecks current state
and custody. Real-kernel tests exercise first, later, stale and refreshed
observations while requiring zero dispatch and legacy lifecycle callbacks.
This read is not yet wired as the production native resolver, and native egress
classification still needs a fresh post-join observation and its own custody.

The original runtime/approval/DPoP selections are retained before their first
claims. Callback failures must remain failed decisions;
cleanup of an attached runtime ledger must use retained operation custody even
when the current hook is missing, changed or cannot report its selection.

Ordinary and nested security rejection now resolve reversible dispatch credentials
before signing a denial. The irreversible legacy nonce boundary follows security
acceptance; a prior payment authorization still retains its actual authorizing
credentials. Shared security-rejection and local-freeze cleanup reports confirmed
rollback, irreversible retention or unknown cleanup without inferring credential
presence from payment alone. A failed legacy nonce callback stays failed on retry
and Drop, including a lost acknowledgement after consumption. Security acceptance
followed by credential-retention failure records `DispatchFailed`; recorder failure
requires recovery. This is local lifecycle correction, not durable native ledger
attachment, a caller credential snapshot or external dispatch permission.

The current flow resolver's egress and declassification request hash binds the
canonical argument payload. The pre-dispatch port separately checks the complete
canonical live tool request. These are different commitments. In particular,
changing the grant's payload hash to hash the envelope containing that same grant
would introduce a self-reference and change the existing grant contract.

`PreparedFlowDispatch` now borrows its original live request and retains its
complete canonical digest separately from the payload hash. Request equality can
be checked before a later custody command; normal commit also rechecks the
borrowed request. The digest includes transient credentials but stores none of
their reusable bytes. It is not credential verification or execution authority.
Retained original admission material deliberately strips those credentials, so
its material digest cannot reconstruct this full live-request commitment.

The SQLite native egress implementation now retains distinct live-request and
payload commitments, original operation/lease evidence and authority selection
in its own typed journal. It requires `CapturePending`, the original retained
authority profile and a prior same-operation join. The live material check
preserves the original request while full-envelope equality prevents replacing
transient credentials between acquisition and commitment. Neither comparison
verifies those credentials or supplies their independently required disposition.

Admission schema v30 adds `security_participant_egress_events` and a separate
global projection kind. Each acquired/committed event has an independent native
egress sequence and previous digest; commitment references its own acquisition.
The immutable initialization and join-v1 journal retain their existing bytes,
catalog hash, counters and eight-table monotone policy. A distinct affine owner
permits one exact fence insertion or owned pending-to-committed update. Imported
or unowned fences cannot become an operation's acquisition, even if equal.
Nested label writes, other fence fields, extra rows and deletions are rejected.

A regression demonstrated that row capture alone did not reject a nested SQL
trigger changing an admission recovery claim outside the native row tables.
Both native owners now install a SQL authorizer for the complete domain command:
only reads and insert/update actions within that owner's closed native table
set are allowed. Deletes, unrelated table writes, schema/pragma changes,
attached databases and transaction commitment deny. Rollback is always allowed.
The authorizer guard is removed before journal append and on error unwinding;
the independent row-capture guard disables any retained callback. A successful
return cannot ignore authorizer-removal errors, and the actual operation lease is rechecked
after domain execution. This is an additional SQL boundary, not a widening of
either family's native row policy.

Native current-row recovery folds the imported rows and both journal families in
anchored global order, checking independent family chains, causal observation
times, actual before/after images and exact current row/byte totals. Later joins
start from the latest global totals without adopting the egress sequence or
digest chain. The combined journal retains the original 65,536-record/64-MiB
bound. Egress command retries and current-owner historical readback do not renew
expired fences or restore stale generations. Fresh commit needs the actual
current operation lease and current flow generation. Migration validates exact
predecessor state and rejects partial or alias-shaped future catalogs; it does
not repair missing current barriers or rewrite historical commitments.

The portable admission-store contract now exposes native acquisition, commitment
and complete history. `NativeSecurityEgressContext` borrows the original live
request, operation, actual lease, selected binding and trusted context/time;
constructing this data grants no authority. SQLite resolves the exact selected
initialization and forwards into the same independently checked writers.
Unsupported backends explicitly reject commands and history instead of returning
an empty success. Portable readback loads the current operation and both egress
phases in one fenced, anchored transaction. `NativeSecurityEgressHistoryV1`
preserves acquisition evidence after commitment, both event digests and the
commitment's acquisition predecessor. It distinguishes an absent operation from
a present operation without custody, exposes no raw transient credentials and
does not renew expired leases or fences. The older latest-event read remains
available separately.

The kernel now exposes a trusted-host custody coordinator for an originally
admitted non-nonce in-kernel operation in `CapturePending`. Preparation derives
authority and identity from original admission, verifies current configuration,
and reads a fresh post-join observation. Its affine prepared handle exposes that
data for a classifier; acquisition refuses if the inspected state changed.
The affine acquired handle commits only its exact original fence and borrowed
live request, with a kernel-derived dispatch commitment. Both writes acquire
current operation leases, contain store panics inside the mutation sequencer,
and independently compare command acknowledgements with full anchored history.
Readback occurs even after a failed write, but a lost acknowledgement remains a
denial. Post-write expiry, changed observations, original admission changes and
history substitutions cannot return confirmed custody.

These are actual SQLite acquire/commit and recovery paths, not kernel lifecycle
activation. The trusted-host coordinator does not certify classification or
credential verification and its return value is historical custody, not an
execution permit. Coupling to the
dispatch ledger and credential dispositions, nonce support, declassification
and explicit native activation remain required. The final native-dispatch
refusal stays in place until that complete lifecycle is verified.

The same unsupported-native boundary now exists inside SQLite capture and
generic operation advancement. Capture resolves the physical hold's original
owner before event replay or quota mutation and checks that owner's retained
native selection. A different operation with a copied hold attachment cannot
capture or replay it. Join-only history and completed egress history both remain
insufficient. Legitimate non-native capture, replay and pre-dispatch reversal
retain their existing contract.

The budget-only API's opaque operation references remain distinct from durable
admission identities. Capture classifies exact durable membership without
allocating arbitrary reference text, and bounds an actual admission identifier
in SQLite before decoding it. Missing committed admission rows deny rather than
falling back to the budget-only path.

Completing native dispatch requires replacing this refusal with an actual
operation-owned ledger check, not deleting the physical-boundary checks. The
ledger must bind original admission and authority profile, the complete live
request, selected grant, verified policy inputs/decision, current native
observation, join/egress predecessors and actual credential ownership. Durable
history alone cannot supply fresh credentials, a lease or a new policy decision.
Nonce/declassification, outcomes, recovery and explicit activation remain
separate required lifecycle work.

The control-plane `NativeFlowResolver` implements the post-join policy phase.
Its shared read-only policy view resolves admitted manifest/bridge metadata and
binds classifier identity and results to canonical arguments. The native caller
must supply a kernel-prepared handle, not an arbitrary flow snapshot or legacy
store. The resulting source label must already be covered by each native
principal, lineage and session label; otherwise it denies without a second join.
The one-shot prepared policy borrows its resolver and original custody through
current operation/time validation. Egress decisions acquire and commit physical
custody; local non-egress decisions return no fence. Historical results expose
no raw credentials and do not authorize invocation. Native declassification and
legacy evidence-store configuration are explicitly unsupported.

Native preparation now retains `chio.native-flow-dispatch-policy.v1` rather than
discarding the exact classifier and policy inputs after evaluation. Its bounded
canonical record commits to operation/version, original-admission and complete
live-request digests, current kernel policy identity, selected native authority,
fresh observation, exact verified classification findings and category bindings,
admitted policy/bridge metadata, signed-manifest attestation, decision and deadline.
Argument payloads and reusable request credentials are not retained. The same
classification call produces both the evaluated label and its evidence; neither
record construction nor custody commitment invokes a second classifier.

Serialization stops at 256 KiB before allocating a parsed JSON value. The
manifest attestation retains the already admitted body digest, signing key and
signature without copying a potentially much larger manifest into the record.
Invalid or oversized policy material denies before
egress acquisition. The prepared handle carries the exact bytes and digest into
successful historical custody unchanged; time and current operation are still
revalidated after preparation and before commitment. This is the policy input
to the pending dispatch ledger, not a durable SQLite attachment or an execution
permit. Atomic capture must additionally bind and verify the selected grant,
actual credential ownership/dispositions and join/egress history under the
current operation lease. Those requirements and native activation remain open.

The same resolver now implements the production before-budget hook. It validates
admitted metadata, classifies original canonical arguments and supplies only the
classified label plus operator floor to the kernel's `join_input` handle. The
kernel derives operation, full flow identity and transition identifier. The
writer resolves all actual inherited labels under the existing fenced write
transaction, before minting the affine native mutation owner. An absent exact
epoch does not erase a global lineage or an existing principal epoch under
another lineage. The complete source is propagated into principal, lineage and
session in one mutation with one captured row set and one journal event.

Raw join events retain their exact v1 schema and independent-label semantics.
Input joins use the explicit internal event `chio.native-security-flow-join.v2`,
retaining both original `NativeSecurityInputJoinRequestV1` and resolved raw
command in the existing bounded canonical-record column. This adds no SQL
catalog migration and rewrites no old record. V1 with input, v2 without input,
unknown versions and noncanonical encodings fail closed. Old v1 readers reject
the new field; they cannot silently adopt an input event as a raw retry. Both
families share the single operation slot, but cross-family command retries deny.

Input acknowledgement and independently loaded input history must match in
every field, including original input, binding, operation, resolved command,
snapshot and mutation digest. Even a committed lost acknowledgement remains a
denial. Historical readback may return the original join after labels advance;
it grants no fresh observation, egress or execution authority. Post-join
classification still rechecks fresh state and denies stronger unrecorded taint
without a second join. Native declassification and legacy dispatch remain
unsupported; this does not activate the native lifecycle.

### Remaining integration sequence

The current caller-report path now produces `chio.kernel-caller-return-context.v1`
before capture. The bounded private payload binds operation/request identity,
selected grant, original material digest, frozen receipt and purchase/recovery
metadata, pre-invocation guard evidence, stream limits, signing identity,
security identity data, original federation evidence and the runtime ledger
root. It excludes reusable request credentials and post-return observations.
The dedicated store port captures quota, commits the nonce and retains this
frame atomically. The kernel then reloads the exact bytes under its fence and
uses the typed decoder before accepting the report as a tool return. Missing or
changed readback is an unconfirmed commitment, not permission to compensate.
Callback panics are contained inside the mutation sequencer so recovery can
still inspect whether the operation committed.

Local freeze validation and historical decoding share binding and canonical
checks. Retained federation evidence is re-verified rather than deserialized
into verified treaty authority. Stream limits and metadata come from the frame,
not fresh defaults. The security identity field and runtime ledger root are
bindings to existing data, not proof of complete security-hook or credential
custody. This return component must not be accepted as the complete context for
an external start. Reports still arrive through the existing two-call path and
the lost-report contract remains open.

1. Persist the validated dispatch/admission context through the existing fenced
   operation authority and physical commit chain. Add schema migration,
   corruption, rollback, owner-fencing and exact-replay tests.
2. Add the authenticated start operation to the kernel's shared dispatch
   pipeline. Reuse approval/nonce/capture and credential revalidation; return a
   signed authorization only after the durable commitment. Prove zero external
   callbacks on every pre-commit rejection.
3. Add the executor-owned durable claim, authenticated delivery evidence and
   loss/restart recovery. Do not qualify a provider using only a public trait
   implementation or transport name.
4. Route report reconciliation through the retained committed context and
   existing durable terminal finalization. Preserve completed receipt replay,
   historical report handling and unknown-outcome retention.
5. Wire trusted sidecar control routes, SDKs, executor adapters, schemas and
   canonical bindings. Update all existing reserve/execute/report integrations;
   an old two-call client must not silently receive executable authority.
6. Enable the previously failing contract test and run the complete crash,
   concurrency, formal, workspace and exact-candidate qualification gates.

The existing in-kernel/remote dispatch profile is not a substitute for this
caller-delivery work. Nor does this document replace provider-signed delivery
receipts, the remaining protocol/active-defense/enterprise plans, native
enforcement, dependency audits, hosted qualification or the operational pilot.
