# chio-kernel

`chio-kernel` is the Chio runtime kernel: the trusted computing base (TCB) of
the protocol. It sits between the untrusted agent and sandboxed tool servers
as the sole trusted mediator, validating capability tokens, running a guard
pipeline, dispatching tool calls, and signing a receipt for every decision.
The agent never learns the kernel's PID, address, or signing key.

Use `chio-kernel` for Rust-level embedding of Chio enforcement. For the
supported operator path, start with `chio-cli`.

## Responsibilities

- Validate capability tokens: signature, time bounds, revocation (including
  delegation-chain ancestors), delegated-scope lineage, grant matching, and
  DPoP proof-of-possession.
- Evaluate the registered `Guard` pipeline before forwarding a call; any guard
  deny or error fails the call closed.
- Admit governed transactions: HITL approval tokens, runtime-attestation
  tier, metered billing, call-chain proofs, autonomy bonds.
- Dispatch validated calls to registered `ToolServerConnection` tool servers
  under a per-server wall-clock budget.
- Sign and durably persist a receipt for every outcome (allow, deny,
  cancelled, incomplete), recomputing the content hash before signing
  (WYSIWYS).
- Build and verify Merkle checkpoints over the receipt log, including
  continuity and equivocation checks.
- Track sessions, in-flight and nested (sampling/elicitation) requests, and
  hold-based monetary/invocation budget accounting.
- Enforce the emergency-stop kill switch and shed load under a configurable
  RSS soft ceiling.

## Public API

Retained admissions bind an `AdmissionAuthorityProfileV1` before acquiring
operation-owned resources. Its explicit selections include runtime and approval
source generations, runtime policy declarations and the DPoP replay domain and
freshness policy. The private retained request v4 and immutable request hash
commit to this profile alongside existing security identity. Constructing or
decoding a profile grants no authority. Older retained versions remain readable,
but cannot select new operation-owned authority from current configuration.
Finalization reloads original material under the store fence; cleanup continues
to use the original ledger rather than current hook selection.

Primary entrypoint:

- `ChioKernel` / `KernelConfig` construct and configure the kernel.
  `ChioKernel::evaluate_tool_call` (async) is the core mediation call;
  `evaluate_plan` previews a multi-step plan without mutating budget or
  receipt state.

Traits a host implements:

| Trait | Role |
|---|---|
| `Guard` | pre-dispatch policy check |
| `ToolServerConnection` | dispatch target |
| `ReceiptStore`, `BudgetStore`, `RevocationStore`, `CapabilityAuthority` | durable persistence and trust roots |
| `PostInvocationHook`, `RuntimeAdmissionHook` | post-dispatch and pre-dispatch product-specific gates |
| `PaymentAdapter` | payment-rail authorization (`X402PaymentAdapter`, `AcpPaymentAdapter` ship as references) |
| `ApprovalStore`, `ApprovalChannel` | HITL approval persistence and delivery (`WebhookChannel`, `RecordingChannel` ship as references) |
| `MemoryProvenanceStore`, `FederationArtifactStore`, `ExecutionNonceStore` | optional durable backing for memory provenance, federation artifacts, and nonce replay |
| `ToolEvaluator` | replace the four-phase evaluation pipeline itself (default `BlockingToolEvaluator` bridges to the sync path) |

Standalone surfaces:

- `checkpoint` - Merkle checkpoints over the receipt log (`build_checkpoint`,
  `verify_checkpoint_continuity`, `ReceiptInclusionProof`).
- `dpop` - DPoP proof-of-possession verification.
- `execution_nonce` - single-use nonces closing the TOCTOU gap between an
  allow decision and dispatch.
- `evidence_export` - signed evidence bundles for external audit.
- `compliance_score`, `compliance_certificate` - weighted compliance scoring
  and signed compliance certificates.
- `receipt_query`, `receipt_analytics`, `operator_report` -
  read-scope-bounded receipt queries and reporting.
- `settlement_observer` - post-signing settlement hook invocation.

Also re-exports the economic and governance artifact types from
`chio_core::{credit, governance, listing, market, open_market, underwriting}`
at the crate root, so an embedder does not need a direct `chio-core`
dependency for governed-transaction workflows.

### Required swarm admission

Call `ChioKernel::require_swarm_admission()` before serving a swarm-only tool
kernel. It requires swarm context on every tool call and a `RuntimeAdmissionHook`
that declares `enforces_swarm_authority()` and `requires_dispatch_revalidation()`.
The built-in Chio runtime hook implements both, verifying stored signed evidence
against pinned keys and binding the selected task to the exact capability.
Missing context, missing hooks, and unsupported hooks deny before dispatch.
Replacing or clearing a hook does not disable the requirement.

Chio YAML exposes the same setting as `kernel.require_swarm_admission: true`.
The setting does not install a verifier or provision its evidence by itself.
Ordinary kernels remain usable for non-swarm work; this is a deployment policy,
not a new capability wire caveat or an enforcement claim for another kernel.

### Caller-executed reservations

`reserve_caller_execution_blocking` prepares a caller-executed tool call without
invoking a kernel tool server. `reconcile_caller_execution_blocking` records the
caller's report against the same durable operation. The reservation receipt is
not durable dispatch authorization or evidence that a provider executed the tool; the
report is caller-supplied, not a provider-signed delivery attestation.

The legacy reserve, external execution, report workflow has an open lost-report
accounting gap. Do not treat reservation alone as permission for an external
effect. The required start commitment, executor claim and historical reporting
are tracked in the [caller dispatch design](../../../docs/superpowers/specs/2026-09-07-caller-dispatch-commitment-design.md).

Caller-report capture now atomically retains a typed private frozen return
component and reloads its exact bytes under the authority fence. It preserves
the original return limits, grant, guard evidence and receipt/federation facts;
it does not include reusable credentials or later tool output. This is a
prerequisite for the future start path, not the complete admission snapshot or
credential/security-hook custody. Unsupported context stores fail closed.

The current two-call caller reservation API rejects DPoP, presented approval or
declassification artifacts, and configured security-hook/enforcement profiles
before acquiring participants or minting authority. Its secret-free retained
request cannot yet recover those owners for reporting. A rejected caller retry
does not consume an existing issued nonce. Ordinary kernel dispatch still uses
the qualified credential paths; this restriction is not a completed external
start protocol.

At the live security boundary, outcome handles must match the current request
and canonical dispatch commitment before connector entry. Acquisition, commit,
outcome recording and final-release callbacks contain unwind panics; post-effect
errors require authoritative recovery without releasing output. Outcome
recording and recorder disposal are contained separately, including during
cancellation. These Rust owners are not serializable security custody, and
panic containment is not isolation from aborts or arbitrary trusted native code.

Ordinary and nested security rejection resolve reversible DPoP, nonce and approval
reservations before signing denial. Irreversible legacy nonce consumption starts
only after security acceptance, unless an earlier payment authorization already
required retention. Payment-authorizing credentials remain retained. Failed or
panicked cleanup is reported as unknown, not successful rollback. A failed legacy
nonce callback remains failed on retry and Drop; confirmed consumption cannot be
erased by later reversible cleanup. These local lifecycle guarantees do not attach
native security custody to the durable dispatch ledger or activate native serving.

Durably covered tool calls bind trusted tenant, session, principal, isolation
epoch, lineage root and context generation before operation begin or replay.
The binding also records whether the security pre-dispatch hook is installed
and whether enforcement is required. Changing or removing that identity or
configuration conflicts with the retained request before result recovery or
dispatch capture. Mutable flow generation is not operation identity; the
pre-dispatch security participant must still validate its live observation.
Unbound operations preserve their exact v1 hash. Security-bound operations use
a domain-separated v2 request hash and, when original request retention is
required, a strictly decoded private v2 artifact. Ordinary requests acquire no
new retention size limit. Stored identity is historical data, never fresh host
authority, native participant custody or an external execution permit.
Older context-bearing operations without this stable binding cannot be silently
upgraded or replayed as v2. Hook presence does not identify a hook implementation
or qualify its underlying security authority; those remain policy/configuration
and operation-owned custody requirements.

For durable tool returns, the requirement for a final lifecycle release is frozen
before dispatch and retained with the raw outcome. A required release has its own
fenced checkpoint after output evaluation and settlement, before terminal receipt
publication. Successful callback acknowledgement constructs an opaque value that
cannot be restored by decoding record data. SQLite binds its immutable checkpoint
to the exact dispatch, request, outcome and evaluation through the admission journal.
Completed replay requires that checkpoint. A failed release or a crash before its
checkpoint leaves the original operation unresolved, with captured quota retained;
recovery cannot acquire a fresh owner to manufacture success. Unsupported stores
reject the profile before dispatch. Historical security-context outcomes lacking
a qualified release requirement cannot silently become releasable after upgrade.
This checkpoint is evidence of the original release, not operation-owned custody
for recovering a lost native owner or an authenticated external-start permission.

With durable admission, funded caller operations also own their delegated budget
shares. The SQLite store projects a complete, fenced view from retained requests
and executable holds. Both caller reservations and ordinary kernel admission
combine that view with local leases; repeated operations on the same child count
as one edge until its final owner closes. Restart and nonce expiry alone do not
release ownership. Settlement or compensation does; outcome-unknown dispatches
retain it. Unsupported, incomplete or invalid store views deny admission.
An established caller reservation cannot be displaced by a competing funded
claim that has not passed share admission. Its reconciliation still checks all
established owners and local leases; new admissions also count pending claims.
Concurrent funded siblings can both deny conservatively; no exactly-one-winner
progress guarantee is provided.

### Recovery lease qualification

Qualified recovery-lease acquisition contains unwinding store callback panics
across claim persistence, operation readback and final revalidation. It returns
an unknown outcome without minting a lease or clearing a possibly durable claim.
Containment happens inside the shared qualification boundary, before a panic
can unwind through a caller's mutation sequencer. Normal validation errors are
unchanged. This does not repair a poisoned backend, contain process aborts, or
qualify other store callbacks; subsequent recovery still requires fresh checks.

### Governed approval custody

The admission-store ports support exact operation-owned approval claims after
explicit source import and activation. SQLite retains canonical claim/release
history, original request and grant bindings, token commitments and validity
bounds. Imported scoped and wildcard replay markers remain blockers, and actual
authority time must reach the imported clock high-water before activation.

Kernel compensation and nonce issuance release only retained pre-dispatch
ownership under a current lease. Expired approvals remain readable for cleanup;
committed dispatch ownership cannot be released. Claim data carries no reusable
approval signature and is not proof of a trusted issuer or execution permission.
`set_operation_owned_governed_approval_source` installs an already activated
generation and its actual sealed source. It performs no migration or activation.
The kernel prepares credentials before replay mutation, claims each selected
grant before budget authorization, and verifies the same ownership at credential
reservation. This route never consumes the legacy approval store. Grant fallback
releases the exact preceding episode; readiness revalidation checks the source
again. Threshold approval sets remain a separate required participant.
Without this explicit configuration, the existing approval replay profile remains
unchanged. Full caller security custody and authenticated external start remain
open. See the [caller dispatch design](../../../docs/superpowers/specs/2026-09-07-caller-dispatch-commitment-design.md).

### DPoP replay source retirement

Session-scoped nested calls carry additional proofs through
`evaluate_tool_call_operation_with_nested_flow_client_and_proofs` or its
`_async` variant. Pass `NestedToolCallProofs` for DPoP and declassification;
execution nonces and governed approvals remain in `ToolCallOperation`. These
are untrusted request artifacts, not verified authority. The original nested
entrypoints remain compatible and supply no additional proofs, so a required
DPoP profile still denies when a proof is absent. Native declassification remains
unsupported and explicitly denied even when its signed artifact is transported.
This Rust API does not change session wire schemas or enable native execution.

DPoP replay identity parts are limited to 4,096 UTF-8 bytes before proof-body
canonicalization or cache-key allocation. Cache admission also enforces a
16 MiB default retained-identity budget independently of marker count. The
charge includes nonce and reservation text plus two capability-key copies per
marker, conservatively covering the count index. Container overhead remains
bounded by marker count; this is not a whole-process memory limit.
`new_with_identity_byte_capacity` permits explicit host tuning, and
`identity_byte_utilization` reports the charged bytes and limit. Exhaustion
denies admission without evicting live markers. Exact rollback and dual-clock
expiry reclamation return the corresponding charge. No identity is normalized,
truncated or echoed in errors. Non-consuming preparation checks shape, not a
promise that byte capacity will still be available when reservation occurs.

`dpop_replay_source()` exposes the actual configured process-local cache through
`DpopReplaySourcePort`. Explicit preview, exact seal and live verification retain
its instance identity, complete physical inventory, reservation owners, replay
clock/prune history, count/byte capacity limits and exact charged bytes. Sealing is one-way: every legacy insert,
reservation and rollback rejects afterwards. Kernel preparation and dispatch
revalidation also reject a retired source. Operators must quiesce consumers and
pin the expected instance before retirement; no automatic migration occurs.

The canonical snapshot is private migration data, not an execution permit or
proof of history before this cache was created. Decoding it cannot reconstruct
the live source, and a fresh cache cannot verify its predecessor's seal. Local
TTL deadlines and signed markers' monotonic deadlines remain process-relative;
they must not be interpreted as restart-portable wall-clock expiry. Losing the
source before committed activation requires refusal or a separately
authenticated authority transition. The SQLite destination implements exact
source pinning, imported-inactive history and explicit v2 domain activation.
Committed activation can be read after source loss without recreating that
source. It does not restore any unknown history.

`dpop::authority` defines the signed `chio.dpop_proof.v2` profile. It binds the
destination UUID, independently configured authority, exact imported generation
and immutable freshness policy. Its stateless verifier returns opaque,
non-consuming cryptographic evidence, not activation or dispatch permission.
The expected domain and observed clock must come from the trusted authority,
never from the presented proof. Legacy verifiers accept only v1 without a
non-null replay authority. The `admission_operation::dpop_claim` contract adds
bounded, signature-redacted credential commitments and exact operation-owned
claim/release/history ports. Decoding these records does not verify a signature
or authorize a claim: only the configured kernel may supply prepared evidence
under its current operation lease. SQLite implements the physical participant,
including fresh budget/preflight/dispatch checks and expired history recovery.
`set_operation_owned_dpop_authority` explicitly selects an already activated
domain through the qualified durable runtime. The kernel verifies that exact
domain without consulting the retired volatile source, then acquires a claim
before budget authorization on normal, nested and strict-nonce preflight routes.
The originating prepared request and selected grant must match the retained
claim at reservation. Read-only tools still require durable admission for this
profile. Lost acknowledgements preserve confirmed operation versions for cleanup;
startup releases only exact pre-dispatch custody, even after proof expiry.
Once selected, the domain cannot be replaced on that kernel. Installing a legacy
cache afterwards neither disables the domain nor permits fallback. The setter
does not import, activate or authenticate deployment configuration for the host.
Full caller credential/security-hook custody, authenticated external start and
complete composed interruption/process qualification remain open. The legacy
`set_dpop_store` API does not establish this profile by installing a new cache.

### Kernel-owned native flow preparation

For a selected native authority, ordinary and nested dispatch admission invokes
`SecurityPreDispatchHook::prepare_native_admission` before budget capture or
runtime replay claims. Its `NativeSecurityFlowJoinAuthority` is call-scoped and
cannot be cloned, serialized or constructed by the hook. The kernel supplies
the original operation, selected destination, trusted flow identity and recovery
lease; the hook supplies only the transition identifier and monotone labels.
Success requires exactly one acknowledged join and independent fenced history
readback. Skipped writes, swallowed errors, repeated joins, substituted requests,
changed selections and callback panics deny admission. A committed monotone join
survives denial and is not released or reused as a fresh flow observation.

The classified-input variant, `NativeSecurityFlowJoinAuthority::join_input`,
accepts only the classified label plus operator floor. It derives the operation,
full flow key and domain-separated transition identifier itself. Its distinct
store ports retain `NativeSecurityInputJoinRequestV1` alongside the full resolved
join. Under the same write transaction, SQLite joins the input with each actual
principal, global lineage and session label, even before the exact epoch exists,
and applies that complete source to all three rows. The input acknowledgement
must exactly equal independently loaded input history. Raw and input joins share
the single-attempt rule but cannot adopt each other's historical operation.

The portable `AdmissionOperationStore::observe_native_security_flow` read can
precede the first admission. Its `NativeSecurityFlowObservationV1` separates
effective inherited labels from the exact persisted context generation. Use
`stored_context_generation()` for native admission, not the effective snapshot's
generation: an unjoined session may inherit labels without a context row.
The observation is data from one fenced snapshot, not an authentication token,
activation, operation lease or dispatch permit. Each subsequent writer rechecks
current state and its own custody; stale observations deny. Unsupported stores
reject this read rather than reporting an empty initialized authority.

The same store trait now exposes `acquire_native_security_egress`,
`commit_native_security_egress` and `load_native_security_egress`. Command inputs
borrow the live request and actual operation/lease; assembling those inputs is
not authorization. Readback returns the current operation and optional
`NativeSecurityEgressHistoryV1` together. The history preserves the original
acquisition even after commitment, including both event digests and the exact
acquisition predecessor. It retains only the live-request hash, not transient
credential bytes. Unsupported backends explicitly reject all three ports.
The SQLite adapter implements these ports. The trusted-host kernel API
`prepare_native_security_egress` derives the selected authority, original
operation and flow identity itself, then reads a fresh post-join observation.
`PreparedNativeSecurityEgress` exposes that observation for classification;
consuming `acquire` and `AcquiredNativeSecurityEgress::commit` obtain their own
current recovery leases. Neither handle is cloneable or serializable. Every
write requires independent matching history, and lost acknowledgements remain
errors even when history records a committed write. Context changes, expired
deadlines, changed operations or substituted evidence deny further progress.
The full live-request commitment remains separate from the argument digest.
Read-only `request` and `operation_id` expose the original borrowed envelope and
bound identity; `validate_current` checks current operation and observation under
the kernel sequencer and returns the kernel's post-read time. These reads do not
verify credentials or grant a dispatch permit. The control-plane native flow
resolver uses them to bind post-join classification without a legacy backend.

This API orchestrates custody only. It neither certifies a policy decision nor
verifies transient credentials, and its historical result is not a dispatch
permit. The control-plane resolver now implements before-budget classification
through the input join above. Complete native authorization, outcome ownership
and explicit activation remain open. The dedicated capture checkpoint below
binds preparation and credential custody without activating execution. The
`admission-test-support` checkpoint exercises the actual pre-dispatch boundary
without removing its unconditional native-dispatch refusal; no checkpoint
storage or call site is compiled without that feature.

Generic SQLite paths still refuse native capture at the physical transaction
boundary. Neither ordinary combined invocation capture, split budget capture
nor generic operation state advancement can substitute join or egress history
for dispatch-security custody.
Capture resolves the physical hold's original operation before mutation or exact
replay. A matching capability and copied hold attachment do not transfer ownership.
Budget-only opaque references retain their standalone lifecycle; a missing row
for a committed admission is corruption, not a budget-only reference.
The native preparation ledger now has independent retain/readback ports and a
physical immutable SQLite journal. `retain_dispatch_ledger` and
`commit_with_dispatch_ledger` retain exact policy bytes, the selected grant,
original operation and lease, join/egress commitments and actual participant
claim histories. The control-plane `commit_custody_with_dispatch_ledger` carries
that same policy evaluation into retention without reclassification. A record
and its exact global authority reference commit together; missing/corrupt rows
or changed owner references deny reopening. Successful callbacks require two
matching bounded readbacks. Errors and lost acknowledgements remain errors even
when their historical records survive.

The composed `acquire_and_commit_with_dispatch_ledger` path checks the selected
grant and bounded canonical policy envelope before acquiring a fence. The
already-acquired entry point performs the same checks before commitment.
These checks do not make the three durable phases atomic. A later journal
failure preserves earlier egress history and returns no successful custody.

The ledger does not capture quota, verify every live credential, or grant an
execution permit. It remains preparation history after compensation and restart.
The separate dedicated capture path borrows the actual credential reservation
and the original affine preparation. In the physical budget transaction it
checks the complete required claim set, owner, lease, journal and current
policy, then attaches `NativeDispatchLedgerDigest` with quota capture. The
aggregate DPoP requirement includes every originally matching grant. No generic,
split or caller native capture refusal is removed.

`PreparedNativeFlowDispatch::capture_invocation` retains its live resolver and
policy through that transaction. The default-off `admission-test-support`
checkpoint exposes the actual evaluation boundary for qualification, but always
stops before connector execution. A captured or unconfirmed invocation keeps
its budget and credential custody. It cannot take the pre-dispatch refund path.

These APIs provide preparation and a capture-only checkpoint, not native serving
activation. The existing `BrokerAttemptRegistered` journal phase and
one-join-per-operation restriction
remain unchanged. Native nonce preflight in `Prepared` denies without borrowing
dispatch authority. Explicit activation, dedicated nonce/declassification
custody, full combined runtime/approval credential qualification, frozen return
context, outcome disposition and participant recovery remain open. Historical
capture is not permission to resume execution after restart.
Hooks that select native authority without implementing preparation fail closed.

### Durable federation recovery

Federated durable tool calls freeze the original signed treaty evidence, local
accepted report binding, participant pins and admission time before dispatch.
The returned raw outcome retains that private context in its content-addressed
blob. Recovery validates the qualified outcome and operation binding before
re-verifying the original signatures; it does not reconstruct authority from
receipt metadata or rerun runtime admission for newly recorded outcomes.

This supports completing missing bilateral receipt projections after a restart,
not authorizing a new external execution. Public replay retains current
capability, revocation, peer and registered-target checks. A changed local
signing identity fails closed. Legacy outcomes retain their original recovery
behavior. Complete caller-start custody and authenticated historical delivery
reporting remain separate, unimplemented boundaries.

## Feature flags

| Flag | Effect |
|------|--------|
| `delegation` (default) | Consults the installed recursive-delegation `RevocationView` snapshot on every delegated dispatch, denying if any chain link is revoked. Also enables `chio-core-types/delegation`. |
| `pq` | Enables the hybrid signing path: constructs a PQ (ML-DSA-65) `HybridBackend` from an operator-supplied seed, gated by the boot-time self-quote check in `boot.rs`. Enables `chio-core-types/pq` and `chio-core/pq`. |
| `otel` | Pulls in `opentelemetry-semantic-conventions` for the GenAI tool-call span attribute contract in `otel.rs`. |
| `dhat-heap` | Enables heap-profiling instrumentation for the `dispatch_allow_dhat` bench. |
| `tokio-console-smoke` | Enables `tokio/tracing` for the `tokio_console_smoke` integration test. |

## Testing

`cargo test -p chio-kernel`

- Hybrid/PQ tests (`hybrid_receipt_sign`, `compliance_certificate_hybrid`,
  `pq_key_load_after_self_quote`, `canonical_bytes_hybrid`) require
  `--features pq`.
- `tokio_console_smoke` requires `--features tokio-console-smoke`.
- `cargo bench -p chio-kernel` runs the criterion benchmark suite (capability
  verification, guard pipeline, dispatch, receipt signing/append);
  `dispatch_allow_dhat` requires the `dhat-heap` feature.
- Dev-dependencies also cover a property-based replay-invariance suite
  (`tests/replay_proptest.rs`) and loom-based concurrency checks.

## See also

- `chio-kernel-core` - portable verifier primitives (`RevocationView`, budget
  registry, receipt-signing handle) this crate builds on.
- `chio-store-sqlite` - durable `ReceiptStore` / `BudgetStore` backend for
  production deployments.
- `chio-cli` - the supported operator entrypoint.
- `chio-guards`, `chio-wasm-guards`, `chio-external-guards`,
  `chio-data-guards` - `Guard` implementations that plug into this kernel.
- `chio-mcp-edge`, `chio-a2a-edge`, `chio-acp-edge` and other protocol edge
  crates - implement `ToolServerConnection` to bring an external protocol
  under kernel mediation.
