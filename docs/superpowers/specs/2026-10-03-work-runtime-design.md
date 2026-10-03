# Reusable work runtime specification

Status: proposed, revised after the second source review. Implements AW01 through AW05 and AW10, plus AW21 through AW25.
Parent: [architecture and constraints](2026-10-03-agentic-work-kernel-design.md).

## Existing foundation and delta

D1 supplies WorkContract, WorkSlot, Signed<Subdivision>, Signed<Selection>, DispatchBinding and Signed<DispatchPermit> in chio-workflow. Its seal_dispatch already returns the retained permit on a live retry. S1 supplies verify_swarm_authority_extension and transactional extend_swarm_authority_bundle in chio-runtime-core. The public chio-runtime SQLite wrapper lacks the extension method. chio-process already freezes logical calls and owns their stable process binding.

Promote reusable composition from examples/federated-work/src/funded_work/composition.rs and evolving.rs. Preserve the existing verifiers and native pre-dispatch revalidation. Do not promote fixture keys, fixed prices, assumed native routes or the standalone Journal as production authority.

The current DelegationStore::open creates missing tables and an allocator namespace. Its comment requires callers to prevent independent rollback; it does not itself establish serving ownership. W1 must close that production boundary, not merely wrap the existing open(path) method.

## Component and Rust boundaries

All Work-prefixed names below are proposed. Existing native types and the recovery PR's proposed ports retain their original ownership.

| Component | Responsibility | Excluded responsibility |
| --- | --- | --- |
| chio-runtime-core::work | Closed wire contracts, checked value types, pure cross-record binding checks | Signer custody, provider I/O, native dispatch ownership |
| chio-runtime::work::WorkClient<T> | Public typed client over authenticated work transport; explicit facade exports | Constructing caller identity or authorizing a native effect |
| chio-control-plane::work | Concrete owner service, narrowly separated preparation, allocation, dispatch, query and recovery adapters | A second kernel, scheduler or recovery reducer |
| chio-workflow::delegation | D1 types, signing domains, validation and shared transition rules | A dependency on kernel, control-plane or SQLite serving-owner implementation |
| chio-store-sqlite | Production D1 persistence under the existing qualified serving authority | Unfenced writable allocation copies |

Add an opt-in work feature to runtime/core and the host composition. Feature names alone do not establish dependency isolation: W1.0 records the existing default dependency graph and W1.5 checks the delta. Do not claim the present default graph is chain-free. Keep existing substrate MSRVs and no_std/alloc contracts.

Replace the earlier WorkRuntime -> WorkHostPort pass-through design. The concrete WorkService lives in control-plane, with private fields for the exact existing authorities it needs. Methods call those authorities directly through their existing interfaces. Pure binding validation stays shared. No universal service locator or one trait that owns signing, storage, dispatch, recovery and release.

WorkClient<T: WorkTransport> supplies prepare, submit and query. WorkTransport is a byte-transport boundary used by local authenticated IPC and remote authenticated HTTP clients, not an authorization port. Its proposed signature is exchange(&self, request: WorkRequestBytes) -> impl Future<Output = Result<WorkResponseBytes, WorkTransportError>> + Send. The two byte wrappers are bounded and redact Debug. Use static dispatch here; no mandatory boxed future, async-trait dependency or dyn downcast. Existing transport clients provide the framing, credential and endpoint policy. Optional in-process test transport exercises the same decoder and service entrypoint.

The service obtains an internal WorkSession from authenticated ingress or the existing worker credential verifier. No public client supplies WorkCaller fields. WorkSession has private construction in the trusted authentication adapter, no serde implementation, and carries the resolved native namespace/process and a checked local role/program scope. A namespace or process ID alone is not proof of authentication. Every mutating owner rechecks its live authority at commitment; service authorization cannot substitute for native admission.

## Checked data and authority

Wire DTOs are untrusted. Decode through the selected security source's UntrustedJsonText contract while original bytes are available, then checked conversions. Do not deserialize to Value before duplicate/numeric checks, or turn a successfully decoded Signed<T> into a verified authority type. Native signature/trust verification remains mandatory.

Use AdmissionIdentifier and AdmissionDigest where their grammar and meaning match. Introduce semantic wrappers for command IDs, allocation digests, graph digests and exact invocation digests where interchange would be a bug. Do not silently tighten legacy D1 identifiers or rewrite persisted signed bytes to fit a new wrapper. Mismatches require an explicit conversion/profile rejection and historical vectors. New quantities/revisions use checked arithmetic. Private fields and checked constructors preserve invariants after decoding; no unchecked setters or DerefMut.

Verified binding results are ephemeral, private-constructor types with no Deserialize. They demonstrate only their named checks at their observed version. They are not native capture handles. Revalidate mutable policy, trust, expiry, revision and owner fence at the final owning mutation. Use consuming local handles only where they prevent an actual omission; persisted protocol state remains a closed enum, not a generic typestate graph.

## Public preparation and command contract

WorkPreparationV1 has schema chio.work.preparation.v1, program_id, command_id and one closed proposal:

- Delegate { parent_id, parent_allocation_hash, child: WorkSlot }
- Offer { slot_id, allocation_hash, receiver_kernel_id, server_id, tool_name, arguments, request_id }
- Select { offer: Signed<WorkOffer>, request_id, capability_hash, expected_revision }
- Extend { expected_bundle_sha256, new_work: bounded work references, dependencies: bounded SwarmGraphEdge values }
- Agreement { commitment: WorkCommitmentV1, funding_profile_id, terms_reference }

Only the configured holder, receiver capability issuer, graph authority or agreement role may prepare its own artifact. Scope includes the authenticated caller, program, root, receiver and purpose. Requests cannot choose keys, trust roots or endpoints. Each owner keeps its own key. Applications need neither private signing keys nor a custom graph/signature builder.

Preparation freezes the exact issuer-selected body, validity interval and issuance reference before an externally observable issuance. Issuer-local issuance/reservation and original-ID readback must be atomic or use that issuer's existing durable protocol. Retaining a reference only after issuing is insufficient. Never hold a store transaction across a remote signature request. Retain remote request intent first, use the peer's original issuance ID, and resolve its retained response on ambiguity. If the issuing authority lacks this contract, extend that authority; a coordinator cache cannot supply it.

WorkPreparedV1 is a closed outcome: Prepared { preparation_ref, artifact }, Pending { preparation_ref, owner_operation_ref }, or Refused { preparation_ref, rejection }. The artifact is a variant for the specific preparation kind, including its exact signed material and invocation custody reference where required. There is no optional catch-all command. Offer preparation conveys capability material only over its authorized channel; it never returns a signing handle. Preparing an agreement authorizes no reserve or transfer. Extend preparation returns an unsigned, owner-retained WorkGraphDraftRefV1. It must not disclose signed competing graph successors before head commitment.

WorkCommandV1 has schema chio.work.command.v1, program_id, command_id and one WorkActionV1:

- Delegate { subdivision: Signed<Subdivision> }
- Select { selection: Signed<Selection> }
- Seal { binding: DispatchBinding }
- Extend { expected_bundle_sha256, draft_ref: WorkGraphDraftRefV1 }
- Submit { commitment: WorkCommitmentV1 }
- Reconcile { handle: WorkHandleV1 }
- Cancel { handle: WorkHandleV1 }

Reconcile advances only already owned historical settlement/evidence through the existing owners. It cannot execute or release result bytes. Cancel requests an existing owner's supported cancellation transition; it does not reclaim D1 budget, erase history, refund earned work or establish absence of an effect.

WorkCommandResultV1 contains the original command reference and a closed outcome: Applied { revision, result: WorkAppliedV1 }, Pending { owner_operation_ref }, or Refused { rejection }. WorkAppliedV1 is a closed per-action result (delegated slot, selected revision, sealed permit, extended head, submitted native reference, reconciliation view or cancellation observation). No independent Option<handle>/Option<view> fields permit contradictory combinations. Applied describes command processing, never an aggregate claim that work succeeded. After ambiguous handoff, return Pending with original references; do not classify a timeout or native unknown effect as a pre-dispatch refusal.

WorkQueryV1 is Work { handle }, Command { command_ref } or Preparation { preparation_ref }. Queries require current authorized metadata access and make no mutations. These original-ID queries work before the client has received any handle. A missing coordination row is not proof that an owning authority has no operation.

## Commitment, custody and projections

WorkHandleV1 names program_id, slot_id, allocation_hash, receiver_kernel_id and original request_id. It is a serializable reference, not a bearer permit. A graph extension can change the containing version without changing this reference.

WorkCommitmentV1 links the handle, Signed<DispatchPermit>, exact invocation custody reference, graph reference and optional WorkFundingRefV1. FundingRef names configured rail, agreement digest and reserve reference; it does not prove funding. The work envelope creates no new signing domain.

Do not put an unrestricted ToolCallRequest in a reusable, clonable public commitment. It carries capability, DPoP, execution nonce, approval and declassification material. Use the recovery lane's protected exact-envelope custody and authorized transfer path. The receiver resolves/imports the exact request under its own policy; a remote reference alone never grants access. A caller cannot make the host fetch an arbitrary URL/path.

Maintain distinct process binding digest, native retained-material digest, approval/flow digest and F1 full-request digest. The adapter's exhaustive request projection accounts for every ToolCallRequest field, including fields deliberately omitted by native retained projections. F1 still hashes the same complete final request as its existing contract. Preparation order is frozen: receiver offer/capability, selection and seal, graph/treaty context, exact invocation custody, agreement, reserve, submit. Resolve any profile-specific approval dependency before freezing the final request. Do not insert the resulting agreement digest into the request it hashes.

WorkViewV1 has independent execution, result-reference, settlement and bilateral-delivery observations. Each observation is NotApplicable, Pending { owner_ref }, Available { source, revision, observed_at, value }, or Unavailable { code }. Native UnknownEffect is a possible execution observation, not a transport error. Reuse the native observation enums; do not implement another effect state machine. Revisions are per authority; a view is not a globally atomic snapshot.

References, task names, topology and error details can themselves be confidential. Query/export use current audience checks and bounded redaction. Result bytes use the recovery lane's existing ArtifactReleasePort/ConfinedReturnPort and client operations, separately from query/reconcile. A successful status query cannot serve as a release grant. Recheck current recipient authority at the release boundary, including after a stalled transport.

## Production allocation, graph issuance and durable coordination

Use the existing SqliteAuthorityStore serving connection, lease/fence and continuity machinery for production D1 state. Keep D1 rules in chio-workflow and move production persistence into a small delegation store module in chio-store-sqlite. Share validation/transition functions with the legacy example adapter, not two copies of the algorithm. Kernel -> workflow and store -> workflow stay acyclic.

Register allocation, selection and sealed-permit mutations in the qualified store's projection/global-commit inventory, integrity verification, snapshot/relocation and migration paths. Merely adding tables to the same database is insufficient. Use checked Rust arithmetic and SQL predicates for remaining allowance and expected revision. Provision explicitly; serving open must not silently recreate missing authoritative rows, tables or namespaces. Reject stale fences and unqualified copied/restored state using the selected authority profile's continuity checks. This is not a new Byzantine or whole-domain rollback guarantee.

The graph issuer has the same production ownership requirement. Existing S1 compare-and-swap serializes one SQLite file, and its pure verifier explicitly assumes a protected head. Qualify mutable graph head, archive and pending issuance under the serving authority, reusing verify_swarm_authority_extension and the existing record format. Runtime graph copies remain lookup/evidence sources, not additional writable issuance heads. A graph copy cannot resume issuing after its owner lease is lost.

Extend resolves the retained draft, validates it against the current qualified head and owner policy, and commits the successor and exact signed artifacts before releasing them. A losing CAS never returns usable signed successor artifacts. Local signing uses existing configured custody; a remote signer is supported only if its existing durable issuance protocol preserves this rule without a database transaction across I/O. Do not invent a distributed signing transaction in this workstream. Raw signed bundle import remains privileged setup/history transfer, not a worker-selected authority operation.

Import a legacy allocator only while quiesced, with an explicit owner-authorized migration that preserves allocator namespace, roots, allocation digests, revisions, selections and exact permit bytes. Retire the old writer. The migration establishes a new qualified baseline; it cannot prove the provenance of an untrusted historical database. Missing/untrusted source requires rejection, not fresh empty capacity.

Live seal uses the existing checks and returns the same retained permit. Add a separate authorized historical read for an already retained permit after expiry, with exact binding verification but no fresh liveness grant. A crash after claim_dispatch but before permit persistence keeps capacity consumed; do not invent or backdate an unissued permit after expiry. A retained permit read after expiry still fails fresh native admission.

The runtime command index remains a non-authoritative projection in the existing runtime store. It stores command/preparation digest, authenticated namespace/program/stage, original owner references and coordination phase. Private request/artifact bytes belong to protected owner custody. Index loss, rollback or eviction cannot renew an issuance, nonce, allocation or financial right. Every mutating owner must independently retain the original idempotency binding. Retention of owner tombstones follows the owning authority's lifecycle, not a client cache TTL.

| Operation | Linearization/authority | Lost response resolution |
| --- | --- | --- |
| Prepare | Issuer's retained exact body and issuance/reservation binding | Query the same preparation/issuer ID, including after caller response loss |
| Delegate / select / seal | Fenced D1 transaction with immutable original command/body binding | Read the same mutation/permit; changed body conflicts |
| Extend | Qualified graph issuer, existing S1 verification, head CAS/archive and publish-after-commit | Match exact candidate digest in retained lineage even if a later head exists |
| Submit | Existing process reservation and native admission/capture | Original recovery operation; never a fresh invoke because an index row is absent |
| Reconcile / cancel | Existing native/recovery/payment transition | Same retained operation, with separate current/history authorization |

There is no transaction across owners. Intermediate states remain visible and may retain capacity. No timeout-driven compensation, release or fresh ID is introduced.

## Bounds, scheduling and compatibility

Work request frames are at most 2 MiB and response frames at most 8 MiB, including existing transport framing. D1's 65,536-byte nested envelope and MAX_UNITS = 9,007,199,254,740,991 stay unchanged. Existing artifact-family limits remain stricter where applicable. Define aggregate graph/artifact counts, nesting and signature-verification budgets before schema freeze; enforce limits during decoding/expansion, not after growing an unbounded Vec. Boundary and one-over tests pin each chosen value.

SQLite and synchronous federation/rail calls run on the existing bounded blocking path. Bounded admission queues, concurrency and deadlines prevent one slow peer from starving the host. No unbounded spawn_blocking, detached task, mutex/transaction across network await, or global mutex around whole workflows. Serialize only the owning root/head/operation mutation. Cancellation/drop does not undo a committed right; supervision drains or hands off the original operation.

Unknown schemas/fields, duplicate keys, unsupported profiles, cross-tenant references and changed body under a reused ID fail closed. Export stable typed rejection codes and authorized original references. Preserve inner causes in trusted errors, but never serialize parser/source strings containing attacker data or secrets. There is no generic InvalidCommand bucket hiding which binding failed.

Negotiate chio.work.v1 alongside the recovery lane's worker protocol design. Preserve chio.process.v1 and historical D1/S1/F1/grant encodings. Reuse WorkerService credential verification, bounds and InvocationPreparer for ordinary preparation; add only the closed work-command extension it cannot express. Do not create a second worker listener, credential journal or negotiation authority.

## Acceptance

Public-facade tests, compile-fail authority construction tests and shared wire vectors establish the new API boundary. Existing D1/S1/native tests remain the authority oracles. Add only missing boundary cases: issuer acknowledgement loss, stale/copied allocator, expired permit history, interleaved graph CAS/readback, absent command index, cancellation at handoff and denied metadata/result release. Observe actual native effects and exact retained references.

The two applications consume the same facade and owner services. No paid flag, transport adapter or SDK may bypass native admission or introduce another recovery reducer. Release acceptance remains W4; a reviewed design is not implementation qualification.
