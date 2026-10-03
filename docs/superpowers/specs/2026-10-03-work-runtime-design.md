# Reusable work runtime specification

Status: proposed. Implements AW01 through AW05 and AW10.
Parent: [architecture and constraints](2026-10-03-agentic-work-kernel-design.md).

## Existing foundation and delta

D1 already supplies WorkContract, WorkSlot, Signed<Subdivision>, Signed<Selection>, DispatchBinding and Signed<DispatchPermit> in chio-workflow. S1 already supplies verify_swarm_authority_extension and transactional extend_swarm_authority_bundle in chio-runtime-core. chio-runtime is the existing public facade, but its SQLite wrapper lacks the extension method. chio-process already freezes calls under logical operation keys and reuses native outcomes.

Promote composition from examples/federated-work/src/funded_work/composition.rs and evolving.rs into existing runtime modules. Keep the example as a client and historical workload. Move reusable invariants, not fixture keys, mock prices, OpenAPI constants, in-process co-signers or LocalChain startup.

## Public contract

All names in this section are proposed, except named D1/S1/process types.

Add the opt-in work feature to chio-runtime and chio-runtime-core. Default builds retain their dependency surface. Public callers use chio_runtime::work. The facade owns errors and intentionally enumerated exports.

The runtime exposes both owner-authorized preparation and application of prepared commands. WorkPreparationV1 has schema chio.work.preparation.v1, program_id, command_id and one closed proposal:

- Delegate { parent_id, parent_allocation_hash, child: WorkSlot }
- Offer { slot_id, allocation_hash, receiver_kernel_id, server_id, tool_name, arguments, request_id }
- Select { offer: Signed<WorkOffer>, request_id, capability_hash, expected_revision }
- Extend { expected_bundle_sha256, new_work: Vec<WorkHandleV1>, dependencies: Vec<SwarmGraphEdge> }
- Agreement { commitment: WorkCommitmentV1, funding_profile_id, terms_reference }

The configured owner service derives and validates the complete signed body using the existing holder, receiver, graph-authority or locally authorized agreement role. It can act only for roles actually entrusted to that local service and permitted by the authenticated principal's scope. Preparing an offer uses the existing receiver capability issuer; preparing a graph uses the current S1 builder/verifier. Agreement preparation resolves owner-approved funding terms and gathers separate signatures over the same final request through W2's financial adapter. It does not itself authorize a transfer or reserve more capital. There is no arbitrary signing endpoint. WorkPreparedV1 contains the original preparation ID, exact issued artifact references and an optional prepared WorkCommandV1. Offer preparation returns the receiver-signed offer and exact request/capability binding, not the receiver's signing handle.

Preparation is idempotent under its original ID and stage. Retain an issued capability or signed body before acknowledging it. A lost response resolves that exact preparation; a new expiry, signature body or request cannot be substituted. The preparation and application stages have distinct persisted namespaces so equal IDs cannot collide. Each owner supplies only its own artifacts. Partial preparation is visible and cannot trigger execution.

The common command envelope is WorkCommandV1:

- schema = chio.work.command.v1
- program_id: existing graph/program identifier
- command_id: caller-stable ID, scoped to the authenticated principal and program
- action: one closed WorkActionV1 variant

WorkActionV1 variants:

- Delegate { subdivision: Signed<Subdivision> }
- Select { selection: Signed<Selection> }
- Seal { binding: DispatchBinding }
- Extend { expected_bundle_sha256: String, candidate: SwarmAuthorityBundle }
- Submit { commitment: WorkCommitmentV1 }
- Collect { handle: WorkHandleV1 }
- Cancel { handle: WorkHandleV1 }

Delegate, offer, selection and graph preparation use the owner-configured services above. Client SDKs submit bounded proposals; worker credentials do not give access to a holder or receiver private key. Signed commands remain subject to both holder verification and authenticated caller/program scope. This authoring surface is required for acceptance; manually signing records in application code is not an acceptable substitute.

WorkHandleV1 is a serializable reference containing program_id, slot_id, allocation_hash, receiver_kernel_id and original request_id. A work handle is never a bearer execution permit. A graph extension can change the containing version without changing the handle.

WorkCommitmentV1 contains handle, signed DispatchPermit, exact ToolCallRequest, swarm graph reference and optional WorkFundingRefV1. WorkFundingRefV1 contains rail_id, agreement_sha256 and reserve_reference. These are linked records; receivers verify every binding and load financial truth from the configured rail. The envelope does not create a new signature or replace existing signing domains.

WorkViewV1 contains the handle, command revision and separate optional native operation reference, execution observation, authorized result reference, settlement observation and bilateral-delivery observation. Observations name their issuing authority and source reference. An unavailable observation stays unavailable. No aggregate succeeded Boolean authorizes anything.

Result payloads remain behind the recovery lane's artifact/return release boundaries. WorkViewV1 carries references and audience-safe diagnostics, not raw retained output.

## Runtime interfaces and dependency direction

Add WorkRuntime in chio-runtime-core/src/work and a wrapping facade in chio-runtime/src/work.rs. It consumes an already configured WorkHostPort; this is a composition seam for trusted hosting, not a network plug-in or a source of verified authority.

Proposed object-safe trait:

    trait WorkHostPort: Send + Sync {
        fn prepare<'a>(&'a self, caller: &'a WorkCaller, proposal: &'a WorkPreparationV1)
            -> Pin<Box<dyn Future<Output = Result<WorkPreparedV1, WorkError>> + Send + 'a>>;
        fn apply<'a>(&'a self, caller: &'a WorkCaller, command: &'a WorkCommandV1)
            -> Pin<Box<dyn Future<Output = Result<WorkCommandResultV1, WorkError>> + Send + 'a>>;
        fn inspect<'a>(&'a self, caller: &'a WorkCaller, handle: &'a WorkHandleV1)
            -> Pin<Box<dyn Future<Output = Result<WorkViewV1, WorkError>> + Send + 'a>>;
    }

WorkCaller is a non-serializable host-constructed context derived from existing authenticated caller/process identity. It includes tenant, principal, process and authorized program scope; no request chooses these fields. The service authorizes access to commands and reads; native admission still independently authorizes effects.

WorkRuntime::prepare(&self, caller: &WorkCaller, proposal: WorkPreparationV1), submit(&self, caller: &WorkCaller, command: WorkCommandV1) and inspect(&self, caller: &WorkCaller, handle: &WorkHandleV1) are async methods returning the corresponding WorkPreparedV1, WorkCommandResultV1 and WorkViewV1 inside Result<_, WorkError>. They validate bounded inputs and call the configured host port. These are request APIs, not publicly clonable native dispatch owners. Live capture remains kernel-private.

The production WorkHostPort adapter belongs in chio-control-plane, which can compose process, runtime, SQLite and settlement dependencies without creating kernel dependency cycles. Runtime-core must not depend on control-plane. The kernel already depends on chio-workflow and chio-settle; neither may gain a dependency back on chio-kernel.

## Durable behavior

Do not reuse the generic record_run_step_state upsert as authority. Retain a dedicated orchestration command index in the existing runtime SQLite store. It records immutable command digest, owner/program scope, phase and references, using the store's qualified integrity/migration discipline. It never owns invocation or financial rights.

Delegation and selection use their existing transactions. Extension uses the existing compare-and-swap head. Seal must gain exact idempotent readback if the existing API cannot return the original sealed permit after acknowledgement loss. The returned permit must remain byte-identical.

Submit retains the exact intended invocation in the existing protected native/recovery custody before handoff. The orchestration index stores only its digest and scoped reference, never a second unclassified copy of credentials, private inputs or output. A lost response is resolved through the native original-operation/recovery contract. A command-index gap cannot establish absence at the receiver. There is no distributed transaction across allocator, graph and receiver: partial preparation remains explicitly incomplete and may retain reserved capacity.

Cancel stops future local planning/submission only through the owning authority's supported cancellation transition. It never erases history, reclaims a D1 allocation automatically, refunds earned work, or certifies no effect. A remote cancellation request is itself authenticated and scoped; a lost response remains unresolved.

## Bounds and compatibility

Identifiers reuse the existing native AdmissionIdentifier validation where applicable. D1's 65,536-byte signed-envelope limit and MAX_UNITS = 9,007,199,254,740,991 remain unchanged. Work command frames are at most 2 MiB; work view frames are at most 8 MiB, matching the existing local worker transport ceilings. The smaller nested artifact limit always applies. Results larger than a response frame use authorized artifact references.

The work profile rejects unknown schema versions, duplicate signed JSON keys, cross-tenant handles, changed payload under a reused command_id and unsupported signature/authority combinations. It carries existing signed bytes intact. Work protocol v1 does not rename D1 v2 or recovery grant v2.

A dedicated work session negotiates chio.work.v1. Older chio.process.v1 clients keep their current behavior and cannot silently opt into the new command family.

## Acceptance

One reusable runtime passes delegation, selection replacement-before-seal, seal replay, additive growth, concurrent head conflict, lost-acknowledgement readback and fresh-process collection. The same integration tests observe actual tool counts and native custody records. A paid/unpaid flag cannot change admission semantics. Every emitted result separates execution, release, financial and bilateral state.

The old D1, S1, native SQLite and composed funded controls continue passing on their declared source. Tests of the new facade must import the facade; a test that calls core directly does not establish the public API.
