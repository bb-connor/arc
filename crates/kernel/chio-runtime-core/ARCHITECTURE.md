# chio-runtime-core architecture

## Responsibility and boundary

The crate implements runtime evidence admission and native kernel integration.
`RuntimeAdmissionInput` binds a profile, store, admission identifier, request,
trusted verifier material, policy inputs, and evaluation time.
`ChioRuntimeAdmissionHook` implements the kernel's runtime admission contract.
Stores own evidence lookup, trust floors, and orchestration state. The destination admission authority owns resource claims.
The kernel owns tool dispatch, capability checks, and receipt signing.
Operations and buyer APIs produce or verify reports from supplied evidence.

## Structure

- `admission.rs` validates admission evidence and trust-floor transitions.
- `admission/preparation.rs` validates without consuming replay authority.
- `admission_hook/` resolves request, treaty, swarm, and operation-owned bindings.
- `types.rs`, `schema.rs`, `serde_io.rs`, and `validation/` define bounded artifacts.
- `hash.rs` defines canonical structured digests.
- `store/traits.rs` defines admission and trust-floor backend contracts.
- `store/memory.rs`, `json.rs`, and `sqlite.rs` implement storage choices.
- SQLite submodules implement source qualification, leases, evidence, exact v1 schemas, and write fences.
- `store/sqlite/source_qualification.rs` verifies the live physical backend binding.
- `orchestration.rs` loads and validates evidence; `ops.rs` generates local reports.
- `pheromone_policy.rs`, `treaty/`, and `buyer/` implement policy and evidence checks.

## Data and control flow

The runtime hook prepares inputs and commits only under kernel-owned claim authority.
Preparation checks profile freshness, stored bundle identity, and request binding.
Supplied trust input is verified; a nonempty trusted-key set requires trust input.
With neither configured, preparation can accept ordinary bound evidence.
Selected policy evaluation adds its own requirements and checks.
The kernel reserves operation-owned resources before the hook records trust-floor transitions.
The kernel hook resolves referenced artifacts from verifier-owned storage.
Swarm verification compares stored hashes, mandatory route metadata, pinned keys,
and the selected task's complete signed request capability.
Immediate dispatch revalidation checks retained evidence and temporal bounds.
Operation-owned admission binds resource claims to kernel-owned authority.
SQLite orchestration APIs record runs and steps under lease/write-fence rules.
Report generators consume evidence and observations supplied by the caller.

## Trust and invariants

A successful function return can contain `accepted: false`; callers inspect the report.
Missing bundles produce `missing_admission_bundle`.
`verify_swarm_authority_reference` resolves the referenced graph version from the
qualified S1 issuer (`SwarmGraphSource`), rejects absent evidence or a missing issuer,
and replaces bundle evaluation time with the verifier's current time before verification.
Canonical digests bind structured artifacts and exact request argument hashes.
Trust-floor validation and recording must be atomic at the backend boundary.
Unsupported trust-floor mutation refuses.
The default `verify_operation_owned_runtime_source` rejects unqualified backends.
Memory state is process-local and clones share mutex-protected state.
JSON coordination covers clones of one open instance, with no independent-open lock.
SQLite transactions serialize state transitions across connections.
Operation-owned admission requires the explicit physical source/destination qualification and kernel participant claim authority. Opening a store alone grants neither. Copy, restore, device or inode changes refuse with `runtime_source_qualification_invalid`; immutable lifetime and replacement limits are specified in [RUNTIME_SOURCE.md](RUNTIME_SOURCE.md).

## Dependencies

`chio-kernel` supplies hook contracts and durable operation ownership.
`chio-swarm-authority` verifies recursive delegation evidence.
`chio-federation` and `chio-attest-buyer-core` verify treaty and buyer artifacts.
`chio-runtime-proof-parity` checks regenerated proof consistency.
`chio-sqlite-file-identity` binds SQLite runtime sources to file identity.
`chio-weights` supports peer-weight policy; `rusqlite` supplies durable transactions.

## Verification

`runtime_admission.rs` covers binding, fault, preparation, swarm, and operation-owned cases.
`runtime_kernel_hook.rs` exercises actual hook installation with a native kernel.
`runtime_store.rs` covers trust-floor races, bounded readers, and source integrity.
`lease_write_fencing.rs` and `lease_boundaries.rs` cover orchestration ownership.
`runtime_treaty.rs` and `runtime_buyer_review.rs` check signed evidence paths.
Run `cargo test -p chio-runtime-core` for local integration coverage.
`cargo bench -p chio-runtime-core --bench cross_boundary_admission` measures admission.
Tests and benchmarks use controlled fixtures and local stores.
