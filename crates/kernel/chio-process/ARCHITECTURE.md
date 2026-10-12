# chio-process architecture

## Responsibility and boundary

`ProcessRuntime` owns a durable process namespace, capability-bound tree,
checkpoints, state blobs, and logical operation bindings.
`ProcessRegistry` provides identity and child-submission access to native services.
The kernel owns tool dispatch, guards, budgets, authority recovery, and receipts.
The public runtime API assumes a trusted host; worker authentication is optional.
A host supplies capability issuance, private filesystem placement, tool connections,
and the security profile used for tenant and isolation attribution.

## Structure

- `lib.rs` implements lifecycle, requests, invocation, and recovery.
- `registry.rs` exposes shared identity, child work, waits, and signer provisioning.
- `types.rs` defines process limits, snapshots, state, and errors.
- `store.rs` and `store.sql` implement the versioned SQLite journal.
- `store/blobs.rs`, `children.rs`, `nonces.rs`, and `prepared.rs` handle retained state.
- `routes.rs` and `security.rs` define host-selected dispatch attribution.
- `state_reader.rs` exposes bounded state reads.
- `worker.rs` and `worker/unix.rs` provide the optional guest transport.
- `mailboxes/` supplies the optional native message and claim server.

## Data and control flow

`open` delegates journal qualification to `ProcessRegistry::open`.
`create_root` registers a root capability and tree limits.
`spawn` attaches an authority-issued capability after validating the parent hop.
`tool_request` derives request identity from namespace, process, operation, and attempt.
`invoke_with_recovery` freezes the request and selected host context in the journal.
It restores delegation ancestors before admitting work through the kernel.
The retained kernel operation supplies replay and crash outcomes.
A kernel-classified read-only call may receive a fresh attempt only when retry
eligibility excludes stateful authority and request-bound artifacts.
`MAX_DISPATCH_ATTEMPTS` limits this recovery to three total dispatch attempts.
`invoke_known_only` durably selects the stricter recovery policy.
Cancellation prevents subsequent admissions and withholds admitted-call output.
An effect already admitted by the kernel can still complete.

## Trust and invariants

`ProcessRegistry::open` requires all-call durable admission and an authority UUID.
`Store::open` validates the journal's authority and kernel-key binding before
changing an existing database, then uses WAL, FULL synchronization, and foreign keys.
`create_root` verifies signatures and rejects delegated capabilities as roots.
`validate_child` requires the signed chain to extend the parent by one hop,
retain issuer and budget family, and narrow scope and validity.
Canonical digests bind logical request content, route, and security context.
Changing that content under an existing operation key causes a conflict.
State blob reads verify process ownership and content integrity.
`MailboxServer::open` also requires all-call durable admission and qualified authority.
Worker bearer credentials must remain private to their selected guest.
Unix sockets and host OS isolation supply transport and process containment.

## Dependencies

`chio-kernel` mediates effects and admission recovery.
`chio-core-types` supplies capabilities, attenuation, canonical JSON, and hashes.
`rusqlite` persists the process journal; `zeroize` supports secret handling.
Optional Tokio, random, hex, and base64 dependencies support worker transport.
Optional `chio-manifest` and `async-trait` support native mailbox tools.

## Verification

`tests/processes.rs` exercises host-flow binding, cancellation, and process operations.
`crash_recovery.rs`, `retry_eligibility.rs`, and `nonce_recovery.rs` cover retained calls.
`state_blobs.rs` checks ownership and quotas; `child_submission.rs` covers native children.
`worker_protocol.rs` and `mailbox_effect_boundary.rs` cover optional boundaries.
Run `cargo test -p chio-process` for the base surface.
Run `cargo test -p chio-process --features worker-server,mailboxes` for optional APIs.
The tests use controlled stores and local servers; host isolation remains a deployment duty.
