# Revocation proof scope implementation plan

> Use superpowers:executing-plans in Root's native thread. Claude reviews source
> and releases proof execution when build capacity is available.

**Goal:** Prepare honest production-boundary proofs for snapshot freshness and
sequential epoch installation without changing revocation behavior.

**Architecture:** Move the kernel's existing freshness arithmetic onto
`RevocationSnapshot`, then call that production method from the kernel and Kani.
Exercise the real `RevocationView::install_if_newer` implementation directly.
Keep the existing boolean refusal/retry harness and its domain unchanged.

**Scope:** `KANI-REVOCATION-SCOPE`; this does not close `KANI-PROOF-QUAL` or prove
concurrent ArcSwap linearizability. No proof campaign starts before Claude's
capacity release. No timeout, domain, assertion or unwinding waiver is allowed.

## Source and ordinary checks

- [ ] In `crates/kernel/chio-kernel-core/src/revocation_view.rs`, introduce
  `RevocationSnapshot::verify_freshness(now_unix_ms: u64, max_staleness_ms: u64)`
  returning `Result<(), RevocationSnapshotFreshnessError>`, with `Future` and
  `Stale` variants. Preserve checked subtraction and the strict `age > maximum`
  refusal. Re-export the error through the existing revocation-view exports in
  `src/lib.rs`.
- [ ] Delegate the existing `crates/kernel/chio-kernel/src/kernel/delegation.rs`
  wrapper to that method, retaining exact `KernelError` variants, feature gates
  and the 500 ms default. Preserve the current empty-sentinel behavior near zero;
  this change does not add a separate sentinel policy.
- [ ] Add ordinary boundary controls for future, stale, exact threshold, zero
  and `u64::MAX`. Run owning revocation/delegation tests and strict owning Clippy
  once capacity permits. Existing concurrent reader/writer tests remain runtime
  controls, not formal refinement evidence.

## Harnesses and enrollment

- [ ] Add `verify_revocation_snapshot_timestamp_freshness` in
  `crates/kernel/chio-kernel-core/src/kani_public_harnesses/revocation.rs`, loaded
  through `mod revocation` and `#[path]` in `kani_public_harnesses.rs` under the
  existing `revocation-view` feature. Use unrestricted
  symbolic `u64` timestamps and maximum age; compare the real production result
  to an independent `u128` arithmetic specification. Cover all outcomes and
  zero, equality and maximum boundaries.
- [ ] Add `verify_revocation_view_epoch_install_sequential`, calling the real
  ArcSwap-backed store from the same child module. From the empty sentinel, seed
  a positive symbolic epoch
  and exercise two unrestricted candidate epochs. Verify exact refusal and Arc
  preservation for equal/older candidates, exact prior Arc on success, candidate
  payload installation, duplicate refusal, and stability of a retained old Arc.
  Disclose finite subject fixtures; retain zero and `u64::MAX` epoch cases.
- [ ] Enroll both harnesses in `.kani/harnesses.toml` and
  `formal/rust-verification/kani-public-harnesses.toml` with matching covers,
  production symbols, checked unwinding and the existing 1800-second cap. Review
  `formal/MAPPING.md` and `formal/proof-manifest.toml`, preserving the existing
  `abstraction_anchor` relationship, then regenerate coverage.
  Enrollment must account for child-module source discovery and qualified
  harness names; a passing parent-only source scan does not enroll these proofs.

Source review split the new harnesses into a child module to retain the existing
2000-line production-file cap. The inherited boolean harness stays in its
original module. Enrollment remains deferred until direct-store feasibility is
verified; source preparation does not update any proof result.

## Acceptance after capacity release

- [ ] Try the direct production install harness first on pinned Kani 0.68.0.
  ArcSwap 1.9.1 uses TLS, reclamation loops and weak compare-and-swap; compatibility
  is unverified. Unsupported operations or failed unwind checks remain open.
  Never substitute a fake store and report production installation proved.
- [ ] Obtain terminal proof results and reachable covers with enabled unwind
  assertions. Any per-harness unwind adjustment must be consistent across both
  runners; do not globally raise bounds or shrink the epoch domain.
- [ ] Confirm regression sensitivity with controlled epoch/freshness mutations
  and retain exact source, commands, terminal logs and domain identity.
- [ ] Obtain Claude's source/evidence review before publication. A sequential
  result excludes racing-writer linearizability, failed-CAS retries, memory
  reclamation and starvation freedom. Record those boundaries explicitly.

Preparation alone closes no proof obligation. If the accepted requirement needs
concurrent installation proof, that remains open after sequential qualification.

## Qualified commands after capacity release

The child-module harness names are:

- `kani_public_harnesses::revocation::verify_revocation_view_epoch_install_sequential`
- `kani_public_harnesses::revocation::verify_revocation_snapshot_timestamp_freshness`

Try installation first, retaining checked unwinding and reachable covers:

```bash
revocation_harness=kani_public_harnesses::revocation::verify_revocation_view_epoch_install_sequential
timeout 1800s bash scripts/run-kani-with-cover.sh "$revocation_harness" -- \
  cargo kani -p chio-kernel-core --features kani --lib \
  --harness "$revocation_harness" --exact --default-unwind 8
```

For the freshness harness, use the same command with
`revocation_harness=kani_public_harnesses::revocation::verify_revocation_snapshot_timestamp_freshness`.
These commands are pending; run neither before the shared capacity release.
