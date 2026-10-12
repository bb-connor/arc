# Revocation proof scope implementation plan

> Use superpowers:executing-plans in Root's native thread. Claude reviews source
> and owns proof execution after capacity release.

**Goal:** Verify production snapshot freshness without changing revocation
behavior. Retain the real sequential epoch-installation experiment and its open
backend limitation.

**Architecture:** The kernel delegates its existing freshness arithmetic to
`RevocationSnapshot::verify_freshness`. A top-level Kani harness calls the child
module's full-domain assertion against independent `u128` arithmetic and requires
one named joint witness from concrete production boundary calls. The separate
sequential harness calls `RevocationView::install_if_newer` directly. The original
boolean refusal/retry harness and its domain remain unchanged.

**Scope:** `KANI-REVOCATION-SCOPE`; freshness alone does not close epoch
installation, `KANI-PROOF-QUAL`, or concurrent ArcSwap linearizability. No timeout,
domain, assertion, cover-checker or unwinding waiver is allowed. This source lane
runs no Rust builds or proofs; Root and Claude own those checks.

## Source and ordinary checks

- [x] Introduce `RevocationSnapshot::verify_freshness(now_unix_ms: u64,
  max_staleness_ms: u64)` in
  `crates/kernel/chio-kernel-core/src/revocation_view.rs`, returning
  `Result<(), RevocationSnapshotFreshnessError>` with `Future` and `Stale`.
  Preserve checked subtraction and strict `age > maximum` refusal. Re-export the
  error through `src/lib.rs` under the existing feature.
- [x] Delegate the kernel's `kernel/delegation.rs` wrapper, retaining exact
  `KernelError` variants, feature gates, the 500 ms default and empty-sentinel
  behavior near zero. This is behavior-preserving extraction, not bug repair.
- [x] Add ordinary controls for future, stale, exact threshold, zero and
  `u64::MAX`. Root reported 24 focused tests and strict owning all-target Clippy
  passing at source `ae6322aa64fb58cc4ba0e323612f28495deb2acb`. These results apply
  to the extraction before the enrollment change. Existing concurrent tests are
  runtime controls, not formal refinement evidence.

The first test-source checkpoint referenced an absent method and error type;
its expected failure was compilation, not a runtime Original. Kernel error
mapping and epoch controls describe behavior that already existed.

## Harnesses and enrollment

- [x] Prepare the freshness assertion in
  `crates/kernel/chio-kernel-core/src/kani_public_harnesses/revocation.rs`, loaded
  through `mod revocation` and `#[path]` under `revocation-view`. Timestamp, current
  time and maximum age remain unrestricted symbolic `u64` values. Epoch and root
  bytes also remain symbolic; the arithmetic does not inspect the revoked set.
- [x] Prepare the separate real-store sequential installation harness in that
  child module. From the empty sentinel it seeds a positive symbolic epoch and
  exercises two unrestricted candidates. It checks exact refusal and Arc
  preservation, prior Arc on success, candidate payload, duplicate refusal and a
  retained old Arc. Every subset of two fixed subject identifiers is modeled;
  epochs, timestamps and root bytes retain their full domains.
- [x] Add the top-level
  `kani_public_harnesses::verify_revocation_snapshot_timestamp_freshness` wrapper
  for the existing strict checker contract. Its only cover is named exactly
  `verify_revocation_snapshot_timestamp_freshness` and belongs to the wrapper.
  The child returns a conjunction of nine already evaluated production boundary
  results, which the wrapper also asserts. This is one joint witness, not nine
  separate cover properties. It supplements the unrestricted arithmetic check.
- [x] Enroll freshness only in `.kani/harnesses.toml` and
  `formal/rust-verification/kani-public-harnesses.toml` with checked unwinding,
  required cover, unwind 8 and the existing 1800-second cap. The metadata scan
  discovers the top-level proof; Rust follows the actual child-module import.
  Mutation controls reject coordinated cover or unwinding downgrades. Do not
  enroll the unsupported installation experiment or waive it into a required
  lane.
- [x] Review `formal/MAPPING.md` and `formal/proof-manifest.toml`. Attribute the
  new Kani artifact only to the production freshness method. The mapping names
  the child assertion source so coverage inputs include its content. Existing
  revocation mirrors retain their `abstraction_anchor` relationships and pinned
  symbol hashes; the selected store and consultation bodies were not changed by
  the extraction or enrollment. No TLA refinement is asserted.
- [ ] Regenerate coverage with the owning Rust runner using
  `cargo xtask gen proof-coverage`, then check with
  `cargo xtask gen proof-coverage --check`. Coverage generation is metadata
  attribution, not a proof result. Do not hand-edit the generated report.

The parent stays below the 2000-line production-file cap. The inherited boolean
harness remains byte-identical. The unsupported install harness remains separate
from the required wrapper in the child module; no fake store replaces it.

## Recorded execution and remaining acceptance

Claude's x86 logs at
`/home/connor/lanes/claude-pr1160-evidence/kani-revocation-x86/` record Kani 0.68.0
and CBMC 6.11.0 on source `ae6322aa64fb58cc4ba0e323612f28495deb2acb`:

- The earlier nested freshness harness passed with 0 of 397 failed checks and
  9 of 9 covers satisfied. This plain proof is historical evidence for the
  earlier source; it does not qualify the replacement one-cover wrapper.
- The installation harness failed on unsupported `pthread_key_create` and
  related TLS operations: 8 failed, 6301 undetermined checks and 0 of 11 covers
  satisfied (all 11 undetermined). Production epoch installation remains open.
- The earlier cover-wrapper attempt retained the nine-cover proof result but
  was refused by `check-kani-cover.py`: nested names and multiple covers do not
  satisfy its contract. Do not claim that run qualified the required gate.

- [ ] Run the replacement top-level freshness harness through the unchanged
  strict cover wrapper. Retain terminal JSON and logs showing enabled unwind
  assertions, successful proof and its exact single satisfied joint witness.
- [ ] Confirm freshness regression sensitivity with controlled arithmetic
  mutations and retain exact source, commands, terminal logs and domain identity.
- [ ] Resolve direct ArcSwap backend feasibility before epoch qualification.
  Unsupported TLS remains open; no toy store or disabled check discharges it.
- [ ] Obtain Claude's source/evidence review before publication.

Even a future sequential installation pass excludes racing-writer linearizability,
failed-CAS retries, memory reclamation and starvation freedom. If the accepted
requirement needs concurrent installation proof, that remains a separate open
obligation. Broader `KANI-PROOF-QUAL` acceptance remains open.

## Commands for the owning runner

Required freshness uses a top-level name and one exact cover. The plain wrapper
does not consume a standalone `--`; pass the executable directly after the name:

```bash
revocation_harness=kani_public_harnesses::verify_revocation_snapshot_timestamp_freshness
timeout 1800s bash scripts/run-kani-with-cover.sh "$revocation_harness" \
  cargo kani -p chio-kernel-core --features kani --lib \
  --harness "$revocation_harness" --exact --default-unwind 8
```

Both lane runners include the required enrollment. They run the selected lane
or crate, not a single harness; use the command above for the focused rerun:

```bash
bash scripts/check-kani-public-core.sh --lane pr
bash scripts/run-kani-manifest.sh --lane pr --crate chio-kernel-core
```

The unsupported installation experiment retains its nested name and multiple
covers. If backend work authorizes another diagnostic attempt, use plain Kani,
not the strict single-cover wrapper:

```bash
revocation_harness=kani_public_harnesses::revocation::verify_revocation_view_epoch_install_sequential
timeout 1800s cargo kani -p chio-kernel-core --features kani --lib \
  --harness "$revocation_harness" --exact --default-unwind 8
```
