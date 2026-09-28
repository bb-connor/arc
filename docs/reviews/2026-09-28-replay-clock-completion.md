# Replay and commit clock completion

Base `2b73690f7c`, branch `packet/3-retention-accounting`, isolated checkout
`/tmp/arc-security-launch`. Single-agent execution. Preexisting `output/` remains
untouched. Evidence directory: `/tmp/chio-replay-clock-completion-20260928`.

## Scope and implementation

- [x] Shared clock for in-memory DPoP, governed approval, retention and source seals.
- [x] Kernel clock ownership and precise DPoP/replay rejection provenance.
- [x] Fallible Finding commit clock sampled within the durable transaction.
- [x] Exact financial receipt accounting with explicit uncapped-budget semantics.
- [x] Focused regressions, consumer checks, source gates and direct review.

The implementation follows the user's implementation-first directive: related
changes were written before running owning checks, without a workspace baseline
or delegated review. Existing local target artifacts were reused.

DPoP and governed approval sample the shared fallible clock under their custody
lock. Signed replay markers require both their original epoch and monotonic
deadlines before reclamation. Retries cannot widen retention. An unrepresentable
retention deadline means indefinite custody, never authority. Clock regression,
outage and an unconfirmed forward jump refuse new work without discarding live
markers. Source previews and seals use the same clock; historical verification
of an existing exact seal remains independent of current clock availability.

Kernel construction binds the default approval store to its clock; installing a
DPoP store binds a pristine source to that same clock. Observed source history
cannot be rebound to another clock domain. Successful DPoP commit clears exact
rollback ownership while retaining the marker, including during a clock outage.
Dropping an evaluation after the effect boundary performs the same promotion,
independently of approval cleanup.
The retained identity-byte charge drops only by the released owner-string size.

The independent Finding commit-clock trait and epoch-zero fallback are removed.
Coordinators own the shared Clock and a regression fence. SQLite invokes the
fallible callback after acquiring its write transaction; read faults propagate as
`FindingStatusStoreError::Clock` and leave no new intent or authorization behind.
Exact historical retries still reuse their original durable evidence.

Financial and economic receipt budget totals and remaining balances now use
explicit nullable values. A capped grant, including an actual `u64::MAX` cap,
reports its ceiling and cumulative remaining balance. An uncapped grant reports
`null` for both fields. Missing fields are invalid. Invocation exposure and
quoted cost cannot masquerade as grant ceilings. Inline settlement, rollback,
denial, reconciliation and durable terminalization use checked subtraction;
inconsistent accounting cannot be hidden by a clamp before signing. Reconciliation
requires captured delegation lineage instead of substituting older-hold defaults.
The Rust consumers, dashboard types/rendering and reference docs are updated.

DPoP failures have distinct registered rule codes for binding, freshness,
signature, replay, capacity, identity, configuration and commit ownership. Both
root and nested preview denials now preserve these through the common signed
rejection path. Canonical encoding/signing errors retain their source. Approval
custody and financial invariant failures also have registered codes.

## Review and verification

Direct review found and corrected missing DPoP commit/drop transitions, two preview
paths that flattened rule codes into text, an acquisition path that still used
the generic replay error, and nullable fields accepting omission as uncapped.
The new composition tests exercise these production paths. Two receipt migration
tests retained old string-error expectations from the prior strict-reader
migration; their assertions now require the precise untrusted-JSON error variant.

Recorded results:

- `control-plane-tests-1.log`: 164 Finding status, challenge and enforcement tests
  passed, including commit liveness, finality, appeal and recovery fixtures.
- `sqlite-tests-1.log`: 400 passed, two obsolete error assertions failed, two scale
  campaigns remained ignored. `chio_store_sqlite-final-tests.log` passes all 143
  selected cases, including both corrected assertions, 33 Finding status-store
  cases and 69 durable DPoP cases. Together these runs cover 504 unique SQLite tests.
- `kernel-tests-1.log`: 210 passed; the new denial-code regression exposed the
  preview bug described above. `chio_kernel-final-tests.log` subsequently passed
  233 tests, including five precise DPoP refusals through root and nested dispatch.
  `kernel-final.log` passes all 234 selected tests after the cancellation fix,
  including retention without rollback ownership after dropping dispatch.
- `clippy-final.log`: strict Clippy passes for core types, kernel, SQLite and
  control plane libraries after the final cancellation fix. Initial documentation
  lint and test-warning fixes are retained in the earlier logs rather than hidden.
- `chio_core_types-final-tests.log`: 75 receipt tests pass, including required
  nullable budgets and full-width ceilings. `dpop-final-tests.log`: all 13 DPoP
  integration tests pass.
- `consumer-check-1.log`: test targets compile for API Protect, ACP edge, credit,
  settlement, SIEM and CLI. No warnings. The extracted ACP permission module
  retains the existing preview tests under its explicit source-directory path.
- `dashboard-check.log`: dashboard TypeScript compilation passed.
- `mutation-results.log`: a standalone harness compiles the actual replay and
  accounting source against the built shared-clock crate, substituting only the
  outer error container. The original six tests pass. Wall-only replay expiry
  and clock-regression clamping each fail the corresponding original regression.
  This is bounded mutation evidence, not a second full-crate qualification.

The source gates retain their original caps and expiries. The clock inventory
shrinks from 198 to 179 sites. The weak-negative baseline shrinks from 1,278 to
1,269 assertions at 1,186 sites, retaining its January 31, 2027 expiry. Fourteen
arithmetic census entries receive dispositions: ten repaired production paths
and four removed fixture clamps. Totals are 252 classified, 117 fixed and 386
pending. The arithmetic operator gate reports zero unchecked sites in its
configured migrated scope; that does not dispose of the pending census.
Trust gates retain 44 constructors, 85 tenant tables and 170 SQL principal
contracts. Error-code generation is synchronized. File-hygiene caps are preserved
by ordinary test/module extraction, with no allowlist increases.

The recorded runs cover 990 unique passing tests: 234 kernel, 504 SQLite,
164 control-plane Finding, 75 core receipt and 13 DPoP integration cases.
The final selected suites account for 629 of these; the earlier 400-case SQLite
pass is retained as additional evidence, with its two failures repaired and
rerun. The 22 Finding route checks are a subset of the 164 transition cases and
are not double-counted. Formatting passes for all 89 touched Rust files and
`git diff --check` passes. No workspace-wide test or lint campaign was run.

The final kernel command was:

```sh
CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=6 RUST_TEST_THREADS=1 cargo test --locked \
  -p chio-kernel --lib --features admission-test-support,delegation,finding-market \
  -- dpop replay_retention governed_approval_replay financial_accounting \
  security_dispatch::clock budget reconciliation execution_nonce \
  dispatch_credentials payment_ambiguity sim_payment
```

The other owning test binaries were built together with `cargo test --locked
-p chio-core-types -p chio-kernel -p chio-store-sqlite -p chio-control-plane --lib
--test dpop --no-run`. The evidence-directory script `final-test-selection.py`
records their exact paths, filters and exit status. Consumer compilation uses
`cargo check --locked --tests -p chio-api-protect -p chio-acp-edge -p chio-credit
-p chio-settle -p chio-siem -p chio-cli`. Strict lint uses `cargo clippy --locked
-p chio-core-types -p chio-kernel -p chio-store-sqlite -p chio-control-plane --lib
-- -D warnings`.

## Remaining acceptance

This batch is implemented and locally verified. No hosted, release, native x86_64 or
operational acceptance is claimed. The wider security plan remains partial:
remaining ambient clocks and arithmetic sites, exhaustive signed-reader/tenant
matrix closure, broad module/pool migration, scale evidence and operational
pilots are separate work. This batch does not mark those packets complete.
