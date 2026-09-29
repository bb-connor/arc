# Kernel and SQLite correctness closure

Source: `packet/3-retention-accounting` in `/tmp/arc-security-launch`, based on
`f16d4e781c`. Implements the [batch plan](../superpowers/plans/2026-09-28-kernel-admission-reader-closure.md).
The bounded batch is implemented and locally verified. This record makes no hosted, merge, release
or operational acceptance claim. Preexisting `output/` is untouched.

## Implementation

- Reviewed all 73 baseline decoder files (36 kernel, 37 SQLite). Original-byte
  readers now use bounded constrained JSON; retained typed conversions and
  closed checkpoint/preflight owners have explicit semantic dispositions in
  `trust-boundary-inventory.json`. The gate registers these owners permanently
  and rejects returning them to an unclassified baseline. Other crates still
  contain 374 baseline files.
- Retained admission requests require schema v4 and an explicit authority
  profile. Producers, recovery, broker capture and fixtures agree. Old schema
  acceptance and optional-profile branches are removed. Inner v1-v3 hash
  domains remain parts of the current cryptographic construction.
- Terminal authorization consumption now retains its signed source receipt.
  The sealed proof's production constructor verifies source and consumer
  signatures, exact request/capability/policy/tool/tenant/parameter bindings,
  source time, outcome identity/version and completed operation attachment.
  Remote projection verification and SQLite readback rerun those checks.
  Deserialization constructs only a private DTO, never the verified proof.
- Local parser failures retain structured causes with redacted Display/Debug.
  Fixed-code external port errors and string-only adapters keep their existing
  redacted projection contract. Parser success never grants authority.
- Dispositioned the 264 historical arithmetic sites. Repairs reject overflowing
  stream totals, receipt counters, lineage depths, execution counts, retention
  durations/cutoffs and impossible analytics totals. Cost ratios use an exact
  u128 denominator. Bounded metrics, capacity hints and fixture arithmetic have
  explicit reasons instead of blanket saturation removal.
- Migrated 22 production ambient clock reads to the shared fallible clock or,
  for child request IDs, UUID entropy. All 90 remaining scoped occurrences are
  fixtures. Session creation, rotation, close and request tracking use the
  injected kernel clock and a shared fence across clones. SQL transactions
  propagate clock refusal; writer health preserves actual commit accounting
  and closes future admission on clock failure.
- Extracted receipt qualification tests, security admission errors, Finding
  validation helpers and fiscal/store boundary helpers into normal modules.
  Existing file-size caps remain unchanged.

## Runtime verification

Logs are retained under `/tmp/chio-kernel-sqlite-20260928/`, including earlier
failed compiler, lint and fixture runs. Commands run from this checkout with
`CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=6 CHIO_CHECKOUT_ROOT=/tmp/arc-security-launch`.
No workspace-wide or hosted campaign is part of this batch.

| Check | Terminal evidence |
| --- | --- |
| Kernel focused owner tests | `kernel-focused-final.log`: 536 passed, 0 failed, 8.23 seconds, from a fixed copy of the restored test executable. |
| SQLite reader families | `sqlite-focused-01.log`: 419 passed, 1 failed, 1 ignored. The old retained-request fixture was repaired; the current profile/owner-rotation case passes in `mutations-04/baseline-authorization-retention.log`. |
| SQLite receipt/retention families | `sqlite-receipt-02.log`: 167 passed, 2 failed. Both overflowing day-count fixtures now use a finite horizon; both repairs and a new production overflow refusal test pass in `mutations-04/baseline-authorization-retention.log`. The existing long retention property finished successfully; it was not rerun. |
| SQLite admission families | `sqlite-admission-01.log`: 493 passed, 5 failed. Two repairs pass in `mutations-04/baseline-authorization-retention.log`; all other failing selectors pass in `sqlite-admission-recheck-01.log` (3 passed, 0 failed). The whole 18.5-minute cohort was not repeated. |
| Authorization and repaired boundaries | `mutations-04/baseline-authorization-retention.log`: 8 passed, 0 failed, 10.18 seconds. Includes both authorization-consumption tests. |
| Direct consumers | `consumers-02.log`: `cargo check -p chio-control-plane -p chio-secret-broker -p chio-cli --all-targets` passed. This includes the HTTP approval error mappings. |
| Source-gate calibration | `trust-calibration-01.log`: 15 passed, including unregistering a reviewed owner and reverting its semantic disposition. |

These rows overlap and must not be added into a distinct-test total. Earlier
cohorts with failures remain failed runs; focused repairs have their own terminal
evidence. Restored-source mutation checks and final source gates passed as recorded below.

The kernel owner filters are `admission_operation retained authority_profile
runtime_replay recovery release delivery return_context native_ session
receipt_analytics stream_total_overflow deterministic_receipt_counter
provider_verdict transport checkpoint`. SQLite checks used the existing reader,
admission and receipt families, then only the failing selectors and the new
boundary tests. Test targets were built together with
`cargo test -p chio-kernel -p chio-store-sqlite --lib --no-run`.

The authorization fixture uses a local-system coordinator and genuine signed
source/consumer receipts. It exercises production envelope verification, SQLite
commit, exact replay and reopen, preserving exact retained projection bytes.
Eight negative variants rebuild the records, manifest and terminal digest and
re-sign the complete envelope: foreign tenant, request, consumer receipt,
parameter hash, outcome ID, outcome version, validly signed foreign source tenant
and source receipt ID. Another claimant, duplicate source consumption and altered
replay reject without a partial terminal commit. Immutable-trigger refusal and
corrupt mirrored-tenant readback are checked independently.

## Final gates

All commands below exited 0. Logs share the prefix
`/tmp/chio-kernel-sqlite-20260928/`.

| Command | Log and scope |
| --- | --- |
| `cargo clippy -p chio-core-types -p chio-kernel -p chio-store-sqlite --lib -- -D warnings` | `clippy-final-02.log`; strict changed-library checks, 29.97 seconds. |
| `cargo fmt --all -- --check` | `format-final.log`; workspace formatter traversal. |
| Explicit `rustfmt --edition 2021 --config skip_children=true --check` on changed includes and included adapter fixtures | `format-fragments-final.log`; eight files outside or alongside normal formatter traversal. The final clock helper was subsequently rustfmt formatted. |
| `python3 scripts/check-trust-boundaries.py` | `trust-final.log`; 240 constructors, 85 tenant tables, 170 explicit SQL principal contracts. |
| `python3 scripts/tests/check-trust-boundaries.test.py` | `trust-calibration-final.log`; 15 passed. |
| `python3 scripts/check-accounting-arithmetic.py` | `arithmetic-final.log`; zero unchecked sites in that gate's accounting scope. This does not close the 122 pending broader inventory entries. |
| `python3 scripts/check-security-clocks.py` | `clocks-final.log`; 157 remaining occurrences, no additions. |
| `python3 scripts/check-negative-assertions.py` | `negative-final.log`; 1,264 assertions at 1,181 baseline sites, no additions. |
| `python3 scripts/check-rust-file-hygiene.py` | `hygiene-final-03.log`; passes without increasing caps. Earlier final attempts exposed a one-line module overflow; the shared clock read and existing integer conversion are now expressed through a local seconds value. |

All 85 SQLite tables now map to exercised families, closing the explicit
terminal authorization-consumption gap. This mapping does not prove exhaustive
independent coverage of every SQL statement. The retained-request parser and
source proof remain sealed behind their production verification contracts.

## Runtime bypass calibration

The two production bypasses were batched into one temporary build. All baseline
checks passed first. Replacing the retained-request constrained canonical reader
with raw `serde_json::from_slice` caused
`retained_current_profile_rejects_downgrades_duplicates_and_aliases` to fail at
runtime (0 passed, 1 failed, exit 101). Removing the consumption tenant check
from `VerifiedAuthorizationReceiptConsumption::from_signed_source` caused
`signed_authorization_consumption_rejects_substitutions_and_reopens_exactly` to
fail on foreign-tenant variant 0 (0 passed, 1 failed, exit 101).

These are runtime failures from compiled production bypasses, not compile errors
or source-gate simulations. The mutation driver's unconditional cleanup restored
both files byte for byte; `mutations-04/runtime-mutations.json` records results
and hashes. The restored build passed, followed by the parser regression (1
passed, 0 failed) and both authorization cases (2 passed, 0 failed). The broader
restored kernel selection then passed 536 tests. Logs are `restored-final-build`,
`restored-parser` and `restored-authorization` under `mutations-04/`.

| Restored production file | SHA-256 |
| --- | --- |
| `admission_operation/retained_request.rs` | `c522b3ea2076c1103c9f3b7232b63dbeb9d4cf629d790effed3a6b81a47b71f9` |
| `admission_operation/projection/authorization.rs` | `f9f51a8e9aa9ca814833a1e30477ccbc33f09d824e62b195efd23c8ff8ebfaf7` |

## Defects and verification corrections

- The initial optional-profile cleanup accidentally removed native egress
  request/context checks with the obsolete guard. The egress and portable-command
  regressions caught this. The complete tenant/principal/lineage/session/isolation/
  flow-generation/request/action binding was restored, its exact refusal is now
  asserted, and every match of that removal operation was audited for swallowed
  code. No other removed block had the same problem.
- Signed authorization reopen exposed a missing dispatch-state reconstruction
  when checking the historical predecessor. Readback now restores Finalizing
  operation and dispatch states, decrements the version with checked arithmetic,
  and removes terminal replay before reconstructing and verifying the source.
  This predecessor is used only for historical evidence checks.
- The first corruption fixture exercised external-write detection instead of
  the sidecar binding. The corrected negative fixture uses the owner's connection
  and restores the exact immutable trigger before calling public readback. It
  requires the specific inconsistent-authorization-projection error.
- Obsolete retained-schema and parser-message expectations, full-envelope fixture
  signing/binding mistakes, and overflowing retention fixture durations were
  corrected. Failed attempts remain in their original logs.
- A child-process crash test ran while its executable was replaced by another
  build, causing `current_exe()` to name a deleted file and spawn to fail with
  ENOENT. Its targeted rerun uses a fixed executable copy and passes alongside
  the acquisition/commit fault and portable-command cases (3 passed in 72.93
  seconds). This environmental failure is not counted as runtime success.

## Remaining scope

This closes one kernel/SQLite batch. Ordinary local completion still supplies
no authorization-consumption participant; the implemented and exercised path is
the signed remote terminal projection. The table has an administrative kernel
coordinator contract, not a tenant point-read API. No claim is made that every
participant combination or every SQL statement has independent runtime proof.

Other decoder/arithmetic/clock owners, broader error cleanup, retention issue
#1045 and temporal-model work, larger module/helper cuts, performance/scale,
native execution, supply-chain audits, hosted qualification, release delivery
and operational acceptance remain separate work. See the
[remaining-work queue](2026-09-28-remaining-security-work.md).
