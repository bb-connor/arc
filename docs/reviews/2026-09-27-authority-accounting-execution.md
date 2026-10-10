# Authority and accounting execution

Continuation of Packet 3 / Correction 3A from `4713fef1b4` on
`packet/3-retention-accounting`, in `/tmp/arc-security-launch`. One implementer,
no subagents, implementation batched before focused owning checks.

## Changes

- SQLite authority rotation acquires an IMMEDIATE transaction before reading the
  generation. The checked next generation, signing seed, public head and trust
  history commit together. Concurrent handles allocate distinct generations;
  failed history writes retain the previous seed and identity.
- Snapshot import validates keys and integer domains within its write
  transaction. A malformed later key or failed head update rolls back the entire
  import. Head ordering uses canonical key representations. Snapshots carry verification
  history; the local signing seed stays local. A mismatched public head refuses
  signing. Bootstrap and multi-read status/snapshot/seed inspection also use one
  transaction, and successful writes update caches only after commit.
- Leader fencing serializes read/check/write with an IMMEDIATE transaction.
  Competing leaders at the same term cannot both succeed. Generation and term
  writes reject values outside SQLite's signed integer range. Negative stored
  authority, trust-history, anchor and fence metadata reject instead of becoming
  zero; public and trusted-key generations must be positive.
- Local, governed and SQLite capability issuers share exact checked expiry.
  Unrepresentable lifetimes reject before signing, including aggregate-family
  issuance. Response validation rejects the same invalid requested lifetime.
  Only the documented upper comparison bounds for clock skew still saturate.
- Budget holder increments and sibling totals use checked arithmetic.
  `BudgetSplit::current_total_child_bps` now returns a `Result`; all consumers use
  the new API. Holder exhaustion grants no extra lease and preserves existing
  shares. New-child admission refuses an overflowing publicly constructed split.
  Re-admission retains its existing lookup cost. Zero-holder verifier-only edge
  cleanup deliberately retains its clamp and has an explanatory comment.
- Import floors validate attributed event sequences as positive SQLite integers
  before subtracting one or writing any origin. Previously an out-of-range
  sequence could become a representable floor. Empty origins also reject.
  Persisted negative floors and nonpositive provenance indices now have explicit
  refusal paths; valid floors remain exact, monotonic and persistent.

## Owning regressions

New cases exercise real SQLite handles and transactions: eight simultaneous
rotations, eight same-term leaders, SQL trigger failures during rotation and
snapshot head publication, late malformed snapshot rows, maximum generation,
negative stored metadata and restart after failure. Snapshot recovery verifies
both public trust history and unchanged private custody.

Budget cases exercise maximum holder depth and an overflowing public sibling
map, then require unchanged ownership on refusal. The latter intentionally
constructs invalid public state; it is not evidence of a remote path through the
validated registry. Existing admission and reservation properties remain in the
owning checks.

Expiry cases cover every local/governed minting entry point, zero calls to the
governed signing backend on failure, a valid signed request and exact numeric
boundaries. SQLite has its own public issuance rejection case. Replication cases
cover mixed valid/invalid batches without partial floor advancement, exact
maximum floor and reopen, empty origins, and corrupt local provenance under an
otherwise valid signed and authenticated snapshot. The corruption fixture
deliberately bypasses SQLite CHECK constraints to test defensive decoding.

## Arithmetic inventory

The [inventory](2026-09-27-arithmetic-inventory.tsv) retains all 638 original
matching source lines and their `4c35ce7867` base locations. This batch classifies
15 more: 12 repaired sites, two intentional clock-skew bounds and one intentional
verifier-only cleanup clamp. The cumulative checkpoint is **60 classified,
including 19 repaired sites; 578 pending**. Checked integer conversions,
transaction repairs and the formerly unchecked iterator sum extend beyond that
original `saturating_` / `wrapping_` search inventory.

## Verification evidence

Local profile: Linux aarch64, `umask 022`, locked dependencies, one Cargo owner,
`CARGO_INCREMENTAL=0`, `RUST_TEST_THREADS=1`,
`CHIO_CHECKOUT_ROOT=/tmp/arc-security-launch`, existing lane-d target directory.

- `/tmp/chio-accounting-authority-focused.log`: initial implementation run,
  23 kernel-core and 24 SQLite tests passed, zero failed/ignored. This preceded
  the shared expiry helper and final rollback/provenance cases.
- `/tmp/chio-accounting-authority-hygiene.log`: retained source-gate failure;
  adding a test-module declaration exceeded an existing file cap by three lines.
  The module now belongs to its parent, within existing limits. The cap was not raised.
- `/tmp/chio-accounting-authority-kernel-final.log`: 45 selected kernel library
  tests and all three reservation-ledger tests passed, zero failed/ignored.
  The two properties use the existing default case count and seed `20260927`.
  Build: 2m 54s. Test execution: 1.53s and 1.18s.
- `/tmp/chio-accounting-authority-store-final.log`: 23 kernel-core and 21 SQLite
  tests passed, zero failed/ignored, including all final rollback and provenance
  cases. Build: 2m 14s. Test execution: 0.13s and 2.66s.
- Final touched-file formatting, `git diff --check`, Rust file hygiene and weak
  negative-assertion checks passed. The assertion baseline remains 1287; no
  baseline or file-size limit was relaxed. All 638 inventory source locations
  were checked against their actual base-commit lines.

The final owning runs cover **92 distinct selected tests**, including **17 new
regressions**. With the profile above, their Cargo commands were:

```sh
PROPTEST_RNG_SEED=20260927 cargo test --locked -j 2 -p chio-kernel \
  --lib --test property_reservation_ledger -- authority:: \
  admitted_child_shares_remain_bounded_and_release_exactly_once \
  mixed_store_reservation_sequences_preserve_the_journal_law \
  omitted_release_is_detected_by_terminal_history_replay
cargo test --locked -j 2 -p chio-kernel-core -p chio-store-sqlite --lib -- \
  budget_split authority::tests:: authority::transaction_tests:: \
  import_boundaries elected_leader_provenance anchor_provenance
```

The unchanged original retention property was not repeated. The historical
retention stall, remaining arithmetic sites, original million-entry campaigns
and Packet 2 privileged x86_64 qualification remain open. This is local
implementation evidence, with no hosted or release qualification claim.
