# Independent checkpoint-publication repair review

Verdict: the two commits close the demonstrated publish-before-root race and preserve bounded staging, retry, and lease behavior. A distinct residual P1 in checkpoint target selection remains: an unsigned checkpoint end column can hide an existing covering root and route its rows through signature-only tail publication. Overall checkpoint-coverage acceptance is therefore incomplete.

Reviewed immutable base: `0d919c3e582afd2bf47d862ccf412c9c51d9589a`.
Reviewed chain: `df64ff46911b1f28cea23a18aea26947ac8a7f88 -> 0c6ce34250f4a5d13562c1e64e1c566a8c24191c`.
Reviewed head tree: `1901640fb6bbd03c8de2e5396db2a656dbfd5c12`.
Worktree: `/home/connor/lanes/claude-v25-checkpoint-publication`. Dirty lineage/capacity follow-ups were excluded; source reads used the exact committed blobs. Contract: Root's revised design section 5.3 at `538791652b`. No Cargo, builds, owner source edits, mailbox/ledger edits, or subagents were used. A small in-memory SQLite evaluation checked the residual query predicate; no Chio service runtime reproduction was run. `git diff --check` passed for the immutable range.

## Demonstrated race repair

`Published::stage` writes pending leaves through the existing quota/custody/SQL-budget hold without advancing E, generation, or receipt/count rows. `extend_cycle` authenticates checkpoint signature/projection/predecessor/chain membership, stages only leaves, and verifies the complete root, contiguous range, exact size, and signer before publishing new rows. Previously authenticated rows remain available subject to the unchanged freshness rules.

Publication re-copies and authenticates each bounded source step, checks its source projection, and compares the resulting pending leaves exactly with the owned leaves whose root was verified. A signed substitution after root verification cannot become a new owned row. Later changes after copying still cannot affect the owned projection; payload fetch retains the existing leaf and lease checks.

On retry, the next cycle reads served E, preserves pending leaves at/below it, discards only staged leaves above it, and resumes publication at E+1. A verified partial prefix remains safe; rows/counts already committed are not inserted again. Checkpoint acceptance updates its record, owned head, frontier, and metadata under one hold; settled-leaf cleanup remains bounded. Staging and published changes use the same page quota and typed capacity outcome. Cancellation and SQL-budget guards remain in those holds, and the staged-shutdown control terminates as Stopped. No new quota or lease bypass was found in these paths.

The second commit changes only the recertification test's retry backoff from 20 ms to 3 s so its Invalid outcome remains observable. It does not change production recovery behavior or weaken the asserted integrity outcome.

The six new controls cover original early exposure, old-version availability, post-root substitution, interrupted staging/publication recovery, staged cancellation, and typed staging capacity refusal. The transient publication control interrupts after one complete verified step; source inspection also confirms retry after a failure between smaller row commit holds resumes from actual served E. The quota control injects Capacity, rather than exhausting the staging medium physically. No new count-mirror test is required solely because the before-root test does not assert total_count directly: staging contains no receipt/count mutations, and C20 remains a separate sequence acceptance boundary.

## P1 CHECKPOINT-TARGET-SHADOW: authenticate checkpoint coverage before classifying tail

Location: `crates/platform/chio-store-sqlite/src/receipt_query_snapshot/walk.rs:1123-1127`, consumed by `receipt_query_snapshot/extend.rs:60` and `:90-100`; recertification inherits the bound at `receipt_query_snapshot/service.rs:1365-1374`.

The observation selects `MAX(checkpoint_seq)` only where the unsigned persisted `batch_end_seq <= head`. It has not authenticated that column. A row whose end column is changed above head is omitted before the signature/projection verifier can reject it. The repaired extension therefore can misclassify its covered receipts as an uncheckpointed tail.

Concrete scenario under the existing SQL-tamper boundary:

1. Ready serves E=8 under checkpoint 2. Append and flush checkpoint 3 covering claim entries 9..12.
2. Before extension ingests that batch, replace one claim and its matching source row with another validly signed receipt, as in the existing substitute fixture.
3. Disable triggers on the tamper connection and change only checkpoint 3's unsigned `batch_end_seq` from 12 to 13. Its signed statement and projection rows still end at 12; the claim head remains 12.
4. `observe` returns checkpoint 2, so the checkpoint loop does not inspect checkpoint 3. The tail loop publishes entries 9..12 on signatures alone, including the substitute and its count contribution. Fetch matches the newly owned substitute leaf, and the writer poison flag need not change without another writer verification.
5. Later recertification can also use checkpoint 2 and authenticate those entries as tail. The excluded column/body mismatch need not be detected while it remains hidden.

This predicate/order is source-confirmed. Running the exact selection query over a minimal in-memory SQLite table returned checkpoint 3 before the end-column edit and checkpoint 2 afterwards, while the stored signed-statement marker remained end=12. Existing `parse_persisted_checkpoint_row` at `checkpoint_validate.rs:318-322` would refuse the column/body mismatch if the row reached it. The actual Chio-service regression remains outstanding.

This flaw predates these two commits and was missed in the initial review. It does not invalidate their genuine closure of the original staging interval. It is a residual of the same A1/A10 covering-root requirement and revised section 5.3: unsigned metadata must not grant permission to treat a covering checkpoint as absent. Required repair: capture the observed checkpoint sequence bound independently of unauthenticated coverage columns, then enforce authenticated body/projection coverage while retaining fixed-target bounded work. Cover the above shadowing scenario with the actual service, require no substituted row/count publication and Invalid, and preserve the checkpoint-appended-during-build control. No broad per-request history authentication is proposed.

## Evidence and limits

Producer evidence directory: `/home/connor/lanes/claude-pr1160-evidence/vfix/v25/checkpoint-publication/`.

- `red.log` (SHA-256 `c9ba659afd670d1155552665dbb5f55677bf184cc1e21ef6f5351dae80fea4b8`) contains two actual assertion failures, exit 101. Original point-read returns the signed substitute before settlement; the healthy batch is also visible before its root. Those failures correspond to the original publication schedule, not compile/setup errors. The log alone is not a frozen original source manifest.
- `green.log` (SHA-256 `f6f6ef788d819427fda3494889d56002f59f9817b4eac26910657a0fdf1d4f19`) reports 109 passed, zero failed, five explicit ignores, test execution 71.37 s, exit 0. All six new controls pass. It does not cover CHECKPOINT-TARGET-SHADOW.
- `clippy.log` (SHA-256 `5c1a475cd3ca5522cf3712681cd1d85db0d6d006dd89bef17d7c841d4d2c07f6`) terminates rc=0. The four supplied static gate logs also terminate rc=0. These are inspected producer results; this reviewer ran no owning/strict suites.
- `capacity-holds-release.log` (SHA-256 `7208563fbb24e77dba06973f9c9ebf6fefbcd830047d762b0413fe123b331aab`) records the full case launch against `0c6ce34250`, then SSH no-route failure and rc=255. It has no test verdict and does not establish the full 150k changed-extension capacity before/after pair. `large-checkpoint-div50.log` has a running-test marker without a terminal result; it is not capacity acceptance.

Initial build/authentication implementation files are unchanged by this chain, as the retained equivalence report notes. That preserves the bounded meaning of earlier 1M signed-build evidence; it does not qualify the changed extension's capacity, throughput, or rotation behavior. Lineage P2/C20 follow-ups are outside this review and remain pending exact handoff.

No hosted, merge, release, native-platform, or activation readiness is claimed.

## Exact reviewed source hashes

SHA-256 from committed blobs at `0c6ce34250f4a5d13562c1e64e1c566a8c24191c`:

| File | SHA-256 |
|---|---|
| `receipt_query_snapshot/extend.rs` | `b161e9c2e022fa45999507b792dfa00676b7d21a44f3caa3e3ee9f6fcad6c861` |
| `receipt_query_snapshot/service.rs` | `1309c2c708ef0f5319b262354f1cd7b0645837ab99a50a889762920169985400` |
| `receipt_query_snapshot/walk.rs` | `47e9bb770b5efa357786f65c0040de6d418322ca847619a65a0721967948dbf3` |
| `receipt_query_snapshot/tests/publication.rs` | `6cf47ba0b112168fd9c058fb892dc6cc3e92fa2201c3e4236d83c0b4f808954e` |
| `receipt_query_snapshot/tests/service.rs` | `cadcd3006d69974e80fda63eaee6b9e5d29b70492b2a908f9f5d4b3d7b413a44` |

File labels above are relative to `crates/platform/chio-store-sqlite/src/`.
