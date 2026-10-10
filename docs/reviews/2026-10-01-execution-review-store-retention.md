# Execution review: SQLite store recovery, analytics, measurement and retention, October 1, 2026

Scope: the twenty commits of this slice, from `79d2e1b9ea` and `57816c2279` (connection
lock-poison recovery), `ba7282e18c` and `dc018fab21` (authorization benchmarks),
`e191a755c3`, `8b29887c25`, `3c3556896c`, `0ad3c88bf0`, `28013e110f` and `414aaea0b1`
(receipt analytics), `f3eb124962`, `b9d6af6fb0` and `d841931148` (retention diagnostics),
`4713fef1b4` and `995b9f1c74` (retention, report accounting, writer accounting and typed
checkpoint predecessors), `8aa3cf1785` and `7177be5092` (statement caching and hold reuse),
to `54d213eccc`, `0daaf44a59` and `1d4f3b4ad3` (revocation progress obligations and durable
lifecycle traces). Plans: umbrella addendum Packets 9.1 to 9.5, 10.1, 10.4 and correction
3A in `docs/superpowers/plans/2026-09-26-security-engineering-excellence.md`;
`docs/superpowers/plans/2026-09-29-sqlite-performance-retention.md`;
`docs/superpowers/plans/2026-09-29-retention-lifecycle-assurance.md`. Execution records:
`docs/reviews/2026-09-27-retention-accounting-execution.md`,
`docs/reviews/2026-09-27-writer-checkpoint-execution.md`,
`docs/reviews/2026-09-29-sqlite-performance-retention-execution.md`,
`docs/reviews/2026-09-29-retention-lifecycle-assurance-execution.md`,
`docs/security/store-measurements-2026-09-26.md`,
`docs/security/retention-diagnostic-2026-09-26.md`. Base `07e963e8f5`, tip `a2630c20a1`.
Method: diffs read commit by commit and the resulting code read at the tip; claims
checked against source, committed logs and artifacts; one High finding reproduced at
runtime in a private scratch worktree (since removed) with the tree's own v6 downgrade
fixture. Paths below are relative to `crates/platform/chio-store-sqlite/src/` unless they
start at the repository root.

**Judgment: The core of this slice is sound and better than the plans required: the
lock-poison fence is correct, structurally unbypassable and tested at every phase, the
analytics totals are exact full-width unsigned sums with a named refusal, the writer
accounting is exact across crash and unwind, and the retention and formal records are
unusually honest about what they did not establish. The most important defect is that
schema 7 strands any receipt store that rotated evidence into an archive before the
upgrade: archive trust reads the new predecessor column from an archive nothing
migrated, serving closes, and neither in-band repair path reopens it (SR1). The second is
a measurement miss inside Packet 9 itself: the benchmarks it built show the
capability-suspension guard costing about 62 ms per tool call at 2,000 suspension sets,
a per-call scan over every set the tenant has ever held, and the packet answered it with
statement caching (SR2). The analytics integrity rework costs 3.5x to 15x per report and
is justified by a claim that is false, while leaving the selection columns unverified
(SR3). The work was worth doing; the analytics integrity cost and the volume of committed
diagnostic and solver artifacts were not proportionate to what they bought.**

## Plan conformance

| Plan item | Recorded status | Verified status | Evidence |
|---|---|---|---|
| 10.1 do not recover blindly | done | Done | `store_connection.rs:98-110`: a poisoned guard is returned only through `recover`; the inner `Mutex` is private, so no store can bypass it |
| 10.1 one shared helper: `is_autocommit`, explicit `ROLLBACK`, consistency check, named fence | done | Done | `store_connection.rs:166-180`; the fence is a `OnceLock<ConnectionFenced>` checked before and after acquisition (`:99-109`) |
| 10.1 per-store classification at the call sites, all 18 mutex stores | done | Done, two sites unannotated | No `Mutex<Connection>` remains in the crate. Fifteen stores share the anchored authority connection (`serving_owner.rs:840`); standalone shapes carry a reason comment except `security_state.rs:252` and `admission_operation_store/part_01.inc:176` |
| 10.1 four cutpoints per anchored store; blind recovery must fail | done | Done | `serving_owner/connection_recovery.rs` drives all four phases through a real revocation write; 91 `#[test]` cases across 20 modules (counted); `store_connection.rs:493-524` fails under blind recovery by construction (`expect_err`) |
| 10.1 coupling to Packet 0.2 recorded; pool decision deferred to 9.4 | done | Done | Release profile has `panic = "unwind"` and `overflow-checks = true` (root `Cargo.toml`), so poisoning is real in production and the fence is load-bearing |
| 10.1 do not reach for `parking_lot` | open (prohibition) | Honored | No `parking_lot` in `chio-store-sqlite` |
| 9.1 composite, charge/release and denial-path benchmarks against a populated store | done | Done | `benches/store_authorization_path.rs:153-205, 496-544`; `benches/support/authorization_composite.rs:39-100` runs under a provisioned serving owner with an admission binding; defaults 20,000 rows and 2,000 suspension sets (`:41-68`); receipt append gains a 20,000-row variant |
| 9.1 baselines recorded; append campaign does not prove authorization | done | Done, but the baseline's largest number was not ranked | `docs/security/store-measurements-2026-09-26.md` composition table (SR2) |
| 9.2 aggregate the typed `cost_charged_be`, checked accumulation, named overflow | done | Done; the named error is a string | `receipt_store/reports/analytics.rs:50-112, 140` (SR7) |
| 9.2 same for `attempted_cost` with a typed column | done | Done, with live migration | `receipt_store/support/claim_log/schema.rs:20-24, 340-411`; `receipt_store/append.rs:63` |
| 9.2 replace the optional-filter shape; `EXPLAIN QUERY PLAN` test | done | Done in analytics, weaker than stated | `receipt_store/reports/analytics.rs:234-299`; the plan check matches only the literal text `SCAN r` (`receipt_store/reports/analytics_tests.rs:909-911`) (SR8); cost attribution still uses the old shape (SR4) |
| 9.2 bound the unfiltered case | done after rewording | Done for analytics only | Base text "required time window or a rollup table" was replaced in `0fbe22e0f0` by a description of the 250,000-match ceiling and instruction budget, then ticked (SR9) |
| 9.2 edge fixtures at 2^63 - 1, 2^63, 2^64 - 1 and an overflowing sum | done | Done for both metrics | `receipt_store/reports/analytics_tests.rs:660-781`; `receipt_store/reports/analytics_tests/attempted_cost.rs:15-64` |
| 9.3 `prepare_cached` on measured per-operation reads, explicit capacity | done | Done; mostly on the legacy budget path | 17 sites in 16 functions (counted); capacity 64 set at `budget_store/store.rs:63`, `security_state.rs:240`, `serving_owner.rs:1485`; the production composite hold statements were not converted (SR12) |
| 9.4 connection strategy | not in candidate | Not started, correctly | No pool migration in range |
| 9.5 fold the duplicate `ensure_open_hold` read | done | Done where the plan pointed | `budget_store/trait_impl.rs:788, 893, 1002, 1100, 1237, 1348`; same `IMMEDIATE` transaction; the path is refused under a serving owner (SR12) |
| 10.4 bind the typed predecessor; triggers copy the column | done | Done | `receipt_store/support/checkpoint_validate.rs:1360-1377`; `receipt_store/support/checkpoint_schema.rs:181-247` |
| 10.4 `CHECK` constraints on checkpoint and chain-link columns | done | Done | `receipt_store/support/checkpoint_schema.rs:114, 130, 144, 163`; test `receipt_store/tests/writer_checkpoint_boundaries.rs:246-281` |
| 10.4 append-only trigger | done after rewording | Done as reworded | Base text "Leave ... exactly as it is" rewritten by `995b9f1c74`; sequence, genesis and continuity rules intact (`receipt_store/support/checkpoint_validate.rs:26-64`) |
| 10.4 v7 verifies during upgrade; typed column checked on reads including archives | done | Partial | Live path done; archives are never migrated by the upgrade and fail archive trust (SR1); archive co-copy omits the column (SR6) |
| 3A retain inventory; record classifications | done | Done | 638 anchors match base `4c35ce7867`; plan counts (516/132/122) are stale against the TSV at tip (553/133/85) |
| 3A classify every site; convert or annotate `saturating_sub` | open | Open, as recorded | Touched report and replication sites are annotated or checked; `receipt_store/evidence_retention.rs:530` is not |
| Performance plan Task 1 (five boxes) | done | Done | Red log `docs/reviews/artifacts/2026-09-29-sqlite-performance-retention/cache-red.log` shows 4 versus 1 compilations and 2 versus 1 hold reads |
| Performance plan Task 2: history, 256-case diagnostic, completion correction | done | Done as recorded | `retention-original-scale-result.json`: 242 completed cases, overall timeout at 900.8 s, exit -15; 242 `phase=complete` lines in the log; `b9d6af6fb0` strengthens the property |
| Performance plan Task 2: regression for a demonstrated cause; full 256-case gate | open | Open, correctly | No cause demonstrated; no production receipt change |
| Assurance plan Task 1 (three boxes) | done | Done | `chio-store-sqlite/tests/receipt_retention_liveness/sync_diagnostics.rs:25-75`: the observation is inserted and removed under the mutex, never held across the delegated sync; snapshots clone out before formatting |
| Assurance plan Task 2 (three boxes) | done | Done | Metadata-only `debug!` events after commit with the guard dropped (`security_state/lifecycle_observation.rs`, `security_state/dispatch.rs:436`); CI regenerates the trace and runs 24 corruption controls (`.github/workflows/apalache-safety.yml`, response_lifecycle job) |
| Assurance plan Task 3 (three boxes) | done | Done, honestly scoped | `scripts/formal/revocation_progress.py`: seven UNSAT obligations and four SAT mutants in the committed summary; source pins match `formal/tla/*.tla` at tip; scheduled lane only |

## SR1. High: a store that rotated evidence into an archive before schema 7 stops serving after the upgrade, and no in-band repair reopens it

Schema 7 (`995b9f1c74`) adds `previous_checkpoint_sha256` to `kernel_checkpoints`. The
live upgrade migrates only the live database. Archive trust then reads that column from
the archive: `load_persisted_checkpoint_row`
(`receipt_store/support/checkpoint_validate.rs:206-232`) selects it, and on an archive
written before v7 the statement fails to prepare. `archive_connection_backs_prefix` maps
that error to `Ok(false)` (`:648`), so `trusted_retention_watermark` (`:537-555`) returns 0
and seeding falls back to full chain verification from the live claim log, whose archived
prefix retention already deleted. Verification fails and the writer's serving gate
closes. The only automatic archive migrator is rotation (`create_archive_schema` after
`ATTACH`, `receipt_store/evidence_retention.rs:903-906`), and rotation refuses while the
head is unverified. `retention_repair` returns `Ok(0)` because it finds no orphaned rows
(`receipt_store/evidence_retention.rs:1737-1739`). The advertised `chio receipt audit
--repair` calls `reseed_verified_head`
(`crates/products/chio-cli/src/cli/trust/receipt/health.rs:242`), which runs the same
archive trust and fails the same way.

Failure scenario, reproduced: seed a checkpointed chain, archive its prefix, downgrade
both live and archive with the tree's own `downgrade_checkpoint_column_to_v6` helper
(`receipt_store/tests/writer_checkpoint_boundaries.rs:235-244`), reopen live with the new
binary. Every append returns `Conflict("receipt store verified head is unavailable
(conflict: claim receipt log has a gap in checkpoint signer binding 1..=1); run chio
receipt audit --repair")`, `retention_repair` returns `Ok(0)` with serving still closed,
and rotation refuses on the poisoned head. The control, with only the live database
downgraded, serves normally. Opening the archive itself writable with the new binary is
the only thing that restores service, and nothing documents that step. Integrity is never
lost (it fails closed), but the store records no new receipts until an operator finds an
undocumented out-of-band step, which is an outage on every upgraded deployment that used
retention.

The existing regression does not catch this because it downgrades only the archive,
migrates it by calling `create_archive_schema` directly, and never reopens the live store
(`receipt_store/tests/writer_checkpoint_boundaries.rs:357-392`). Fix: in the live upgrade
transaction, attach each archive the watermark ledger names and run
`create_archive_schema`, which already verifies signatures; add the live-plus-archive v6
upgrade regression. The same gap applies to the v6 `attempted_cost_be` archive migration
only if a reader consults that archive column before rotation; that was not traced.

**Confidence:** Confirmed. Reproduced at runtime against the tip with a control, and the
failure path is a step-by-step source trace.

## SR2. Medium: the capability-suspension guard scans every suspension set the tenant has ever held, under the store mutex, on every tool call, and Packet 9 treated it with statement caching

`SqliteSecurityStateStore::evaluate_capability_suspension`
(`security_state/capability_set_suspension.rs:838-888`) selects every `affected_set_hash`
for the tenant (`:846-867`), calls `load_snapshot` for each (`:870-871`), which reads the
state row and every contribution with its `affected_ids_body`, and binary-searches each
member list (`:872-877`). It backs `CapabilitySetSuspensionGuard::evaluate`
(`crates/security/chio-security-kernel/src/capability_set_suspension.rs:62`), which the
control plane installs as a kernel guard
(`crates/platform/chio-control-plane/src/security.rs:203`), so it runs on every tool call
of a security-enabled kernel. The set count only grows: `persist_state` upserts the state
row (`security_state/capability_set_suspension.rs:455-475`) and nothing deletes it; a lift
deletes only the effect row (`:784-797`), so a lifted set still costs two queries on every
evaluation. The scan holds the security store's single connection mutex (`:842`), so every
security-state operation in the process, for every tenant, waits behind it.

The slice's own measurements show this is the largest authorization cost it measured.
`docs/security/store-measurements-2026-09-26.md` reports 61.6 ms for a suspension denial
read and 62.9 ms for an allow read at 2,000 sets (one capability each, one tenant, as the
fixture builds them in `benches/store_authorization_path.rs:306-403`), against 108.4 ms for
the whole composed store path. Packet 9's contract says "Rank by cost growth ... a scan
that grows with the data is a defect", and standard rule 13.1 says the same. The record
does not name the scan, and Packet 9.3 converted its four statements to `prepare_cached`,
which the September 29 record measures at about -30 percent at 128 sets: a constant factor
on a linear cost. No record or the remaining-work queue mentions it. Failure scenario: a
tenant whose active-response history reaches a few thousand distinct suspended capability
sets makes every tool call pay tens of milliseconds holding the security-state mutex,
which caps the process near 16 suspension evaluations per second across all tenants at
the measured point, and the cost never recedes. Whether an external party can drive set
creation by provoking active responses against many distinct sets was not traced; if it
can, this is an amplification path.

The members projection (`security_state/schema.rs:855-867`) carries `capability_id` and
would support a point lookup, but reading the projection alone lets a deleted member row
hide a suspension. This needs the same authenticated-index design the analytics work
needed: find candidate sets by index, then verify only those against their hashed
contribution bodies. Also prune or skip state rows with no contributions.

**Confidence:** Confirmed. The loop and the never-deleted state rows are in source at the
cited lines; the cost is the slice's own recorded measurement.

## SR3. Medium: the analytics integrity check verifies only the cost columns and only against the key embedded in each receipt, while the records claim it closes external mutation

`414aaea0b1` added `verify_report_costs`
(`receipt_store/reports/analytics/integrity.rs:6-37`), which re-reads every selected
receipt, verifies its signature and compares `cost_currency`, `cost_charged_be` and
`attempted_cost_be` with the signed body. It is the stated reason the unfiltered report went
from 397.51 ms to 4,858.7 ms. Two gaps make the documented guarantee false.

First, the report selects and groups by projection columns the check never compares:
`decision_kind` for decision counts (`receipt_store/reports/analytics.rs:134-139`),
`capability_id`, `tool_server`, `tool_name`, `timestamp` and `subject_key` in the
predicates (`:246-277`) and groupings (`:330-366`). The integrity scan selects through the
same predicates, so a receipt excluded by a tampered filter column is never examined.
Scenario: with the same write access the existing integrity test assumes (drop the guard
triggers, update, restore), set one receipt's `subject_key` from A to B. A report filtered
to A silently undercounts by that receipt's charge; `by_agent` attributes it to B; no error.
The test mutates only the two cost columns (`receipt_store/reports/analytics_tests/integrity.rs:9`).

Second, the signature check is anchored only to the receipt's own `kernel_key`
(`receipt_store/support/receipt_verify.rs:79-83` into
`crates/core/chio-core-types/src/receipt/body.rs:504-506`). The store holds no trusted kernel
key here, and the fixture signs with a fresh `Keypair::generate()`. An attacker with that
same write access rewrites `raw_json`, re-signs with any key, updates the content-derived
`receipt_id` and the cost column, and the report sums the forged amount. What the
signature step adds is detection of naive unsigned edits; the projection comparison alone
already detects the reproduced projection-only drift. So the measurement record's
sentence "Removing signature verification or trusting the projections again would reopen
the reproduced corruption defect" (`docs/security/store-measurements-2026-09-26.md:37-38`)
is false for its first half, and `docs/reference/AGENT_ECONOMY.md:604-606` ("A schema-valid
projection alone cannot authorize a reported amount, including after an external database
mutation") overstates the check. The split of the 12x cost between signature verification
and parsing was never measured.

Fix: either anchor verification to a trusted key or checkpoint commitment and verify every
column the report reads (lineage-derived subjects need their own source), or drop the
signature step, keep parse-and-compare for the cost columns, re-measure, and narrow the
documentation to "amounts of the selected rows; selection and grouping trust stored
projections".

**Confidence:** Confirmed by source trace of the compared columns and the verification
key; the scenario follows the existing test's own mutation method.

## SR4. Medium: the cost attribution report keeps every defect the analytics repair removed, and the slice edited it without bounding it

`receipt_store/reports/cost_attribution.rs:57-90` still uses the `(?N IS NULL OR ...)` filter
shape with a per-row `json_type(r.raw_json, ...)`, collects every matching `raw_json` into a
`Vec` with no row ceiling or SQL work budget, then verifies each signature and walks a
delegation chain of up to 32 queries per receipt (`:105-114`). The count (`:41-55`) and the
data (`:71-90`) come from separate pooled connections, so a concurrent append can make the
reported `matching_receipts` disagree with the totals. Lineage errors are swallowed by
`get_combined_delegation_chain(..).unwrap_or_default()` (`:112-114`), so a storage error or a
cycle is reported as a lineage gap rather than refused (standard 3.2), and
`u64::try_from(value.max(0)).unwrap_or_default()` (`:55`, `:83`) clamps rather than refuses.
Scenario: an unfiltered administrative request against a store with a million receipts
holds a million `raw_json` strings plus a million lineage walks in one call. This predates
the slice, and Packet 9.2 named only the analytics aggregate, but `4713fef1b4` rewrote this
loop for checked sums and left the growth (standard 13.1 to 13.3) in place. Fix: reuse the
analytics snapshot, ceiling and `SqlWorkBudget`, and propagate lineage errors.

**Confidence:** Confirmed by source trace; the growth is structural.

## SR5. Low: the fence's named reason is discarded or relabeled at most store seams

`StoreConnection::lock` returns a typed `ConnectionFenced` carrying a `FenceReason`
(`store_connection.rs:42-58`). Three stores drop it: `security_state.rs:373`,
`enterprise_migration_state.rs:272` and `sealed_decoy_registry.rs:69` all
`map_err(|_| PortError::unavailable())`. The rest flatten it into a string inside a variant
that varies by store: `BudgetStoreError::Invariant` (`budget_store/store.rs:281`),
`RevocationStoreError::Sync` (`revocation_store.rs:149`), `SqliteServingOwnerError::Invalid`
(`serving_owner.rs:876`), and `Unavailable` in the finding, fiscal, frost and channel stores.
A budget caller cannot tell a fenced connection (reopen required) from an accounting
invariant violation, and after the single `tracing::error!` at fencing time
(`store_connection.rs:155-160`) every refusal from the three port-based stores carries no
cause. This is the "named fenced error" the plan asked for, lost at the seam (standard
rules 3.2 and 3.4). Fix: a `Fenced(#[source] ConnectionFenced)` variant per store error, or
the store's unavailable variant with `#[source]`.

**Confidence:** Confirmed; each mapping is one line at the cited location.

## SR6. Low: the archive co-copy identity check omits the new predecessor column, and the record says it includes it

The rotation completeness check compares every `kernel_checkpoints` column except
`previous_checkpoint_sha256` (`receipt_store/evidence_retention.rs:1417-1430`), under a
comment that says "every content column". `docs/reviews/2026-09-27-writer-checkpoint-execution.md:54`
states "Archive co-copy comparison includes the new column". Scenario: an archived row left
by an interrupted rotation, with a tampered typed column, survives `INSERT OR IGNORE`, the
completeness check passes, and the live prefix is deleted; the divergence surfaces later
through archive trust as the SR1 failure mode. The trigger needs archive write access, so
the added risk is small. Fix: add `AND a.previous_checkpoint_sha256 IS m.previous_checkpoint_sha256`.

**Confidence:** Confirmed by reading the SQL.

## SR7. Low: the analytics overflow refusal reaches callers as a string inside a SQLite error

The overflow paths return `rusqlite::Error::UserFunctionError` with a message
(`receipt_store/reports/analytics.rs:87-89, 109-111`), which surfaces as
`ReceiptStoreError::Sqlite`, so callers and the tests
(`receipt_store/reports/analytics_tests/attempted_cost.rs:60-63`) match on text. Cost
attribution and underwriting use `ReadBoundary` for the same condition. Plan 9.2 asked for
"a named error rather than a saturated value"; it is no longer saturated, but it is not
named (standard 3.1, 3.4). Fix: carry a typed overflow variant out of the aggregate.

**Confidence:** Confirmed.

## SR8. Low: several analytics regressions are weaker than the records state

The query-plan test's predicate matches only the exact strings `SCAN r` or
`SCAN chio_tool_receipts` (`receipt_store/reports/analytics_tests.rs:909-911`), so a full
index scan (`SCAN r USING INDEX ...`) passes; the ceiling query and the integrity scan, the
most expensive statement, are never plan-checked. No test mutates `cost_currency` alone, so
deleting the currency comparison at `integrity.rs:26` keeps every test green. The snapshot
test (`analytics_tests.rs:835-867`) builds its own snapshot, so reverting production to
unpinned reads would keep it green. `attempted_cost_still_comes_from_the_signed_body`
(`analytics_tests.rs:496-515`) and the `json_aggregate_*` tests exercise only removed JSON
SQL, and the first one's name contradicts the current design. Fix: match any `SCAN` on the
receipt table without a covering-index qualifier, add a currency-only mutation, drive the
snapshot through the production entry point, and delete the stale tests.

**Confidence:** Confirmed for each by reading the test; "would stay green" is reasoned from
what each test asserts.

## SR9. Low: plan items were rewritten by the commits that ticked them

Three items changed meaning at completion time instead of recording a deviation. Packet 9.2's
"Bound the unfiltered case with a required time window or a rollup table" became a
description of the 250,000-match ceiling and instruction budget in `0fbe22e0f0`, then was
ticked; the substitute is defensible, but an unfiltered report at the ceiling was never
timed, and refusal is a different contract from a rollup. Packet 10.4's "Leave
`kernel_checkpoints_enforce_append_only` exactly as it is" was rewritten and ticked in
`995b9f1c74`; the change is justified (the single-parser rule conflicts with byte
preservation) and the structural rules survive. The sentence authorizing removal of the
pattern-based standing-approval API was added by the same commit that removed it (the
removal itself is correct: only tests, re-exports and docs referenced it, and the API had a
real check-then-update race). Correction 3A's "Record the classification so the next
reviewer does not redo the sweep" became a satisfiable progress item in `4713fef1b4`, and its
counts (516 classified, 132 repaired, 122 pending) no longer match the TSV at tip (553, 133,
85). Fix: restore the original text and record each as an accepted deviation with its
reason.

**Confidence:** Confirmed by `git show 07e963e8f5:docs/superpowers/plans/2026-09-26-security-engineering-excellence.md`
(original lines 633 and 768) against the tip.

## SR10. Low: the human-in-the-loop protocol still documents the removed batch approval routes

`docs/protocols/HUMAN-IN-THE-LOOP-PROTOCOL.md:737-739` lists `POST /approvals/batch`,
`GET /approvals/batch/{id}` and `DELETE /approvals/batch/{id}`, and `:409-410` still shows
`supports_batch`; the only real batch route is `/approvals/batch/respond`
(`crates/platform/chio-http-core/src/routes.rs:61`). `:719` narrates "removed on 2026-09-27",
changelog text inside a protocol document (standard 11). The writer record's claim
(`docs/reviews/2026-09-27-writer-checkpoint-execution.md:67`) that the proposal now
describes the actual boundary is therefore only partly true. Fix: delete the three routes
and the narration.

**Confidence:** Confirmed.

## SR11. Note: a waiter that re-runs recovery on an already fenced connection can log "recovered" and clear the poison

If one thread fences the connection while another is already blocked in
`self.connection.lock()` (`store_connection.rs:102`), the waiter receives the poisoned guard
and calls `recover` again (`:104`). If the second `reestablish` passes (the first failure was
transient, for example an I/O error reading the anchor), it logs `outcome = "recovered"` and
calls `clear_poison` (`:139-145`) before `:106` correctly refuses because the fence is set.
Service stays refused, so this is not fail-open; the log line and the poison flag are
wrong, and the permanent fence was decided by a check that later passed. Fix: return the
fence from `recover` before re-running `reestablish` when one is set.

**Confidence:** Confirmed as a source trace for the log and flag.

## SR12. Note: the folded hold read and most cached budget readers sit on a path the serving authority refuses

Packet 9.5 folded the duplicate `ensure_open_hold` read where the plan pointed, and the
change is correct: the reused hold is read inside the same `IMMEDIATE` transaction, no
trigger on `capability_grant_budgets` touches holds, and `validate_hold_authority` is pure
(`budget_store/store.rs:1514-1551`). But all three functions begin with
`require_standalone_mutation` (`budget_store/trait_impl.rs:751, 965, 1189`), which refuses
under a serving owner (`budget_store/joint_guard.rs:5-24`). The production release of an
admission-bound hold takes the connection lock in `is_structured_hold`
(`budget_store/composite/transitions.rs:81-101`), releases it, then locks again and reads
the hold again in `release_composite_hold`
(`budget_store/composite/transitions/terminal.rs:22-40`), and neither statement was cached.
The September 29 record honestly says the write-pair intervals include zero; the point is
that 9.5's measured value is on the legacy path, and the production path's double lock and
double read remain.

**Confidence:** Confirmed by source trace.

## SR13. Note: hygiene and proportionality

The projection comparison is written three times (`receipt_store/append.rs:90-92`,
`receipt_store/support/claim_log/schema.rs:395-396`, `integrity.rs:26-28`);
`receipt_store/support/checkpoint_schema.rs:3-15` duplicates `EvidenceDatabase`, the archive
DDL is produced by string-replacing `REFERENCES` clauses (`checkpoint_schema.rs:70-91`), and
the hex `CHECK` expression is copied nine times. `995b9f1c74` bundles accounting, schema 7,
the API removal and unrelated rustfmt churn in one commit, and `4713fef1b4` ("fix: harden
receipt retention and report accounting") and `995b9f1c74` carry no body. The 9.3 edits were
applied by a regex code-mod committed as evidence
(`docs/reviews/artifacts/2026-09-29-sqlite-performance-retention/implement-cache.py`), which
imports from another batch's artifact directory. A clock error when finishing an
already-committed command latches writer accounting closed until reopen
(`receipt_store/writer_accounting.rs:129-133`), while the same error at admission rejects
only that command. The 24 durable-lifecycle corruption controls assert only `ValueError`
(`scripts/tests/check-durable-lifecycle.test.py:71-72`), so a mutant rejected for an
unrelated reason would pass (standard 3.1's test). Retained evidence is large relative to
what it closes: about 8,000 lines of SMT-LIB and a 4,000-line trace for checks CI
regenerates anyway, and a 1,277-line VFS shim that documents a non-reproduction.

## Execution-record claims checked

| Claim (record:line) | Verdict | Evidence |
|---|---|---|
| 91 connection recovery cases across 20 per-store modules (umbrella plan, 10.1 status) | True | 20 `connection_recovery.rs` files; `#[test]` counts sum to 91 |
| Blind recovery fails the rollback-failure regression (`79d2e1b9ea` message; plan 10.1) | True by construction | `store_connection.rs:500` `expect_err` fails when blind recovery returns a guard |
| Sixteen hot reader functions, explicit capacity 64 (sqlite-performance-retention-execution:16-17) | True | 17 `prepare_cached` sites in 16 functions; `lib.rs` constant used at three connection owners |
| Four repeated usage reads compile once; two hold validation reads become one; both failed before repair (:26-30) | True | `budget_store/tests/statement_caching.rs:117-175` counts authorizer calls at prepare time; `cache-red.log` shows 4 vs 1 and 2 vs 1 |
| Write-pair intervals include zero; admission write control +6.28 percent (:66-70) | True | Matches the table and the committed `change-*.json` files |
| 242 of 256 cases completed, overall timeout at 900.80 s, no no-progress timeout (:92-99) | True | `retention-original-scale-result.json`; 242 `phase=complete` lines in the log |
| Removing signature verification would reopen the reproduced corruption defect (store-measurements:37-38) | False | SR3: the projection comparison alone detects the reproduced drift |
| Independent review accepted the integrity and SQL-work repairs (store-measurements:54) | Unverifiable | No committed review artifact; evidence is under `/tmp` only |
| 17 report tests pass after the integrity additions (store-measurements:53) | True | 12 + 3 + 2 at `414aaea0b1` |
| Checked charged, attempted, root/leaf and premium sums with a named error (retention-accounting-execution:25-28) | True | `receipt_store/tests/accounting_boundaries.rs:7-86` fail on revert |
| 45 classified, 593 pending at `4713fef1b4`; 41 classified at `995b9f1c74` (retention:62-67, writer:76-79) | True | TSV diffs at each commit |
| Every original inventory anchor was checked (writer:79) | True | 638 of 638 anchors match base `4c35ce7867` |
| Append computes the claim count before commit; overflow latches admission closed (writer:23, 28) | True | `receipt_store.rs:2970` precedes `:2998`; `receipt_store/writer_accounting.rs:71-73` |
| Archive co-copy comparison includes the new column (writer:54) | False | SR6 |
| v7 checks the typed column "including archived evidence" (plan 10.4) | Partly false | SR1 |
| Support module now under the cap; allowlist entry removed (writer:70) | True | 2,056 to 1,717 lines against a 2,000-line test cap; removal tightens the gate |
| Seven UNSAT obligations, four SAT mutants, every query under ten seconds (lifecycle-assurance:31-38, 64-68) | True | Committed `progress-obligations/summary.json`; mutants violate their named obligation rather than fail to parse (`scripts/formal/revocation_progress.py:108-115`) |
| Twenty-four corruptions of the emitted artifact reject (lifecycle-assurance:43, 116) | True as a count | 24 mutants in `scripts/tests/check-durable-lifecycle.test.py:26-28`; each asserts only `ValueError` (SR13) |
| Source manifest binds the evidence to exact sources (`1d4f3b4ad3`) | True | All 29 hashes in `source-manifest.json` match `1d4f3b4ad3`; two have since drifted at tip, as expected for a point-in-time record |

## Verified clean

- **Fence is unbypassable and phase-correct.** The inner `Mutex<Connection>` is private to
  `store_connection.rs`; recovery rolls back explicitly, checks `is_autocommit` again, and for
  the shared authority connection runs `verify_authority_anchor`, which compares the
  rollback anchor with the database head. A panic between commit and anchor sync fences
  until `open_serving` reconciles forward, the same repair a crash receives. In-flight
  callers serialize behind recovery; a caller whose operation panicked after commit sees a
  panic, and its retry is idempotent (revocation returns `Ok(false)`; budget events replay by
  `event_id`). Note that production opens the authority once at startup, so "until reopen"
  means until process restart.
- **Revocation write split is behavior-preserving.** `record_revocation`
  (`revocation_store.rs:169-233`) returns false on both the existing and the conflicting
  insert, matching the old rollback-and-`Ok(false)` branches.
- **No result caching exists.** "Cache authorization reads" means compiled-statement reuse.
  rusqlite resets and clears bindings when a cached statement returns to the cache, the test
  observes another connection's committed update through the cached read, and no row,
  decision or revocation state is retained between calls, so there is nothing to invalidate.
- **Hold reuse has no TOCTOU.** The reused hold is read and used inside one `IMMEDIATE`
  transaction on a connection no other writer can interleave with.
- **Analytics SQL is injection-free and the totals are exact.** Only fixed text and
  positional parameter indexes are interpolated; no `json_extract` or BLOB `CAST` remains on
  cost; accumulation is `u128` with `checked_add` and a refusal above `u64`; absent stays NULL
  and zero stays eight zero bytes. The ceiling check, integrity scan and aggregation run in
  one deferred snapshot, and the instruction-budget progress handler is removed before the
  pooled connection returns (`receipt_store/reports/analytics/work_budget.rs:57-63`). No
  tenant predicate existed at base, so none was dropped; the administrative gate still runs
  first.
- **Attempted-cost migration** fills the typed column from verified signed bodies, refuses
  any disagreeing projection, and runs in one transaction; an invalid cost rolls it back.
- **Writer accounting is exact across crash and unwind.** The claim count lives in the
  in-memory head and is re-derived from SQLite on seed; permits are finished idempotently and
  released on drop and unwind; the checkpoint commits in its own guarded transaction.
- **Retention diagnostics change no production code.** The completion fix in `b9d6af6fb0`
  strengthens the property (both writers must be torn down and their `Weak` handles dead
  before completion is reported). The sync shim never holds its diagnostic mutex across the
  delegated `xSync`. Every record keeps issue 1045 and the 256-case gate open.
- **Revocation progress obligations are faithful and honestly scoped.** The projection
  matches `Revoke`, `Propagate`, `Evaluate` and `Attenuate` in
  `formal/tla/RevocationPropagation.tla:187-249`; the rank `pending + 4 * nonrevoked` strictly
  falls on revoke and propagate; the fairness step is stated as a manual argument; the
  original length-24 query stays recorded as unverified; the source pins match the TLA files
  at tip.
- **Lifecycle observations are metadata only, emitted after commit with the guard dropped**,
  carry no secrets, cost nothing when `debug` is disabled, and CI regenerates the trace
  rather than validating a committed copy against itself.
- **House rules.** No em dashes in any of the 308 touched files; no `unwrap` or `expect` in
  production code; no process vocabulary in production code. The test comment at
  `receipt_store/tests/retention/state_machine.rs:43` cites issue 1045.

## Recommendations for the remaining plan

1. Fix SR1 before any upgraded store with a retention archive is opened: migrate named
   archives inside the live v7 upgrade and add the live-plus-archive regression. Until then,
   document "open each archive writable with the new binary first" as a required upgrade step.
2. Open a Packet 9 item for the suspension guard (SR2): an authenticated candidate-set index,
   pruning of empty state rows, and a benchmark curve at 200, 2,000 and 20,000 sets. Re-rank
   the remaining measurement work by growth, as the packet's own contract says.
3. Decide what the analytics integrity check is for (SR3). If it defends against database
   writers, anchor it to a trusted key and verify every column the report reads; otherwise
   drop the signature step, re-measure, and correct `AGENT_ECONOMY.md` and the measurement
   record.
4. Bring cost attribution under the analytics snapshot, ceiling and work budget (SR4).
5. Give each store error a typed `Fenced` variant with its source (SR5), and update standard
   14.1's "Enforced by" line, which still says the per-store test does not exist and names
   the "next operation succeeds" oracle the rule itself rejects
   (`docs/security/engineering-standard.md:679`).
6. Restore the original plan wording for the items in SR9 and record each change as an
   accepted deviation; refresh correction 3A's counts from the TSV.
7. Stop committing regenerable solver queries and traces as evidence; retain the summary and
   source hashes, which already bind the result.
