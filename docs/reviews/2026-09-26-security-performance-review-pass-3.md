# Security performance review, pass 3, September 26, 2026

Reviewed candidate: `3cd73631a18a6ec169b1e1a5bbd3ebe8bcb00130` on draft
[PR #1160](https://github.com/bb-connor/arc/pull/1160).

Fourth review in the lineage, and the first to look at performance rather than
correctness. It does not restate the September 25 boundary review, the
[remediation record](2026-09-25-security-roadmap-remediation.md),
[quality pass 1](2026-09-26-security-code-quality-review.md) (Q series) or
[pass 2](2026-09-26-security-code-quality-review-pass-2.md) (R series).

Findings are numbered `P`.

**The question this pass answers:** if a performance-minded critic read this
codebase looking for the pattern where idiomatic-looking Rust is quietly doing
far more work than it needs to, what would they screenshot?

**Judgment: there is one query that genuinely deserves it, one measurement gap
that is worse than any individual slow line, and a set of type-design habits that
cost allocations without being on a path where allocations matter. Most of the
codebase is not slow, and the honest finding is that nobody can currently tell,
because the only benchmark points at the one store path that was already
optimized.**

A note on method, because it matters for this kind of review: a list of five
hundred micro-optimizations on paths that run once per launch is itself the
failure mode being criticized. Per-operation cost in this system is dominated by
Ed25519 signing and verification and by `fsync`, both of which are tens to
hundreds of microseconds. An avoided `String` allocation is tens of nanoseconds.
So findings below are tiered by whether they scale with data volume, cost per
operation, or cost nothing measurable. Section 6 lists what I checked and
deliberately did **not** call a finding.

---

## Tier 1: scales with data volume

### P1. High: the receipt analytics summary parses JSON out of every row to sum a column that already exists

`crates/platform/chio-store-sqlite/src/receipt_store/reports/analytics.rs:35`:

```sql
COALESCE(SUM(CAST(COALESCE(json_extract(r.raw_json, '$.metadata.financial.cost_charged'), 0) AS INTEGER)), 0) AS total_cost_charged,
COALESCE(SUM(CAST(COALESCE(json_extract(r.raw_json, '$.metadata.financial.attempted_cost'), 0) AS INTEGER)), 0) AS total_attempted_cost
FROM chio_tool_receipts r
LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
WHERE (?1 IS NULL OR r.capability_id = ?1)
  AND (?2 IS NULL OR r.tool_server = ?2)
  AND (?3 IS NULL OR r.tool_name = ?3)
  AND (?4 IS NULL OR r.timestamp >= ?4)
  AND (?5 IS NULL OR r.timestamp <= ?5)
  AND (?6 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?6)
```

Three compounding problems, and the third is what makes this the one genuinely
indefensible query in the store:

1. **`json_extract` per row, twice, to read a financial value.** SQLite parses
   the receipt's `raw_json` text for every row scanned, for each of the two
   aggregates.
2. **The `(?N IS NULL OR col = ?N)` optional-filter shape defeats index
   selection.** Six indexes exist on exactly the columns being filtered
   (`idx_chio_tool_receipts_timestamp`, `_capability`, `_subject`, `_grant`,
   `_tool`, `_decision`, at `receipt_store/bootstrap/open.rs:579-589`). This
   predicate shape generally prevents the optimizer from using them, so the query
   degrades to a full table scan plus a `LEFT JOIN`. They built the right indexes
   and then wrote the one query shape that cannot use them.
3. **A typed column for this value already exists.** `open.rs:569` declares
   `cost_charged_be BLOB` with a `CHECK` constraint enforcing
   `typeof(cost_charged_be) = 'blob' AND length(cost_charged_be) = 8`, an 8-byte
   big-endian integer. The schema already has the correct, checkable, indexable
   representation of exactly this field, and the analytics query re-derives the
   same number by parsing JSON text.

There is no `LIMIT`, no time-bucket rollup and no materialized aggregate. The
same `json_extract` aggregate appears in four queries in the file (`:35-36`,
`:77-78`, `:131-132`, `:184-185`); the summary query is the one analyzed. This is
the store whose roadmap claims million-receipt scale and whose retained M8
evidence is a million-receipt campaign.

**This is the finding a critic would screenshot**, and they would be right. It is
not a micro-optimization: cost grows linearly with receipt count, with a JSON
parse as the per-row constant.

**Fix:** aggregate over `cost_charged_be` (and the equivalent for attempted
cost), which removes the JSON parse entirely. Split the optional-filter query
into the shapes callers actually use, or build the predicate dynamically so the
planner sees a usable index, and confirm with `EXPLAIN QUERY PLAN` in a test.
Add a bounded time window or a rollup table for the unfiltered case. Assert the
query plan in a regression test so the shape cannot silently regress.

**Confidence:** high, and upgraded in pass 6 from inferred to observed. Against the
repository's own `chio_tool_receipts` DDL with all six indexes on SQLite 3.50.4,
`EXPLAIN QUERY PLAN` for the production predicate shape returns `SCAN r` whether
`capability_id` or a timestamp range is bound; the direct-predicate shape returns
`SEARCH r USING COVERING INDEX idx_chio_tool_receipts_grant`. The table was empty
after `ANALYZE`, so this is the structural plan, not a statistics artifact.

### P2. High: there is one benchmark, and it measures the one store path that is already clean

`crates/platform/chio-store-sqlite/benches/store_receipt_write_throughput.rs` is
the only benchmark in the store crate. It measures
`store_receipt_write_throughput`, the receipt append path.

`receipt_store.rs` contains **zero `.prepare()` calls**. It uses `execute()`
directly. It is, by construction, the store path least likely to have the problem
in P3. Pass 7 traced the call graph: the append path reaches one `.prepare()` in
`checkpoint_projection.rs:563` (`validate_adopted_claim_log_delta`), but only on
the stale-head branch where another writer adopted claim-log rows
(`pre_delta > 0`); the code's own comment at `receipt_store.rs:2830` documents the
flat per-append cost in the single-writer case. Steady-state append compiles no
SQL per receipt.

Meanwhile the paths that do recompile SQL per call, and that sit on the
per-authorization critical path, have no benchmark at all:

| Path | `.prepare()` sites | Benchmarked |
| --- | --- | --- |
| Receipt append | 0 in `receipt_store.rs`; one helper reached only on the stale-head branch | **yes** |
| Security state (`security_state_parts/*`) | 43 | no |
| Budget store (`budget_store/*`) | 55 | no |
| Global commit chain | 13 | no |
| Revocation store | 11 | no |
| Admission operation store | 8 | no |

(Per-directory totals corrected in pass 6; the first version summed only the files
that made a truncated top-18 list.)

The measurement points at the fast path. Every unmeasured path is on the request
critical path, and several are behind the mutex in P4.

This is a worse finding than any individual slow line, because it means none of
the other findings in this document can currently be prioritized by evidence, and
no regression on those paths would be detected. It also means the "million
receipt" scale evidence proves something narrower than it reads: it proves
receipt append scales, not that authorization scales.

**Fix:** benchmark the per-authorization composite operation (admission check plus
budget charge plus security-state read plus receipt append), the budget
charge/release pair, and the security-state read on the denial path. Populate to a
realistic row count first; a benchmark against an empty table measures the wrong
thing regardless of which path it covers.

---

## Tier 2: costs per operation, cheap to fix

### P3. Medium-high: 420 `.prepare()` calls and zero `.prepare_cached()`

`rusqlite`'s `prepare()` compiles the statement with `sqlite3_prepare_v2` on
every call. `prepare_cached()` uses the connection's statement cache and returns a
reset handle. For short statements, compilation is frequently comparable to or
more expensive than execution.

Across `chio-store-sqlite/src` there are **420 `.prepare(` calls and 0
`.prepare_cached(` calls.**

Scoped honestly, because the raw number overstates the impact: many of these are
in schema setup, migration, `list_*` and reporting functions that run once or
rarely. I checked `budget_store/store.rs` and its eight sites are in
`list_abandoned_event_seq_ranges`, `list_all_usages` and similar, not on the
charge path. Those do not matter.

What does matter is that the per-operation reads in `security_state_parts/*` (33),
`global_commit_chain.rs` (13), `revocation_store.rs` (11) and
`admission_operation_store/part_01.inc` (8) are on the authorization path, and
`prepare_cached` is used nowhere in the crate, so there is no path where it was
considered and rejected.

**Fix:** switch the per-operation reads to `prepare_cached`, leave setup and
reporting alone, and set the connection's statement cache capacity explicitly.
Measure with P2's new benchmarks rather than converting all 420 on faith.

### P4. Medium-high: several stores serialize all access through a single mutexed connection

`Arc<Mutex<Connection>>` or `Mutex<Connection>` appears in at least
`fiscal_store.rs:159`, `finding_challenge_store.rs:636`,
`finding_purchase_store.rs:375` and `sealed_decoy_registry.rs:30`. One connection,
one lock, all readers and writers serialized, including read-only queries that
SQLite in WAL mode could serve concurrently.

This is a **known** ceiling: the earlier principal review of the cognition market
recorded "sqlite mutex" alongside the DPoP `COUNT` and spend `SUM` ceilings. It is
still present, and it compounds P3: every operation on these stores takes a global
lock and then recompiles its SQL inside the critical section.

**Fix:** a read pool in WAL mode with a single writer, which is the standard
SQLite shape, rather than one mutexed connection for both. This is a real change
and should be sequenced behind P2's measurements, not ahead of them.

### P5. Low-medium: the charge path reads the same hold row twice per operation

In `budget_store/trait_impl.rs`, `reduce_charge_cost_with_ids_and_authority`
loads the hold via `ensure_open_hold` at roughly `:965` for the guard at `:972`,
then loads it again at `:1037` before the subtraction at `:1048`. Both reads are
inside one transaction, so correctness is fine (pass 2 confirmed the guard holds),
and the second read is almost certainly a page-cache hit.

It is still two statement preparations, two lock acquisitions inside the
transaction and two row decodes where one would do, on a money-path operation.
Worth folding into the P3 pass rather than its own change.

---

## Tier 3: type-design habits that cost allocations

These are the ones that look most like the pattern being criticized, and they are
the ones least likely to show up in a profile. Fix them for type-correctness,
not for speed.

### P6. Medium: 121 sites across 80 files hex-encode a digest to a `String` in order to compare 32 bytes

Examples, all production:

- `chio-cage/src/launch/linux_parts/part_01_sections/sandbox.inc:63` and `:72`:
  `if chio_core::sha256_hex(&plan_bytes) != envelope.plan_digest`
- `chio-cage/src/linux.rs:809`: `if chio_core::sha256_hex(&content) != artifact.binding_digest`
- `chio-finding-challenge/src/receipts.rs:35`, `chio-finding-verifier/src/verify.rs:1223`,
  `chio-federation/src/frost/verify.rs:598` and `:895`, `chio-credit/src/iou_v2.rs:278`

Each comparison hex-encodes 32 bytes into a 64-byte heap `String` and then does a
`String` comparison, to decide whether two 32-byte values are equal.

Three separate problems, in descending order of how much they matter:

1. **The wrong type is stored at rest.** A `Digest32` type already exists and is
   used elsewhere (`chio-security-types` imports it in `response.rs`). These
   fields are `String` hex. Storing a digest as text means every comparison
   round-trips through an encoding, every serialization is twice the bytes, and
   nothing prevents a malformed or differently-cased value from being assigned.
2. **Allocation per comparison**, on paths including cage launch verification and
   receipt verification.
3. **`String` comparison is not constant-time.** For a plain content digest this
   is usually irrelevant. It is not irrelevant where the compared value functions
   as an authenticator, and `credit_authority_digest`
   (`chio-credit/src/iou_v2.rs:278`) and `binding_digest`
   (`chio-cage/src/linux.rs:809`) are worth deciding about explicitly rather than
   by default.

**Fix:** `[u8; 32]` or the existing `Digest32` at rest, compare bytes, and use a
constant-time comparison where the value authenticates rather than merely
identifies. Hex only at the display and serialization boundary.

### P7. Low: allocation density on the per-request admission path

Counted in production files on the per-tool-call path:

| File | `.clone()` | `.to_string()` | `.to_owned()` | `format!` |
| --- | --- | --- | --- | --- |
| `kernel/validation.rs` (2,747 lines) | 90 | 71 | 26 | 29 |
| `kernel/admission_coordinator.rs` | 46 | 40 | 35 | 19 |
| `receipt_store.rs` | 29 | 92 | 0 | 36 |
| `kernel/dpop.rs` | 3 | 22 | 1 | 8 |

This is the texture a critic would point at, and in isolation each one is
defensible: clone a `String` id into an owned struct, format an error message.
Cumulatively it is roughly 200 heap allocations per request on paths whose real
cost is an Ed25519 verification, so **removing them would not measurably help.**

The reason to care is different: `.clone()` density is usually a symptom of
ownership not being designed, and it is what makes the 5,000-line modules from
finding Q1 hard to reason about. Fix it where Packet 7 is already restructuring a
module, using borrows and `Cow<'_, str>` where the owned copy is not retained.
Do not open a campaign for it.

`dpop.rs` is notably clean (3 clones) and is the model.

---

## Tier 4: the string-keyed map, which is a correctness bug rather than a slow one

### P8. Low (core claim retracted in pass 6): syscall argument constraints are keyed by name `String`

`chio-cage/src/lib_parts/part_02.rs:171-230` builds
`argument_constraints: BTreeMap<String, Vec<SyscallArgumentConstraint>>` keyed by
syscall name:

```rust
argument_constraints.insert(
    "prlimit64".to_string(),
    vec![SyscallArgumentConstraint { argument_index: 0, comparison: Equal, value: 0 }],
);
```

This is literally the shape the critique names, a `String`-keyed map where an
enum or a syscall number belongs. **On performance grounds it does not matter at
all**: the map is built once per launch and compiled into a BPF program. Saying
otherwise would be the overclaim this review is trying to avoid.

**Retraction.** The first version of this finding said no check exists that the
constraint keys are a subset of the allowed syscall names. That was wrong.
`sandbox.inc:1086-1094` rejects any plan whose `argument_constraints` key is not
among the allowed names (`SeccompInstallFailed`, `"seccomp_constraint"`), and
`:1068-1073` rejects an allowed name that has no syscall number for the
architecture. A misspelled constraint key therefore fails the launch; it does not
silently leave the syscall unconstrained. `:1077` does compile absent constraints
as an unconditional allowance, and that is irrelevant once the subset check
refuses the plan. I searched for the wrong identifiers and inferred an absence.

What remains is small: the check runs at launch in the helper rather than at plan
construction, so a bad plan is discovered late rather than early, and the map is
still keyed by `String` when an enum or numeric id would make the typo a compile
error.

The same fragility appears in the inverse direction at
`launch/linux_parts/part_02.rs:1398`:

```rust
unconfined_limits.argument_constraints.remove("prlimit64");
```

Removal by string literal. If the insertion key and this removal key ever drift,
the removal silently no-ops and the test that depends on a weakened plan stops
testing what it names.

**Fix:** key the map by a `Syscall` enum or the numeric syscall id, so a
nonexistent name cannot be expressed. If the string key must stay for
serialization, validate at plan construction that every constraint key appears in
the allowed set and reject the plan otherwise, in the same helper that already
rejects plans which remove the `prlimit64` constraint. Add the negative test: a
plan with a constraint for an unlisted syscall is refused.

**Confidence:** high on the corrected state. The launch-time check was read
directly in pass 6. There is no security defect here; the residual is type-design
preference plus one test-fragility point.

---

## 6. Checked and deliberately not called findings

Recorded because a performance review that reports everything it noticed is the
thing being criticized.

- **Eager error construction: clean.** Zero instances of
  `ok_or(Error::X(format!(...)))` or the `unwrap_or`/`or` equivalents across the
  kernel, security crates, control plane and stores. `ok_or_else` and
  `map_err(|e| ...)` are used correctly throughout, so error strings are built
  only on the error path. This is the single most common performance-naive Rust
  pattern and it is absent.
- **N+1 `prepare()` inside a loop: not found.** My detector reported 103
  candidates. I hand-checked the most plausible ones and the top hits were false
  positives: `finding_operator_bundle_store.rs:929` is in a separate function
  whose loop had already closed, and `fiscal_store.rs:2142` is inside a `match`
  arm, not the `for` loop above it. No confirmed instance. The detector's scope
  tracking was wrong, not the code.
- **Receipt append is clean.** Zero `.prepare()`, three `.execute()`. The hottest
  write path in the system is the best-written store code in it.
- **1,841 `canonical_json_bytes` call sites: inventory, not a finding.**
  Canonical serialization before signing is required, not redundant. A finding
  here would need a specific instance of the *same* value being re-serialized
  within one operation, which I did not establish. Worth a targeted look at
  `fiscal_store.rs` (24 calls) and `secret_broker/ipc_client.rs` (24) if P2's
  benchmarks implicate them.
- **146 `collect::<Vec<_>>()` and 106 `HashMap`/`BTreeMap<String, _>`:**
  inventory. Some are justified, some are not, and without P2's measurements
  triaging them is guesswork. Listed so the numbers exist, not as work items.
- **533 `COUNT(*)`/`SUM(...)` sites:** the same. Two are known ceilings (the DPoP
  replay `COUNT` at `governed_approval_replay_store.rs:381` and the budget
  `SUM`s in `composite_schema/state_invariants.rs`), already recorded by the
  earlier principal review. P1 is the one I am willing to call a defect on its
  own evidence.
- **`saturating_*`/`wrapping_*` (632 occurrences):** already assigned to
  correction 3A by pass 2 on correctness grounds, not performance.

## Sequencing

P2 comes first. It is the only finding that unblocks judgment about the others,
it requires no production change, and without it P3 and P4 would be changes made
on the strength of a code read rather than a measurement.

P1 is independent of P2 and should be fixed regardless, because its cost model is
visible from the query text and the existing `cost_charged_be` column makes the
fix small.

P8's residual (typed keys, test-helper drift) is small type-design work for the
cage and is not a security fix; pass 6 retracted the security half.

P3, P4 and P5 follow P2's measurements, in that order.

P6 and P7 are type-design work for Packet 7's restructuring, explicitly not
performance work, and should not be justified as such.
