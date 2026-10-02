# Execution review: accounting, clocks, replay and runtime boundary, October 1, 2026

Scope: commits `881823ced2` (caller deadlines), `4c35ce7867` (runtime recovery and
confinement), `916e5d8364` (authority atomicity and accounting overflow), `8288bd56be`
(auth epochs, replay accounting, lease fencing), `0fbe22e0f0` (checked budget
transitions), `00536cc902` (shared clock port), `2b73690f7c` and `0460314617` (replay
clocks and exact financial receipts), `a8b5f11d3e`, `f965330c2a` and `c2015692b5`
(native authority clocks, emergency stop, deterministic expiry fixtures). Plans:
umbrella addendum Packet 8, corrections 3A and 4A, and the clock half of
`docs/superpowers/plans/2026-09-29-native-clock-test-ownership.md`. Execution records:
`2026-09-27-runtime-boundary-execution.md`, `-authority-accounting-execution.md`,
`-authentication-replay-leases-execution.md`, `-checked-budget-accounting.md`,
`-shared-clock-response-assurance.md`, `2026-09-28-replay-expiry-execution.md`,
`-replay-clock-completion.md`, the clock parts of
`2026-09-29-native-clock-test-ownership-execution.md`, the arithmetic inventory and
`scripts/security-clock-inventory.json`. Base `07e963e8f5`, tip `a2630c20a1`. Method:
diffs read against the resulting code at the tip, gates run locally
(`check-security-clocks.py`, `check-accounting-arithmetic.py`), the clock gate's
scanner probed with synthetic sources, and every finding traced through production
callers. No cargo run was needed; no finding above Medium depends on runtime behavior.

**Judgment: The accounting half is sound and worth its cost. Budget transitions in
both stores now use checked types, SQLite writers compare-and-set every counter they
change under an IMMEDIATE transaction with an affected-row check, replay markers have
consistent exclusive expiry boundaries, lease fencing tokens are durable and checked,
the emergency stop now latches before reading time, and a caller cannot extend its
frozen start deadline. The clock half delivered a good typed port but its claims
overstate the result: a public thread-local fixed-time override now takes precedence
over the injected kernel clock and skips its regression fence (AC1), several kernel
and SQLite production paths still read the process `SystemClock` instead of the
injected clock, including aggregate capability issuance and finding-pool debits
(AC2), and the clock gate neither covers the process host nor sees those adapter
reads (AC3). The "154 remaining sites" figure is therefore a count of one lexical
pattern, not of ambient time in the TCB.**

## Plan conformance

| Plan item | Recorded status | Verified status | Evidence |
| --- | --- | --- | --- |
| P8: private-field `ExposureUnits` / `InvocationCount`, checked add/sub with specific errors | Done | Done | `crates/kernel/chio-kernel-core/src/accounting.rs:8-73` |
| P8: extend count types to remaining quota/lease owners | Open | Open, consistent | `leases_scheduler.rs:20-60` uses raw checked `u64`, no shared type |
| P8: migrate the four release-invariant implementations | Done | Done | `in_memory/accounting.rs:20-71`, `trait_impl.rs:407-452`, composite terminal transitions; formal models keep guarded subtraction |
| P8: SQL predicate in every store's UPDATE | Done | Done for grant usage and holds | `trait_impl.rs:422-452` (CAS on count, exposure, spend), `store.rs:1371-1408` (`remaining >= consumed AND remaining - consumed = new`) |
| P8: property tests over the newtype | Done | Done | `accounting/tests.rs:4-45` (proptest, 128 cases) |
| P8: Kani over the newtype | Done | Done, low marginal value | `accounting/kani.rs:4-88` proves checked add/sub equal wide arithmetic |
| P8 exit: "a fifth store cannot get it wrong" | Implied by record | Not met | `ExposureUnits::new` is public and infallible (`accounting.rs:23`); storage stays primitive; the lexical gate is scoped by path words (`check-accounting-arithmetic.py:57-66`) and excludes `finding_pool.rs`, `reconciliation.rs`, `validation.rs` |
| 3A: retain 638-site inventory | Done | Done | TSV has 638 rows |
| 3A: finish classifying | Open | Open, 85 pending | Matches `2026-09-28-remaining-security-work.md:15`; 320 of 553 classified rows are fixture dispositions |
| 3A: `wrapping_*` and `saturating_sub` in accounting paths | Open | Open; retained clamps carry call-site reasons | 12-entry spot check below |
| 3A: record classifications | Done | Done | Spot check matches tip |
| 4A: one port, distinct `UnixMillis` / `MonotonicInstant`, fail-closed | Done | Done | `chio-security-types/src/clock.rs:16-216`, compile-fail doctest at `:56-59` |
| 4A: migrate three traits, no fourth | Done | Traits done; an untyped fourth time source remains | AC1 |
| 4A: replace production `SystemTime::now()` with the injected port; gate new calls | Open | Partial; gate under-covers | AC2, AC3 |
| 4A: classify deadlines, state skew policy once | Open | Partial | `docs/security/trusted-time.md:32-40`; AC5 |
| 4A: property and Kani coverage | Done | Present, not re-run | `chio-security-types/src/kani_public_harnesses.rs:3-71` |
| Clock plan T1: pin fixture epoch, wire native-flow owners | Done | Done for fixtures | `c2015692b5` drives the injected clock, no fabricated expiry |
| Clock plan T1: repair reproduced production clock bypasses, no production test clocks | Done | Partial, and the constraint was broken | AC1 (`a8b5f11d3e`), AC2 |
| Clock plan T1: parallel campaign, focused reruns | Done | Not re-run; record states three fixture failures and reruns honestly | native clock record lines 52-56 |

## AC1. Medium: a public thread-local fixed time overrides the injected kernel clock and bypasses its regression fence

`a8b5f11d3e` replaced the kernel's `trusted_now_millis`, which read only the injected
clock through the kernel fence, with `kernel/clock.rs:8-14`, which first consults
`fixed_runtime_unix_secs_for_current_thread()` and returns that value without touching
the injected clock or the fence. The same override sits ahead of
`authority_clock_reading` (`kernel/clock.rs:38-44`), capability issuance time
(`authority.rs:414-417`) and the SQLite admission authority time
(`admission_operation_store/schema/clock.rs:39-43`). The setter
`scope_fixed_runtime_for_current_thread` is a public, always-compiled export
(`receipt_support/receipt_scopes.rs:56-75`, `lib.rs:219-223`). Every kernel authority
read on a thread holding that scope (capability expiry, execution-nonce liveness,
credential deadline refresh in `credential_reservation/preparation.rs:47-59`, the
durable commit time in `return_context.rs:137-147`) therefore uses an arbitrary caller
value, and the kernel's high-water fence is neither consulted nor advanced.

Failure scenario: an embedding service sets the scope to make receipt identifiers
reproducible, or holds the guard across an `.await` on a multi-thread runtime. A
capability that expired at T is evaluated on that thread with a fixed time before T
and is admitted; a wall-clock regression that the fence would refuse is invisible.
The only in-tree non-test user, `chio-runtime-harness/src/kernel.rs:506-507`, already
injects `FixedClock` with the same instant (`:339-344`); it needs the thread-local
only so the SQLite admission store, opened without that clock, agrees with the
kernel. This is the hidden channel the plan forbade: "No ... production test clocks"
(`2026-09-29-native-clock-test-ownership.md:15`), and 4A's "one injected clock port".
No gate checks it: the clock gate matches `SystemTime::now(` and `Utc::now(` only.

Fix: delete the time half of `FixedRuntimeScope`; open the harness's authority store
with `open_serving_with_clock` using the same `FixedClock`; if deterministic receipt
identifiers must remain, keep them behind a separate type that cannot affect time.

**Confidence:** Confirmed. Source trace of the `a8b5f11d3e` diff and every consumer of
the override at the tip.

**October 2 resolution:** AC1 is repaired and locally qualified in the
[CI and authority-time execution record](2026-10-02-ci-authority-time-repair-execution.md).
The public ambient time override is removed; receipt identifier scope cannot
change authority time. Kernel and SQLite controls prove the injected clock and
regression fence remain authoritative. Harness and fixture owners now inject
their clocks explicitly. AC2 and AC3 remain separate work.

## AC2. Medium: kernel and SQLite production paths read the process `SystemClock` instead of the injected clock

The 4A item asks for direct wall-clock reads to be replaced "with the injected port".
Many were replaced with the global adapter instead, which is ambient time under a
different name. At the tip, `kernel/mod.rs:1791-1799` (`read_unix_timestamp_ms`) reads
`SystemClock` and feeds `debit_finding_pool_purchase` (`finding_pool.rs:729-734`),
whose allocation-liveness and authorization-expiry decisions follow
(`finding_pool.rs:778-783`), outbox claim and acknowledgement times
(`:1004`, `:1019`), the terminal trusted-time floor (`:1242`), governed active-response
admission and dispatch commit (`governed_active_response.rs:144-145`, `:255`), child
receipt timestamps (`receipt_support/receipt_building.rs:25`) and security-release
acknowledgement time used for lease validation (`tool_outcome/security_release.rs:84-85`).
Kernel aggregate family-root issuance signs with the injected clock
(`LocalCapabilityAuthority::issue_aggregate_family_root`, `authority.rs:478-486`, wired at `kernel/construction.rs:285`) and then validates the
result with `validate_issued_aggregate_family_root_response`
(`kernel/validation/aggregate.rs:37`), which reads `SystemClock`
(`authority/aggregate.rs:18`) with a 30-second skew (`authority.rs:30`).

Failure scenario: a kernel built with `new_with_clock` whose clock is more than 30
seconds ahead of the host, for example the native fixture epoch `1800000000000` ms
used by this very batch, issues an aggregate family root with `issued_at` in the
host's future, and the kernel's own validator refuses it as "too far in the future";
a clock lagging the host by more than the TTL refuses it as already expired. Finding
pool allocations are judged live or expired on host time while the same kernel's
admission uses the injected clock, and an injected-clock fault does not stop those
debits. In a default deployment the injected clock is `SystemClock`, so the two agree
and the visible effect is limited; the cost is that the clock contract in
`trusted-time.md:10-17` does not hold for these paths and deterministic tests cannot
drive them. The native clock record states that "kernel issuance/evaluation/recovery
... now use the correct owner" (`2026-09-29-native-clock-test-ownership-execution.md:19-22`);
the aggregate path contradicts that.

Fix: thread the kernel's `authority_clock()` into these owners, delete
`read_unix_timestamp_ms`, and make the public validators take a reading instead of
sampling `SystemClock`.

**Confidence:** Confirmed. Each call site traced at the tip; the aggregate mismatch
follows from two clocks compared under a 30-second bound.

## AC3. Medium: the clock gate does not cover the TCB and cannot see the forms the migration produced

`scripts/check-security-clocks.py:21-40` scopes the scan to listed roots that omit
`crates/products/chio-cli`, although process-host files are trust boundaries in
`docs/security/trust-boundary-inventory.json:380-386`. In
`chio-cli/src/cli/process_host/native_broker.rs:53-60`, an ambient `SystemTime::now()`
supplies the time used to verify broker capabilities (`:90-97`), to bound the live
process authority window (`:109-110`), and to stamp security-participant source
import and hydration in the authority store (`:164-185`). `00536cc902` edited this file
to migrate its verifier clocks and created the gate in the same commit, leaving this
read outside it. The scanner (`:51-65`) also misses, as a synthetic probe confirmed,
the function-path form (`unwrap_or_else(SystemTime::now)`), `UNIX_EPOCH.elapsed()`,
`time::OffsetDateTime::now_utc()`, `chrono::Local::now()`, type aliases, time traits
not named `*Clock`, every `SystemClock` adapter call (AC2), and the thread-local
override (AC1). None of the lexical gaps is exploited at the tip; the scope gap and
the adapter blindness are.

Failure scenario: a new ambient read in the process host, or a new
`Clock::unix_millis(&SystemClock)` anywhere in the kernel, passes the gate, and the
records keep reporting a shrinking count as 4A progress.

Fix: scope the gate to the trust-boundary inventory rather than a hand list; count
`SystemClock` references outside composition roots; match `now` as a path, not only a
call.

**Confidence:** Confirmed. Gate source read, scanner exercised on synthetic inputs,
production read traced in the process host.

## AC4. Low: run-lease fencing tokens fence only heartbeats

`8288bd56be` made acquisition and heartbeat transactional with checked, durable,
monotonic fencing tokens (`leases_scheduler.rs:37-53`, `:261-275`). No protected write
consumes the token. `record_run_state` and `record_run_step_state`
(`store/sqlite/runs_steps.rs:11-82`) upsert run status and step state, including the
destructive flag and receipt digests, with no lease or token predicate; the stored
`lease_id` is never compared. Failure scenario: owner A stalls, a scheduler tick
expires its lease and owner B acquires token 2; A resumes and its step write
overwrites B's. `crates/kernel/chio-runtime/ARCHITECTURE.md:72` describes these as
"fenced run leases". No in-tree production caller races two owners today, so the
trigger is narrow. Fix: require the lease token on run and step writers and add
`AND fencing_token = ?` against the active lease in the same transaction.

**Confidence:** Confirmed. Source trace of every writer in the runtime store.

## AC5. Low: the trusted-time contract is stale and the skew policy is not stated once

`docs/security/trusted-time.md:46-48`, last changed in `00536cc902`, still lists
session helpers and `FindingStatusCommitClock` as unmigrated; the session uses the
injected clock (`session.rs:874-917`) and `FindingStatusCommitClock` no longer exists.
The document says nothing about the thread-local override (AC1) or adapter reads
(AC2). 4A asks for the skew policy to be stated once; the tip has independent
constants for replay retention (`clock.rs:13`), SQLite admission
(`MAX_TRUSTED_CLOCK_SKEW_MS`), capability issuance (`authority.rs:30`), DPoP (30 s
default, `dpop.rs:173`), execution nonces and governed approvals
(`execution_nonce_store.rs:66`, `governed_approval_replay_store.rs:39`). Fix: one table
in `trusted-time.md` naming each constant, its domain and why it differs.

**Confidence:** Confirmed. Document and constants read at the tip.

## AC6. Note: the emergency stop is process-local

`f965330c2a` is a correct repair: the latch is published before time is read
(`kernel/construction.rs:1671-1679`), a clock error leaves the kernel stopped, and only
`emergency_resume` clears it. Its regression would fail if reverted, because the old
code returned on the clock error before setting the flag. The latch is an
`AtomicBool`; a process restart resumes execution, and no document claims otherwise.
The HTTP handler's comment that the flag flips "before any fallible step"
(`chio-http-core/src/emergency.rs:205-208`) was false before this commit and is true
now.

## Execution-record claims checked

| Claim (record:line) | Verdict | Evidence |
| --- | --- | --- |
| Newtypes keep full domains; settlement cannot spend more than its reservation (checked-budget-accounting:10-15) | True | `accounting.rs:113-125` |
| SQLite writers compare stored counters and check affected rows; refusal rolls back all participants (checked-budget-accounting:20-26) | True | `trait_impl.rs:422-452`, `store.rs:1371-1408`, begin_write IMMEDIATE at `store.rs:284-298` |
| Direct-writer test bypasses Rust validation (checked-budget-accounting:51-53) | True; real production path | `tests/checked_accounting.rs:417-438`; trigger matrix at `:205-279` fails if any `changed != 1` check is removed |
| Kani harnesses use the production source (checked-budget-accounting:64-71) | True | in-crate `#[cfg(kani)]` module `accounting/kani.rs` |
| Six transition files have no unchecked operators (checked-budget-accounting:30-32) | True, superseded: gate now reports 0 sites | `check-accounting-arithmetic.py` run at tip |
| Only skew upper bounds still saturate in issuance (authority-accounting:24-27) | True, with call-site comments | `authority.rs:251-253`, `:266-269` |
| Epochs checked, `u64::MAX` reserved for terminal close (auth-replay-leases:14-18) | True | `session.rs:651-664` |
| Fencing tokens checked and never reused (auth-replay-leases:51-56) | True; tokens fence heartbeats only | AC4 |
| In-memory nonce store never evicts live markers, refuses at zero capacity (replay-expiry:30-33) | True | `execution_nonce/store.rs:71-92` |
| Stores resample time inside the serialized reservation (replay-expiry:20-22) | True for SQLite nonces | `execution_nonce_store.rs:594-610` |
| DPoP commit clears ownership during a clock outage (replay-clock-completion:29-30) | True; no clock read | `dpop.rs:531-555` |
| Kernel issuance/evaluation/recovery use the correct clock owner (native-clock:19-22) | False for aggregate issuance, finding pool, receipts | AC2 |
| Emergency-stop regression failed before the fix (native-clock:84-87) | True by reasoning | AC6 |
| Production fences never reset (native-clock:92-94) | True literally; the thread-local override bypasses them | AC1 |
| 85 pending / 553 classified / 133 repaired; 154 occurrences at 149 keys (remaining-security-work:15-16) | True | TSV counts; clock gate run: 154, slack 0 |

Inventory spot check (12 entries, all consistent at the tip): `session.rs` 1102 fixed
(`session.rs:653-664`); `leases_scheduler.rs` 53 fixed (`:37-53`), 339 fixed
(`:55-60`), 243 intentional bound (`:321-324`, commented); `dpop.rs` 747 fixed
(`:642-648`), 682 intentional bound (`:686-688`, commented); `reconciliation.rs` 394
fixed (`:383`, `financial_accounting.rs:3-14`); `execution_nonce_store.rs` 710-711
fixed (`:719-724`); `agent_web_replay_store.rs` 735 fixed (`:735`, `:929`);
`approval.rs` 959 fixed (`:736-745`, `:932`); `budget_split.rs` 383 intentional
exhaustion (`:415-417`, commented); `authority.rs` 262/277 intentional bounds.

## Verified clean

- Caller start deadlines (`881823ced2`): the live presentation must equal the retained
  issuance (`admission_coordinator/execution_nonce.rs:106-110`), request material is
  compared with the retained request (`preparation.rs:61-75`), the deadline is a `min`
  over capability, approval, DPoP, nonce and declassification expiries
  (`preparation.rs:97-137`), and consumers only shrink it (`caller.rs:206`). A caller
  cannot extend its deadline.
- Budget atomicity: every grant-usage and hold write runs inside an IMMEDIATE
  transaction and a compare-and-set; no read-modify-write spans statements unguarded.
- In-memory budget preparation: duplicate quota keys cannot reach
  `prepare_accounting` because quotas are strictly sorted and unique
  (`budget_store.rs:156-163`), and legacy and composite holds are mutually exclusive.
  Post-publication `?` paths in reversal depend on earlier validation, not on
  construction; I found no reachable failure.
- No checked arithmetic on money or deadline paths maps an error to a permissive
  default; `require_live_nonce` and reconciliation saturate to `i64::MAX`, which denies.
- Replay windows: nonce validity (`now < expires_at`) and store retention
  (`now_ms < expires_at * 1000`) agree; signed DPoP markers need both the epoch and the
  monotonic deadline before reclamation (`replay_retention.rs:165-179`), so a forward
  wall jump cannot evict them early; a wall regression is refused by every fence.
- Lease boundaries: acquisition conflicts while `expires_at > now` and heartbeat
  requires `expires_at > now`, so the boundary is consistent; tokens persist in SQLite
  and no path deletes lease rows.
- Seccomp plan validation (`chio-cage-plan/src/seccomp_plan.rs:289-353`): the only
  comparison is `Equal`, so the `prlimit64` pid constraint cannot be inverted; decode
  uses the same validator.
- Keyring startup resumption (`4c35ce7867`): the check-then-rotate window is closed by
  the exclusive selector owner; startup cannot invent a rotation.
- House rules in the slice's changed source: no em dashes, no process vocabulary, no
  `unwrap`/`expect` outside test, fuzz or Kani scope.

## Recommendations for the remaining plan

1. Before any further 4A ratchet, remove the thread-local time override (AC1) and
   route the AC2 paths through `authority_clock()`; only then is the remaining-site
   count meaningful.
2. Re-scope the clock gate to the trust-boundary inventory and count `SystemClock`
   references outside composition roots (AC3). Expect the count to rise; report that
   as measurement, not regression.
3. Make the lease token a required argument of run and step writers (AC4), or stop
   describing the leases as fenced.
4. For the 85 pending arithmetic rows, report fixes separately from fixture
   dispositions; 320 of the 553 classified rows are fixtures, and only 133 are repairs.
5. Treat Packet 8's exit as open until a new money module outside the path-word scope
   would fail a gate; today `finding_pool.rs` and `kernel/validation.rs` are outside it.
