# Security code quality review, pass 2, September 26, 2026

Reviewed candidate: `3cd73631a18a6ec169b1e1a5bbd3ebe8bcb00130` on draft
[PR #1160](https://github.com/bb-connor/arc/pull/1160), plus the uncommitted
Packet 1 working tree.

Third review in the lineage. It does not restate the September 25 boundary review
(retained at `/tmp/chio-security-review-24b995/security-roadmap-review.md`), the
[remediation record](2026-09-25-security-roadmap-remediation.md), or
[pass 1](2026-09-26-security-code-quality-review.md), which covered gate
measurement integrity, the execution-mode binding's design, and clock
abstraction.

This pass covers ground none of them touched: memory safety and fork safety in
the cage, cryptographic domain separation, arithmetic and build-profile parity,
error taxonomy, and the measurable strength of the negative test corpus.

Findings are numbered `R`. Pass 1 used `Q`; the September 25 review used `P1`
and `P2`.

**Judgment: the low-level engineering is better than the reviews so far have
given it credit for. The cage's fork-safety discipline and the money path's
guard placement are both exemplary. The two findings that matter are not defects
in that code, they are missing backstops underneath it: release builds disable
the arithmetic check that tests rely on, and the error taxonomy discards the
provenance that Packet 1's and Packet 4's own acceptance criteria require in
order to be provable.**

## R1. High: release builds disable overflow checks, so tests and production have different arithmetic semantics

`[profile.release]` in the workspace manifest sets `codegen-units`, `lto`,
`strip` and `panic`. It does **not** set `overflow-checks`, so Cargo's release
default of `false` applies. `[profile.dev]` and `[profile.test]` keep it on, and
the manifest comment at line 333 says so explicitly: "Debug-assertions and
overflow-checks are unaffected (still on), so test behaviour is unchanged."

`[workspace.lints.clippy]` denies `unwrap_used` and `expect_used` only.
`arithmetic_side_effects` and `indexing_slicing` are not denied, and the block's
own comment invites tightening ("When tightening the policy, for example adding
`panic = "deny"`, edit it here only").

The consequence is a semantic split on the one class of bug that matters most in
a system built on budgets, exposure units, quotas, lease counters, receipt
sequence numbers and generation counters:

| Build | `remaining - cost` when `cost > remaining` |
| --- | --- |
| `cargo test` | panics, test fails, defect found |
| `cargo build --release` | wraps to ~1.8e19, becomes an effectively unlimited budget |

A `u64` underflow in an exposure calculation does not produce a small error. It
produces the largest representable value, which in a ceiling comparison reads as
unlimited authority. The direction of the failure is maximally unsafe and it is
silent.

**What is not wrong:** every money-path subtraction I sampled is correctly
guarded, and one is guarded twice.

| Site | Guard |
| --- | --- |
| `chio-kernel/src/budget_store/in_memory/terminal.rs:719, :733` | `:649` `hold.remaining_exposure_units < cost_units`, `:709` `entry.total_cost_exposed < cost_units` |
| `chio-store-sqlite/src/budget_store/trait_impl.rs:1048` | `:972` same-transaction check before the second `ensure_open_hold` read |
| `chio-store-sqlite/src/budget_store/composite/transitions/terminal.rs:73, :77` | `:57` and `:67` in Rust, **plus** a SQL-level `AND remaining_exposure_units >= ?9` in the UPDATE at `:91` |

I initially suspected the composite path because its Rust guard names
`usage.total_cost_exposed` while the subtraction names `hold.remaining_exposure`.
It is guarded: line 57 checks the hold quantity as well. The code is more careful
than the hypothesis.

**Why it is still a high finding.** That correctness rests on eight
hand-maintained comparisons spread across **four separate implementations of one
invariant** (in-memory store, SQLite store, composite transitions, and the
formal models in `kani_harnesses.rs` / `formal_aeneas.rs`, which subtract
unguarded because Kani proves the bound). Only the composite path has a
database-level backstop. There is no type, no lint and no release-build check
that would catch a fifth implementation, or a future edit to any of the four,
getting it wrong. The test suite cannot catch it either, because the wrap only
happens in a profile the tests never run under.

**Fix, in order of value:**

1. `overflow-checks = true` in `[profile.release]` and `[profile.docker-release]`.
   For a fail-closed security kernel a panic on overflow is the correct outcome:
   it is an availability fault instead of a silent authority grant, which is the
   same reasoning the manifest already gives for denying `unwrap_used`. Measure
   the cost on the release benchmark rather than assuming it.
2. An `ExposureUnits` newtype whose only subtraction is `try_sub(self, other) ->
   Result<Self, BudgetStoreError>`. One implementation of the invariant, enforced
   by the type, in every store. This is the durable fix; the profile change is
   the backstop.
3. `arithmetic_side_effects = "deny"` scoped to the budget, quota and
   counter modules, with reviewed `#[allow]` at sites where a bound is proved.
4. Carry the SQL-level `>=` guard into the other stores' UPDATE statements so the
   database refuses the write even if the Rust check is bypassed.

**Confidence:** high on the profile and lint state, which are direct manifest
reads. The absence of a current defect is sampled, not exhaustive: 321 files use
`checked_*` and there are 632 `saturating_*`/`wrapping_*` occurrences in these
crates, which I did not audit individually. A `wrapping_*` in an accounting path
would be a defect; that sweep is worth running.

## R2. High: the error taxonomy discards rejection provenance, which blocks Packet 1 and Packet 4 acceptance

Two independent collapses compound.

**Collapse one: the inner cause is discarded.** `map_err(|_| ...)` appears **112
times** in `chio-quarantine` plus the kernel's response coordinator: 26 in
`state_machine.rs`, 21 in `blast.rs`, 16 in `correlation.rs`, 12 in
`executor.rs`, 10 in `scheduler.rs`, the rest spread thinner. Each one throws
away what actually failed. The new Packet 1 code does it too:

```rust
plan.require_execution_mode(ResponseExecutionMode::Live)
    .map_err(|_| StateMachineError::InvalidDispatch)?;
```

`ResponseShapeError::InvalidExecutionBinding` is computed and immediately
dropped.

**Collapse two: the outer variant is shared by unrelated rules.**
`StateMachineError` has 17 variants
(`state_machine_parts/canonicalization_and_errors.inc:360`), all with
category-level messages. `InvalidDispatch` ("response dispatch authorization is
invalid") is produced at **6 distinct sites in `state_machine.rs` alone**,
covering at minimum: wrong execution mode, capability digest mismatch, zero
executor generation, authorization timestamp outside the plan window, initial
lease outside the plan window, and approval-requirement versus commit-mode
mismatch.

So six different security rules, each rejecting for a different reason, are
indistinguishable to the caller, to a receipt, to an operator reading a log, and
to a test.

**Pass 6 correction and sharpening.** The enum has 17 variants, not the 12 first
counted from a truncated read, and two of the five missed are
`Shape(#[from] ResponseShapeError)` and `Store(#[from] PortError)`: variants that
preserve their source already exist in this enum. The new mode check computes a
`ResponseShapeError` and writes `.map_err(|_| InvalidDispatch)`, discarding a
cause that `?` would have kept for free. The six `InvalidDispatch` return sites
(`:685`, `:687`, `:696`, `:707`, `:715`, `:878`) cover at least eleven distinct
conditions; the `||` chain at `:689-696` alone carries six.

**This is not a cosmetic finding. It blocks two packets' stated exits.**

Parent plan Packet 1 requires tests that "Cover all six effect kinds, both
approval requirements, missing/expired approval, stale scope, overlap, both
expiry orders, rollback conflict, receipt failure, restart and cross-mode
replay." Every one of those rejections currently surfaces as
`InvalidDispatch`. A test for "expired approval" and a test for "cross-mode
replay" assert the same value, so neither test can demonstrate it exercised the
rule it is named after. Both would still pass if the rule under test were
deleted and an unrelated earlier check rejected the input first.

Parent plan Packet 4 requires the semantic oracle "a malformed or rebound
envelope grants no authority." With one variant, the oracle cannot distinguish
"rejected by the binding check" from "rejected because the fuzzer produced bytes
that failed canonical decoding three checks earlier." That is the standard reason
a fuzz campaign reports trust-boundary coverage it does not have.

**Fix:** give each rule its own variant, or a single `InvalidDispatch` carrying a
`DispatchRejection` enum discriminant. Replace `map_err(|_| ...)` with
`#[source]` chaining via `thiserror` so the inner cause survives. Then the
Packet 1 tests can assert the specific rejection, and the Packet 4 oracles can
assert *which* boundary refused. Do this before writing Packet 1's test corpus,
because retrofitting assertions across a corpus written against one variant is
strictly more work than writing them against many.

**Confidence:** high. Variant count, production site count and discard count are
all direct measurements.

## R3. Medium: 39 percent of negative assertions in the security crates only assert that something failed

Measured across `crates/security`, `chio-kernel` and `chio-control-plane`:

| Assertion strength | Count | Share |
| --- | --- | --- |
| Weak: `assert!(x.is_err())` | 213 | 39% |
| Medium: asserts on `unwrap_err()` / `err()` | 239 | 44% |
| Strong: `matches!(.., SpecificError::Variant)` | 91 | 17% |

The engineering acceptance contract in `docs/security/launch-plan.md` already
states the rule: "Negative controls must fail for the intended reason." It is
stated and 39 percent unenforced.

A weak negative assertion in a fail-closed system is close to vacuous, because
almost any mistake produces an error. It passes if the code rejects for the wrong
reason, if an unrelated earlier validation rejects first, and in many cases if
the feature under test does not exist.

R2 is partly the cause, not just a companion: with six rules sharing
`InvalidDispatch`, a conscientious author writing a negative test has nothing
stronger than `is_err()` available. Fixing R2 is what makes fixing R3 possible,
which is why R2 should land first.

**Fix:** after R2, convert the 213 weak assertions to specific-variant
assertions, prioritizing the response, broker, keyring and cage boundaries. Add a
gate that fails on a new bare `assert!(..is_err())` in the security crates. Pair
each conversion with the mutation check from standard rule 7.2: break the rule
deliberately and confirm the test now fails for the named reason.

**Confidence:** high on the counts. The classification is a regex heuristic, so
treat the shares as accurate to a few percent, not exact.

## R4. Medium: eight signature domain-separation strings are re-declared per crate instead of imported

243 domain-separation constants exist across the workspace. **Eight byte strings
are declared in more than one place:**

| Domain string | Declarations |
| --- | --- |
| `chio.response-affected-set.v1\0` | `chio-security-types/src/ports_parts/part_01.rs:38` as **`pub const RESPONSE_AFFECTED_SET_DOMAIN`**, plus private copies in `active_response_coordinator.rs:58`, `active_response_admission.rs:19`, and a test |
| `chio.response-effect.v1\0` | `chio-quarantine/src/state_machine.rs:31`, `active_response_coordinator.rs:59`, a test |
| `chio.response-request.v1\0` | `chio-quarantine/src/state_machine.rs:32`, `chio-core-types/src/receipt/security_parts/definitions_and_projection.inc:31` |
| `chio.response-transition.v1\0` | `chio-quarantine/src/state_machine.rs:33`, `definitions_and_projection.inc:32` |
| `chio.runtime-replay-source-seal.v1\0` | `chio-runtime-core/src/replay_source.rs:16`, `chio-kernel/src/admission_operation/runtime_replay.rs:15`, plus 4 test literals |
| `chio.verified-security-event-evidence.v1\0` | `chio-control-plane/src/security/event_consumer_parts/part_01.inc:76`, `chio-store-sqlite/src/security_state_parts/part_01.rs:111`, a test |
| `chio.fincred.source-artifact.v1\0` | `chio-credentials/src/financial.rs:15`, `chio-credit/src/financial_credentials.rs:33` |
| `chio.fincred.source-disclosure.v1\0` | same two crates |

The first row is the clearest case: a canonical `pub const` already exists in the
shared types crate, and the kernel declares its own private copies of the same
bytes anyway rather than importing it. Note also that the *names* differ across
copies (`EFFECT_ID_DOMAIN` versus `RESPONSE_EFFECT_ID_DOMAIN`,
`TRANSITION_ID_DOMAIN` versus `RESPONSE_MUTATION_ID_DOMAIN`), so a grep by name
does not find the duplication; only a grep by value does.

**This is not a signature-confusion vulnerability today.** The strings match, so
producer and verifier agree. It is a drift landmine with a cryptographic blast
radius: the day one copy is bumped to `.v2`, the others keep signing or verifying
under `.v1`. Because several of these pairs are a producer in one crate and a
verifier in another, the failure mode is a silent disagreement about identity
between two components rather than a compile error. Four of the eight are in the
`chio.response-*` family, which is exactly the surface Packet 1 is modifying.

Separately: 14 domains are not null-terminated while the dominant convention
appends `\0` (for example `chio-decoy-*-v1`, `chio-revocation-oracle:v1:epoch-root`,
`chio:active-defense-evidence-id:v1`). Three naming conventions coexist
(`chio.a.b.v1\0`, `chio-a-b-v1`, `chio:a:b:v1`). Unterminated, variable-convention
domain prefixes are how length-extension and prefix-ambiguity mistakes get made
later, even where the current uses are safe.

There is also a constant literally named
`PLACEHOLDER-SIGNATURE-OVERRIDE-IN-PRODUCTION` in the domain set. It should be
confirmed unreachable in a release build, and ideally made
`#[cfg(any(test, feature = "test-support"))]` so it cannot be.

**Fix:** one module owns every domain constant, exported `pub`, imported
everywhere else. Add a gate that extracts all domain byte strings and fails on a
duplicate value or a non-conforming shape (single convention, always terminated).
Gate the placeholder behind a test-only cfg.

**Confidence:** high. Values and locations are direct measurements; the drift
risk is a judgment, and the absence of current signature confusion was confirmed
by checking that each duplicate pair covers the same logical payload.

## R5. Verified clean: five sweeps with no findings

Recorded so no one repeats them. Two of these are genuinely excellent and worth
preserving deliberately during any refactor.

**Fork safety in `pre_exec` is exemplary.** Between `fork` and `exec` only
async-signal-safe operations are legal; allocating or taking a lock there can
deadlock against a malloc lock held by another thread at fork time. All three
reviewed closures are clean:

- `chio-cli/src/cli/process_host/runner/child.rs:250` calls only `prctl`,
  `getppid` and `setrlimit`, iterates a `Vec` captured by move without
  allocating, and constructs errors only via `io::Error::last_os_error()` and
  `from_raw_os_error()`, both of which wrap an `i32` and do not allocate. It also
  implements the PDEATHSIG race guard correctly: set `PR_SET_PDEATHSIG`, then
  re-check `getppid() != parent` and fail with `ECHILD`, which closes the window
  where the parent dies between spawn and prctl.
- `chio-cli/src/supervise/descriptor_credentials.rs:140` calls only `fcntl`.
- `chio-cli/src/cli/dispatch/finding/verified_fix.rs:761` calls only `setrlimit`.

None uses `io::Error::new(kind, String)`, which would allocate. That is a
non-obvious discipline applied consistently.

**Seccomp posture is correct.** `default_action` is `KillProcess` at every
construction site, and it is re-asserted at the enforcement boundary
(`launch/linux.rs:29`, `sandbox.inc:52`, `bootstrap.inc:1179`), so a plan that
weakens it is rejected by the helper rather than trusted. Architecture is
validated in Rust (`sandbox.inc:1043`, `current != plan.architecture`) and the
BPF prologue is delegated to `seccompiler`'s `target_arch`. The x32 ABI concern
on x86_64 is neutralized by default-deny: an `__X32_SYSCALL_BIT` syscall number
matches no allow rule and reaches `KillProcess`.

**`unsafe` is documented.** 101 `unsafe` occurrences in `chio-cage`, confined to
the OS boundary modules, with SAFETY comment counts matching or nearly matching
unsafe counts per file (`linux.rs` 11/11, `launch.rs` 3/3, `part_02.rs` 38/39,
`bootstrap.inc` 23/23, `sandbox.inc` 22/25). The two small shortfalls are worth a
targeted pass but the discipline is real.

**Schema version comparisons are exact.** Zero `>=`, `<=`, `>` or `<`
comparisons against a schema version constant anywhere in the security crates,
kernel, control plane or core types; 13 files use exact `==` / `!=`. This is the
correct closed-schema pattern and it eliminates the version-downgrade vector
outright. Preserve it.

**Money-path subtraction guards.** See R1: all sampled sites guarded, one
double-guarded at the SQL level.

## R6. Test coverage gaps worth naming

Not defects, absences.

- **No test asserts that a foreign-architecture or x32 syscall is killed.** Arch
  validation is delegated to `seccompiler`'s prologue and is untested locally, so
  a `seccompiler` upgrade that changed prologue behavior would pass CI. Add one
  native probe.
- **No test asserts the release profile's arithmetic behavior.** By construction
  the test profile cannot exercise it. After R1's fix, add one release-profile
  check that an overflow aborts rather than wraps.
- **No inventory of `wrapping_*` in accounting paths.** 632
  `saturating_*`/`wrapping_*` occurrences exist in these crates. `saturating_sub`
  in an exposure calculation silently clamps to zero, which is a different wrong
  answer than a wrap but still a wrong answer. Worth one targeted sweep.

## Sequencing consequences

R1's profile and lint change belongs in pass 1's Packet 0, which is already the
build and gate integrity packet. It is a two-line manifest change plus whatever
the resulting release-build failures reveal, and it should be measured on the
benchmark before it is accepted.

**R2 should land before Packet 1's test corpus is written**, not after. It is the
only finding in either pass that gates another packet's ability to demonstrate its
own exit criteria. Writing the corpus first means rewriting it.

R3 follows R2 mechanically and can be spread across packets as each boundary is
touched.

R4 is small, self-contained, and best done while Packet 1 is already editing the
`chio.response-*` family.

R6's probes attach to the packets that own their boundaries: the arch probe to
Packet 2's native lane, the arithmetic check to Packet 0, the `wrapping_*` sweep
to Packet 3's storage work.
