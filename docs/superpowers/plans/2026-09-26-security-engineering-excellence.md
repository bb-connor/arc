# Security Engineering Excellence Addendum

> **For agentic workers:** Use superpowers:executing-plans. This extends the
> [assurance closeout plan](2026-09-25-security-assurance-closeout.md); it does not
> replace it. Preserve the single-agent execution instruction and one Cargo owner
> per checkout. Every constraint in the parent plan still applies.

**Goal:** Make the security TCB's invariants enforced rather than conventional,
make the gates and build profiles that bound its risk actually measure it, and
remove the one obstacle that prevents two parent packets from demonstrating their
own exit criteria.

**Source:** findings Q1 to Q6 in
[quality review pass 1](../../reviews/2026-09-26-security-code-quality-review.md),
R1 to R6 in
[pass 2](../../reviews/2026-09-26-security-code-quality-review-pass-2.md), and
P1 to P8 in
[performance pass 3](../../reviews/2026-09-26-security-performance-review-pass-3.md),
S1 to S6 in [pass 4](../../reviews/2026-09-26-security-review-pass-4.md), and T1 to T2
in the [unrepresentable-defects design](../specs/2026-09-26-unrepresentable-defects-design.md)
(pass 5), re-verified by the [pass 6](../../reviews/2026-09-26-review-validation-pass-6.md)
and [pass 7](../../reviews/2026-09-26-review-validation-pass-7.md) validations,
against `3cd73631a1` plus the uncommitted Packet 1 tree. Standing rules live in the
[security engineering standard](../../security/engineering-standard.md).

## Revised execution order

```
Packet 0   build, gate and measurement integrity     <- NEW, before parent Packet 1
Packet 1   production signed response dry-run        (parent)
             + 1D  error taxonomy          <- FIRST, gates Packet 1's own test corpus
             + 1A  binding unconstructible
             + 1B  fresh and resume authority types
             + 1C  legacy provenance, obligation-inventory retirement
             + 1E  domain constants
Packet 2   prove repaired boundaries                 (parent) + 2A arch probe
                                                              + 2B syscall key validation
Packet 3   retention liveness                        (parent) + 3A wrapping sweep
Packet 4   fuzz and model linkage                    (parent) + 4A clock port
                                                              + 4B assertion strength
Packet 5   delivery blockers                         (parent, unchanged)
Packet 6   freeze, qualify, review, deliver          (parent, unchanged)
Packet 7   structural remediation                    <- NEW, after Packet 6
Packet 8   accounting type safety                    <- NEW, after Packet 7
Packet 9   measurement and hot-path cost             <- NEW, 9.1 can start any time
Packet 10  state recovery and isolation boundaries   <- NEW, 10.1 is COUPLED to Packet 0.2
```

The external review of September 26 corrected four designs in this order (1B, 1C,
10.1, 10.3) and the aggregation contract in 9.2; the corrected text is in place
below and the dispositions are in
[the review response](../../reviews/2026-09-26-external-design-review-response.md).
The sequencing rule it set is adopted: finish the bounded production dry-run and
its recovery and fuzz evidence first; keep gate work and CI repair independent;
defer broad connection, module and toolchain migrations to separately reviewable
changes with their own qualification.

Packet 9's first task (benchmark coverage) has no dependency on any other packet
and changes no production code, so it can run in parallel with Packet 0 whenever a
second checkout is available. Everything else in Packet 9 waits for it, because
those changes should be justified by a measurement rather than by a code read.

Three sequencing claims, in order of how much they matter:

1. **Correction 1D comes before Packet 1's test corpus is written.** This is the
   highest-value item in either review pass, and not because it is the most severe.
   Packet 1's exit requires tests distinguishing missing approval, expired
   approval, stale scope, overlap, both expiry orders, rollback conflict and
   cross-mode replay. All of those currently reject with the single value
   `StateMachineError::InvalidDispatch`, so those tests cannot demonstrate they
   exercised the rule in their own name, and Packet 4's fuzz oracles cannot tell a
   real boundary refusal from an earlier incidental one. Writing the corpus first
   means rewriting it.
2. **Packet 0 comes before Packet 1.** It is tooling-only, it is small, and every
   later packet adds code to modules the hygiene gate cannot measure and to
   profiles whose arithmetic semantics the tests cannot see. Fixing it later means
   re-baselining against more debt.
3. **Corrections 1A, 1B, 1C and 1E are cheapest now**, while the execution-mode
   binding is uncommitted and has exactly five call sites and four duplicated domain
   constants. Once the dry-run evaluator, the signed simulation report and the
   kernel and scheduler wiring land on top, the same changes touch far more code.

A reproduced P0 or P1, or a failing security invariant, still takes priority over
this order.

---

### Packet 0: Build, gate and measurement integrity

**Owners:** `Cargo.toml` (workspace lints and profiles),
`scripts/check-rust-file-hygiene.py`,
`scripts/tests/check-rust-file-hygiene.test.sh`, the workspace format gate,
`rustfmt.toml`, and two new gate scripts.

**Contract:** A gate that cannot see the code it governs, and a release profile
that drops a check the tests depend on, both produce false assurance. No
production code changes in this packet.

#### 0.1 Hygiene gate measures assembled modules (Q1)

- [ ] Resolve `include!` transitively and attribute fragment lines to the
      including module. Measure the assembled total against `PRODUCTION_LIMIT`.
      Fail loudly on an unresolvable `concat!`/`env!` include rather than skipping
      it silently.
- [ ] Add `.inc` to `TEXT_HYGIENE_SUFFIXES` and `TEXT_HYGIENE_PATTERNS`. Expect
      zero new violations: the em-dash scan is currently clean across all 79
      fragments, so this converts discipline into enforcement at no cost.
- [ ] Extend the self-test with a deliberately violating fixture: a parent plus a
      fragment that together exceed the cap, and a fragment containing an em dash.
      The self-test must fail without the fix.
- [ ] Make `cargo fmt --check` reach fragments, or record in the gate that
      fragments are unformatted and fail on any new `.inc` file. Do not leave the
      format gate silently blind.
- [ ] Run the gate, capture the expected red across the 46 over-cap logical
      modules, and allowlist each at its measured size through `--ratchet`. Commit
      the baseline as debt with expiries, not as configuration.
- [ ] Record the measured baseline (logical size, fragment count, gate-visible
      size) in the ledger so Packet 7 can be sequenced against real numbers.

#### 0.2 Release profile keeps overflow checks (R1)

- [ ] `overflow-checks = true` in `[profile.release]` and
      `[profile.docker-release]`. Justify it in the manifest comment with the same
      reasoning already given for `unwrap_used`: in a fail-closed kernel an
      overflow panic is an availability fault, and a silent wrap is an authority
      grant.
- [ ] Build the release profile and run the existing release-tier tests. Any new
      panic is a real latent defect: triage it, do not suppress it.
- [ ] Measure the cost on the existing release benchmark and record the delta. If
      it is material on a specific hot path, fix that path with a newtype per
      Packet 8, do not turn the check back off.
- [ ] Add one check that runs under the release profile and asserts an overflow
      aborts rather than wraps, since no ordinary test can observe this (R6).
- [ ] **Land Packet 10.1 in the same packet.** Enabling overflow checks adds panic
      sites to arithmetic inside store critical sections, and four stores currently
      poison their connection mutex permanently on a panic (finding S1). Shipping
      0.2 alone trades a silent budget wrap for a permanently unavailable money
      store. The two are coupled; say so in the ledger (standard rule 14.2).

#### 0.3 Accounting arithmetic lint (R1)

- [ ] `arithmetic_side_effects = "deny"` scoped to the budget, quota, counter and
      lease modules. Reviewed `#[allow]` at sites where the bound is proved; a Kani
      harness under a proved precondition qualifies, a store path does not.
- [ ] Leave the workspace-wide policy unchanged in this packet. Widening it is a
      separate, larger decision.

#### 0.4 Domain-separation gate (R4)

- [ ] New gate that extracts every domain byte string in the workspace and fails
      on: a value declared in more than one place, a value not matching
      `chio.<area>.<payload>.v<N>\0`, or a placeholder domain reachable outside
      `#[cfg(any(test, feature = "test-support"))]`.
- [ ] Self-test with a duplicate and a malformed fixture.
- [ ] Expect red on the 8 duplicates and 14 unterminated values. Allowlist the
      unterminated ones with expiries; fix the 8 duplicates in correction 1E and in
      follow-ups for the non-response families.

#### 0.5 Assertion-strength gate (R3)

- [ ] New gate that fails on a *newly added* bare `assert!(..is_err())` in the
      security crates, with the existing 213 recorded as a shrinking baseline.
      Ratchet only downward, same discipline as the hygiene allowlist.
- [ ] Do not attempt to convert the existing 213 in this packet. They depend on
      correction 1D and on per-boundary work in 4B.

**Exit:** The hygiene gate measures assembled modules; release builds keep
overflow checks with a recorded cost; accounting modules deny unchecked
arithmetic; domain duplication and weak assertions have gates with shrinking
baselines; every new gate fails on its own violating fixture.

**Do not:** raise `PRODUCTION_LIMIT`, add a blanket `.inc` exemption, disable
`overflow-checks` again to recover benchmark numbers, or split further files with
`include!` to get under the new measurement.

---

### Correction 1D: Restore rejection provenance before writing the test corpus

**Owners:** `chio-quarantine/src/state_machine_parts/canonicalization_and_errors.inc`,
`chio-quarantine/src/{state_machine,executor,scheduler,approval,blast,correlation}.rs`,
`chio-kernel/src/kernel/active_response_coordinator.rs`.

Addresses R2. **Do this first within Packet 1.** It is the only item in either
review pass that gates another packet's ability to demonstrate its exit criteria.

- [ ] Give each distinct rejection rule its own discriminant. Either separate
      `StateMachineError` variants or a single `InvalidDispatch(DispatchRejection)`
      whose payload names the rule. `InvalidDispatch` currently covers at least six
      rules in `state_machine.rs` alone: wrong execution mode, capability digest
      mismatch, zero executor generation, authorization timestamp outside the plan
      window, initial lease outside the plan window, and approval-requirement
      versus commit-mode mismatch.
- [ ] Replace `map_err(|_| ...)` with `#[source]` chaining so the inner cause
      survives. There are 112 such discards in the quarantine crate plus the kernel
      response coordinator (26 in `state_machine.rs`, 21 in `blast.rs`, 16 in
      `correlation.rs`, 12 in `executor.rs`, 10 in `scheduler.rs`). Prioritize the
      dispatch, approval and executor paths; the rest can follow per boundary.
- [ ] Do not let the discriminant leak attacker-supplied bytes. It names the rule,
      not the input.
- [ ] Confirm the rejection reason reaches the receipt and the operator log, not
      only the `Result`. A discriminant that is dropped before it is recorded has
      not solved the operator half of the problem.
- [ ] Then write Packet 1's test corpus against specific variants, and mutation-
      check each one per standard rule 10.2.

**Exit:** Every security rejection in the response path is distinguishable by a
caller, a receipt, a log and a test. Packet 1's and Packet 4's acceptance criteria
become demonstrable rather than nominal.

---

### Correction 1A: Make the execution binding unconstructible when invalid

**Owner:** `chio-security-types/src/response_execution.rs`.

Addresses Q2.

- [ ] Private fields with accessors on `ResponseExecutionBinding`. Add
      `ResponseExecutionBindingWire` with `deny_unknown_fields`, and
      `#[serde(try_from = "ResponseExecutionBindingWire")]` on the domain type, so
      deserialization is the validation point.
- [ ] Delete the detached `validate()` from the public surface once nothing can
      construct an unvalidated value.
- [ ] Carry expected and observed schema versions in the rejection, per correction
      1D's discriminant. Do not echo attacker-supplied bytes beyond the version
      number.
- [ ] Add a `compile_fail` or trybuild case asserting the invalid literal does not
      compile, and a test asserting an invalid payload fails to deserialize with
      the specific error.

**Exit:** An invalid binding cannot exist as a value, and the rejection is
diagnosable from a receipt.

---

### Correction 1B: Replace the manual mode checks with two authority types

**Owners:** `chio-security-types/src/response.rs`,
`chio-quarantine/src/state_machine.rs`,
`chio-kernel/src/kernel/{active_response_coordinator,active_response_committed_recovery}.rs`.

Addresses Q3. Land before the dry-run evaluator is wired, while the surface is six
call sites (`state_machine.rs:118`, `:684`, `:1000`;
`active_response_coordinator.rs:269`, `:281`).

- [ ] Introduce `FreshLiveAdmission`, whose only constructor requires provenance
      bound to the live mode, and `CommittedResumeAuthority`, constructible only
      inside the durable recovery verification and binding the exact operation,
      plan hash, tenant, dispatch and executor generation it verified. A single
      token parameterized by a caller-supplied commit mode is rejected by the
      external review's finding R1: it let a caller obtain authority for a legacy
      plan by naming a resume mode.
- [ ] Fresh dispatch and both kernel admission entry points accept
      `FreshLiveAdmission` only; resume paths accept `CommittedResumeAuthority`
      only. Fresh admission must not accept the resume type, as a compile error.
      Remove the duplicated inverse condition at `state_machine.rs:686-687`; each
      type carries its own rule exactly once.
- [ ] Confirm by construction that no live path accepts a bare `ResponsePlan`.
      Grep for remaining `require_execution_mode` callers and expect only the
      constructor.
- [ ] Negative tests, each asserting its `DispatchRejection` variant: a `DryRun`
      plan at every fresh entry point; a legacy plan at every fresh entry point; a
      legacy plan plus a caller-selected resume mode with no durable commitment;
      and a simulated plan that cannot populate recoverable live dispatch work.
- [ ] Record in the module docs that signature coverage of `execution` via
      `authorization_body()` is what blocks strip-to-legacy laundering, so a future
      change to the signed body does not silently remove that property.

**Exit:** Omitting the mode check is a compile error, fresh and resume authority
are distinct types with distinct constructors, a caller cannot reach the resume
rule by naming a mode, and the property that defeats laundering is written down
where the signed body is defined.

---

### Correction 1C: Give legacy tolerance a named variant and a sunset

**Owners:** `chio-security-types/src/response.rs`, the receipt schema v5 migration
note, `chio-store-sqlite` response dispatch readback.

Addresses Q4.

- [ ] Replace `Option<ResponseExecutionBinding>` with
      `PlanProvenance::{Legacy, Bound(ResponseExecutionBinding)}`. Matches become
      exhaustive and the three cases are named at every site.
- [ ] Separate two switches. Stopping new legacy admissions is one and may happen
      early. Retiring historical reconciliation is the other and requires an
      inventory of every unresolved obligation: admission commitments without a
      dispatch row (the kernel explicitly recovers a crash at that point,
      `active_response_committed_recovery.rs:365` and `:509`), dispatches in
      flight, retained preparations and cleanup obligations. A count of dispatch
      rows is not that inventory.
- [ ] Encode the retirement condition as: every inventoried obligation is
      terminal or explicitly migrated. Neither a zero row count nor an elapsed
      horizon is sufficient, per the external review's finding R2. Acceptance
      includes the exact case: crash after admission commitment and before the
      dispatch row, then migration, then restart, and the owed recovery completes.
- [ ] Record the inventory and the condition in the schema v5 migration note
      beside the existing forward-migration warning.

**Exit:** Legacy tolerance is named, new admissions can be stopped independently,
and reconciliation retires only when the obligation inventory is terminal.

---

### Correction 1E: One declaration per domain constant

**Owners:** `chio-security-types/src/ports_parts/part_01.rs`,
`chio-quarantine/src/state_machine.rs`,
`chio-kernel/src/kernel/{active_response_coordinator,active_response_admission}.rs`,
`chio-core-types/src/receipt/security_parts/definitions_and_projection.inc`.

Addresses R4 for the `chio.response-*` family, which Packet 1 is already editing.

- [ ] Import `RESPONSE_AFFECTED_SET_DOMAIN` from `chio-security-types` and delete
      the three private copies. It is already a `pub const` at
      `ports_parts/part_01.rs:38`; the kernel declaring its own copies is the
      clearest instance of the problem.
- [ ] Promote `chio.response-effect.v1`, `chio.response-request.v1` and
      `chio.response-transition.v1` to the same module and import them in
      `chio-quarantine`, the kernel coordinator and `chio-core-types`' receipt
      projection. Keep the byte values identical; this is a no-behavior-change
      commit and must be verified as one.
- [ ] Give the constants one name each. Four different names currently carry the
      same bytes (`EFFECT_ID_DOMAIN` versus `RESPONSE_EFFECT_ID_DOMAIN`,
      `TRANSITION_ID_DOMAIN` versus `RESPONSE_MUTATION_ID_DOMAIN`), which is why a
      grep by name missed the duplication.
- [ ] Production shares one declaration per value. Tests do **not** reference it:
      a test that reads the constant it exists to pin asserts nothing about its
      value and cannot detect a compatibility break (the external review's R10).
      Tests keep independent literal known-answer fixtures for the domain bytes and
      for digests computed over them.
- [ ] Leave the `chio.fincred.*` and `chio.runtime-replay-source-seal.*` families
      to follow-ups outside this packet; they are not on the response path.

**Exit:** The response-family domains have one declaration and one name each, the
Packet 0 gate passes for that family, and the commit provably changes no bytes.

---

### Correction 1F: Name the strict-canonicalization boundaries before adding a new signed payload (S2)

**Owners:** `chio-core-types/src/canonical.rs` (documentation only), the security
TCB crates' wire, file and database read boundaries.

Addresses S2. Do the enumeration inside Packet 1, because the signed simulation
report is new signed JSON crossing a boundary and is the natural place to pick the
wrong entry point.

- [ ] Enumerate every place in the security TCB where JSON *text* crosses a trust
      boundary and is then signed or digested: signed deployment configuration,
      signed cage manifests, broker wire payloads, stored `statement_json` and
      `raw_json` read back for verification, and the new signed simulation report.
- [ ] For each, record which canonicalization entry point it uses and why. The
      strict form (`canonical_json_bytes_from_str`) is required wherever the bytes
      originated outside this process; the typed form is correct only where the
      value was constructed in-process.
- [ ] Fix any boundary using the typed form on untrusted text. Treat a finding here
      as a P1, because it is a signature-equivalence bypass.
- [ ] Use the strict form for the simulation report's inputs where they arrive as
      text, and state that choice in the report's module docs.
- [ ] Preserve the `canonical.rs` doc comment verbatim. It is the only record of the
      render-A / sign-B reasoning and a refactor would quietly lose it.

**Exit:** Every signed-JSON boundary in the security TCB has a named entry point
and a recorded reason, and the new simulation report is not the first exception.

---

### Correction 2A: Prove the architecture check (R6)

**Owner:** the native x86_64 enforcement lane in parent Packet 2.

- [ ] Add one native probe asserting that a syscall issued under a foreign
      architecture or with the `__X32_SYSCALL_BIT` set is killed, not permitted.
      Architecture validation is currently delegated entirely to `seccompiler`'s
      BPF prologue and is untested locally, so a dependency upgrade that changed
      prologue behavior would pass CI.
- [ ] Add the probe to the mandatory native inventory count so it cannot be
      silently dropped.

**Exit:** The arch boundary is asserted by this repository, not assumed from a
dependency.

---

### Correction 2B: Make a syscall constraint key impossible to misspell (P8)

**Owners:** `chio-cage/src/lib_parts/part_02.rs`,
`chio-cage/src/launch/linux_parts/part_02.rs`, the cage plan validator.

Addresses P8 as corrected by pass 6. The launch-time subset check already exists
(`sandbox.inc:1086-1094` refuses a plan whose constraint names an unlisted
syscall), so this is reduced from a security fix to type design: move the check to
compile time or construction time, and remove the test helper's string drift. Belongs
with the cage work in parent Packet 2. The map is built once per launch, so it must
not be justified as an optimization either.

- [ ] Key `argument_constraints` by a closed `Syscall` type or the numeric syscall
      id so a nonexistent name cannot be expressed. If the string key must persist
      for serialization, keep it only at the wire boundary.
- [ ] Keep the launch-time subset check at `sandbox.inc:1086-1094` exactly as it
      is. Add the same check at plan construction so a bad plan fails when built,
      not when launched, and so one validator owns both that rule and the
      `prlimit64` constraint-removal refusal.
- [ ] Replace the literal `argument_constraints.remove("prlimit64")` at
      `launch/linux_parts/part_02.rs:1398` with the same typed key, so an insertion
      and a removal cannot drift and silently no-op.
- [ ] Add the negative test: a plan carrying a constraint for a syscall that is not
      in the allowed set is refused, asserting the specific rejection variant from
      correction 1D.
- [ ] Add the construction-time negative test: a plan with a constraint for an
      unlisted syscall is refused at build. The launch-time refusal already exists;
      `sandbox.inc:1077` compiling absent constraints as an unconditional allowance
      is unreachable for a misspelled key because `:1086` refuses the plan first.

**Exit:** A misspelled or stale constraint key is a compile error or a
construction-time rejection. (It is already a launch-time rejection.)

---

### Correction 3A: Sweep clamping arithmetic in accounting paths (R1, R6)

**Owner:** parent Packet 3's storage work.

- [ ] Inventory the 632 `saturating_*` and `wrapping_*` occurrences in the security
      crates, kernel and stores. Classify each as correct-by-intent or defect.
- [ ] A `wrapping_*` in an accounting, quota, counter or deadline path is a defect:
      fix it and add the regression.
- [ ] A `saturating_sub` in an accounting path silently clamps to zero, hiding the
      underflow a guard should catch. Convert to `checked_*` with explicit handling,
      or annotate why clamping is the correct semantics there per standard rule 4.3.
- [ ] Record the classification so the next reviewer does not redo the sweep.

**Exit:** Every clamping or wrapping operation in an accounting path is either
fixed or justified in one line at the call site.

---

### Correction 4A: One injected clock port for the TCB

**Owners:** `chio-security-types/src/ports.rs`, `chio-kernel-core/src/clock.rs`,
`chio-keyring/src/time.rs`, `chio-guards/src/external/cache.rs`, the security
composition roots.

Addresses Q5. Belongs with parent Packet 4, whose Kani and property obligations
depend on a deterministically drivable time source.

- [ ] Define one clock port with `UnixMillis` and `MonotonicInstant` as distinct
      types that cannot be compared or subtracted across the boundary, and an
      explicit fail-closed contract on a non-monotonic or unavailable reading.
- [ ] Migrate the three existing traits onto it. Do not add a fourth.
- [ ] Replace direct `SystemTime::now()` calls in production security paths with
      the injected port. Inventory first: 60 production files and 80 call sites, including
      `chio-control-plane/src/security/active_response.rs` and `keyring_runtime.rs`.
      Add a gate forbidding new direct calls in the TCB.
- [ ] Classify every deadline as monotonic-compared or epoch-signed, and state the
      skew policy once for the TCB rather than only in the broker's deployment
      config.
- [ ] Add property and Kani coverage now that time is injectable: wall-clock
      regression, skew at the policy boundary, `u64` overflow at the limits, and a
      retry that must not widen the original window.

**Exit:** One clock port, units in the type, skew policy stated once, no direct
`SystemTime::now()` in the TCB, deadline logic driven deterministically.

---

### Correction 4B: Convert the weak negative assertions (R3)

**Owner:** the security crates' test corpora, per boundary.

Depends on correction 1D: until rules have discriminants, there is nothing stronger
to assert.

- [ ] Convert the 213 bare `assert!(..is_err())` assertions to specific-variant
      assertions, in this order: response dispatch, broker credential, keyring
      rotation, cage admission, storage retention.
- [ ] Mutation-check each conversion: break the rule and confirm the test now fails
      for the named reason. A conversion that passes both before and after the
      mutation has asserted the wrong variant.
- [ ] Shrink the Packet 0.5 baseline by ratchet as each boundary completes.
- [ ] Apply the same standard to Packet 4's fuzz oracles: each oracle asserts which
      boundary refused, not merely that authority was absent.

**Exit:** Negative tests in the security crates fail for the intended reason, and
the gate baseline has shrunk to the boundaries not yet converted.

---

### Packet 7: Structural remediation

**Owners:** the 46 over-cap logical modules from Packet 0's baseline, highest-risk
first.

**Contract:** Convert textual fragments into real module boundaries, in priority
order, without changing behavior. Runs after parent Packet 6 and is sequenced by
the Packet 0 baseline, not by file size alone.

Priority is by trust-surface criticality, not line count:

| Rank | Logical module | Logical lines | Why first |
| --- | --- | --- | --- |
| 1 | `chio-security-types/src/ports.rs` | 5,033 | Defines the trait boundary every security adapter implements; 4 gate-visible lines |
| 2 | `chio-secret-broker/src/service.rs` | 5,087 | Held P1 #3; credential dispatch path; 3 gate-visible lines |
| 3 | `chio-store-sqlite/src/security_state.rs` | 13,473 | Durable security state; 14 fragments, nested |
| 4 | `chio-control-plane/src/security/*` fragments | varies | Active response, event consumer, scheduler worker: 22 fragments |
| 5 | `chio-kernel/src/kernel/tests.rs` | 40,754 | Test module; lowest risk, largest win in reviewability |

- [ ] For each module in rank order: convert `include!` fragments to `mod` with
      `#[path]`, then draw the privacy boundary. The conversion commit is a pure
      mechanical cut with no behavior change, verified by an unchanged test
      inventory and a reviewed diff containing no logic edits.
- [ ] Immediately after each cut, in a separate commit, restrict visibility:
      `pub(crate)` down to `pub(super)` or private wherever the compiler allows. The
      encapsulation, not the file split, is the deliverable. A cut that leaves
      everything `pub(crate)` has achieved nothing.
- [ ] Reassign responsibilities to the five categories in standard rule 1.1. A
      module that still mixes two of them after the cut is not done. Name modules
      after the responsibility, not the sequence number.
- [ ] Preserve invisible discipline during the cut. Specifically: the `pre_exec`
      closures are async-signal-safe by construction and the seccomp
      `default_action` is re-asserted at three boundaries. Add the comments from
      standard rules 9.5 and 9.4 before moving that code, so a later cleanup cannot
      break it silently.
- [ ] Run `cargo fmt` on the newly visible code as its own commit, so formatting
      noise never mixes with a logic or visibility diff.
- [ ] Shrink the Packet 0 allowlist entry for each module through `--ratchet`. Do
      not hand-edit caps.
- [ ] Re-run the affected owning test targets plus strict Clippy per module. A
      mechanical cut that changes a test result is not mechanical; stop and
      investigate.

**Exit:** The ranked modules have real module boundaries with minimized visibility,
responsibilities match rule 1.1, the allowlist has shrunk by ratchet, and no
behavior changed.

**Do not:** combine a cut, a visibility change, a format pass and a logic fix in
one commit. Do not split a file merely to satisfy a line count, which is the
mistake this packet exists to undo.

---

### Packet 8: Accounting type safety

**Owners:** `chio-kernel/src/budget_store/*`,
`chio-store-sqlite/src/budget_store/*`, quota and lease counters.

**Contract:** Replace the hand-maintained guard-before-subtract invariant with one
enforced by the type system. Packet 0.2's `overflow-checks` is the backstop; this
is the durable fix.

- [ ] Introduce `ExposureUnits` (and siblings for quota and lease counts) as
      newtypes whose only subtraction is `try_sub(self, other) -> Result<Self, _>`
      and whose construction validates range once.
- [ ] Migrate the four existing implementations of the release invariant onto it:
      `chio-kernel/src/budget_store/in_memory/terminal.rs` (guards at `:649`,
      `:709`), `chio-store-sqlite/src/budget_store/trait_impl.rs` (`:972`),
      `chio-store-sqlite/src/budget_store/composite/transitions/terminal.rs`
      (`:57`, `:67`), and the formal models in `kani_harnesses.rs` /
      `formal_aeneas.rs`, which may keep proved-precondition subtraction under a
      reviewed allow.
- [ ] Carry the SQL-level predicate into every store's UPDATE, not only the
      composite path. `AND remaining_exposure_units >= ?` at
      `composite/transitions/terminal.rs:91` is the reference shape: the database
      refuses the write even if the Rust check is bypassed.
- [ ] Add property tests over the newtype: subtraction below zero returns the
      specific error, addition at the `u64` ceiling returns the specific error, and
      no arithmetic path can produce a value the constructor would have rejected.
- [ ] Extend the existing Kani conservation harnesses to the newtype so the
      proof and the production type share one definition of the bound.

**Exit:** The exposure invariant has one implementation, enforced by a type, with a
database predicate underneath it and a proof above it. A fifth store cannot get it
wrong.

---

### Packet 9: Measurement and hot-path cost

**Owners:** `crates/platform/chio-store-sqlite/benches/`,
`receipt_store/reports/analytics.rs`, `receipt_store/bootstrap/open.rs`, the
per-operation store reads in `security_state_parts/*`, `budget_store/*`,
`global_commit_chain.rs`, `revocation_store.rs`,
`admission_operation_store/part_01.inc`.

**Contract:** Rank by cost growth, not by how inefficient a line looks. Per-operation
time here is dominated by Ed25519 and `fsync`, so an avoided allocation is noise and
a scan that grows with the data is a defect. No change in this packet lands without a
before-and-after number (standard rule 13.9).

#### 9.1 Close the measurement gap (P2) - start first, no production change

- [ ] Add benchmarks for the per-authorization composite operation (admission check
      plus budget charge plus security-state read plus receipt append), the budget
      charge/release pair, and the security-state read on the denial path.
- [ ] Populate to a realistic row count before measuring. A benchmark over an empty
      table measures the wrong thing whatever path it covers, and the existing
      receipt benchmark should be re-checked for this too.
- [ ] Record the baselines in the ledger. These numbers are what justifies or
      cancels 9.3 to 9.5.
- [ ] State plainly in the ledger that the retained million-receipt campaign proves
      receipt append scales and not that authorization scales (standard rule 13.10).

#### 9.2 Fix the analytics aggregate (P1) - independent of 9.1

- [ ] Aggregate over the existing typed `cost_charged_be` column
      (`receipt_store/bootstrap/open.rs:569`) instead of
      `json_extract(r.raw_json, '$.metadata.financial.cost_charged')`. The column
      is the eight big-endian bytes of a `u64` (`to_be_bytes()`), so SQL `SUM` or
      `CAST` on the BLOB is not decoding it (the external review's R9). The
      contract is exact: decode each row through a registered scalar function or
      in Rust after a typed fetch, accumulate in `u128` or checked `u64`, and give
      overflow a named error rather than a saturated value.
- [ ] Do the same for `attempted_cost`, adding a typed column if one does not exist.
- [ ] Replace the `(?N IS NULL OR col = ?N)` optional-filter shape so the six
      existing indexes on `timestamp`, `capability`, `subject`, `grant`, `tool` and
      `decision` become usable.
- [ ] Add a test that runs `EXPLAIN QUERY PLAN` and fails on a `SCAN` where an index
      is expected, so the shape cannot silently regress (standard rule 13.3).
- [ ] Bound the unfiltered case with a required time window or a rollup table.
- [ ] Do not require byte-identical output: the current JSON path saturates any
      value at or above 2^63 to 2^63 minus 1, a latent defect that "unchanged"
      would preserve. Confirm equality against a populated fixture for every value
      below 2^63, and add edge fixtures at 2^63 minus 1, 2^63, 2^64 minus 1 and a
      sum that overflows `u64`, each asserting the exact decoded result or the
      named overflow error. This is a financial report; the contract must be exact
      and stated.

#### 9.3 Statement caching on per-operation reads (P3)

- [ ] Switch the per-operation reads to `prepare_cached`, leaving schema, migration
      and `list_*`/reporting paths on `prepare`. Set the connection statement-cache
      capacity explicitly rather than relying on the default.
- [ ] Do not convert all 420 sites on faith. Convert the paths 9.1 shows on the
      authorization critical path and record the delta.

#### 9.4 Connection strategy (P4)

- [ ] Replace `Arc<Mutex<Connection>>` with a WAL-mode read pool plus a single
      writer in the 18 stores that carry it (pass 7 census), not only the four
      first named (`fiscal_store.rs:159`, `finding_challenge_store.rs:636`,
      `finding_purchase_store.rs:375`, `sealed_decoy_registry.rs:30`). The target
      shape already exists in the tree: 13 stores use `Pool<SqliteConnectionManager>`.
- [ ] Sequence this behind 9.1 and 9.3. It is a real concurrency change to durable
      stores and must not be made on the strength of a code read.
- [ ] Preserve every durability and fencing property: WAL mode changes crash
      semantics, so the Packet 2 process-cutpoint harness reruns against the new
      connection strategy before this is accepted.

#### 9.5 Redundant read on the charge path (P5)

- [ ] Fold the duplicate `ensure_open_hold` read in
      `budget_store/trait_impl.rs` (once for the guard near `:972`, again near
      `:1037`) into one, preserving the guard semantics pass 2 verified. Do this
      inside the 9.3 pass rather than as its own change.

**Exit:** The authorization path has benchmarks against a populated store, the
analytics aggregate reads a typed column with an asserted query plan, and every
other change in this packet cites a measured delta.

**Do not:** open a campaign to remove clones or replace collections. Findings P6
(digests as hex strings) and P7 (allocation density on the admission path) are
type-design work for Packet 7 and must be proposed as type-design work, not as
optimization (standard rule 13.9).

---

### Packet 10: State recovery and isolation boundaries

**Owners:** the seven SQLite stores' connection guards, `canonical.rs` consumers,
the 64 tenant-scoped tables, `receipt_store/bootstrap/open.rs` triggers.

#### 10.1 Phase-aware lock-poison recovery (S1, corrected by the external review's R3) - COUPLED to Packet 0.2

- [ ] Do not recover blindly. The first version of this item said "recover with
      `into_inner()`, because an aborted transaction rolls back." `Transaction::drop`
      discards the rollback result, an independent probe showed the recovered
      connection still inside a transaction with the uncommitted row readable, and
      every one of the 18 stores pairs commits with external anchors or filesystem
      state (`fiscal_store.rs:338` commits before its anchor sync).
- [ ] One shared helper that, on a poisoned lock, establishes state before returning
      the guard: `is_autocommit()`, an explicit `ROLLBACK` if a transaction is open,
      then the store's owner and anchor consistency check against the database head.
      Where any step fails or cannot be verified, the helper returns a named fenced
      error and the store stays fenced until reopened. Fail closed with a reason.
- [ ] Per-store classification, recorded at the call sites, across all 18
      mutex-guarded stores (22 files, 26 connection lock sites; the 13 pooled stores
      including the receipt store are not exposed): which stores pair a commit with
      an external artifact and what the consistency check is; which have no external
      pairing and all writes through RAII transactions, where recovery after a
      verified rollback is permitted with the reason stated.
- [ ] Four tests per store with specific outcomes, never "the next operation
      succeeds": panic before commit (rollback verified, next operation succeeds);
      panic with rollback made to fail through the authorizer (fenced, uncommitted
      row never read); panic after commit before the anchor write (refuse or
      reconcile per the store's contract, assert which); panic after anchor before
      acknowledgement (the store's prescribed recovery). Mutation check: blind
      recovery in place of the fence must fail the rollback-failure test.
- [ ] The coupling to Packet 0.2 stands with a changed argument: with fencing, a new
      arithmetic panic becomes a named fenced store instead of an anonymous permanent
      "unavailable", and that is the improvement the two changes deliver together.
      Decide with Packet 9.4 which stores move to the pool shape instead; where one
      does, the fence is removed in the same change.
- [ ] Do not reach for `parking_lot`: a non-poisoning mutex hides the panic.

#### 10.2 Type the untrusted-serialization boundary (S2)

- [ ] Introduce `UntrustedJsonText(String)`, constructed at every wire, file and
      database read boundary, whose only canonicalization method is the strict one.
- [ ] Migrate the boundaries enumerated by correction 1F onto it, so the permissive
      path is unreachable from untrusted input without an explicit conversion.
- [ ] Add a gate listing the constructors, so a new boundary that forgets the type
      is visible in review.

#### 10.3 Classify tenant scoping by the enforcing principal (S3, corrected by the external review's R4)

- [ ] Classify each of the 64 tenant-scoped tables by who is allowed to read it:
      tenant predicate required; privileged administrative read under a named
      principal; or an explicit bearer-capability contract where possession of an
      identifier is deliberately authority. "Unguessable derived identifier" is not
      a class: a content hash is computable from its inputs and identifiers appear
      in receipts and logs.
- [ ] Record the class next to the schema. Gate on statements touching a
      tenant-predicate table without the predicate.
- [ ] Every isolation test gives tenant B the exact valid identifier belonging to
      tenant A and requires denial, for every table in every class. None exists
      today.
- [ ] Resolve how `chio_tool_receipts.receipt_id` is produced first
      (`receipt/body.rs:240` derives it from the body); if unscoped reads on it are
      meant to be authorized by possession, that is a bearer contract to specify,
      not a property to assume. If no such contract is intended, the 72 unscoped
      statements are a possible cross-tenant read and this becomes a P1.
- [ ] Typed derivation (standard rule 14.7, following `enterprise_receipt.rs:414`)
      is still worth having for collision resistance and construction discipline;
      it is not the isolation mechanism and is not recorded as one.

#### 10.4 One parser for signed data, and constrained columns (S4)

- [ ] Bind `previous_checkpoint_sha256` from the verified typed struct as a
      parameter and have the triggers copy the column instead of calling
      `json_extract` on signed `statement_json`
      (`receipt_store/bootstrap/open.rs:1361`, `:1376`, `:1379`, `:1400`).
- [ ] Add a `CHECK` constraint on the projected chain-link columns' hex shape,
      matching the discipline `cost_charged_be` already has at `open.rs:569`.
- [ ] Leave `kernel_checkpoints_enforce_append_only` exactly as it is. Its
      append-only structural enforcement is correct and is defense in depth at a
      second mechanism, which the standard encourages.
- [ ] Sequence with parent Packet 3's storage work; this touches receipt-store
      schema and must not run concurrently with the retention changes.

**Exit:** Poison policy is uniform and tested, untrusted serialized text is a type,
every tenant-scoped table has a recorded and gated classification, and no signed
field is re-derived by a second parser.

---

## Acceptance for this addendum

- Every new gate in Packet 0 fails on its own deliberately violating fixture
  before the fix and passes after (standard rule 12.6).
- Correction 1D lands before Packet 1's test corpus, and Packet 1's negative tests
  assert specific variants.
- Corrections 1A, 1B, 1C and 1E land inside parent Packet 1's reviewable commit,
  not as follow-ups. 1E is provably byte-identical.
- Correction 4A lands with parent Packet 4, and no new direct `SystemTime::now()`
  appears in the TCB after its gate exists.
- Packet 7 changes no behavior, and each module's cut, visibility restriction and
  format pass are separate commits.
- Packet 8 leaves one implementation of the exposure invariant, and Packet 0.2's
  `overflow-checks` stays on regardless of Packet 8's progress.
- Every item is subject to the parent plan's evidence rules: source SHA, command,
  inventory count, tool versions. Focused regressions per change, full
  qualification on the frozen candidate.
- Packet 9 lands no change without a before-and-after number, and 9.2's aggregate
  values are proved identical against a populated fixture before the query changes.
- Correction 2B is reviewed as a correctness fix, not an optimization.
- Packet 0.2 and Packet 10.1 ship together. Neither is accepted alone.
- Correction 1F's enumeration is complete before the signed simulation report lands,
  and any boundary found using the permissive entry point on untrusted text is
  treated as a P1.
- Packet 10.3's classification is finished before any tenant-scoping remediation is
  scheduled, because it determines whether S3 is severe.
- Independent review still required for every P0 and P1, per standard rule 12.1.
  Both quality passes were written by a reviewer, not an independent one.
