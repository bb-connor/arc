# Security code quality review, September 26, 2026

Reviewed candidate: `3cd73631a18a6ec169b1e1a5bbd3ebe8bcb00130` on draft
[PR #1160](https://github.com/bb-connor/arc/pull/1160), plus the uncommitted
Packet 1 working tree (execution-mode binding).

This is a second, independent pass. It does not restate the September 25 boundary
review (retained outside the tree at
`/tmp/chio-security-review-24b995/security-roadmap-review.md`, with its supporting
notes and live snapshots alongside it) or the
[remediation record](2026-09-25-security-roadmap-remediation.md). It covers
what those explicitly deferred: enforcement integrity of the hygiene gates, the
design of the newest in-flight code, and four systematic sweeps the boundary
review did not run.

Findings are numbered `Q` to keep them distinct from the boundary review's `P1`
and `P2` series. Severity here means effect on the durability of the security
properties, not remote exploitability.

**Judgment: the boundary repairs are real and verified where sampled. The
remaining quality risk is not in the mechanisms, it is that three of the
invariants they establish are enforced by convention rather than by the compiler
or by a gate, and one gate that is supposed to bound TCB complexity does not
measure the code it is pointed at.**

## Q1. High: the file-hygiene gate cannot see `include!` fragments, so the production line cap is bypassed on 46 logical modules

`scripts/check-rust-file-hygiene.py` sets `PRODUCTION_LIMIT = 2_000` and walks
`TEXT_HYGIENE_SUFFIXES = (".rs", ".md")` (line 53). Fragments carry the `.inc`
suffix, so the walker never opens them. Because `include!` splices a fragment
into its parent at compile time, the parent and all its fragments are one
lexical module with one namespace, and the gate counts only the parent's own
lines.

Measured across `crates/`: 57 logical modules are assembled by `include!`, and
**46 of them exceed the 2,000-line production cap** once fragments are counted.
The gate reports green on every one.

| Logical module | Lines the gate counts | Actual logical lines | Fragments |
| --- | --- | --- | --- |
| `chio-kernel/src/kernel/tests.rs` | 80 | 40,754 | 49 |
| `chio-store-sqlite/src/security_state.rs` | 49 | 13,473 | 14 |
| `chio-secret-broker/src/service.rs` | 3 | 5,087 | 13 |
| `chio-security-types/src/ports.rs` | 4 | 5,033 | 5 |
| `chio-store-sqlite/src/finding_challenge_store.rs` | 731 | 6,031 | 13 |
| `chio-control-plane/src/trust_control/finding_challenge_coordinator.rs` | 1,270 | 7,173 | 15 |

The two most consequential entries are in the TCB's own trust surface. The
secret broker's service module, where boundary finding P1 #3 lived, presents 3
lines to the gate. The security port surface, which defines the trait boundary
every security adapter implements, presents 4.

There are 208 `include!` sites in the reviewed crates and 79 fragments in the
security TCB, nested two levels deep in six fragments that themselves
`include!` further fragments.

Four consequences, in descending order of importance:

1. **The split bought no encapsulation.** `include!` creates no module, so it
   creates no privacy boundary. Every item in a 5,087-line assembled module is
   in one namespace and can reach every other item. The stated goal of the
   split (bounded, auditable units) is not achieved by the mechanism used.
2. **`cargo fmt --check` does not visit `.inc` files.** rustfmt formats files
   reachable through `mod` declarations, not `include!` targets. Formatting in
   fragments drifts silently, and the workspace format gate cannot see it.
3. **The text hygiene checks (including the no-em-dash house rule) also skip
   `.inc`.** This is currently latent, not active: a scan for U+2014 across all
   `.inc` files returns zero matches, so discipline has held. The rule is
   unenforced on 79 TCB files, not violated.
4. **The gate's own allowlist discipline is undermined.** The header states
   "entries are debt, not configuration" and `--ratchet` can only shrink caps.
   That mechanism is sound, and the 77 allowlist entries are honest debt. But
   `include!` is an unmetered escape from the mechanism entirely, which is
   strictly worse than an allowlist entry, because an allowlist entry is
   visible and expires.

This is an inconsistency, not a blanket oversight, which makes it cheaper to fix
and harder to excuse. Four other gates already treat `.inc` as first-class
source and match on `{".rs", ".inc"}`:

- `scripts/check-proof-report.sh:295`
- `scripts/generate-proof-report.sh:293`
- `scripts/check-security-adversarial-evidence.py:504`
- `scripts/check-linux-enforcement-stack.py`

So the repository's established convention is that a fragment is source. The one
gate whose purpose is bounding module complexity is the one that departs from
that convention.

This reframes the boundary review's "auditability is poor for a security TCB"
from a discipline problem into an **enforcement problem**, which is the more
tractable of the two. The fix is in the gate, not in a refactoring campaign.

**Fix:** make the gate resolve `include!` and attribute fragment lines to the
including module, then treat the assembled total as the production measurement.
Add the `.inc` suffix to the text hygiene walk so the em-dash and trailing
whitespace rules cover fragments. Configure rustfmt or the format gate to reach
fragments, or stop using `include!` for hand-maintained code. Expect the gate to
go red on 46 modules on the first run: allowlist them at their measured size
with the existing ratchet so the cap can only shrink from there. Do not
retrofit the measurement quietly, because the resulting red is the accurate
baseline.

**Confidence:** high. The gate's suffix tuple and the line attribution are
directly readable, and the logical sizes were computed by resolving `include!`
transitively from each parent.

**Pass 6 confirmation.** `cargo fmt --all -- --check` flags 18 files, every one in
Codex's uncommitted working set and none of them `.inc`; running `rustfmt --check`
directly on 36 sampled fragments would reformat **21 of them**. The blind spot is
measured, not inferred.

## Q2. High: `ResponseExecutionBinding` can be deserialized into an invalid state, and validation is by convention

New in the uncommitted Packet 1 tree,
`crates/security/chio-security-types/src/response_execution.rs`:

```rust
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseExecutionBinding {
    pub schema_version: u8,
    pub mode: ResponseExecutionMode,
}
```

`new()` is the checked constructor and `validate()` is the checker, but neither
is on the deserialization path and neither is required to reach the fields. A
wire payload carrying `schema_version: 99` deserializes successfully, and a
caller can also write the literal `ResponseExecutionBinding { schema_version:
99, mode: Live }` directly. The value is only rejected if some later caller
remembers to call `validate()`.

This is the exact pattern the closeout plan's own acceptance standard rules out:
"Keep authority types opaque after verification, bounds explicit and legal
transitions exhaustive." A public-field struct with a detached validator is
neither opaque nor self-enforcing.

**Fix:** private fields with accessors, and `#[serde(try_from =
"ResponseExecutionBindingWire")]` so deserialization is the validation point and
an invalid binding cannot exist as a value. The wire struct keeps
`deny_unknown_fields`; the domain type becomes unconstructible without the
check.

Secondary: `validate()` returns `PortError::invalid_data()`, which discards the
observed version. A security boundary should reject with the data needed to
diagnose the rejection from a receipt or log, without echoing attacker-supplied
bytes wholesale. Carry the expected and observed version numbers.

**Confidence:** high. This is a direct read of the new file; no execution
needed.

## Q3. High: execution-mode enforcement is five hand-placed call sites, not a type-enforced invariant

The security property Packet 1 exists to establish is that simulated response
evidence can never authorize a live effect. Its entire enforcement surface is
five literal calls, plus the definition at `response.rs:268`:

| Site | Path |
| --- | --- |
| `chio-quarantine/src/state_machine.rs:118` | dispatch preparation entry |
| `chio-quarantine/src/state_machine.rs:684` | `prepare_response_dispatch`, `Fresh` |
| `chio-quarantine/src/state_machine.rs:1000` | snapshot-based transition |
| `chio-kernel/src/kernel/active_response_coordinator.rs:269` | kernel admission |
| `chio-kernel/src/kernel/active_response_coordinator.rs:281` | kernel admission |

Nothing in the type system prevents a seventh live path from being added without
the check, and nothing fails if one is. `validate_plan` deliberately does not
enforce mode (`response.rs:314` validates the binding only when present), so the
plan can be fully valid and still unchecked.

The rule is also written twice, in inverse form, seven lines apart
(`state_machine.rs:684` and `:686-687`):

```rust
if matches!(commit_mode, ResponseDispatchCommitMode::Fresh) {
    plan.require_execution_mode(ResponseExecutionMode::Live)...?;
} else if plan.execution.is_some_and(|binding| binding.mode != ResponseExecutionMode::Live) {
    return Err(StateMachineError::InvalidDispatch);
}
```

Both branches are currently correct. They are correct by coincidence if a third
mode is ever added: `Fresh` would reject it because it is not `Live`, and the
resume branch would reject it because it is not `Live`, but neither branch was
written with a third mode in mind, and the second branch's negation would need
re-reading to confirm that. Two expressions of one rule in a TCB is a drift
site.

**Fix:** typestate. Introduce `LiveAuthorizedPlan(ResponsePlan)` whose only
constructor performs `require_execution_mode(Live)`, and change
`prepare_response_dispatch` and the kernel admission entry points to accept it
instead of `ResponsePlan`. The check then cannot be omitted, because the value
cannot be produced without it, and the rule exists once.

*Corrected by the external review of the same day (finding R1):* the inverse branch
must **not** collapse into the same constructor parameterized by commit mode, because
a caller could then obtain authority for a legacy plan by naming a resume mode with
no durable proof. Fresh admission and committed recovery are two types with two
constructors, the second reachable only from the durable recovery verification. The
design document's mechanism A and addendum item 1B carry the corrected text.

This is the plan's own standard ("Share security decisions across live, recovery
and simulation paths. Avoid duplicate policy implementations") applied to the
code that standard was written alongside.

**Confidence:** high for the structure; the branches themselves are correct
today, so this is a durability finding, not a live defect.

## Q4. Medium: legacy tolerance is encoded as `Option`, with no sunset and no inventory

`ResponsePlan.execution` is `Option<ResponseExecutionBinding>`
(`response.rs:201`, `:247`). Absence means "plan predates the binding". The
resume branch accepts absence permanently.

The laundering attack this invites does not work today, and the reason is worth
recording so it is not lost: `authorization_body()` includes `execution`
(`response.rs:283`), so stripping `Some(DryRun)` to `None` changes the signed
body bytes and the signature fails. The property holds because of signature
coverage, not because of the `Option`.

What remains is lifecycle debt with three gaps:

- The `None` acceptance branch has **no expiry**. Nothing retires it, so it is
  permanent attack surface for every future change to the resume path.
- There is **no inventory** of how many durable rows actually carry a legacy
  plan, so nobody can say what accepting `None` currently costs or when it would
  be safe to stop.
- Readers must re-derive three-way semantics (`None`, `Some(DryRun)`,
  `Some(Live)`) at every site, which is what produced the duplicated inverse
  rule in Q3.

**Fix:** replace the `Option` with an explicit two-variant enum
(`PlanProvenance::{Legacy, Bound(ResponseExecutionBinding)}`) so the three cases
are named and matches are exhaustive. Add a migration deadline tied to the
maximum lease horizon, after which the `Legacy` arm rejects, and a gate that
counts legacy rows so the deadline is evidence-backed rather than a guess.
Record the count in the receipt schema v5 migration note.

**Confidence:** high on the structure and the absence of a sunset; the security
property itself is intact.

## Q5. Medium: the TCB has no single clock port, and three unrelated `Clock` traits

Every authorization decision in this system is deadline-bound: approval
horizons, DPoP freshness, credential deadlines, lease expiry, plan expiry,
nonce windows. That makes the clock part of the TCB. It is not treated as one.

Three unrelated traits exist, with different units and different failure
semantics:

| Trait | Unit | Failure mode |
| --- | --- | --- |
| `chio_kernel_core::clock::Clock` | `u64` Unix seconds | infallible, fail-closed documented at the verdict path |
| `chio_guards::external::cache::Clock` | `Instant` (monotonic) | infallible |
| `chio_keyring::time::TrustedClock` | `u64` Unix milliseconds | fallible, `Result` |

Beneath all three, 60 production files (80 call sites) in the security crates,
kernel and control plane call
`SystemTime::now()` directly and bypass every trait, including
`chio-control-plane/src/security/active_response.rs` (the module Packet 1 is
modifying) and `chio-control-plane/src/keyring_runtime.rs` (where boundary
finding P1 #5 lived). `chio-security-types/src/ports.rs`, the security port
surface, defines no clock port at all.

Consequences: deadline and expiry logic cannot be driven deterministically in
tests without wall-clock manipulation, wall-clock regression handling is
decided per call site instead of once, and `maximumClockSkewSeconds` is
enforced in the broker's deployment config while other components have no skew
policy. Packet 4's intended Kani checks on "expiry and legal transitions" will
be weaker than they look while the time source is ambient rather than injected.

**Fix:** add one clock port to `chio-security-types` ports, with explicit units
and an explicit fail-closed contract on non-monotonic readings, and inject it
through the existing composition roots. Deadlines that must survive wall-clock
adjustment compare monotonic readings; deadlines that must be comparable across
processes or appear in signed evidence stay Unix-epoch and carry the skew
policy. Migrate the three existing traits onto it rather than adding a fourth.

**Confidence:** high on the inventory; the impact assessment is a design
judgment, not a demonstrated defect.

## Q6. Verified clean: four sweeps with no findings

Recorded so the next reviewer does not repeat them.

- **Panic discipline in production.** All 59 `#[allow(clippy::unwrap_used)]` /
  `expect_used` sites in the security TCB sit on `#[cfg(test)]` modules or
  test-only `#[path]` module declarations. No production escape of the
  workspace-wide deny. Spot-checked `budget_store.rs:67`, `security.rs:252`,
  `scope.rs:686`, `migration_evidence.rs:691`.
- **`deny_unknown_fields` coverage.** 614 sites across 94 files in the security crates and
  control plane. Of the two files that derive `Deserialize` without it,
  `chio-keyring/src/store.rs` does so on a fieldless enum, where the attribute
  is a no-op and unknown variants already reject. `chio-decoy/src/materialize.rs`
  does **not**: it derives `Deserialize` on three structs
  (`MaterializationIdentity`, `FileOwnershipProof`, `MaterializationReceipt`).
  Pass 6 found no parse site for them inside the security crates, so the derive
  may be unused or consumed by tooling; severity unresolved, low. The original
  statement that both were fieldless enums was wrong for this file.
- **No em dashes.** Zero U+2014 in `.rs` and zero in `.inc` across `crates/`.
  See Q1 for why the `.inc` result is discipline rather than enforcement.
- **Two remediation fixes verified against source, not just the report.** The
  cage cross-process fix is real: `prlimit64` carries a
  `SyscallArgumentConstraint` pinning argument 0 to `0`
  (`chio-cage/src/lib_parts/part_02.rs:188`), with the reason stated in a
  comment. The broker credential fence is real: `credential_version` is retained
  as a `BlobHandle` at preparation (`service_parts/part_01.rs:219`) and
  rechecked at final dispatch
  (`service_parts/part_02_sections/execution_and_failure.inc:372`).

## What this means for sequencing

The boundary review's execution order stands. These findings change two things
about it.

Q1 should move **before** Packet 1, because it is a gate change of bounded size
(one Python file plus an allowlist baseline) and because every packet after it
adds code to the modules it currently fails to measure. Fixing it later means
re-baselining against more debt.

Q2, Q3 and Q4 are corrections **inside** Packet 1 rather than new work after it,
and they are cheapest now, while the execution-mode binding is still
uncommitted and has exactly five call sites. Once the dry-run evaluator, the
signed simulation report and the kernel and scheduler wiring land on top, the
same change touches far more code.

Q5 belongs with Packet 4, whose formal and property obligations depend on a
time source that can be driven deterministically.
