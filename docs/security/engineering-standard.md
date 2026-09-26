# Chio security engineering standard

The standard the security TCB is held to. It is written to be *enforced*, not
admired: every rule names how it is checked and what happens when it is
violated. A rule with no gate is marked as such and is a debt item, because an
unenforced standard in a TCB decays to whatever the last contributor believed.

Scope: `crates/security/*`, `crates/kernel/chio-kernel*`,
`crates/platform/chio-control-plane`, `crates/platform/chio-store-sqlite`,
`crates/core/chio-core-types` security surfaces, and the cage, broker, keyring
and quarantine trust boundaries.

Companion documents: [launch execution plan](launch-execution-plan.md),
[assurance closeout plan](../superpowers/plans/2026-09-25-security-assurance-closeout.md),
[engineering excellence addendum](../superpowers/plans/2026-09-26-security-engineering-excellence.md).
Findings that produced these rules:
[quality review pass 1](../reviews/2026-09-26-security-code-quality-review.md) (Q series),
[pass 2](../reviews/2026-09-26-security-code-quality-review-pass-2.md) (R series),
[performance pass 3](../reviews/2026-09-26-security-performance-review-pass-3.md) (P series),
[pass 4](../reviews/2026-09-26-security-review-pass-4.md) (S series),
the [unrepresentable-defects design](../superpowers/specs/2026-09-26-unrepresentable-defects-design.md) (pass 5, T series),
and the [pass 6](../reviews/2026-09-26-review-validation-pass-6.md) and
[pass 7](../reviews/2026-09-26-review-validation-pass-7.md) validations, which together
corrected twenty-three figures and retracted one finding across the earlier passes.

The organizing principle, from which most rules below are derivable:

> **An invariant that depends on a human remembering it is not an invariant. It
> is a convention with a good reputation.**

Encode invariants in types where the compiler can hold them, in gates where the
compiler cannot, and in property or model checks where a gate cannot. Prose is
the last resort and is documentation of the encoding, never a substitute for it.

A second principle, learned from finding R1:

> **Where a safety net exists only in the build profile the tests run under, it
> does not exist.**

---

## 1. Module and boundary design

**1.1 A module owns exactly one of: an authorization decision, a pure state
transition, a durable journal, effect I/O, or signed evidence.** These five
categories are the TCB's actual seams. A module that mixes two of them cannot be
reviewed independently of the other, and every boundary defect found in the
September 25 review sat where two of them met without a named boundary.

*Enforced by:* review. No gate. Debt item.

**1.2 Never use `include!` for hand-maintained code.** `include!` splices text
into the parent at compile time. It creates no module, therefore no privacy
boundary, therefore no encapsulation. It also hides the code from `cargo fmt`
and from any gate that walks source by suffix. A 5,000-line module split into
thirteen fragments is one 5,000-line module with thirteen extra files and worse
tooling. Use `mod` with `#[path]` when the file layout must differ from the
module tree, so the privacy boundary is real and the tooling follows.

*Enforced by:* `scripts/check-rust-file-hygiene.py` once it resolves `include!`
(finding Q1). Until then, unenforced, and 46 logical modules exceed the
production cap undetected. Note that `check-proof-report.sh`,
`check-security-adversarial-evidence.py` and `check-linux-enforcement-stack.py`
already match on `{".rs", ".inc"}`, so treating a fragment as source is the
repository's existing convention; the hygiene gate is the outlier.

**1.3 The production file cap is 2,000 lines, measured on the assembled logical
module.** The cap is not a style preference. It is a proxy for how much shared
mutable namespace one reviewer must hold in their head to verify a change.
Splitting a module to satisfy the cap without introducing a privacy boundary
defeats the cap's purpose and is treated as a violation even when the gate
passes.

*Enforced by:* the hygiene gate's `PRODUCTION_LIMIT`, plus the allowlist ratchet,
which may only shrink caps and expires entries monthly. Allowlist entries are
debt with an expiry date, which is the correct shape; `include!` was an unmetered
escape from it, which is not.

**1.4 Traits are introduced at real dependency boundaries only.** A trait with
one implementation and no test double is indirection without abstraction. A
trait with a default method body is a permissive default: an implementer that
forgets to override it silently inherits behavior the trait author chose, which
in a TCB means inheriting an authorization decision. Security traits have no
default method bodies.

*Enforced by:* review. No gate. Debt item.

**1.5 One invariant, one implementation.** When the same rule is implemented in
an in-memory store, a SQLite store and a composite transition path, it will drift,
and the drift will be discovered in production. If the rule must appear in
several layers, put the decision in one shared function or type and let each
layer call it. Defense in depth means the same rule enforced at a second
*mechanism* (a database constraint under a Rust check), not the same rule
*retyped* at a second call site.

*Enforced by:* review. No gate. Debt item. Instances: the exposure-release
invariant exists in four implementations (finding R1); eight domain constants are
redeclared per crate (finding R4).

---

## 2. Type design

**2.1 An invalid value must be unconstructible, not merely rejected.** Private
fields, a checked constructor, and `#[serde(try_from = "...Wire")]` so that
deserialization *is* the validation point. A public-field struct with a detached
`validate()` method permits an invalid value to exist and travel, and relies on
every caller remembering to call the checker (finding Q2).

The test for whether a type meets this rule: can you write the invalid literal,
or deserialize an invalid payload, and get a value back? If yes, the rule is not
met.

**2.2 Authority is opaque after verification.** A verified capability, approval,
or authorization is a distinct type that cannot be forged by struct literal, and
its constructor is the verification. Downstream code takes the verified type and
therefore cannot skip verification. This is the codebase's strongest pattern where it is
applied: 116 of 169 `Verified*`/`Authorized*` types have private fields. It is a
naming convention in the other 45, 18 of them in TCB crates and 4 of those
`Deserialize` (design finding T1). A `Verified*` type with public fields is a
data carrier wearing a token's name; the
[unrepresentable-defects design](../superpowers/specs/2026-09-26-unrepresentable-defects-design.md)
retrofits them.

**2.3 Use typestate when it removes a whole class of omission.** When a security
check must precede an operation, make the check produce a token the operation
requires. `prepare_response_dispatch` should accept `LiveAuthorizedPlan`, not
`ResponsePlan` plus a remembered call to `require_execution_mode` (finding Q3).
Five hand-placed call sites is five chances to forget and no compiler help on the
sixth.

Typestate is not free, so the bar is: it must remove a *demonstrated* invalid
state or a *demonstrated* omission risk, not a hypothetical one. Five manual call
sites guarding a TCB property meets that bar.

**2.4 Legacy tolerance is a named variant with a sunset, never `Option`.**
`Option<T>` where `None` means "predates this field" forces every reader to
re-derive three-way semantics and gives the legacy branch no expiry. Use an
explicit enum (`PlanProvenance::{Legacy, Bound(T)}`), record the migration
deadline, and gate on a count of affected durable rows so the deadline is
evidence-backed (finding Q4).

Every legacy acceptance branch in the TCB answers three questions in code or in a
gate: how many rows still need it, what retires it, and what date it fails
closed.

**2.5 State machines are exhaustive enums with no catch-all arm.** `_ =>` in a
security transition is how a new state silently inherits the behavior of the
states that existed when the arm was written. Match every variant. Let the
compiler find every site when a variant is added.

**2.6 Quantities that have an invariant carry it in the type.** An exposure
amount, a budget remainder, a quota and a lease count are not `u64`. They are
newtypes whose subtraction is `try_sub(self, other) -> Result<Self, _>` and whose
construction rejects out-of-range values once. This removes the entire class of
hand-placed guard-before-subtract (finding R1) and makes the invariant impossible
to forget in a fifth implementation.

*Enforced by:* review, and by the arithmetic lint in rule 4.2 once scoped. No
gate today. Debt item.

**2.7 Schema versions are compared for exact equality, never ordering.** A `>=`
comparison on a closed security schema is a downgrade vector: it accepts a version
whose semantics the reader was not written against. The current code is fully
compliant (zero ordering comparisons, 13 files using exact equality). Preserve it
deliberately.

---

## 3. Errors and rejection provenance

Promoted to its own section because finding R2 showed the error taxonomy is not a
cosmetic concern here: it determines what the test suite and the fuzz oracles are
*able* to prove.

**3.1 One rejection reason, one discriminant.** If six distinct security rules can
reject an operation, a caller must be able to tell which one did. Six rules
sharing `StateMachineError::InvalidDispatch` means no test, receipt, log line or
fuzz oracle can distinguish them (finding R2). Give each rule a variant, or give
the shared variant a `DispatchRejection` payload.

The test for this rule: can a negative test assert *which* rule fired? If not,
that test cannot demonstrate it exercised the rule in its own name, and it would
still pass if the rule were deleted.

**3.2 Never discard an inner cause.** `map_err(|_| Outer::Category)` throws away
the diagnosis. Use `thiserror` with `#[source]` so the chain survives to the
boundary that formats it. There are 112 such discards in `chio-quarantine` plus
the kernel response coordinator; each one is a place where an operator debugging a
denial has to read source instead of a log.

**3.3 Errors carry the data needed to act, and nothing an attacker supplied
verbatim.** `PortError::invalid_data()` tells an operator reading a receipt
nothing; `expected schema 1, observed 99` tells them everything and leaks nothing.
Conversely, never echo attacker-controlled bytes into a log or receipt without
bounding and labeling them.

**3.4 Errors are typed enums, not strings, at every component seam.** A stringly
error cannot be matched on by the caller, so the caller either ignores it or
parses prose, and both are worse than a variant. Where a string is genuinely
needed for an operator, it is a field on a variant, not the variant.

**3.5 Fail-closed means the error path is the reviewed path.** The denial branch
gets the same review attention as the success branch, because it is the branch
that carries the security property. Most of the findings in this review lineage
are in denial, recovery and cleanup paths, not in happy paths.

---

## 4. Arithmetic, accounting and build-profile parity

**4.1 Release builds keep the checks the tests rely on.** `overflow-checks =
true` in every profile that ships. A `u64` underflow in an exposure or quota
calculation does not produce a small error, it produces the largest representable
value, which a ceiling comparison reads as unlimited authority. In a fail-closed
kernel a panic on overflow is the correct outcome: an availability fault instead
of a silent authority grant, which is exactly the reasoning the workspace manifest
already gives for denying `unwrap_used` (finding R1).

Corollary, and the reason this is a rule rather than a preference: if `cargo test`
runs with overflow checks and `cargo build --release` runs without, then the test
suite is structurally incapable of finding a wrapping bug, because the wrap only
happens in a profile no test executes under.

*Enforced by:* the workspace manifest, once set. Currently unset for
`[profile.release]` and `[profile.docker-release]`. Debt item.

**4.2 Accounting modules deny unchecked arithmetic.**
`arithmetic_side_effects = "deny"` scoped to budget, quota, counter and lease
modules, with reviewed `#[allow]` at sites where the bound is proved (a Kani
harness subtracting under a proved precondition is a legitimate allow; a store
path is not).

**4.3 `saturating_*` is a decision, not a default.** `saturating_sub` in an
accounting path silently clamps to zero, which is a different wrong answer than a
wrap but still a wrong answer, and it hides the underflow the guard was supposed
to catch. Use `checked_*` and handle the `None`, or use a newtype per rule 2.6.
Every `saturating_*` in an accounting path carries a comment saying why clamping
is the correct semantics there.

**4.4 Guards at the database as well as in Rust.** Where a store enforces a
quantity invariant, the UPDATE carries the same predicate (`AND
remaining_exposure_units >= ?`). The composite transition path already does this
and it is the reference shape: the database refuses the write even if the Rust
check is bypassed or reordered. That is defense in depth at a second mechanism,
which rule 1.5 permits and encourages.

---

## 5. Concurrency, durability and recovery

**5.1 Durable intent precedes external effect; unknown outcomes stay unknown.**
Already the practice in the reviewed paths, and the reason the system degrades
honestly. Retry never creates new authority. An unknown effect outcome resolves
only by exact durable readback, never by inference or by re-execution.

**5.2 A lock covers exactly the commitment it protects, and never external
I/O.** Holding a lock across a network call converts a correctness mechanism into
an availability failure. Releasing it before the commitment converts it into
nothing. The broker's fix is the reference shape: the backend mutation lock
linearizes final version and status validation together with the durable dispatch
commitment, and is released before provider I/O.

*Enforced by:* review, plus the deterministic-barrier tests required by Packet 2.
No static gate. A clippy lint for `await` while holding a guard covers the async
case only.

**5.3 Every check-then-act across a mutable store is fenced by a version or
generation, validated under the same lock as the mutation.** Preparation that
retains a credential, a policy, or a capability records its version, and final
commitment revalidates that exact version. This is the shape of the P1 #3 fix and
it generalizes: any retained decision is stale by default.

**5.4 Resource cleanup is ownership, not a call at the end of a function.** RAII
guards, `Drop` that releases exactly what the guard owns and nothing shared. The
rotation and relocation defects both involved cleanup that released or retained
the wrong scope: a dropped staging handle must release its own pending lease and
not another authority's, and relocation cleanup must remove only the relocating
authority's artifacts.

**5.5 Cancellation has an explicit durable outcome.** A cancelled operation is in
a named state in the journal. "The task stopped" is not a state.

**5.6 Recovery shares the decision code with the live path.** A recovery path
with its own copy of an authorization rule will drift from the live rule, and the
drift will be discovered by an attacker rather than a test. Where live and
recovery must differ, the difference is a parameter to one shared function, not a
second implementation. Three of the five P1 findings were live-versus-recovery
divergences.

---

## 6. Time

**6.1 The clock is part of the TCB and is injected, never ambient.** Every
authorization decision here is deadline-bound, so `SystemTime::now()` in a
production security path is an untestable, unfenced dependency. One clock port,
defined in `chio-security-types` ports, injected through the composition roots
(finding Q5).

**6.2 Units are in the type, and the failure mode is explicit.** Not `u64`.
`UnixMillis` and `MonotonicInstant` are different types and cannot be compared or
subtracted across the boundary. A clock that can fail returns `Result` and the
caller fails closed.

**6.3 Deadlines that must survive wall-clock adjustment compare monotonic
readings. Deadlines that appear in signed evidence or cross a process boundary are
Unix-epoch and carry an explicit skew policy.** Pick per deadline, document which,
and never mix the two in one comparison. The broker's `maximumClockSkewSeconds` is
the right idea applied in one component; it needs to be the TCB's policy, not the
broker's.

---

## 7. Secrets

**7.1 Secret material is a type that zeroizes on drop and does not implement
`Debug`, `Display`, `Serialize` or `Clone` without a named reason.** Accidental
inclusion in a log line or a serialized struct is the most common real leak.

*Enforced by:* `secrecy::SecretBox` for key material and credentials, whose
`Debug` prints `[REDACTED]` and whose reads go through a greppable
`expose_secret()`. Not adopted yet; hardening spec item H7. Debt item.

**7.2 Scan every release surface, including the ones that are not values.** The
P2 header-name finding is the lesson: containment scanning covered header values
and a credential was releasable as a header *name*. Enumerate the surfaces a
secret can occupy on any egress path (values, names, paths, query strings, error
messages, receipts, metrics labels) and cover all of them, including normalized
and original forms.

**7.3 Credentials are delivered through the kernel's credential mechanism, never
through the environment or a file the process can re-read.** Already the practice
via `$CREDENTIALS_DIRECTORY` and sealed memfds.

---

## 8. Cryptographic domain separation

**8.1 Every signed or hashed payload type has a distinct domain string, and that
string is declared exactly once.** 243 domain constants exist; eight byte strings
are declared in two to four places, including one
(`chio.response-affected-set.v1`) that already has a canonical `pub const` in
`chio-security-types` while the kernel keeps private copies (finding R4). The
strings currently match, so this is a drift landmine rather than a live confusion
bug, and the failure mode when it drifts is a silent producer/verifier
disagreement rather than a compile error.

One module owns the domain constants. Everything else imports them.

**8.2 One naming convention, always terminated.** Three conventions coexist today
(`chio.a.b.v1\0`, `chio-a-b-v1`, `chio:a:b:v1`) and 14 domains are not
null-terminated. An unterminated, variable-shape domain prefix is how
prefix-ambiguity mistakes are made later even where current uses are safe. Pick
`chio.<area>.<payload>.v<N>\0` and gate on it.

**8.3 Test and placeholder domains cannot compile into a release binary.** A
constant named `PLACEHOLDER-SIGNATURE-OVERRIDE-IN-PRODUCTION` exists in the domain
set. Gate it behind `#[cfg(any(test, feature = "test-support"))]` so the property
is structural rather than reviewed.

**8.4 Canonicalization is one implementation, and its edge cases are tested.**
Duplicate keys, key ordering, non-finite floats, integer width, string escaping
and unicode form all change bytes and therefore change signatures. One
`canonical_json_bytes`, property-tested against round-trips and against known
adversarial inputs.

*Enforced by:* a domain-extraction gate (duplicate value, shape, cfg) that does
not exist yet. Debt item.

---

## 9. Confinement

**9.1 Deny by default, and constrain arguments, not just syscall names.** An
allowed syscall with no argument constraint is unconditional authority. The
`prlimit64` finding is the canonical case: allowed everywhere, unconstrained, and
therefore authority over every same-UID process. Argument 0 pinned to `0` restores
the intent.

**9.2 Confinement applies before the confined code's first instruction.** Any
"resolve inputs, then confine" ordering means the resolution step runs unconfined.
Discovery, manifest resolution, tool probing and version checks all execute
selected code and all belong inside the boundary with the selected identity
(P1 #1).

**9.3 Assume same-UID peers are hostile unless a namespace or an explicit kernel
scope says otherwise.** `ProtectProc=invisible` is not a signal authorization
boundary. Landlock signal scoping requires ABI 6 and cannot be assumed on the
supported 6.7 floor. State the assumed kernel floor and derive the profile from
it.

**9.4 A helper that can be given a weakened plan rejects it.** The cage helper
refusing plans that remove its own constraints is the correct shape: the
enforcement point validates that it is still an enforcement point. `default_action
== KillProcess` is re-asserted at three separate boundaries, which is why a
weakened plan cannot be smuggled in.

**9.5 Post-fork code is async-signal-safe only.** Between `fork` and `exec`, the
child may hold a malloc lock another thread owned at fork time, so allocating,
locking, or calling a non-reentrant libc function can deadlock forever. In a
`pre_exec` closure: no allocation, no `String`, no `format!`, no
`io::Error::new(kind, String)`, no locks, no logging. Construct errors with
`last_os_error()` or `from_raw_os_error()`, which wrap an `i32`. Capture
everything needed by move before the fork.

The existing closures comply exactly, including the PDEATHSIG race guard (set
`PR_SET_PDEATHSIG`, then re-check `getppid()` and fail `ECHILD`). Preserve this
during any refactor; it is invisible discipline that a well-meaning cleanup would
break.

*Enforced by:* `clippy::undocumented_unsafe_blocks` and `unsafe_op_in_unsafe_fn`
as workspace denies, and a Miri lane on every crate whose `unsafe` is pure Rust.
Neither exists yet; both are specified in the
[hardening toolchain spec](../superpowers/specs/2026-09-26-hardening-toolchain-spec.md)
(H1, H2). Debt item.

---

## 10. Testing

Each layer proves something the layer below cannot. A test that duplicates a
lower layer's coverage is cost without assurance.

| Layer | Proves | Anti-pattern to reject |
| --- | --- | --- |
| Unit / property | Exact boundaries: expiry, overflow, legal transitions, argument constraints | Asserting a function returns `Ok` on the happy path only |
| Integration | Real composition: kernel plus SQLite plus broker plus authority plus receipts | Mocking the component whose interaction is the risk |
| Process / chaos | Recovery after process death, lost acknowledgement, contention, storage failure | `sleep` as synchronization |
| Fuzz | Stateful sequences and protocol mutation from valid seeds | A target that only reaches the parser's first reject |
| Formal | Bounded safety tied to production code, with caught negative mutations | A model of code that no longer exists |

**10.1 A negative test asserts which rule rejected, not that something failed.**
`assert!(result.is_err())` in a fail-closed system is close to vacuous: almost any
mistake produces an error, so the assertion passes when the code rejects for the
wrong reason, when an unrelated earlier validation rejects first, and often when
the feature under test does not exist. Assert the specific variant.

Currently 213 of 543 negative assertions in the security crates are the weak form
(finding R3). This rule is only achievable once rule 3.1 is satisfied, because six
rules sharing one variant leave an author nothing stronger to assert.

*Enforced by:* a gate rejecting new bare `assert!(..is_err())` in the security
crates. Does not exist yet. Debt item.

**10.2 Every regression test is mutation-checked.** Break the fix deliberately and
confirm the new test fails, for the named reason. An untested test is a comment.
This is cheap, it is the single highest-yield habit in this repo's history, and it
has repeatedly caught tests that passed for the wrong reason.

**10.3 Fuzz targets are seeded to reach meaningful states.** An unseeded target on
a signature-verifying protocol spends its whole budget failing verification. Seed
with valid signed fixtures and valid plans, and mutate binding fields and ordering
as well as raw bytes. A successful build is not a campaign; record target, source,
duration, corpus and crash artifacts.

**10.4 Semantic oracles, not just "no crash".** For this TCB: a malformed or
rebound envelope grants no authority; dry-run never enters live execution; partial
rollback cannot report a clean lift; removing one contribution preserves
overlapping restrictions; retry never widens authority. Each oracle must be able
to tell *which* boundary refused, which again depends on rule 3.1.

**10.5 Deterministic barriers, never wall-clock sleeps.** Every race the review
found (prepare versus disable, expiry versus commit, emergency stop versus replay,
archive authentication versus replacement) needs a barrier-driven test that fails
reliably before the fix.

**10.6 Test what the tests cannot see.** Run tests in isolated processes with
bounded time and leak detection (`cargo-nextest`, hardening spec H5), so a test
that depends on a sibling's leftover state, or leaves a child behind, is named
rather than hidden. Some properties are invisible to the test
profile by construction: release-profile arithmetic, a `seccompiler` prologue
delegated to a dependency, a fragment excluded from `cargo fmt`. Each needs an
explicit check outside the ordinary suite, or it is unverified (finding R6).

**10.7 Evidence names its source.** A passing result is bound to a source SHA, a
command, an inventory count and tool versions, or it is not evidence. Historical
results stay attached to their original source identity and do not migrate forward
when code changes.

---

## 11. What "no AI slop" means concretely

The failure mode is not bad grammar. It is code and comments that describe
process instead of behavior, and volume that simulates thoroughness.

**Remove:** comments that restate the code (`// increment the counter`);
references to tickets, findings, rounds, review passes, agent names or plan
packets inside source; changelog narration in a doc comment; "note that", "it is
important to", "as mentioned above"; defensive hedging about what the code might
do; `// TODO` with no owner or condition.

**Keep:** why a non-obvious choice was made, especially a security one. The
`prlimit64` comment is the model: *"PID zero selects the calling process. A
same-UID peer must never be able to change the kernel's limits through this
otherwise useful call."* That sentence encodes a threat model a future reader
cannot recover from the code.

A second class worth keeping, and currently under-documented: a comment that
protects invisible discipline. The `pre_exec` closures are async-signal-safe by
careful construction and nothing says so, so a future cleanup that adds a
`format!` for a better error message would introduce a deadlock and pass review.
Where correctness depends on what the code does *not* do, say so.

**Rules:**

- Comment density matches the surrounding module. A function that needs a
  paragraph usually needs splitting instead.
- Doc comments on public security items state the invariant the item upholds and
  the caller's obligation. Not a restatement of the signature.
- Name things after the domain concept, not the mechanism or the sequence.
  `part_02.rs` is not a name. `execution_and_failure.inc` is a topic list, not a
  responsibility. Names must also be greppable by value and by concept: eight
  duplicated domain constants went unnoticed partly because the same bytes carry
  four different constant names.
- No em dashes (U+2014). Hyphens or parentheses.
- Conventional commits. One reviewable packet per commit: behavior plus its
  regressions, never behavior in one commit and its tests in another.
- Do not narrate the work in the artifact. The code says what it does; the commit
  says why it changed; the ledger says what was verified. Nothing says "I then
  proceeded to".

---

## 12. Review process

**12.1 Self-review is not review.** The September 25 review was performed by the
same agent that wrote much of the code, and it says so plainly. That is honest and
it is still not independent evidence. Every P0 and P1 needs an independent
reviewer before the affected boundary is called complete.

**12.2 Audit the newest code first.** The least-reviewed code is the code written
most recently, and the fix for a finding is written under time pressure by someone
who has just proved they misunderstood that boundary. Three of the four in-flight
findings in pass 1 are in code less than a day old.

**12.3 A source-traced finding is not a reproduced finding, and the difference
goes in the report.** The September 25 review labels every finding's confidence
and states which were reproduced. Preserve that discipline. "High confidence from
the supported call path; no privileged exploit was run" is a more useful sentence
than either overclaiming or silence.

**12.4 Report the clean sweeps.** A review that lists only findings invites the
next reviewer to redo the same searches. Both quality passes record what was
checked and found sound, which is also the only way a strength gets protected
during a later refactor.

**12.5 Status prose drifts behind implementation; reconcile it as part of the
change.** Several stale claims in the qualification ledger (the M7 inventory, the
App secret, the external consumer package) were stale in the pessimistic
direction, which is the safer drift but still misdirects effort. The ledger entry
is part of the packet, not a follow-up.

**12.6 A gate that cannot measure what it points at is worse than no gate, because
it produces false assurance.** Q1 is the instance, and R1 is the same failure in
the build profile rather than in a script. When adding a gate, write the test that
proves it fails on a real violation, and include a deliberately violating fixture
in its self-test. The hygiene gate's own `--ratchet` design and the 51-mutation
self-tests elsewhere in this repo show the team already knows how to do this.

**12.7 Prefer a finding that blocks another packet's exit.** Not all findings are
equal in sequencing value. R2 is the highest-value finding in either pass, not
because it is the most severe but because Packet 1 and Packet 4 cannot demonstrate
their own acceptance criteria until it is fixed. Look for those first.

---

## 13. Performance and measurement

A security kernel has an unusual cost profile: per-operation time is dominated by
Ed25519 signing and verification and by `fsync`, both tens to hundreds of
microseconds, while an avoided allocation is tens of nanoseconds. That makes two
opposite mistakes equally easy. One is shipping a query whose cost grows with the
data. The other is spending a week removing allocations that no profile would ever
show, and calling it optimization.

**13.1 Cost that scales with data is a defect; cost that is constant per
operation is a budget.** Rank by growth, not by how inefficient a line looks. A
full table scan with a per-row JSON parse is a defect at any size because it gets
worse forever. Two hundred heap allocations behind an Ed25519 verification is a
rounding error and stays one.

**13.2 Never re-derive at query time what the schema already stores.** Finding P1
is the instance: the receipt analytics summary parses `raw_json` per row to sum a
financial field for which a typed, `CHECK`-constrained `cost_charged_be BLOB`
column already exists. If a value is worth aggregating, it is worth a column. JSON
extraction in an aggregate over an unbounded table is the clearest performance
defect in this codebase.

**13.3 An optional-filter query shape defeats the indexes you built.**
`WHERE (?1 IS NULL OR col = ?1)` prevents index selection, so six correct indexes
on the filtered columns buy nothing. Build the predicate for the shape the caller
actually uses, and assert the plan: a test that runs `EXPLAIN QUERY PLAN` and
fails on `SCAN` where an index is expected is the only way this does not silently
regress.

**13.4 Use `prepare_cached` on per-operation statements and `prepare` on the
rest.** `prepare()` recompiles the statement every call. Setup, migration and
reporting paths do not care; the authorization path does. Zero uses of
`prepare_cached` across 420 `prepare` sites means the choice was never made, which
is the actual finding.

**13.5 One mutexed connection is not a database.** `Arc<Mutex<Connection>>`
serializes readers against writers, including read-only queries WAL mode could
serve concurrently, and it holds the lock across statement compilation. A read
pool plus a single writer is the standard SQLite shape.

**13.6 Digests are bytes, not hex strings.** Storing a digest as `String` hex
means every comparison allocates an encoding to compare 32 bytes, every
serialization doubles, nothing rejects a malformed or differently-cased value, and
the comparison is not constant-time. Use `[u8; 32]` or the existing `Digest32` at
rest and hex only at the display boundary. Where the digest authenticates rather
than identifies, compare in constant time and say so at the call site.

**13.7 Security data structures are keyed by closed types, not strings.** A
`BTreeMap<String, _>` keyed by syscall name makes a typo a runtime rejection at
best and a silent no-op at worst. In the cage it is the former: `sandbox.inc:1086`
refuses a plan whose constraint names an unlisted syscall, which pass 6 confirmed
after pass 3 wrongly reported the check absent. The rule stands on type-design
grounds: an enum or numeric key makes the typo a compile error and moves the
check from launch time to construction time. The map is built once per launch, so
the speed argument is irrelevant and invoking it would be the overclaim.

**13.8 Benchmark the composite operation, not the component you already trust.**
The one benchmark in the store crate measures receipt write throughput.
`receipt_store.rs` is the only store file with zero `prepare()` calls, and its
append path compiles no SQL per receipt in the single-writer case. The budget,
security-state, admission, commit-chain and revocation paths, all on the
authorization critical path, have none. Measurement that points at the fast path
produces confidence without information, which is worse than no benchmark because
it also hides regressions. Benchmark the per-authorization composite, against a
populated store; a benchmark over an empty table measures the wrong thing whatever
path it covers.

**13.9 No performance change without a before-and-after number.** A refactor
justified as an optimization, with no measurement, is a behavior change with extra
risk. This applies hardest to the tempting ones: removing clones, replacing a map,
switching a collection. If it cannot be shown in a benchmark, it is type-design
work and should be proposed and reviewed as type-design work.

**13.10 Scale claims name the path they measured.** A million-receipt append
campaign proves receipt append scales. It does not prove authorization scales, and
the ledger should not let the second be read out of the first.

---

## 14. State recovery, serialization boundaries and tenant isolation

**14.1 Lock-poison policy is uniform and decided once.** `std::sync::Mutex`
poisons on a panic and stays poisoned for the process lifetime, so a single panic
inside a critical section permanently disables whatever the lock guards. Pick one
policy per guarded resource and apply it to every store: recover with
`into_inner()` where the state is known-consistent after a panic, or wrap the
critical section in `catch_unwind` so the panic becomes one failed operation. For
a SQLite connection the state is recoverable, because an aborted transaction rolls
back, so recovery is the default. Every mutex-guarded store's connection lock
(18 stores, 26 sites) maps poison to a permanent error (finding S1). The 13 pooled
stores, including the receipt store, are not exposed, and poison recovery is
applied to a public-key cache lock elsewhere. So both remedies, pooling and
recovery, are already in the tree and neither is applied to the 18.

*Enforced by:* a per-store test that panics inside the lock and asserts the next
operation succeeds. Does not exist. Debt item.

**14.2 Turning on a check that panics requires panic recovery first.** This is the
rule that binds 4.1 to 14.1. Enabling `overflow-checks` in release is correct,
and on its own it adds panic sites to arithmetic inside store critical sections,
converting a silent budget wrap into a permanently unavailable store. A
correctness fix that introduces an availability failure is half a fix. Ship the
two together, in one packet, and say in the ledger that they are coupled.

More generally: before adding any assertion, bound check or lint that converts a
silent wrong answer into a panic, establish what the panic does to shared state.
In a fail-closed system a panic is an acceptable outcome only if something
contains it.

**14.3 Untrusted serialized text is a type, not a convention.** A strict parser
that rejects duplicate keys, non-I-JSON numbers and over-precise literals defeats
a real signature-equivalence class, and it defeats nothing at a call site that
used the permissive entry point by mistake. Wrap the boundary:
`UntrustedJsonText(String)`, constructed at every wire, file and database read,
whose only canonicalization method is the strict one. Then the permissive path
cannot be reached from untrusted input without an explicit, greppable conversion.

A strict primitive available at 91 of roughly 2,850 call sites with no policy naming
which paths require it is a convention with a good reputation (finding S2), which
is the thing this standard exists to eliminate.

**14.4 Signed data has exactly one parser.** Once a payload's authenticity is
established over canonical bytes by one parser, no other component re-derives a
field from the same text with a different parser. A SQL trigger calling
`json_extract` on a signed statement is a second parser in the trust base, and it
buys nothing that binding the already-verified typed value as a parameter would
not (finding S4). Parse once, verify once, pass the verified value.

**14.5 A column holding a security-critical value carries a `CHECK`
constraint.** The database is the last enforcement layer and the cheapest one.
`cost_charged_be BLOB CHECK (typeof(...) = 'blob' AND length(...) = 8)` is the
reference shape; a chain-link column declared bare `TEXT` next to it is the
inconsistency. Shape, nullability and range all belong in the schema, in addition
to the Rust check, because rule 1.5 permits the same rule at a second *mechanism*.

**14.6 Every tenant-scoped table is classified, and the classification is
gated.** A table with a `tenant_id` column is either "tenant predicate required"
or "accessed by a globally unique unguessable identifier whose derivation is
named". Record which, next to the schema. Gate on statements touching the first
class without a `tenant_id` predicate. 64 tables and 72 unscoped statements with
no classification means nobody can state the isolation property, including a
reviewer who tries (finding S3).

**14.7 Unguessability is a derivation, not a hope.** Where isolation depends on
an identifier being unguessable, derive it (`domain_hash(DOMAIN, &canonical)`, as
`enterprise_receipt.rs:414` does) and give it a type whose constructor is that
derivation. An opaque `String` identifier that *happens* to be unpredictable today
is one convenience change away from being sequential, and nothing would fail.

**14.8 A vendored fork records its upstream, its patches and its diff.** The
existing practice is the standard: an exact upstream pin, a `-chio` version
suffix, a README, a `PATCHES.md`, a `provenance/` directory, and for the most
security-critical fork a parallel unmodified checkout so divergence is diffable.
Any new fork matches it before it enters the build, and a fork inside the TCB
additionally needs a named reviewer for the delta.
