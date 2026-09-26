# Spec: hardening toolchain for the security TCB

What Chio's verification and enforcement stack already contains, what it lacks,
and the exact target state for each gap. Companion to the
[security engineering standard](../../security/engineering-standard.md), whose
"Enforced by: review. No gate. Debt item." markers this spec retires one by one.

The measurements below were taken on `integration/process-security-m4` at
`e8e5d592ec`. Where a number is a workflow count, it is the number of files under
`.github/workflows/` that mention the tool, not a count of lanes that gate on it;
each item's first task is to confirm what actually gates.

## Position first

The stack is already unusually deep for a Rust security product. Present in at least one workflow (whether each gates is item H9's first question): cargo-mutants (7), Kani (6), Creusot (4), Aeneas
(4), Lean (16), Apalache and TLA+ (7), loom (2), proptest (6), libFuzzer (5),
sanitizers (5), cargo-vet (8), cargo-deny (6), cargo-auditable (4), SLSA
provenance (9), reproducible builds (8). The gaps are not "add formal methods".
They are narrower and mostly cheap: undefined-behaviour detection on the code
that contains `unsafe`, compiler enforcement of two disciplines the codebase
already follows by hand, a test runner that isolates processes, a proof that has
no lane, and the type for secrets that the standard already requires.

The organizing principle is the standard's: an invariant that depends on a human
remembering it is a convention with a good reputation. Every item below converts a
convention the codebase already follows into something the compiler, a gate, or a
lane enforces.

## The gaps

### H0. Workspace lint additions do not reach 20 crates unless mirrored

**Census.** 157 crate manifests; 137 inherit `[lints] workspace = true`; 20 do
not, because they carry a local `[lints.rust] unexpected_cfgs` check-cfg table
(for `kani`, `loom`, `dhat` and `creusot` cfgs) and Cargo forbids mixing
`workspace = true` with local entries. Among the 20 are `chio-kernel`,
`chio-kernel-core`, `chio-store-sqlite` and `chio-core-types`. All 19 library
crates replicate `unwrap_used = "deny"` and `expect_used = "deny"` by hand in
their own `[lints.clippy]`; the twentieth, `chio-wasm-guards/fuzz`, is a fuzz
harness and does not, which is acceptable there.

So the current policy is intact everywhere it matters, by 19 hand-maintained
copies. The trap is what happens next: every lint this spec adds to the workspace
table (H1, H4) silently misses those 19 crates unless each manifest is edited
too, and nothing today would notice. The manifest's own comment ("every member
crate inherits this block") is already untrue.

**Target.** A gate that parses every opt-out manifest and asserts that both its
`[lints.rust]` and `[lints.clippy]` tables carry every workspace lint at the same
level with the same explicit exceptions (H1 adds `unsafe_op_in_unsafe_fn` to the
*Rust* table, which a Clippy-only comparison would miss, per the external review's
R8), with a self-test that fails when a workspace lint is added to either table and
not mirrored. Run it first in Lane K, so
H1 and H4 land on a base where reaching all crates is checked rather than
assumed.

**Acceptance.** The gate passes on the current tree; adding a lint to the
workspace table alone turns it red; the manifest comment is corrected.

### H1. `clippy::undocumented_unsafe_blocks` and `unsafe_op_in_unsafe_fn`

**Census.** `undocumented_unsafe_blocks`: 0 crates. `unsafe_op_in_unsafe_fn`: 2
lib roots. The cage carries 101 `unsafe` occurrences with SAFETY comments at
nearly one to one per file (`linux.rs` 11/11, `launch.rs` 3/3, `part_02.rs`
38/39, `bootstrap.inc` 23/23, `sandbox.inc` 22/25). That discipline is what pass 2
called exemplary and invisible; nothing enforces it.

**Target.** Workspace-wide:

```toml
[workspace.lints.rust]
unsafe_op_in_unsafe_fn = "deny"

[workspace.lints.clippy]
undocumented_unsafe_blocks = "deny"
multiple_unsafe_ops_per_block = "deny"
```

Every `unsafe` block carries a `// SAFETY:` comment stating the invariant that
makes it sound, or the build fails. Every unsafe operation inside an `unsafe fn`
gets its own block and its own comment. One operation per block, so the comment
and the operation it justifies cannot drift apart.

**Expected red, measured.** 34 crates contain `unsafe`: 210 `unsafe {` blocks against
195 `// SAFETY` comments. The gap is **16 blocks in five crates**: `chio-cage` 4,
`chio-cli` 5, `chio-guard-sdk` 5, `chio-guard-sdk-macros` 1, `chio-commerce-order` 1.
Every other crate with `unsafe` is already at one comment per block. Five crates
also declare `unsafe fn` (`chio-secret-broker` 3, `chio-guard-sdk` 1,
`chio-secure-ipc` 1), which is where `unsafe_op_in_unsafe_fn` will add blocks. Measure first with
`cargo clippy --workspace -- -W clippy::undocumented_unsafe_blocks -W
clippy::multiple_unsafe_ops_per_block` and record both counts per crate; the
second lint may split many blocks in the FFI-heavy crates, so decide its level
from the count. Then write the missing comments, each stating the invariant and
not the mechanism. Do not `#[allow]` any of them. Mirror both lints into the 19
opt-out manifests (H0) or they reach none of the kernel, the store or
`chio-core-types`.

**Acceptance.** The lint is `deny` at workspace level; `cargo clippy --workspace
--all-targets -- -D warnings` passes; a deliberately uncommented `unsafe` block in
a scratch test fails the build.

### H2. Miri on every crate whose `unsafe` is pure Rust

**Census.** Miri: 0 workflows. 22 crates contain `unsafe` (files with unsafe in
parentheses): `chio-kernel` (6), `chio-cage` (6), `chio-secret-broker` (6),
`chio-transaction-passport` (4), `chio-active-response-authority` (3),
`chio-agent-web-interop` (2), `chio-commerce-order` (2), `chio-control-plane` (2),
`chio-enterprise-export` (2), `chio-cpp-kernel-ffi` (2), `chio-guard-sdk` (2),
`chio-secure-ipc` (2), `chio-core-types` (1), `chio-wasm-guards` (1), and eight
more with one file each.

**Target.** A nightly `miri.yml` lane running `cargo +nightly miri test -p <crate>`
on every crate in a committed list, with `MIRIFLAGS` and a nightly date pinned in
the workflow so the lane is reproducible; the workspace's stable 1.94.1 pin is
untouched. Two limits bound the scope honestly, and they are the only two exclusion reasons.
Miri cannot execute `seccomp`, Landlock, `fork`, `memfd` or raw socket syscalls;
Miri cannot call into C, so anything that opens SQLite (`rusqlite`, the whole store
crate) or signs through `aws-lc-rs` is out of reach unless a pure-Rust backend
feature exists for the test build. Every excluded test names which of the two
applies in its `#[cfg_attr(miri, ignore)]` reason. A crate on the list must show
that its `unsafe` code actually executes under Miri (a canary test per `unsafe`
module, or coverage), because a green list of crates whose unsafe paths were all
ignored proves nothing. Unit tests only; Miri is 10 to 100 times slower. Everything else runs: pointer casts, slice
construction, FFI-adjacent buffer handling, the decimal formatter in
`write_current_pid`, transmute-free but layout-sensitive code, the parsers under
their proptest generators.

**Classification task.** For each of the 22 crates, record: runs under Miri
entirely; runs with named syscall tests ignored; excluded with a reason (only the
OS-boundary modules of the cage should qualify). Commit the classification as the
lane's crate list with a one-line reason per exclusion.

**Acceptance.** The lane is green on the committed list; a deliberately
introduced out-of-bounds read in a scratch test under one listed crate fails the
lane; the exclusion list names a syscall for every excluded test.

### H3. `#![forbid(unsafe_code)]` on every crate that has none

**Census.** 101 of 149 lib roots forbid unsafe. Of the 48 that do not, 26 contain
no `unsafe` at all: among them `chio-bounded`, `chio-supervisor`,
`chio-web3-bindings`, `chio-data-guards/redactors/default`, `chio-wasm-guards/fuzz`,
`chio-kernel-browser`, `chio-kernel-core`, `chio-swarm-authority`,
`chio-finding-market-store-postgres`, `chio-finding-worker`. The remaining 22 use
`unsafe` legitimately and are the H2 list.

**Target.** `#![forbid(unsafe_code)]` at the root of all 26. `forbid` rather than
`deny` so no inner `#[allow]` can reopen it. A gate (extend the hygiene gate or a
short sibling) fails on any lib root that neither forbids unsafe nor appears in
the H2 list with a reason.

**Acceptance.** 127 of 149 lib roots forbid; the remaining 22 are exactly the H2
list; the gate has a self-test.

### H4. The TCB deny set

**Census.** In the 22 security, kernel and store crates: `clippy::indexing_slicing`
0, `clippy::panic` 0, `clippy::todo` 0, `clippy::unimplemented` 0,
`clippy::dbg_macro` 0, `clippy::print_stdout` 0, `clippy::as_conversions` 0,
`missing_docs` 1, `unreachable_pub` 0.

**Target.** Cargo rejects `workspace = true` combined with local entries in one
`[lints]` table (`cannot override workspace.lints in lints`, reproduced by the
external review's probe), so each of the 22 crates either carries a complete local
mirror of the workspace tables plus the additions below, kept in parity by H0's
gate, or applies the additions as crate-root `#![deny(...)]` attributes. Each
category is mutation-tested: a violating fixture in the crate fails the build. The
remediation of existing sites is performed by the lane that owns each crate, not by
the gates lane. The additions:

| Lint | Why, for this TCB |
| --- | --- |
| `clippy::indexing_slicing = "deny"` | an out-of-bounds index is a panic, and a panic in a fail-closed kernel is a denial of service that in 18 stores also poisons the connection mutex |
| `clippy::panic`, `todo`, `unimplemented`, `unreachable` = `deny` | explicit panics in production paths; `unreachable!` in a security match is how a new variant crashes instead of denying |
| `clippy::dbg_macro`, `print_stdout`, `print_stderr` = `deny` on library targets | the two most common ways secret material reaches a log; the 31 existing sites are all in `src/bin/` daemons writing startup diagnostics to stderr, which is legitimate for a binary, so scope these to `lib` targets |
| `clippy::as_conversions = "deny"` | the lossy-cast cousin of the overflow finding; `as` between integer widths silently truncates; use `try_from` |

| `unreachable_pub = "warn"` | the visibility-minimization Packet 7 performs by hand, as a lint; promote to `deny` per crate as Packet 7 finishes each module |
| `missing_docs = "warn"` on public security items | rule 2.2's "state the invariant and the caller's obligation" needs a doc comment to exist |

**Allow discipline.** Where a deny must be relaxed at a site, the attribute
carries a reason: `#[allow(clippy::indexing_slicing, reason = "index bounded by
the length check two lines above")]`. A gate fails on any `#[allow(clippy::` in
these crates without `reason =`. That gate is the mechanism that keeps the deny
set honest over time.

**Expected red and sequencing.** A lexical scan of production files in the 22
crates gives upper bounds only, because inline `#[cfg(test)]` modules cannot be
excluded reliably without compiling: at most 563 `as` integer casts, at most 49
variable-index expressions, 31 print sites (all in binaries), and 0 production
`unwrap`/`expect` by construction, since that deny is active in every TCB crate
and Clippy is green. The only trustworthy measurement is `cargo clippy -p <crate>
-- -W clippy::<lint>` per lint, per crate; record those counts before choosing
`deny` versus `warn`. Fix or reason-allow each site. Land per crate, one commit
per crate, so a regression is attributable. This lane touches files owned by
other Wave 1 and Wave 2 lanes, so it runs after they merge (see sequencing).
Do not add `clippy::exhaustive_enums` or `exhaustive_structs`: they push public
types toward `#[non_exhaustive]`, which forces downstream `_ =>` arms, the exact
thing the standard's rule 2.5 forbids for closed wire and state-machine types.

**Acceptance.** All 22 crates carry the table; `-D warnings` passes; every
`#[allow(clippy::` in the 22 has a reason; the reason gate has a self-test.

### H5. cargo-nextest

**Census.** 0 workflows; not installed on the build host.

**Target.** `cargo-nextest` pinned by version, installed by the CI setup step, with
`.config/nextest.toml` committed:

- `slow-timeout` with **per-group overrides that preserve every existing inner
  deadline**: a native recovery harness already allows its child 300 s before
  restart verification (`native_flow_caller_process_tests.rs:174`), so a global
  180 s cutoff would kill a correct test and misreport it as isolation-dependent
  (the external review's R7). The default applies only to tests with no declared
  deadline
- `leak-timeout` for what it actually detects: a child process still holding the
  test's inherited stdout or stderr. It does not see threads, nor a child whose
  streams were redirected to a file, which the native harness does; keep the
  existing child-lifecycle assertions for those. Set the leak outcome to fail
  explicitly, since nextest treats leaks as passing by default
- `retries = 0` in the required lanes. Retries hide flakes. A separate,
  non-required "flake census" lane runs with `retries = 2` and `--no-fail-fast`
  and publishes which tests needed a retry, so flakes are measured, never
  green-washed
- `fail-fast = false` so one failure does not hide the rest
- JUnit output archived per lane, so the inventory counts the ledger requires are
  machine-produced rather than typed
- doctests still run through `cargo test --doc`; nextest does not execute them
- the parent plan's `RUST_TEST_THREADS=1` for the store suites becomes a nextest
  `test-group` with `max-threads = 1` scoped to those binaries, so isolation is
  per group rather than a global environment variable

Process-per-test isolation is the point: any test that passes under `cargo test`
and fails under nextest was depending on state left by a sibling test in the same
process. Each such failure is a real finding about the test, occasionally about the
code.

**Acceptance.** The workspace test step runs under nextest; every test that
failed only under isolation has a recorded disposition; the flake census lane
publishes its list.

### H6. A Verus lane

**Census.** `formal/experiments/verus-eval/` exists, pinned to
`release/0.2026.07.18.3a4d30b`. 0 workflows. The FV-B5 spec records the outcome:
executed 2026-07-23, the concurrent conservation law proved unbounded in
schedules, actors and amounts, both broken variants falsified, and **no lane
created, because the FV-E5 enforcement precondition is the sole blocker**: the
formal estate's own rule is that no seventh proof toolchain is added until one
existing lane has completed the FV-E5 promotion runbook, so that the enforcement
layer is exercised before the estate widens. That is a good rule and this spec
keeps it.

**Target.** In order: first, run the FV-E5 promotion runbook to completion on the
strongest existing lane (the PR-tier Kani lane, with its 49 proofs, is the
natural candidate), which satisfies the precondition and exercises the ratchet
machinery on a lane that already gates. Then `formal-verus.yml`, nightly, at the
spike's pinned release, running the conservation proof, failing on any proof
failure, registering the obligation in `formal/proof-manifest.toml`, and taking
FV-B5's decision outcome (a): a narrow concurrency-only lane. A proof with no
lane rots the day its target changes; a lane with no required status is a lane
nobody reads. Make it required on the formal-proof contract once it has been
green for a week.

**Acceptance.** The FV-E5 runbook is recorded complete for one existing lane; the
Verus lane is green; a deliberate mutation of the proved function (the spike's
own broken variants) turns it red; the manifest entry names the production
function the proof is about.

### H7. `secrecy` for secret material

**Census.** `zeroize` is a workspace dependency; `secrecy` is not.

**Target.** `secrecy::SecretBox<T>` and `SecretString` for key material,
credentials, seeds and tokens. `secrecy` wraps `zeroize`, so nothing is lost, and
it removes what the standard's rule 7.1 forbids: `Debug` prints `[REDACTED]`,
there is no `Display`, no `Serialize` without an explicit opt-in, and access is
through `expose_secret()`, which is greppable. The inventory, measured: **8 structs** carry a `Zeroizing` field and derive `Clone`
or `Serialize`; none derives `Debug`. Seven derive `Clone` only (six external-guard
configurations holding API keys, and `DualSignReleaseInput`), which `Zeroizing`
tolerates because clones zeroize on drop. One, `FrostAuthenticatedDkgPackage` in `chio-federation-authority`, derives
**`Serialize`** on key-generation material, and pass 8 confirmed (finding U8) that
for round 2 the field is the recipient's secret signing share, hex-encoded, signed
by the transport key and not encrypted. No in-tree transport serializes it yet, so
there is no live exposure; the type permits one. H7's first task is therefore not
`secrecy` but sealing: encrypt round-2 package bytes to the recipient's transport
key inside `authenticated_package`, or split the type so the plaintext round-2 form
never implements `Serialize`, with a test asserting the share bytes are absent from
the serialized output.

**Acceptance.** No secret-bearing struct derives `Debug` or `Serialize` on the
secret field; `expose_secret()` call sites are the complete inventory of where
secrets are read; a gate fails on a new `Zeroizing<` field in a `Debug`-deriving
struct in the security crates. For the FROST round-2 package specifically: the
immediate boundary is removing `Serialize` from the plaintext round-2 form;
sealing is a separate design note (encryption key suite distinct from the
signature key, recipient binding, authenticated metadata, decryption and replay
tests), because encrypting to the existing transport *signature* key is not an envelope,
per the external review. The design note now exists:
[FROST round-2 sealing design](2026-09-26-frost-round2-envelope-design.md).

### H8. `cargo-semver-checks` and `cargo-public-api` for the publishable crates

**Census.** 0 workflows. Every crate is `publish = false` today; Milestone D plans
`0.2.0-alpha.N` publication.

**Target.** A lane that runs both against every crate whose manifest is
publishable, with public-API snapshots committed and diffed on every change. It
gates nothing until the first crate flips to publishable, and it exists before
that flip, because the first breaking release is otherwise discovered by a
consumer.

**Acceptance.** Snapshots exist for the intended publishable set; the lane turns
red on a deliberate public signature change.

### H9. Confirm the sanitizer lanes

**Census.** 5 workflows mention sanitizers; which sanitizers run on which crates
was not extracted.

**Target.** Record which of ASan, TSan, MSan and UBSan run and on what. ASan is
expected via libFuzzer. TSan on the loom-adjacent concurrent code (the store
writer actor, the broker service, the scheduler worker) is the one most likely to
be absent and most valuable; it finds data races loom's bounded model does not
reach. Add it if absent.

**Acceptance.** A table in the ledger: sanitizer, lane, crates, last green run.

### H10. Wire-schema pinning

**Census.** 588 hand-written `const ..._SCHEMA...: &str = "chio....vN"` constants
in production code (the spec codegen produces one; everything else is typed by
hand). Crediting Rust test literals, JSON and TOML fixtures under test
directories, and `spec/`, **308 are pinned somewhere and 280 are not; 68 of the
unpinned are in the security TCB**, densest in `chio-kernel` (36),
`chio-control-plane` (23) and `chio-keyring` (12), and including the entire
secret-broker wire protocol (`chio.broker-execute.v1`, `chio.broker-capability.v1`,
`chio.broker-execution-receipt.v2`), the key-log family, the cage envelopes and
receipts, and `chio.dpop_proof.v2`. Separately, **55 schema values are declared in more than one file, 54 of them
across crate boundaries** (38 as the same constant name copy-pasted, 17 under
different names); `chio.receipt.v1` alone is declared in six files across five
crates. Concentrated in `chio-runtime-core` (25), `chio-runtime` (23) and
`chio-cli` (20).

The CI regression at `3cd73631a1` is the case study: the caller-return-context
bump from v4 to v6 was caught only because two round-trip tests happened to pin
the literal. A bump to `chio.broker-execute.v1` would be caught by nothing.
"Never break userspace" has no enforcement for 280 of 588 wire formats.

**Target, narrowed per the external review's R10.** A committed snapshot,
`spec/wire-schemas.lock` (value, declaring files, first-seen commit), and a
generated test per crate asserting every schema constant equals its snapshot entry.
This makes an identifier change an *acknowledged* change and nothing more: renaming
a field while keeping the identifier passes it, and bumping identifier and snapshot
together says nothing about historical readers. Compatibility is a separate
mechanism: each schema entry is associated with a canonical-byte shape fixture and
an old-reader test, so a shape change fails independently of the identifier. For the 55 duplicates: one
declaration per value in a `WireSchema` registry, the same shape as the `Domain`
enum in the unrepresentable-defects design, imported everywhere else. The
snapshot and generated tests are additive and belong early in Lane K; the
deduplication touches owned files and lands with Packet 7 or the owning lane.

**Acceptance.** Every hand-written schema constant appears in the snapshot; the
generated tests fail on a deliberate bump without a snapshot edit; the duplicate
count is 0 or each remaining duplicate has a reason in the registry.

### H11. A dependency budget for privileged helpers

**Census.** `chio-cage`, the package that ships the confinement helper binary
`chio-cage-init`, has a normal-dependency **package graph** of **344 unique
crates**,
unchanged with default features off, including `tokio`, `hyper`, `hyper-util`,
`reqwest`, `tower-http`, `rustls-webpki`, `aws-lc-rs`, `regex`, `fancy-regex`,
`serde_json` and `tracing`. The cause is the crate's dependency on `chio-core` and
`chio-manifest`. `chio-secret-broker` is at 640, `chio-keyring` at 94,
`chio-security-types` at 10.

A package graph is not binary linkage: `cargo tree` reports what a package depends
on, not what the linker kept in a particular target's artifact, and Cargo does not
promise equivalence. So the first version's "an HTTP client compiled into the
helper" is withdrawn until measured; what is established is that the helper's
*package* carries the platform's graph. The helper is still the most privileged
program at runtime, and the existing static-PIE and ELF checks prove only the
absence of dynamic dependencies.

**Target.** Move the helper into its own crate depending only on the plan and
envelope types, `seccompiler-chio` and `nono-chio`. Measure its graph on the musl
target, set a committed ceiling from that measurement, and gate it: a script runs
`cargo tree -p chio-cage-init --edges normal --target x86_64-unknown-linux-musl`,
fails above the ceiling, and fails on any crate from a deny-list (`tokio`,
`hyper`, `reqwest`, `rustls`, `regex`, `serde_json` unless the plan format needs
it). Apply the same gate, with its own ceiling, to the `chio-secret-broker` package
(`chio-secret-brokerd` is a binary target inside it, not a package name), whose
640 is the next question. Artifact provenance, what the release binary actually
contains, is measured separately from the package budget.

**Acceptance.** The helper's graph is under its ceiling with no deny-listed
crate; the gate has a self-test that fails when a deny-listed crate is added;
the ceilings are recorded in the ledger with the date measured.

## Direction, not yet tasks

### Deterministic simulation testing

The hardest bugs in this system are crash, recovery and concurrency across
processes; that is the entire content of parent Packet 2 and of the P1 findings.
The process-cutpoint harness is a hand-built partial deterministic simulation.
The full form (FoundationDB, TigerBeetle, and Antithesis as the commercial
whole-system version) runs the system under a seeded scheduler and injected
faults so a failure reproduces from a seed.

Correction 4A's injected clock port is the prerequisite; an ambient
`SystemTime::now()` in 60 files is why the system cannot be simulated today. The
next step after 4A is a seeded scheduler over the store and broker actors and the
scheduler worker, with the existing cutpoint hooks as the fault-injection points.
`turmoil` is worth evaluating for the tokio-network parts. Antithesis is the
option for launch qualification if the budget exists; it is not a substitute for
the in-tree work, because the in-tree work is what makes the system simulable at
all.

### Hegel

Hegel (hegel.dev) is a property-based testing engine built on Hypothesis by the
Hypothesis maintainers at Antithesis, with client libraries for Rust, Go, C++,
TypeScript, Java and OCaml behind one server that owns generation and shrinking.
It is a PBT tool, not verification. Chio runs proptest in six workflows.
Replacing proptest inside the TCB with a young client library plus a server
process is maturity risk for better shrinking; not worth it now.

The place it could earn its keep is the one gap proptest cannot cover: one
generator driving malformed and edge-case protocol payloads (`spec/PROTOCOL.md`,
canonical JSON, receipts) into the Rust kernel and the TypeScript, Python, Go and
C++ SDKs at once, with one shrinker. SDK parity testing is example-based today.
Pilot Hegel there, in Wave 3, on the SDK surface only, and measure whether it
finds anything the example suite does not before extending it.

## Sequencing

| Item | Depends on | Wave | Owner lane |
| --- | --- | --- | --- |
| H0 lint-parity gate | nothing | 2, first | K |
| delete the unreferenced `admission_cleanup/recovery_and_compensation.inc` (1,228 lines, found by Lane A) | a build confirming nothing needs it | 2 | K |
| H10 schema snapshot and generated pins | nothing (additive) | 2, second | K |
| H1 unsafe lints | the H1 measurement; the cage is owned by no Wave 1 lane; H0 for the mirror | 2 | K |
| H3 `forbid` on 26 crates | nothing; disjoint from all lanes | 2 | K |
| H5 nextest | nothing | 2, first, so later lanes' tests run isolated | K |
| H2 Miri lane | H1 (comments) helpful, not required | 2 | K |
| H6 FV-E5 runbook on Kani, then Verus lane | FV-E5 runbook completion | 2 (runbook), 3 (lane) | K |
| H11 helper dependency budget | measuring `chio-cage-init` on the musl target; touches the cage crate, which no Wave 1 lane owns | 2 | K |
| H9 sanitizer audit | nothing | 2 | K |
| H4 TCB deny set | B, C, D merged (touches their files) | 2, last in K | K |
| H7 `secrecy` | inventory first; touches broker and keyring | 2 or 3 | K or D follow-on |
| H8 semver and public API | the publishable set decision | 3 | K |
| DST scheduler | 4A clock port | 3 | new lane |
| Hegel SDK pilot | nothing | 3 | new lane |

Lane K's items land one commit each, each with its gate's self-test or its lane's
red-on-mutation demonstration, per the standard's rule 12.6: a gate that cannot
fail on a real violation has not been shown to work.

## Rationale

Most of this is the oldest kind of engineering advice: turn on every warning that
finds real bugs and make it fatal; refuse patches that add an exemption without a
reason; keep each patch small enough to review; never break the wire format
without saying so; and understand that no tool fixes a data structure that lies
about what it is. The type-design work in the
[unrepresentable-defects design](2026-09-26-unrepresentable-defects-design.md)
addresses the last point and comes first. This spec is everything that can be done
mechanically alongside it.
