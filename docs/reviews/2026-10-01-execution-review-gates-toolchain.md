# Execution review: build gates, hardening toolchain, FFI, compiler and secret hardening, October 1, 2026

Scope: commits `407a590e17` (lint parity), `5c94611c7d` and `3ae2cd7733`
(wire-schema lock), `a56e2edbe6` (dependency budget), `3f8948e76e` (nextest),
`72bd03d057` (Miri lane), `de68fe51f7` (sanitizer audit and lane), `7080e415b1`
(FV-E5 Kani runbook), `d0469ce384` (negative assertions by site), merge
`37ce39c8a0`, `f928453692` (census corrections), `4c5d43dfe5` (FFI buffer
ownership), `3b596d22bb` (release overflow checks) and `d51afb4a5f` (compiler
enforcement and secret ownership, 666 files), plus every gate script, self-test
and workflow they wire as it stands at the tip `a2630c20a1` (base `07e963e8f5`).
Plans: the hardening toolchain spec (H0 to H11), the umbrella addendum's Packet 0
(0.1 to 0.5) and corrections 2A and 2B, and the September 28 compiler and
secret-hardening plan. Records: the September 29 compiler and secret-hardening
execution record, the gate rows of the September 26 resumed-execution record,
`docs/security/toolchain/{miri-crates,sanitizer-audit}.md` and the FV-E5
runbook. Method: source reading at the tip; every Python gate and self-test in
the slice run locally against the tip; bypass fixtures built in a scratch
directory and run through the real gate scripts; the GitHub API for workflow
runs, job logs and the `main` ruleset. No cargo build, test or Miri run.

**Judgment: The individual gates are mostly well built: each has a real
self-test with violating fixtures, the dependency budget and release-overflow
probe are exemplary, and the FFI fix is correct. But none of them runs in
hosted CI. The required job's structural step fails at the tip on three checks,
two caused by this slice itself (its new `.config` and probe files are
unclassified by the review-slice gate, and `d51afb4a5f` broke the lint-parity
self-test), so the step aborts before every gate here, Clippy, the build and the
tests; the first hosted run after the gate merge failed on that same
classification on September 26 and stayed red. The nightly Miri and sanitizer
lanes have never run because neither workflow is on the default branch, and two
of the six Miri-listed crates execute no unsafe code under Miri. The
secret-ownership work wrapped the downstream types but left the plaintext
sources (an authority seed handoff and the policy-loaded guard API keys) as
`String` fields deriving `Debug` in a TCB crate, and the shipped Lambda
extension still builds the kernel without overflow checks. The machinery is
proportionate to its goals; its value is unrealized until CI reaches it.**

## Plan conformance

| Plan item | Recorded status | Verified status | Evidence |
| --- | --- | --- | --- |
| H0 lint-parity gate | done | Gate correct; its self-test is red at the tip (GT1) | `scripts/check-lint-parity.py:68`, `scripts/tests/check-lint-parity.test.sh:191-196`; gate output 179 manifests, 160 inherit, 19 mirror |
| H1 unsafe lints, workspace and mirrors | done (compiler plan task 1) | Present in `Cargo.toml:319-324` and all 19 mirrors; compiler probes pass locally; not exercised in hosted CI (GT1) | lint-parity run; probes run by subagent |
| H2 Miri lane and classified crate list | done (configuration) | Lane has never run; two of six listed crates execute no unsafe code under Miri; four crates with unsafe remain unclassified (GT3) | `.config/miri-crates.toml:21-66`; `gh run list --workflow miri.yml` returns 404 |
| H3 `forbid(unsafe_code)` on eligible roots | done (167 roots, 14 exceptions now) | Done; exceptions are crate-wide (GT6) | `scripts/check-rust-hardening.py:57-63`, `docs/security/toolchain/rust-hardening.json` |
| H4 TCB deny set and reason gate | done for the named deny set; docs/visibility lints deferred | Nine lints on all 27 TCB roots as `cfg_attr(not(test), deny(...))`; reason gate satisfied by boilerplate on 164 sites (GT5); gate bypasses (GT6) | `check-rust-hardening.py:43-54,151-167` |
| H5 nextest lane | done | Additive PR lane, hosted green at `f25cd61f49` (673 tests); not required; the non-required flake-census lane with `retries = 2` was not built | `ci.yml:442-490`, `.config/nextest.toml` |
| H6 FV-E5 runbook on Kani | executed locally, flip pending | Accurate except one false claim about requiredness (GT10); acceptance ("recorded complete") not met, and the record says so | `docs/formal/plan/FV-E5-kani-promotion-runbook.md:42` |
| H7 secret ownership | done (compiler plan task 4) | Partial: downstream owners wrapped, plaintext sources not (GT4); allocation copies remain (GT11) | `keyring_runtime.rs:1285-1293`, `guard_config.rs:113-139` |
| H8 semver and public API | Wave 3 | Not started, as planned | none |
| H9 sanitizer audit and TSan | done | Audit table honest; lane added but covers none of the concurrent code H9 named, and has never run (GT9) | `.github/workflows/sanitizers.yml:34` |
| H10 wire-schema lock | done for identifiers | Lexical lock gate instead of generated per-crate tests; gate correct on the tree, with a bypass (GT7); 163 duplicate values remain, owned elsewhere | `scripts/check-wire-schemas.py:291-318` |
| H11 dependency budget | done | Done; real-graph self-test, 12 cases pass at tip | `scripts/check-dependency-budget.py`, `scripts/tests/check-dependency-budget.test.py` |
| 0.1 hygiene gate on assembled modules | done | Done; ratchet-dropped caps permit unbounded growth (GT8); gate red at tip on `chio-market/src/tests.rs`, out of slice | fixture run; local gate run |
| 0.2 release overflow checks | three of five boxes | `release` and `docker-release` set, probe gate real; shipped Lambda extension and one workflow job build without them (GT2); release-tier tests and cost measurement honestly unchecked | `Cargo.toml:339-350`, `sdks/lambda/chio-lambda-extension/Cargo.toml:59-63` |
| 0.3 accounting arithmetic | lexical gate done; compiler lint unchecked | The compiler lint is applied to 49 modules by `d51afb4a5f`; the plan box at `2026-09-26-security-engineering-excellence.md:196` was never updated | `rust-hardening.json` `accounting_modules` |
| 0.4 domain-separation gate | done; debt retirement open | Gate correct; its self-test is red at the tip, broken by `a8b5f11d3e` (GT1) | `scripts/tests/check-domain-separation.test.sh:98-108` |
| 0.5 assertion-strength gate | done | Done; narrow by design (GT13) | `scripts/check-negative-assertions.py:201-226` |
| 2A arch probes | done (native run pending) | x32 and i386 probes present in the mandatory inventory; native execution still pending as recorded | `crates/security/chio-cage/tests/linux_enforcement.rs:1325-1330` |
| 2B typed syscall keys | done | Done: `BTreeMap<Syscall, ...>`, construction-time rejection and test | `crates/security/chio-cage-plan/src/seccomp_plan.rs:184,203,384` |
| Compiler plan task 5: calibration | done | Probes and 19 source cases pass; the self-test never calls `check()`, so the census and stale-exception logic is untested (GT6) | `scripts/tests/check-rust-hardening.test.py:15-101` |

## GT1. Medium: the required CI job cannot reach any gate in this slice, or Clippy, build and tests, at the tip

Every gate this slice added runs inside one multi-line `run:` block, the
"Workspace structural gates" step of the required `Build, lint, test` job
(`.github/workflows/ci.yml:97-197`). The step runs under `bash -e`, so the first
failing command ends it, and every later step in the job (format, hygiene,
Clippy, build, tests) is skipped.

At the tip three commands in that block fail, and I reproduced each locally:

- `python3 scripts/check-review-slices.py` (`ci.yml:115`) exits 1 with
  "unclassified changed paths" for `.config/miri-crates.toml`,
  `.config/nextest.toml`, `crates/tooling/chio-profile-probe/Cargo.toml` and
  `crates/tooling/chio-profile-probe/src/main.rs`. All four were added by this
  slice (`72bd03d057`, `3f8948e76e`, `3b596d22bb`), and no review slice in
  `scripts/check-review-slices.py` matches `.config/**` or the probe crate.
- `bash scripts/tests/check-domain-separation.test.sh` (`ci.yml:178`) exits 1.
  Its over-cap fixture (`scripts/tests/check-domain-separation.test.sh:98-108`)
  depends on a `chio.fincred.source-artifact.v1\0` debt entry that `a8b5f11d3e`
  retired from `scripts/check-domain-separation.py` without updating the fixture.
  The `grep` for "cap is 2" then fails silently under `set -e`.
- `bash scripts/tests/check-lint-parity.test.sh` (`ci.yml:186`) exits 1 with
  `FAIL: a recorded unreached manifest passes while the entry is live`.
  `d51afb4a5f` emptied `UNREACHED` (`scripts/check-lint-parity.py:68`), which is
  the right change, but left the fixtures at `check-lint-parity.test.sh:191-196`
  and `:205-212` that depend on a live entry.

Because line 115 fails first, nothing from line 116 to 197 runs, which is every
gate in this slice: negative assertions, lint parity, Rust hardening and the
compiler probes, wire schemas, dependency budget, the Miri list and release
overflow. Clippy at `ci.yml:270` never runs either. Fixing line 115 alone would
expose line 178, then line 186. Separately, the hygiene gate in the next step
fails at the tip on `crates/economy/chio-market/src/tests.rs` (2,388 lines
against a cap of 2,387, from `a2630c20a1`, outside this slice).

Hosted CI shows the same thing, earlier. The first push after the gate merge,
`f928453692` (run 36270284621, September 26), failed at `ci.yml:115` listing
`.config/miri-crates.toml` and `.config/nextest.toml`: the merge broke the
required job on arrival, and the failure stood for five days. The October 1 run
on the PR head `f25cd61f49` (run 36868648646) failed even earlier, at
`check-web3-contract-parity.sh` (`ci.yml:113`), whose nested schema-registry
check reported a stale `MANIFEST.sha256` (fixed by the tip). In that run steps
13 to 45, including "Workspace clippy", "Workspace build" and "Workspace tests",
are `skipped`. No hosted run on this branch has executed any gate from this
slice other than the nextest lane, or the compiler-enforced lint set.

The records overstate what CI does. The dispatch ledger says the merge was
preceded by every self-test and that "all nine gates run on the merged tree by
the integration script"
(`docs/superpowers/plans/2026-09-26-security-execution-dispatch.md:277`), which
is true of the nine and silent on the pre-existing required gate the merge
broke. The compiler record says "CI invokes both gates"
(`2026-09-29-compiler-secret-hardening-execution.md:48`), and the remaining-work
queue says "Compiler/source calibration and CI wiring prevent silent removal of
the policy" (`2026-09-28-remaining-security-work.md:199`). Both gates are
wired; neither is reachable. The record's verification table (`:89`) lists the
gates but not their self-tests or the neighbouring structural checks, which is
how a self-test broken by the same commit went unnoticed.

The fix: classify `.config/**` and `crates/tooling/chio-profile-probe/**` in a
review slice, repair the two fixtures (for lint parity, construct the debt
entry inside the fixture instead of depending on the live table), and make the
qualification checklist run the whole structural step, not a chosen subset.
Then split the block so each gate is its own step, or collect failures and exit
at the end; a single `bash -e` block means one red check hides the result of a
hundred others.

**Confidence:** Confirmed. All three commands reproduced at the tip against
`origin/main` (`f5566d9a76`, the current `main`); the hosted failures are from
the job logs of runs 36270284621 and 36868648646.

**Independent verification:** Reproduced again by the orchestrator at `a2630c20a1`:
`check-review-slices.py` exits 1 on `.config/miri-crates.toml`, `.config/nextest.toml` and the two
`chio-profile-probe` files; `check-domain-separation.test.sh` exits 1; `check-lint-parity.test.sh`
fails "a recorded unreached manifest passes while the entry is live". PR #1160's status rollup at
`f25cd61f49` shows `Build, lint, test` as FAILURE. The executing branch
`packet/3-retention-accounting` has no pull request, so no required check has run on any commit
after `f25cd61f49`.

## GT2. Medium: the shipped Lambda extension builds the kernel without overflow checks, and the gate cannot see it

`3b596d22bb` sets `overflow-checks = true` in `[profile.release]` and
`[profile.docker-release]` of the root manifest (`Cargo.toml:339-350`).
`sdks/lambda/chio-lambda-extension/Cargo.toml` declares its own `[workspace]`,
so Cargo reads profiles from that manifest alone. Its `[profile.release]`
(`:59-63`) sets `opt-level`, `lto`, `strip` and `codegen-units` and no
`overflow-checks`, which defaults to `false`. The crate depends on `chio-kernel`,
`chio-kernel-core`, `chio-core-types` and `chio-store-sqlite` by path, and
`scripts/package-layer.sh:61-63` builds the layer with `cargo build --release`.
`README.md:606` lists it as Shipping. Any arithmetic in the kernel, core types
or store that is not written as a checked operation (the lexical and compiler
arithmetic rules cover only the 49 accounting modules) therefore wraps silently
in this binary instead of trapping, which is the exact outcome the manifest comment at
`Cargo.toml:329-338` says the setting exists to prevent.

`scripts/check-release-overflow.sh:33-43` checks only the text of the root
manifest's two profile headers, and builds only the probe crate. It cannot see
a nested workspace, a `[profile.release.package.<name>]` override, a
`CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS` environment variable, or `RUSTFLAGS`.
One of those already exists: the `optimized-comparison` job in
`.github/workflows/process-workers.yml:394` sets
`CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS: "false"` to build a release CLI for a
performance comparison. That job predates the slice (`515ee6fd05`) and only runs
on dispatch, but Packet 0.2's "Do not" list forbids exactly this use.

Fix: add `overflow-checks = true` to the Lambda extension's release profile, and
extend the gate to enumerate every `Cargo.toml` that declares `[workspace]` or
`[profile.*]`, refuse any `overflow-checks = false` in a package override, and
grep workflows for the environment form.

**Confidence:** Confirmed. A source trace through Cargo's documented profile
resolution for a nested workspace root; the binary was not built.

## GT3. Medium: the Miri lane is documentation, and its crate list overstates what it would test

**Never run.** `.github/workflows/miri.yml` runs on `schedule` and
`workflow_dispatch` only (`:19-23`). Neither fires for a workflow absent from
the default branch, and `gh run list --workflow miri.yml` returns "workflow
miri.yml not found on the default branch". PR CI runs only
`run-miri-crates.sh --list` and the validator (`ci.yml:194-195`). The only green
evidence is the local aarch64 run recorded in `miri-crates.md`. The
remaining-work queue says this plainly ("A source declaration of a job is not
hosted passing evidence"), so this is a status finding, not a records finding.

**Listed crates whose unsafe code Miri cannot execute.** Spec H2's acceptance
requires that "every listed crate that contains `unsafe` names a test that
executes an unsafe block under Miri". Two of the six do not:

- `chio-keyring` is listed with `reached = 6` (`.config/miri-crates.toml:57-66`).
  Five of its unsafe sites are libc ACL calls inside `#[cfg(target_vendor =
  "apple")]` (`crates/security/chio-keyring/src/lib.rs:540-602`), which are not
  even compiled on Linux. The other two are `connection.handle()` and
  `sqlite3_file_control` (`:633-639`), which are calls into C. Under Miri on
  Linux none of the crate's unsafe code runs.
- `chio-guard-sdk` is listed with `reached = 8` (`:21-24`). The `host.rs`
  unsafe blocks are `#[cfg(target_arch = "wasm32")]` (`host.rs:24-35,79-87`).
  The one native block in `read_request` (`glue.rs:55`) sits behind an early
  return for `ptr <= 0` (`:47-49`), and no unit test calls it with a valid
  pointer; `read_request_deserializes_valid_json` (`glue.rs:250`) simulates the
  read instead of calling it.

The "reached" figures come from `scripts/miri-unsafe-reach.py`, a name-based
call-chain match that ignores `cfg` and early returns and is not run in CI.
The toml header discloses that it over-approximates, but the list still
presents these counts as reach. Four crates with unsafe code, including
`chio-secret-broker` (17 sites) and `chio-kernel`, are recorded as unclassified
(`miri-crates.md:49-52`), and the September 29 `chio-cage-init` and
`chio-cage-plan` crates are not mentioned.

**Likely red at the tip for a non-UB reason.** `a9ae42ed69` (September 26,
after the measurement) added the keyring unit test
`synchronization_page_and_head_share_a_snapshot_during_concurrent_append`
(`crates/security/chio-keyring/src/sqlite/synchronization_tests.rs:62-100`),
which opens SQLite through `SqliteKeyLogStore::open_with_clock` (`:94`) and has
no skip entry. Miri cannot call into C, so the first nightly run on `main` would
fail on keyring. Nothing in PR CI would notice the drift.

**Validator and runner gaps.** `scripts/run-miri-crates.sh:31,42` checks only
that a reason starts with `calls into C:` or `syscall:`, and `[[ineligible]]`
reasons need only be non-empty (`:96-97`), so ineligibility is an unchecked
third exclusion route. The time box is 6 crates times 1,800 s, which exceeds
the job's `timeout-minutes: 150` (`miri.yml:36`).

Fix: move keyring to `[[excluded]]` with "calls into C" and guard-sdk to
`[[ineligible]]` (or add a native test that calls `read_request` on a live
buffer); add the keyring SQLite test to the skip list; run the reach script's
output through the validator instead of hand-typed counts; land the workflow on
`main` so it actually runs.

**Confidence:** Confirmed for the listing and never-run claims (source and API).
Plausible for "red at tip": the SQLite call is traced, but Miri was not run.

## GT4. Medium: secret ownership wrapped the downstream types and left the plaintext sources in a TCB crate as `Debug` strings

Compiler-plan task 4 and the record (`2026-09-29-compiler-secret-hardening-execution.md:36-45`)
claim explicit ownership for "six external-guard configurations, authority key
documents, broker-owned credentials ... and settlement release keys". The
`chio-external-guards` configs now hold `SecretString`. Their only production
constructors, though, are `policy/guards.rs:200` and `:251` in
`chio-control-plane`, which call `Config::new(config.api_key.clone())` from
`AzureContentSafetyPolicyConfig` and `SafeBrowsingPolicyConfig`
(`crates/platform/chio-control-plane/src/policy/guard_config.rs:113-139`). Those
hold `api_key: String` and derive `Debug, Clone, Serialize, Deserialize`, and
they live inside `ChioPolicy` (`policy/types.rs:131-145`, itself
`Debug, Clone, Serialize`) for the lifetime of the loaded policy. So the key's
plaintext copy outlives the wrapped one, and any `{:?}` or serialization of the
policy prints it.

The same crate holds the authority's Ed25519 seed as
`AuthoritySeedHandoff { seed_hex: String }` with
`#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]`
(`crates/platform/chio-control-plane/src/keyring_runtime.rs:1285-1293`), and
`validate_keypair` creates another unzeroized copy through `keypair.seed_hex()`
in a non-constant-time comparison (`:1328`). `Serialize` is the point of a
handoff file; `Debug` and `Clone` have no stated reason, which standard rule 7.1
requires. Both owners predate the commit, but task 4 was "remaining guard,
broker and authority secrets", and these are the remaining ones.

The source gate cannot see either. `secret_errors`
(`scripts/check-rust-hardening.py:78-105`) flags only a `struct` that contains
`Zeroizing<` or `Secret{Box,String,Slice}`. A plain `String`, `Vec<u8>` or
`[u8; 32]` secret passes, as do enums, type aliases and renamed imports. A
pre-existing instance outside the gate's scope is
`crates/observability/chio-siem/src/exporters/elastic.rs:24-36`, an enum
deriving `Debug` with a `Zeroizing<String>` password, and `Zeroizing`'s `Debug`
prints its contents.

I found no current site that logs or serializes `ChioPolicy` or the handoff
with `{:?}`, so an actual leak is not demonstrated; the retained copies and the
derives are.

Fix: deserialize policy secrets directly into `SecretString` (the `secrecy`
serde feature is already enabled at `Cargo.toml:376`) and pass ownership into
the guard config instead of cloning; give `AuthoritySeedHandoff` a
`SecretString` seed with a redacting `Debug`, no `Clone`, and a constant-time
comparison over decoded bytes.

**Confidence:** Confirmed for the field types, derives and constructors by
source trace; the leak path is Plausible.

## GT5. Medium: 164 existing allows received a boilerplate reason that narrates the commit instead of stating an invariant

The new reason rule (`check-rust-hardening.py:66-75`) refuses any
`#[allow(clippy::...)]` in a TCB directory without `reason = "..."`. To pass it,
`d51afb4a5f` rewrote 164 existing `#[allow(clippy::too_many_arguments)]`
attributes (167 at the tip) with one identical string: "Keep the existing
explicit boundary parameters together; changing the owning API is separate from
enforcing unsafe and panic rules." Examples are
`crates/core/chio-core-types/src/capability/cumulative_approval.rs:773` and
`crates/kernel/chio-kernel/src/admission_operation.rs:1193`.

The string describes how this commit chose its scope. It says nothing about the
function it annotates, which is narration of the work inside the artifact
(standard section 11, "Do not narrate the work in the artifact"). It is also a
mass syntactic edit made to satisfy a gate, where spec H4's allow discipline
asks for a reason that states the bound at that site ("index bounded by the
length check two lines above"). And it shows that the reason gate, the mechanism
H4 says "keeps the deny set honest over time", is satisfied by any non-empty
string. `too_many_arguments` is not in the TCB deny set, so these allows did not
need to be touched for that set to be enforced.

Fix: revert these 164 to their prior form, or exempt `too_many_arguments` and
other style lints from the reason rule. Reserve reasons for the deny-set lints,
where a reason states a bound.

**Confidence:** Confirmed. `git show d51afb4a5f` shows 164 removed bare allows
and 167 added reasoned ones; `git grep` counts the string 167 times.

## GT6. Low: the Rust-hardening gate is lexical, partly untested, and its policy does not reach feature-gated code in CI

The subagent built each case below as a fixture and ran it through the real
gate (and `clippy-driver` 1.94.1 where compilation mattered). I re-read the
relevant gate lines at `scripts/check-rust-hardening.py:43-175`.

- A crate-root or module-level `#![allow(clippy::panic, reason = "x")]` after
  the root deny passes the gate and silences the deny; `has_deny` checks only
  that a deny exists.
- The reason rule misses `#[allow(clippy :: panic)]` (spaced path, accepted by
  rustc), a `cfg_attr(all(), allow(clippy::x), allow(dead_code, reason = "y"))`
  whose reason belongs to the sibling, an allow emitted by `macro_rules!`, and
  `#[path]` or `include!` files outside the TCB `src/` directory.
- Bin targets of TCB packages (`chio-keyring`'s `chio-keylog-audit` and
  `chio-keylog-witness`) get neither `forbid(unsafe_code)` nor the deny set.
- Ten of fourteen unsafe exceptions are crate-wide with no root
  `deny(unsafe_code)`; `chio-kernel` has one unsafe block
  (`kernel/kernel_struct.rs:525`) but any new module may add more.
- `scripts/tests/check-rust-hardening.test.py` tests helper functions only and
  never calls `check()`. Deleting the TCB census (`:146-147`), the stale
  exception check (`:148-149`) or the directory reason scan (`:166-167`) leaves
  all 19 cases green.
- CI lints with `cargo clippy --workspace --lib --bins --examples -- -D warnings`
  (`ci.yml:270`), default features only. No workflow runs Clippy with
  `chio-kernel`'s `pq` or `otel`, `chio-secret-broker`'s
  `real-linux-enforcement` or `chio-core-types`'s `pq`. That feature-gated
  production code is outside the deny set in CI. Plausible: no build was run to
  find violations.

None of these is exploited at the tip. Fix: refuse root- or module-level allows
of deny-set lints; normalise lint paths before matching; add `check()`-level
fixtures; add a Clippy invocation per production feature set of the TCB
crates.

**Confidence:** Confirmed for the gate bypasses (fixtures) and the untested
paths (mutation); Plausible for the feature-gated lint gap.

## GT7. Low: a brace inside a string in a test-only item hides every later production identifier from the wire-schema gate

`test_scoped_spans` (`scripts/check-wire-schemas.py:291-318`) finds the extent of
a `#[cfg(test)]` item by counting braces in text where string literals are kept,
because identifiers live in literals. A test-only item containing a `"{"`
literal opens a depth that never closes, so the span runs to the end of the
file. Every production declaration after it is skipped, and its value is
recorded as pinned. Fixture (`#[cfg(test)] const OPEN_BRACE: &str = "{";`
followed by `pub const BUMPED: &str = "chio.secret-wire.v9";`, lock without the
value): the gate prints "Wire schema check passed". Replacing `"{"` with `"x"`
turns it red with "not in the lock". Re-running the whole tree with strings
blanked for brace counting found no declaration hidden today (1,324 either way).

The scan also cannot see an identifier declared through a newtype
(`const X: SchemaId = SchemaId::new("chio.x.v1")`), a type alias or `concat!`.
That matters because H10's planned `WireSchema` registry would move values into
exactly such a type, at which point the lock goes blind. H10's target was a
generated compiled test per crate; a lexical lock was built instead.

Fix: blank string contents before counting braces (the accounting gate's
`blank_rust_noise` already does), and when the registry lands, generate the
lock from it rather than from source text. The six gate scripts that each carry
their own copy of the Rust lexer (`RUST_NOISE` in `check-accounting-arithmetic.py`,
`check-domain-separation.py`, `check-negative-assertions.py`,
`check-rust-file-hygiene.py`, `check-wire-schemas.py`, `miri-unsafe-reach.py`)
should share one module, as `check-rust-hardening.py` already does with `lexer`.

**Confidence:** Confirmed by fixture through the real gate.

## GT8. Low: the hygiene ratchet can uncap a production module and then excuse unbounded growth

When `--ratchet` finds a module under its base limit that still has
`include!` fragments, it drops the line cap and keeps the entry with
`max_lines` unset (`scripts/check-rust-file-hygiene.py:1356-1362`). A later
`PRODUCTION_OVER_LIMIT` violation starts with an allowlist excuse
(`:1185-1190`), and only test files are required to carry a cap
(`:1500-1504`). So the module can grow without limit while one fragment remains.
Fixture: `crates/security/chio-quarantine/src/state_machine.rs` at 3,001 lines
plus its one fragment passes with "max_lines uncapped". Thirteen live entries
are uncapped; eight are production files the test-only guard does not cover,
including `crates/kernel/chio-kernel/src/budget_store.rs`,
`crates/guards/chio-policy/src/evaluate.rs`, `crates/economy/chio-credit/src/lib.rs`
and `crates/products/chio-cli/src/bin/chio.rs`. This defeats 0.1's "Do not raise
`PRODUCTION_LIMIT`" from the inside. Fix: when the line cap
is dropped, set it to the base limit rather than to none.

**Confidence:** Confirmed by fixture through the real gate.

## GT9. Low: the TSan lane covers none of the concurrent code H9 asked for, and it has never run

H9 named the target precisely: "TSan on the loom-adjacent concurrent code (the
store writer actor, the broker service, the scheduler worker)". The lane's
crate list is `chio-security-types`, `chio-bounded`, `chio-supervisor` and
`chio-keyring` (`.github/workflows/sanitizers.yml:35`). The store and broker
runs did not complete within their time boxes and are recorded as such
(`docs/security/toolchain/sanitizer-audit.md`, "Measurements that did not
complete"). The lane also forces `RUST_TEST_THREADS=1` (`:58`, `:85`), so TSan
sees only races inside a single test's own threads. The comment "Every crate
below passed under both sanitizers on 2026-09-26" (`:34`) describes an aarch64
measurement; the lane runs `x86_64-unknown-linux-gnu`. Like Miri, the workflow
is not on `main`, so the schedule has never fired. The audit document is
candid about all of this; the shortfall is in delivery, not in the record.

**Confidence:** Confirmed (workflow source, audit document, GitHub API 404).

## GT10. Low: the FV-E5 runbook says the run-always Kani job is required, and it is not

`docs/formal/plan/FV-E5-kani-promotion-runbook.md:42` says the `ci.yml` job
`kani-public-pr (all lane=pr harnesses)` is "required through the `Security
contract` aggregate job". The aggregate does depend on it (`ci.yml:603-633`),
but the `main` ruleset (`gh api repos/{owner}/{repo}/rules/branches/main`)
requires only `Build, lint, test`, `MSRV build and test`, `cargo-vet` and
`cargo-deny`; `Security contract` is not a required context. The runbook's
step 4 reasoning ("already required indirectly ... a direct requirement in
addition, not a new gate") rests on this. On the PR head `f25cd61f49` that job
failed ("Verify all PR Kani harnesses"), which a required check would have
surfaced. The runbook is otherwise careful, and correctly reports that H6's
acceptance is not yet met.

**Confidence:** Confirmed via the ruleset API at review time. Whether
`Security contract` was required on September 26 cannot be checked from here.

## GT11. Low: three secret buffers leave plaintext in freed allocations

- `canonical_json_bytes_zeroizing` starts its output as
  `Zeroizing::new(String::new())` and grows it by `push`/`push_str`
  (`crates/core/chio-core-types/src/canonical/secret.rs:14-16`). Each
  reallocation frees the previous block unwiped. For the authority custody
  document, which writes the seed fields early, the abandoned blocks carry seed
  hex. The record's "projects borrowed plaintext into zeroizing canonical
  output" (`2026-09-29-...-execution.md:39-40`) holds for the final buffer only.
- `build_request_head` starts `Zeroizing::new(Vec::new())` and appends secret
  headers before more bytes (`crates/security/chio-secret-broker/src/generic_https/rustls_transport.rs:215-243`).
  When a later push crosses capacity, the freed block holds
  `authorization: Bearer <credential>`. Pre-existing; this is the broker's core
  path.
- `parse_secret_key` decodes the settlement release key into a plain `Vec<u8>`
  and a `Copy` secp256k1 `SecretKey` (`crates/economy/chio-settle/src/evm/sign.rs:222-231`),
  twice per release preparation. `SecretString` protects only the hex.

The record disclaims "every transient plaintext copy", so these are not record
contradictions. Fix: compute the exact length and allocate once, or write into
a pre-reserved `Zeroizing<Vec<u8>>`; decode the key into a `Zeroizing<[u8; 32]>`.

**Confidence:** Confirmed by source trace of allocation behavior.

## GT12. Low: status prose was not reconciled with what shipped

Rule 12.5 makes the ledger part of the change. The engineering standard still
says overflow checks are "Currently unset for `[profile.release]` and
`[profile.docker-release]`" (section 4.1) and that `secrecy` is "Not adopted yet"
(section 7.1); the spec says its items retire exactly these markers. Packet 0.3's
compiler-lint box remains unchecked although `d51afb4a5f` applied it to 49
modules. Both FFI `ARCHITECTURE.md` files still describe the `mem::forget`
pattern `4c5d43dfe5` removed (`crates/sdk/chio-bindings-ffi/ARCHITECTURE.md:56-61`,
`crates/sdk/chio-cpp-kernel-ffi/ARCHITECTURE.md:55-59`), the second calling the
defect "`Box::into_raw`-equivalent". And `f928453692`, whose message says the
census numbers were "corrected in place beside the originals", replaced the
488-line hardening spec with an empty file. An unrelated commit (`0fbe22e0f0`)
restored it a day later from the base revision with a banner marking its
measurements historical, so nothing is lost, but the spec never received the
corrected 260/478 and 1,369/200/169 figures the commit message describes.

**Confidence:** Confirmed (file contents at the tip; `git show f928453692`
shows `index d0b785b30b..e69de29bb2`).

## GT13. Note: the negative-assertion gate detects one spelling of a weak assertion

`weak_assertions` (`scripts/check-negative-assertions.py:201-226`) flags an
`assert!` whose condition ends in `.is_err()`, and treats any condition
containing `matches!`, `&&` or `||` as strong. `assert!(matches!(r, Err(_)))` is
exactly as weak and passes, as do `prop_assert!(r.is_err())` and
`assert!(!r.is_ok())`. The scope excludes `chio-store-sqlite`,
`chio-kernel-core` and `chio-core-types`. There are no instances of the
`matches!` form in scope today, and the per-site identity scheme from
`d0469ce384` is a real improvement over per-file counts. Worth a two-line
extension when 4B converts the baseline, so the conversion cannot move to an
equivalent weak form.

## GT14. Note: `d51afb4a5f` buries roughly a dozen behavior changes in a 666-file policy commit

Besides lints, attributes and secret wrappers, the commit changes behavior:
typed rejection in `PublicKey::ed25519_bytes`, capacity rejection in the DPoP
and approval-replay constructors, signing-permit length conversion, exact
integer credit-limit percentages in the control plane, clock-failure
propagation on attestation import, bounded slicing in the broker's HTTP parser,
a harness clock injection and a `uuid/v4` feature declaration, alongside
several hundred lines of test-module extraction to stay under hygiene caps.
Spec H4 asked for "one commit per crate, so a regression is attributable", and
standard section 11 asks for one reviewable packet per commit. The spec banner
records that the user's batching directive governs execution, so this is not a
plan violation. The cost is real anyway: a regression in any of those
behaviors bisects to a 12,000-line commit. The record's own next-package
section commits to separating mechanical moves from behavior changes; holding
to that is the remedy.

## Execution-record claims checked

| Claim (record:line) | Verdict | Evidence |
| --- | --- | --- |
| "All 177 member manifests participate: 158 inherit and 19 explicitly mirror" (`2026-09-29-compiler-secret-hardening-execution.md:15-16`) | True at the commit | Tip gate: 179, 160 inherit, 19 mirror, 0 unreached |
| "165 library roots and names 12 justified exceptions" (`:20-21`) | True at the commit | 167 and 14 at the tip after `c5ca13ddd3` added the two cage crates |
| "The production deny policy covers 25 TCB libraries" (`:25`) | True | 25 at `d51afb4a5f`, 27 at the tip; nine lints on every root |
| "Compiler probes include a positive control and 14 named violations" (`:46`) | True | Run by a subagent: each violation asserts the named lint or error code |
| "CI invokes both gates" (`:48`) | Wired, not reachable | GT1 |
| "every self-test and gate rerun independently ... all nine gates run on the merged tree by the integration script" (`2026-09-26-security-execution-dispatch.md:277`) | True for the nine, incomplete | The merge failed the existing review-slice gate in hosted CI (run 36270284621) and at the tip (GT1) |
| "The broker budget grows from 479 to 480 solely for that audited dependency" (`:50-51`) | True | `d51afb4a5f` diff of `check-dependency-budget.py` |
| "Source policy calibration: 19 passed" (`:88`) | True, weaker than implied | 19 tests run green; none calls `check()` (GT6) |
| "Lint parity ... passed" among source checks (`:89`) | Gate true, self-test false | Gate exits 0; its self-test exits 1 (GT1) |
| "Six compile-fail examples and two positive controls" (`:85`) | True | Subagent matched the doctests; compile-fail crates carry the needed dependencies |
| Independent review's two gate defects "failed before their fixes" (`:118-128`) | Fixes present | Split derives and inactive `cfg_attr` denies are rejected by fixtures |
| "Compiler/source calibration and CI wiring prevent silent removal of the policy" (`2026-09-28-remaining-security-work.md:199-200`) | False at the tip | GT1, and the self-test survives deleting three checks (GT6) |
| "44 Miri tests and 44 native tests passed" for the FFI fix (`2026-09-26-resumed-execution.md:24`) | Count consistent | 24 tests in `chio-cpp-kernel-ffi` and 20 in `chio-bindings-ffi` at `4c5d43dfe5`; Miri not rerun |
| "Workspace formatting, logical file hygiene, negative-assertion, wire-schema and domain-separation gates also passed" (`2026-09-26-resumed-execution.md:38-39`) | True then, false now | At the tip the hygiene gate and the domain-separation self-test fail |
| "required through the `Security contract` aggregate job" (`FV-E5-kani-promotion-runbook.md:42`) | False at review time | GT10 |
| "Every crate below passed under both sanitizers on 2026-09-26" (`sanitizers.yml:34`) | True for aarch64 only | The lane targets x86_64 and has never run (GT9) |
| "the numbers are corrected in place beside the originals" (`f928453692` message) | True for pass 8, false for the spec | The spec was emptied, then restored uncorrected (GT12) |

## Verified clean

- **FFI buffer ownership (`4c5d43dfe5`).** Both crates allocate with
  `Vec::into_boxed_slice` then `Box::into_raw` and free by rebuilding the same
  `Box<[u8]>` from `slice_from_raw_parts_mut(ptr, len)`
  (`chio-bindings-ffi/src/lib.rs:75-102`), so layout at free equals layout at
  allocation. The defect was real: the old code took `as_mut_ptr()` and then
  moved the box into `mem::forget`, which retags it under Stacked Borrows and
  invalidates the pointer. Null and zero-length frees are no-ops; null input
  with nonzero length is refused (`:196-208`). Every fallible body runs under
  `catch_unwind`, and `panic = "unwind"` in release keeps that effective. The C++
  wrappers free only through the Rust free functions and delete copy
  construction. Double free by copying a returned struct in C is inherent to
  the by-value ABI and not preventable on the Rust side.
- **Release overflow probe.** The probe reads operands at run time, the gate
  requires death by "attempt to subtract with overflow" specifically, and the
  self-test drives both failure directions (manifest without the setting, and
  `-C overflow-checks=off`).
- **Dependency budget.** Real `cargo tree` graphs in the self-test, including a
  transitive denied edge and a lowered ceiling; gate and self-test pass at the
  tip (72 and 481 packages).
- **Lint parity gate logic.** Both tables, level and priority normalised,
  unreached manifests refused, debt expiry enforced. Only its fixture is stale.
- **Wire-schema cfg evaluation (`3ae2cd7733`).** Three-valued evaluation is
  correct for `not(test)`, `any(test, feature)` and `all(test, feature)`; no
  constant was hiding on the tree.
- **nextest lane.** `retries = 0`, leak result `fail`, per-group overrides above
  each declared deadline, JUnit archived; hosted run at `f25cd61f49` passed 673
  tests with no leak or timeout.
- **Hardening gate positives.** `deny` in place of `forbid`, commented or
  child-module forbids, `cfg_attr(any(), ...)` and inactive `cfg_attr` denies,
  `allow(clippy::all)`, `allow(clippy::restriction)` and reasonless `expect` are
  all refused. Every TCB root carries all nine deny-set lints.
- **`secrecy` adoption.** No `SerializableSecret` or `CloneableSecret` impls
  exist, so `SecretBox<Vec<u8>>` is neither `Clone` nor `Serialize`; the six
  guard configs, `DualSignReleaseInput`, `NamedSeedHex`, the authority signing
  document and `SecretHeader` have redacting `Debug`; broker secret vectors keep
  their original allocation.
- **Corrections 2A and 2B.** Separate x32 and i386 probes exist and are counted;
  constraint keys are a closed `Syscall` type with construction-time rejection
  and a test, and the test-only mutator is behind `enforcement-mutants`.
- **Merge `37ce39c8a0`.** No conflict hunks.
- **House rules.** No em dashes added by any commit in the slice; no process
  vocabulary in the gate scripts, `rust-hardening.json` or code added by
  `d51afb4a5f` other than the reason string in GT5.

## Recommendations for the remaining plan

1. Make the required job reach these gates before any further gate work:
   classify `.config/**` and the probe crate in a review slice, fix the two
   fixtures (GT1) and the hygiene cap, push, and confirm a green hosted run of
   the whole structural step. Then split it into steps or collect-then-fail, and
   make "the whole structural step, self-tests included" the qualification
   checklist the records use.
2. Land `miri.yml` and `sanitizers.yml` on `main` with corrected lists (GT3),
   then let them build a history before any promotion. Prioritise classifying
   `chio-secret-broker` for Miri and the store and broker for TSan on a warm
   instrumented cache; that is the work H2 and H9 were for.
3. Finish H7 at the sources: policy-loaded guard keys and the authority seed
   handoff (GT4), then the three allocation copies (GT11). Widen the secret gate
   to plain `String`/`Vec<u8>`/`[u8; N]` fields with secret-like names in TCB
   crates, and to enums.
4. Fix the Lambda extension profile and generalise the overflow gate (GT2).
5. Revert the 164 boilerplate reasons (GT5) and restrict the reason rule to the
   deny-set lints.
6. Reconcile the standard's "Enforced by" markers, the 0.3 checkbox, the FFI
   architecture notes and the spec's census figures (GT12).
