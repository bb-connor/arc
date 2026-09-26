# Security execution dispatch

How the [closeout plan](2026-09-25-security-assurance-closeout.md) and the
[engineering excellence addendum](2026-09-26-security-engineering-excellence.md)
are executed as concurrent lanes under one orchestrator, against the
[security engineering standard](../../security/engineering-standard.md) and the
[unrepresentable-defects design](../specs/2026-09-26-unrepresentable-defects-design.md).

This document adds nothing to the packets. It assigns them to lanes, fixes the
order and the ownership boundaries, and states the review gate every lane passes
before its work reaches the integration branch.

## Facts the dispatch is built on

- `integration/process-security-m4` is at `d115ff3636` (documents only) locally
  and on `origin`. PR #1160 is a draft, `BLOCKED`, with 101 green, 14 red and 15
  skipped checks at the previous head `3cd73631a1`.
- Codex's Packet 1 work is uncommitted in `/tmp/arc-security-launch`: 31 modified
  files plus the new `chio-security-types/src/response_execution.rs`, unchanged
  since 2026-09-25 23:42, stopped mid-red on
  `combined_deployment_requires_and_authenticates_response_execution_mode`
  (the authenticated deployment config does not yet accept
  `responseExecutionMode`). `output/` is an untracked evidence directory and is
  never committed. `.superpowers/sdd/` is Codex's gitignored execution ledger.
- No other agent is in that worktree. (An earlier note claiming a resident Codex
  process was a `pgrep` self-match on the orchestrator's own shell.)
- Host: aarch64, 12 CPUs, 46G RAM, 263G free on `/home`, 49G on `/`. Toolchain
  pinned at rustc 1.94.1. `kani` and `cargo-fuzz` present. No local PostgreSQL
  server (Docker is available), no `sqlite3` CLI (Python's `sqlite3` works), no
  `cargo-nextest`. **Native x86_64 cage enforcement cannot run on this host**;
  those lanes use the designated CI runner or an x86_64 VM.
- Red at `3cd73631a1`, by failing step: `Build, lint, test / Workspace structural
  gates`; `MSRV workspace lane`; `cargo vet --locked` (the `aws-lc-rs 1.18.1`
  audit, Packet 5); `enterprise-security-contract / Build canonical exact merge
  binding` (Packet 5 trusted-capture chain); `nonce-fips-contract / Exact kernel
  caller execution`; `Security contract / Require every security dependency`.
  Lane E's triage ([record](../../reviews/2026-09-26-ci-triage-3cd73631a1.md))
  found steps 2 and 5 are one code regression (a v4-to-v6 wire-schema bump left two
  pinning tests on v4; reproduced locally), step 1 is a racy new test (a fixed 50 ms
  sleep before a `/proc` identity check), and steps 3, 4 and 6 are Packet 5
  prerequisites (the audit, a trusted-definition pin that predates the `GH_TOKEN`
  fix, and an unconfigured `CHIO_COMMITTED_LINUX_EVIDENCE_SHA` repository variable).

## Principles

1. **One packet, one lane, one worktree, one branch, one Cargo owner.** Lanes that
   run concurrently own disjoint files. A conflict is resolved by sequencing, never
   by merging two lanes' edits to one file.
2. **Checkpoint to git at every wave boundary.** Work exists when it is pushed. No
   destructive git operation in any tree another lane can see.
3. **Shared dependency build, isolated workspace artifacts.** One
   `CARGO_TARGET_DIR` on `/home` for all lanes, so third-party crates compile once;
   workspace crates are fingerprinted per worktree path. `CARGO_INCREMENTAL=0`,
   `umask 022`, and `RUST_TEST_THREADS=1` where the parent plan requires it. Never
   `cargo clean` while any lane is building.
4. **Every commit carries its regressions.** Conventional commits, behavior and
   tests together, mutation check recorded in the report (break the rule, name the
   failing assertion), no em dashes, no production `unwrap`/`expect`, no new
   `map_err(|_| ...)`, no new `pub` field on a `Verified*`/`Authorized*` type, no
   new `include!`.
5. **The orchestrator reviews every lane against the standard before merge.** The
   orchestrator is not the independent reviewer rule 12.1 requires for P0 and P1;
   that gate remains in Packet 6.
6. **A lane reports what it did not verify** in the same message as what it did.

## Step 0: take custody of the in-flight work

Before any lane starts, in `/tmp/arc-security-launch`:

1. `git checkout -b packet/1-dry-run` (branch pointer only; the dirty files stay).
2. Stage the 31 modified files and `response_execution.rs`. Do not stage
   `output/`.
3. Commit as `feat(security): checkpoint execution-mode binding for response
   plans`, with a body stating that the work is intentionally incomplete, naming
   the one red test and why it is red, and listing what is done (binding type,
   plan field, fresh-dispatch and admission checks) and what is next (the
   deployment config field).
4. Push `packet/1-dry-run`.

The integration branch stays at `d115ff3636`. Lane D continues from this
checkpoint. The reason to checkpoint rather than re-derive: the binding, the plan
field threading and the signed-body coverage are exactly what corrections 1A to
1C refactor, so the work is reusable, and the repository has lost uncommitted
agent work before.

## Wave 1

Five lanes. A, B, C and E are disjoint from each other and from D. D is the
longest and is internally sequential.

| Lane | Packets | Owned files (exclusive) | Model | Exit |
| --- | --- | --- | --- | --- |
| **A** gates and profile | 0.1, 0.2 (manifest half), 0.3, 0.4, 0.5 | `scripts/check-rust-file-hygiene.py` and its test; new `scripts/check-domain-separation.py` and `scripts/check-negative-assertions.py` with self-tests; root `Cargo.toml` (`[workspace.lints]`, `[profile.*]`) and scoped lint tables in budget/quota crates | Opus 5 | every new gate fails on its violating fixture; baselines recorded by ratchet; `overflow-checks = true` in release and docker-release with a release-profile check that an overflow aborts |
| **B** poison policy | 10.1 (store half of the 0.2 coupling) | the 22 `chio-store-sqlite` files holding `Mutex<Connection>` and their test modules; no other store file | Fable 5.1 | 26 of 26 connection lock sites go through one phase-aware helper that verifies rollback and anchor consistency or fences with a named error (the external review's R3); four phase tests per store with specific outcomes, and the blind-recovery mutation fails the rollback-failure test |
| **C** measurement and analytics | 9.1, 9.2 | `chio-store-sqlite/benches/`, `receipt_store/reports/analytics.rs`, `receipt_store/bootstrap/open.rs` (typed column for attempted cost if absent), a populated-fixture test module | Opus 5 | composite-authorization, charge/release and denial-read benchmarks against a populated store, baselines in the ledger; all four `json_extract` aggregates replaced by the typed columns; `EXPLAIN QUERY PLAN` asserted in a test; aggregate values proved byte-identical against the fixture |
| **D** Packet 1 continuation | 1D, then 1A 1B 1C 1E 1F, then the parent Packet 1 tasks | `chio-security-types/src/response*.rs`, `chio-quarantine/src/**`, `chio-kernel/src/kernel/active_response*`, `chio-active-response-authority/src/**`, `chio-control-plane/src/security/**`, `chio-core-types/src/receipt/security*` | Fable 5.1 | see below |
| **E** CI triage (read-only) | none; a report | no edits; reads CI logs at `3cd73631a1` | Sonnet 5 | each of the six red steps classified as infrastructure, Packet 5 prerequisite, or code regression; a reproduction and proposed fix for any regression, delivered as a report for a Wave 2 lane |
| **R** regression repair | the two regressions Lane E confirmed | `crates/kernel/chio-kernel/src/kernel/admission_coordinator/return_context/caller.rs` (a schema-pinning test beside the constants only), `crates/kernel/chio-runtime-core/tests/runtime_admission/operation_owned/caller.rs`, `crates/platform/chio-store-sqlite/tests/execution_nonce_caller_execution/dispatch_context.rs`, `integrations/required-agents/prepare-session.py` and `qualification/test_prepare_session_readiness.py` | Opus 5 | both reproduced failures pass; the two v4 literals are v6 by deliberate edit and a kernel test pins `SCHEMA` v6 and `CUSTODY_SCHEMA` v4; the fixed sleep is a bounded poll with a unit test that injects a probe failing N times before succeeding; 40 consecutive runs of the suite clean |

**Lane D order.** The mechanical gate run on the checkpoint against `3cd73631a1`
found four new `map_err(|_| ...)` discards in the in-flight code
(`state_machine.rs` mapping to `InvalidPlan`, `InvalidDispatch` and
`InvalidTransition`; `response.rs` mapping to `InvalidExecutionBinding`); those
are 1D's first four edits. Correction 1D first: `DispatchRejection` with one variant per
rule, `StateMachineError::InvalidDispatch(DispatchRejection)`, replacement of the
112 `map_err(|_| ...)` discards in the quarantine crate and the kernel response
coordinator (26 in `state_machine.rs` first), and registration of the five ad-hoc
`chio-security-types` port codes. Then 1A to 1F together, while the binding has
five call sites: private fields with `try_from`, `FreshLiveAdmission` plus the two recovery authorities
(`CommittedDispatchAuthority` with an automatic-or-governed approval, and
`CommittedAdmissionAuthority` for a governed commitment before its dispatch row)
replacing the five `require_execution_mode` sites and the inverse rule at
`state_machine.rs:686-687` (R1, then the follow-up review's F2),
`PlanProvenance` with the obligation-inventory retirement (R2), the response
domain constants imported from `chio-security-types`, and the strict
canonicalization boundary enumeration. Then the parent packet's remaining tasks,
resuming from the red test: the deployment config accepts and authenticates
`responseExecutionMode`; the simulation evaluator runs on an immutable snapshot with
isolated state and no live `EffectPort`; the signed simulation report binds tenant,
plan, configuration, authorization, snapshot versions and outcomes and persists
through the real receipt path; the authority, kernel approval, scheduler and
receipt store are wired through the profile; `response_dry_run.rs` corpora in
`chio-quarantine/tests/` and `chio-control-plane/tests/` cover all six effect
kinds, both approval requirements, missing and expired approval, stale scope,
overlap, both expiry orders, rollback conflict, receipt failure, restart and
cross-mode replay, every negative case asserting its `DispatchRejection` variant,
and every case asserting zero live effect calls.

**Merge order within Wave 1.** E reports first (it gates nothing but informs D). R merges as soon as it passes the gate; it is disjoint from every other lane and turns two required checks green.
A and B merge together, because 0.2 without 10.1 trades a silent wrap for a bricked
store. C merges independently. D merges last, after A and B, so its new tests run
under the new gates and the release-profile arithmetic check.

**Scheduling on this host.** Four building lanes on 12 cores is the edge. Start E
and A first (cheap), then B and C, then D once A has the gate baselines committed
so D's code is measured by them from its first commit.

## Wave 2

Rewritten after the external review's findings R5 and R6. The first version
assigned four lanes to the same store files and left parent Packet 4 with no
owner. Ownership below is by directory, published, and store changes are
sequenced inside a single owner rather than merged across lanes. The
requirement-to-lane ledger in
[the review response](../../reviews/2026-09-26-external-design-review-response.md)
is the authoritative map; nothing in the parent plan is without an owner.

| Lane | Owns (exclusively, for the wave) | Work, in order | Starts after |
| --- | --- | --- | --- |
| **M** parent Packet 4 | `fuzz/`, `formal/proof-manifest.toml`, `formal/rust-verification/`, `formal/apalache/`, the trace-validation surface | the `response_authority_protocol` and `response_lifecycle` fuzz harnesses with seeded corpora and recorded campaigns; production-linked Kani checks for the helpers 1A to 1C introduced; the response lifecycle model and trace validation; resolution of the temporal timeout in its owning lane | D merges |
| **S** store owner | all of `chio-store-sqlite/src/` except `receipt_store/`; `chio-kernel/src/budget_store/` | Packet 8 `ExposureUnits`, then 9.3 `prepare_cached` on the paths C measured, then 10.3 classification, then 3A's store portion, then the H1/H3/H4 remediation for these crates. 9.4 (connection strategy) is not in this candidate: it runs against the separately qualified successor, except a store whose 10.1 fence cannot be made safe, which is a fix here and is reported before it starts | B, C merge |
| **J** receipt-store owner and boundaries | `chio-store-sqlite/src/receipt_store/`, `chio-keyring/tests/`, `chio-secret-broker/src/process_boundary_tests/`, the process-cutpoint harness | Packet 3 retention liveness with #1045, then 10.4 chain-link bind and `CHECK`, then Packet 2 boundary proofs and 2A/2B (native cases on the CI runner); the cutpoint harness reruns against any store S moves to the pool before that move is accepted | C merges; 2A/2B need the runner |
| **G** kernel and security-types owner | `chio-security-types/src/`, `chio-kernel/src/` outside `budget_store/`, `chio-keyring/src/`, `chio-guards/src/external/cache.rs` | 4A clock port (one port, three traits migrated, gate on new `SystemTime::now`), then 10.2 `UntrustedJsonText` on 1F's enumeration, then 4B assertion conversion and H1/H3/H4 remediation for these crates | D merges |
| **K** gates and configuration only | `scripts/`, `.github/workflows/`, `.config/`, `Cargo.toml` lint and profile tables, `formal/experiments/` | H0 parity gate (both lint tables), H10 snapshot and generated pins, H5 nextest configuration with per-group overrides, H9 sanitizer audit, H11 package dependency budget gate, H2 Miri lane configuration and crate list, FV-E5 runbook for H6; K writes no production source and hands the measured remediation lists to S, J and G | A merged (done) |

Freeze and qualification (parent Packet 6) depend on the last source-changing
lane above, not on the wave label. Corrections 4B, H1, H3 and H4 are exit
criteria of the owning lanes, not separate work; K supplies the measurement and
the gate. One commit per item, each with its gate's self-test or its lane's
red-on-mutation.

## Wave 3

Packet 5 (the genuine `aws-lc-rs` audit, trusted definitions, capture, App-bound
check) is assurance work that needs Connor's authority at several steps and runs
alongside Waves 1 and 2 without competing builds. Packet 6 freezes the candidate
and obtains the independent review. Packet 7 (structural remediation) runs last,
against Lane A's measured baseline, one module at a time, cut and visibility and
format as separate commits, and against a **separately qualified follow-up
candidate**, not the frozen launch candidate: broad post-freeze structural work
would otherwise invalidate the qualification. Two further lanes open here per the
hardening spec: a seeded deterministic scheduler over the store and broker actors,
which depends on correction 4A's clock port, and a Hegel pilot on the SDK-parity
surface only. H7's FROST round-2 envelope has its design note
([sealing design](../specs/2026-09-26-frost-round2-envelope-design.md): X25519 sealing
keys separate from the Ed25519 transport keys, HKDF-SHA256, ChaCha20-Poly1305,
encrypt-then-sign over one canonical metadata string, per-ceremony replay rule);
its step 1, the type split that removes `Serialize` from the plaintext round-2
form, may land earlier than the lane. H8 semver follows here as well.

## The brief every lane receives

Worktree path and branch; base SHA; `CARGO_TARGET_DIR` and the environment
variables above; the exclusive file list and the forbidden list; the packet text
verbatim from the addendum; the path to the standard, with section 11 (no AI slop)
quoted in full; the commit rules; the exit criteria; the report format (SHA,
commands run, inventory counts, tool versions, what was not verified, mutation
check per regression); and the standing instructions: do not run `cargo clean`,
do not touch another lane's files, do not push to the integration branch, poll
your own background jobs rather than waiting on them, and stop and report if a
change would cross an ownership boundary.

## Orchestrator review gate

Run on every lane branch before merge. Mechanical checks first, judgment second,
then merge, checkpoint, push.

Mechanical: em dash scan; `unwrap`/`expect` outside `cfg(test)`; new
`map_err(|_|`; new `pub` fields on `Verified*`/`Authorized*`; new `include!`;
`#[allow(` outside test modules; new direct `SystemTime::now()` in TCB production
code once 4A lands; new `.prepare(` on a path 9.1 measured as hot once 9.3 lands;
conventional commit type and the co-author trailer; tests in the same commit as
the behavior they cover; the lane's owning test targets and `cargo clippy -p
<crate> --all-targets -- -D warnings` re-run by the orchestrator, not taken from
the report.

Judgment, against the standard: one responsibility per module (1.1); invalid
values unconstructible and authority opaque (2.1, 2.2); rejection provenance
preserved and one discriminant per rule (3.1, 3.2); locks covering the
commitment and not I/O (5.2); negative assertions naming the variant and a
recorded mutation check (10.1, 10.2); comments that preserve a threat model or
an invisible discipline and nothing that narrates the work (11).

A lane that fails the gate gets the specific finding back and revises on its own
branch. Nothing is merged with a known standard violation to be fixed later.

## Wave 1 ledger

**Lane E** delivered its triage (recorded in
[the triage record](../../reviews/2026-09-26-ci-triage-3cd73631a1.md)).

**Lane R** merged at `bfe421a6f6`: both regressions repaired, gate 11 of 11, tests
re-run and the pin mutation-checked by the orchestrator.

**Lane A** delivered five commits on `packet/0-gates`. Four are on the integration
branch (`ad29ee469f` 0.1, `613025d7c8` 0.3, `94b12c679b` 0.4, `ee7170ca6c` 0.5);
**0.2 (`19809a63c7`, `overflow-checks = true` plus the probe crate and the
release-overflow gate) is held on `packet/0-gates` and merges together with Lane
B's 10.1**, per the coupling. Mechanical gate 11 of 11; every gate and self-test
re-run green by the orchestrator; the old gate confirmed green at `e8e5d592ec`
while `chio-secret-broker/src/service.rs` assembled to thousands of lines from 3
own, and the new gate with one allowlist entry removed reports `9371 ... (3 own
plus 16 include! fragments) violation`.

Lane A's design choice, accepted: fragments are frozen rather than forbidden.
Every assembled module carries a `max_fragments` cap that only shrinks and any
new `include!` fragment fails, because making `cargo fmt` reach the 21 fragments
with genuine diffs would mean editing files the lane did not own.

**Measured baselines from the gates, which supersede the review heuristics:**
61 assembled modules (57 under `crates/`), 340 fragments (50 `.inc`, 290 `.rs`),
48 over the 2,000-line cap, allowlist 77 to 123 entries; largest
`chio-kernel/src/kernel/tests.rs` 40,754 (48 fragments),
`control-plane/src/security/adapters.rs` 13,956 (40),
`chio-store-sqlite/src/security_state.rs` 13,473 (13),
`chio-secret-broker/src/service.rs` 9,371 (16), `chio-security-types/src/ports.rs`
5,033 (4). Domain separation: 334 byte-string constants, 321 distinct, 10
duplicated (the review's 8 plus two the tree grew since), 32 off the stricter
shape. Accounting arithmetic: 55 unchecked sites in 13 modules, the three money
stores holding 35. Negative assertions: 1,298 weak across 229 files including
tests (282 production single-line). Lane A did not force these to match the
review figures, which was correct.

**Handed on by Lane A:**
`crates/kernel/chio-kernel/src/kernel/admission_cleanup/recovery_and_compensation.inc`
(1,228 lines) is referenced by nothing in the tree: no `include!`, no `#[path]`.
Dead code, for Lane K or Packet 7 to delete after a build confirms it.

## Decisions taken, 2026-09-26

1. Step 0 approved: Codex's in-flight work is checkpointed on `packet/1-dry-run`
   and pushed; the integration branch stays at the docs commits.
2. Models: Fable 5.1 on lanes D and B, Opus 5 on A and C, Sonnet 5 on E. The
   orchestrator runs on Fable 5.1.
3. Wave 1 runs all five lanes, staggered: E and A first, then B and C, then D.
4. Native x86_64 work is deferred to the designated CI runner for Waves 1 and 2;
   no local native lane.
