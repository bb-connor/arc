# PR 1173 Production Readiness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. The user requires inline execution without subagents. Steps use checkbox syntax for tracking.

**Goal:** Close the five reported production readiness blockers and qualify the exact candidate.

**Architecture:** Repair existing qualification gates and dependency boundaries, then compose PostgreSQL through existing mediated native execution. Preserve the kernel's admission, confinement, durable recovery and receipt contracts.

**Tech Stack:** Rust 1.95, Kani, Cargo Vet, Wasmtime, Python process SDK, TypeScript SDK, PostgreSQL 17, Linux x86_64 cage, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-10-04-pr1173-production-readiness.md`

## Global Constraints

- No subagents; execution and a distinct final self-review happen in this session.
- Fail closed; no audit exemptions or additional advisory suppressions.
- No MSRV bypass, removed proof selection, relaxed confinement or substituted database.
- Preserve exact attempt/SHA provenance and unsuccessful results.
- No em dashes in authored source or documentation; conventional commits.
- Keep one Cargo build owner per target directory.

## Review Focus

- Cached Kani executables must match the selected version; a successful version command alone is insufficient.
- Dependency updates must not leave vulnerable copies in standalone locks or test harnesses.
- A local path fork must not inherit a registry audit for different bytes without a separate fork review.
- Database credentials and caller bindings must not cross into an untrusted tool or appear in qualification artifacts.
- A committed database claim with a lost reply must recover under its original identity without issuing a second claim.

---

### Task 1: Restore complete CI and proof selection

**Files:** `.github/workflows/chio-tee-fips.yml`, `.github/workflows/formal-pr-smoke.yml`, `.github/workflows/{ci,nightly,release-qualification,proof-mutants}.yml`, `scripts/{proof-mutants.py,kani-mutant-killer.sh}`, matching tests under `scripts/tests/`.

**Interfaces:** Keep the existing exact-test log checker, `check-kani-public-core.sh --lane pr` and `run-kani-manifest.sh --lane pr --exclude-crate chio-kernel-core`. No harness API changes are planned.

- [x] Retain the hosted failure logs and compare exact inventory failures to the source test names.
- [x] Add the omitted pending-intent and typed-proposal tests to the existing exact inventories.
- [x] Pin every executable Kani consumer to 0.68.0, validate the installed version, and update the mutation tool version assertions.
- [x] Run the existing proof-runner and mutation-control tests; prove stale/mismatched versions and empty harness selection still fail.
- [x] Run both real Kani PR sweeps with the pinned, narrowly repaired compiler on a supported host, retaining proof outcomes rather than only successful compilation. `scripts/kani-toolchain.py` binds the exact release, upstream repair and cached compiler bytes; its real controls require proof success and rejection of reachable unsupported code.
- [x] Rerun the affected crypto workflow commands and confirm exact test counts. Commit the independently verified changes.

### Task 2: Remediate dependency advisories

**Files:** `crates/guards/chio-wasm-guards/Cargo.toml`, `Cargo.lock`, affected standalone locks, `package.json`, `bun.lock`, `sdks/guard/chio-guard-ts/package-lock.json`, `sdks/typescript/package*.json`, affected package locks beneath `sdks/typescript/packages/`.

**Interfaces:** Preserve the guard backend API and TypeScript package peer contracts. Consume the original scanner JSON retained from run 37184775249; produce locks with no newly suppressed advisory.

- [x] Enumerate affected versions and primary upstream fixes; reuse the security prerequisite's Wasmtime 48.0.5 and Rust 1.95. There is no Wasmtime WASI dependency to upgrade in this backend.
- [x] Update each affected dependency through its package manager, reviewing unrelated lock changes. For unpatched transitive packages, identify the owning feature and specify a bounded removal or source repair before editing it.
- [x] Run the full affected guard backend suite, component examples and Clippy. Exercise the affected TypeScript SDK and conformance package suites.
- [x] Run the same Cargo Audit and OSV selections as CI. Require no non-ignored vulnerabilities and no additions to the ignore policy.
- [x] Commit validated dependency and compatibility changes with retained scanner outputs.

### Task 3: Complete source-backed supply-chain review

**Files:** `supply-chain/{audits.toml,imports.lock,aws-lc-rs-fork.json,aws-lc-lint-exceptions.json}`, `docs/security/audits/aws-lc-rs-1.18.1-*.md`, `scripts/check-{supply-chain.sh,aws-lc-fork.py,aws-lc-lints.py}`, and the exact `third_party/aws-lc-rs-chio/` source from merged PR 1168.

**Interfaces:** Reuse the completed upstream and fork reviews from PR 1168. The published wrapper has confirmed defects and is explicitly not certified safe to deploy. The non-implying upstream review criterion, exact corrected fork inventory and reconstruction, lint dispositions, locked deployment source/feature checks, native/transitive deployment audits and regressions form one mandatory gate. No new exemption is authorized.

- [x] Verify archive hash, upstream origin and the complete local fork delta, including restored test fixtures.
- [x] Review the completed source audit's coverage of FFI ownership/lengths, key generation/parsing, AEAD and nonce behavior, zeroization, thread safety, build scripts and ambient authority. Preserve its findings, source identity and deployment limits.
- [x] Run the combined gate on the merged candidate: exact source reconstruction and six deployment resolutions, default/FIPS lint inventories, Cargo Vet, DES parity, AES initialization and FIPS wrong-key rejection. Historical full default/FIPS suites remain attributed to the prerequisite.
- [x] Reconcile new dependency audit obligations from Task 2 using trusted imports or documented source review, without exemptions.
- [x] Add certifications only for completed reviews; run `cargo vet --locked` and retain its successful result. Commit the review evidence and records.

### Task 4: Qualify confined PostgreSQL work and crash recovery

**Files:** `examples/postgres-job-swarm/`, `crates/platform/chio-finding-market-store-postgres/examples/agent_jobs/`, `.github/workflows/postgres-job-swarm.yml`, existing native broker interfaces selected by the subordinate design, `scripts/check-native-protocol-ci.py` and its tests.

**Interfaces:** Preserve public worker lease API, tenant/owner/fence inputs, `qualify.py` and `qualify_claim_loss.py` evidence contracts, and signed receipt verification. Reuse the original admission authority.

- [x] Write and self-review a focused design/plan after tracing the existing prepared broker and resource adapter implementation; pin exact modules and custody interfaces before transport implementation.
- [ ] Add failing boundary tests for credential isolation, forged caller, wrong tenant/lease fence, denied direct networking and lost committed replies.
- [x] Implement the smallest mediated composition preserving these properties and the real TLS PostgreSQL resource.
- [ ] Run the public worker API suite and both native qualification trajectories on Linux x86_64, including actual host termination and recovery without redispatch.
- [ ] Verify receipts and nonsecret artifact contents, update operator documentation, run relevant Clippy and workflow contract tests, then commit.

### Task 5: Qualify and review the exact production candidate

**Files:** Source-bound records under `docs/research/dynamic-delegation/evidence/`, review evidence under `docs/papers/verifiable-work/evidence/pr1173-review/`, paper artifact manifests, this plan's execution ledger.

**Interfaces:** Consume all completed tasks; produce a clean committed candidate matching the PR head and terminal hosted results.

- [ ] Perform a separate final review of every change against the spec and Review Focus; resolve P0/P1/P2 findings with regression evidence.
- [ ] Freeze source and run the existing 21-command native qualification, format and artifact checks. Preserve superseded evidence through the existing history mechanism.
- [ ] Push the authorized branch and refresh all exact-SHA CI checks; diagnose and fix any remaining failed or cancelled required gate, then requalify changed boundaries.
- [ ] Confirm local/remote/PR identity, clean worktree, exact terminal checks and draft state. Report production acceptance separately from research publication gates, merge and deployment.

### Kani traversal resource bound

The repaired compiler exposed a previously hidden solver cost: the inclusion
walk fixture expanded 36 alternative heap allocations to 25 million variables
and 111 million clauses, exceeding an ordinary CI runner's memory. The local
run was terminated after exceeding 35 GiB, and is retained as interrupted.
Quantify directly over the bounded path instead: every size and index 0..=8,
every length 0..=3, and every 32-byte leaf/sibling value. This is a superset of
the former valid fixtures and six mutation modes. Preserve the production walk,
independent model, hash abstraction and enabled unwinding checks. Require the
full proof and existing Merkle mutant-killer controls before acceptance.

The direct-path run still expanded recursive `chio_core_types::Error` drop glue
through unrelated JSON error variants and exceeded 19 GiB. Avoid eagerly
constructing the fieldless rejection error on successful sibling lookups. The
harness checks the returned error is exactly `MerkleProofFailed` before omitting
the generic destructor with `ManuallyDrop`. This excludes no owned error payload;
the valid traversal, invalid-path result, allocation checks and unwinding checks
remain enabled. Preserve both interrupted runs and qualify the public method.

The model-only quote harness also expanded unrelated recursive attestation error
destructors. Its abstract validator now uses a fieldless model error vocabulary
with the same rejection classes and precedence. This does not alter production
quote verification or claim that the model proves the parser. The complete PR
manifest sweep passes all 21 selected harnesses with the repaired compiler.

The integrated source also carried stale formal mirrors. Review the reported
source changes, follow moved validators and deadline helpers, and regenerate
the anchors and coverage inventory only after that review. The review and model
limits are recorded in `docs/formal/PR1173-SOURCE-REVIEW.md`.

### Mutation coverage at the receiver record boundary

The retained x86 run reported a surviving OR-to-AND mutation in the receiver's
lease-reference comparison before its overall job was cancelled. SQLite's
independent record checks reject the malformed record first, so an end-to-end
SQLite fixture cannot isolate this defensive predicate. Extract the unchanged
comparison into a private function and test independent substitution of either
lease identifier, issuer, scope, hash algorithm and expiry. Retain the source
check for every `RuntimeAdmissionStore` implementation. Prove an actual Boolean
mutation is rejected, then rerun the existing integrated treaty suite.

### Retained CI timeout dispositions

The x86 changed-target ASan build completed after approximately 66 minutes,
leaving less than nine minutes of its 75-minute job for unchanged fuzz budgets.
Set that outer budget to 150 minutes, preserving every target and fuzz duration.
The 73-mutant runtime slice exhausted its 45-minute job while still testing;
set the outer PR budget to 120 minutes without changing selection, concurrency,
per-mutant timeout, or score requirements. These are interrupted historical
campaigns, not passing evidence; require terminal reruns on the new source.

### Fuzz selection across the nested build container

The retained `2e296de197` and `2ae8ee2979` runs stopped with runner shutdown
signals while compiling the response-authority feature graph. Neither reached
fuzz execution. The logs do not establish the shutdown cause. Investigation
also found two independently reproducible selection defects: the pinned action
does not forward `CHIO_CFLITE_TARGETS` into its nested builder, and the CFLite
builder omits the mapped FROST round-two target.

The action also clones a clean checkout, so a generated file in the invoking
checkout cannot carry the selection into its build. Keep the complete upstream
build and select the exported executables immediately before fuzzing. Verify
every mapped binary is a regular executable before removing any unselected
binary; preserve corpora, options and shared runtime files. Reject empty,
unknown and duplicated selections and incomplete or substituted build results.
Restore builder inventory parity, including FROST. Execute the real shell
builder with only Cargo replaced at the expensive compiler boundary, and test
export selection against real files. Require unchanged sanitizer and feature
flags and agreement with the owning target map. Run these controls in the fuzz
workflow itself, including stacked PRs that do not select the main-only CI job.
Correct the workflow comments: the upstream action defines `fuzz-seconds` as
the total budget, not a per-target budget. Retain the configured 60/120 seconds.
Require a terminal hosted build and fuzz run; local orchestration controls do
not establish that the runner shutdown is resolved.

### Security execution image reconciliation

The merged workspace requires Rust 1.95, but the evidence image still binds
Rust 1.94.1 and the previous lockfile. Pin the official x86 Rust 1.95.0 Alpine
3.22 image manifest and the Rust release manifest's Clippy/rustfmt archives.
Retain the exact APK inventory, independent installed-component comparisons,
read-only source mount, Cargo tool pins, and immutable authority entrypoints.
Bind the reviewed final Cargo and toolchain files in both the image and its
contract checker. Build the complete image on the x86 CI runner before accepting
the transition. A local ARM execution-format failure is not image qualification.

### Local acceptance before the next hosted candidate

The selected 32 public-core and 21 manifest Kani harnesses passed. The actual
Merkle leaf-boundary mutation failed its independent oracle and the restored
walk passed all 963 checks. The real DSSE OR-to-AND mutation was rejected by
the added predicate regression; restored tests passed. Compiler installation
controls reject reachable unsupported catch-unwind and require a working proof.
Version, empty-selection, inventory and proof-mutant runner controls passed.

The combined AWS-LC gate passed on the integrated source: reconstruction, six
deployment resolutions, reviewed lint inventories (37 default, 38 FIPS), locked
Cargo Vet, three DES parity tests, AES schedule initialization and FIPS wrong-key
rejection. Vet retained 730 existing exemptions; this work adds none. Cargo Audit
and OSV passed their existing policies. The npm source repairs are authenticated
against the original upstream packages, reconstructed exactly and checked for
new advisories. Braces' upstream Bash-compatibility failures remain recorded.

PostgreSQL adapter tests, the prepared-payload regressions, all 34 shared Python
tests and TypeScript transport tests passed, as did affected Rust Clippy and
workflow negative controls. The actual confined PostgreSQL and SIGKILL
trajectories and the x86 evidence image remain required hosted checks. No local
aarch64 result substitutes for those checks. The final source-bound paper
qualification and terminal hosted acceptance follow the integration commits.

### Final workflow review

The path-scoped formal lane omitted registered `chio-open-market` and
`chio-security-types` PR harnesses, and its wiring test still expected the old
version-only cache probe. Restore both trigger paths and lane classification.
The existing wiring test now exercises the real shell classifier for every PR
crate discovered from the harness manifest and workspace, including each crate
manifest and source. A removed security-types classifier route must fail the
control. Run this cheap contract in the formal scope job itself.

The tracked acceptance ledger is
`docs/papers/verifiable-work/evidence/pr1173-review/REVIEW.md`. It records final
source-bound and hosted results separately from these implementation checkpoints.

### Hosted integration corrections

The `eddd3e18c6` image build fails before compilation because Alpine replaced
OpenSSL 3.5.8 and Python 3.12.14 in its repository. Resolve the pinned Rust 1.95
x86 base against OpenSSL 3.5.9, Python 3.12.15 and the September 2026 certificate
package and bundle. Review the entire installed inventory, including the musl
and Alpine release versions inherited from the new base. Retain all 225 package
identities, the complete inventory comparison, package signatures and the
downloaded certificate archive hash. An ARM-native package resolver targeting
the copied x86 package database can check resolution, but cannot qualify x86
execution or package install scripts. Require the actual hosted image build.

The same hosted candidate passes all 34 caller-execution tests, then rejects
the workflow's 33-test inventory. Add the existing v34 schema-migration test to
that exact inventory, matching `check-authenticated-caller-delivery.sh`. Review
the one-line workflow addition before rebinding its structural contract. Run
the corrected inventory and every remaining step of the crypto-floor job;
preserve the original hosted failure and contract rejection.

The subsequent cumulative-approval sweep exposes a fixture clock regression:
it truncates wall time to seconds after the kernel has observed milliseconds.
Install the scoped fixture clock before opening either authority owner, keep
that scope alive, and advance to the issued nonce's exact expiry. Preserve the
production monotonic fence, expired-nonce denial, prepared state and zero
invocation assertions. Require the focused regression and complete nine-test
cumulative-approval target to pass before continuing the remaining workflow.

The x86 PostgreSQL attempt passes native confinement and the real TLS worker API,
then times out before broker readiness. Rust's default test renderer prefixes
the helper's first marker with its test name, so the strict line matcher cannot
recognize it. A real Rust test subprocess reproduces the timeout; terse test
output produces the exact marker and passes the same reader. Select terse output
for the existing helper without changing its test selection, startup barrier or
exact readiness check. Retain both the failed hosted attempt and the subprocess
control, then rerun the actual ownership and response-loss scenarios.

### Unfiltered advisory review

The current hosted policy passes, but its retained unfiltered report still finds
`GHSA-866g-f22w-33x8` in the standalone AI SDK 5 peer-test lock. The inherited
waiver claims that remediation requires AI SDK 6. Upstream has since published
the response-body bound in `@ai-sdk/provider-utils` 3.0.28. Align this standalone
development graph with the existing workspace's AI SDK 5.0.210 and provider-utils
3.0.28, remove the stale waiver, and preserve the published peer contract.
The latest 5.0.271 trial introduced an affected Undici 5 graph; retain that failed
scan and use the repository's already qualified compatible selection. Run the
standalone build, type check and full existing tests, then require the actual
unfiltered OSV selection to contain no findings. Refresh the source-bound
qualification before pushing the final candidate.

### Explicit aggregate budget for native initialization

The next x86 attempt passes the readiness marker, native enforcement and the
public PostgreSQL worker API, then fails at `chio process init`. Native broker
hosts require `--aggregate-invocations`; this example omitted that argument.
Bind it to the same 100-call fixture limit already used by the process tree,
using one shared value for both settings. Preserve the kernel's mandatory
budget check and the children's 40-percent shares. Reproduce the rejection with
the real CLI before the repair and verify that the corrected initializer passes
that boundary. This local configuration probe does not qualify native execution;
both complete x86 PostgreSQL trajectories remain required.

### Cold Kani compiler provisioning

The hosted manifest lane installs the release runtime, then fails to rebuild
the compiler because `rustc-dev` is absent. The explicit `RUSTUP_TOOLCHAIN`
override bypasses the component list in the pinned upstream toolchain file.
Provision that exact nightly with its four declared build components before
reconstruction. Keep the source revisions, intrinsic repair and proof selection
unchanged. A prerequisite failure must stop before any compiler replacement or
acceptance marker. Exercise this failure boundary and provision an isolated Rust
toolchain to verify that the compiler-private crates are available without prior
host state. Require both complete hosted Kani sweeps on the final candidate.

The source qualification started after the PostgreSQL budget fix was interrupted
to incorporate this newly observed CI failure. Retain its partial outputs as
interrupted evidence; run the complete profile after the source repair is frozen.

### Consume the existing verified broker response contract

The `2e296de197` PostgreSQL lane now reaches the first admitted tool result.
The qualifier incorrectly expects an MCP wrapper around the kernel value.
`BrokerMcpConnection` already consumes that transport wrapper, verifies the
broker response, and returns `BrokerExecuteResponse` directly. The installed
process and LangGraph clients preserve this value. Align both the PostgreSQL
qualifier and shared prepared-resource graph decoder with that existing
contract. Keep signature verification, confinement and broker custody unchanged.

Reproduce the failure with the direct broker response shape before the repair.
Require the decoder to preserve the original response and signed artifact,
reject an extra wrapper or incomplete broker evidence, and refuse kernel or
resource errors. Run the complete affected Python suites. Retain the failed
hosted run separately, freeze the repaired source, and repeat the source-bound
qualification and both complete x86 PostgreSQL trajectories.

The export handoff also requires both build modes to retain unaffected fuzzers
until the owned selector validates the complete inventory. The runner creates
`build-out` before the root build container enters, so later subset selection can
remove unselected executables without changing file ownership or permissions.
Two additional red/green workflow controls exercise those integration contracts.
The 60/120-second inputs remain the upstream action's total sampling budgets.
