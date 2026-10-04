# PR 1173 Production Readiness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. The user requires inline execution without subagents. Steps use checkbox syntax for tracking.

**Goal:** Close the five reported production readiness blockers and qualify the exact candidate.

**Architecture:** Repair existing qualification gates and dependency boundaries, then compose PostgreSQL through existing mediated native execution. Preserve the kernel's admission, confinement, durable recovery and receipt contracts.

**Tech Stack:** Rust 1.94, Kani, Cargo Vet, Wasmtime/WASI, Python process SDK, TypeScript SDK, PostgreSQL 17, Linux x86_64 cage, GitHub Actions.

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

- [ ] Retain the hosted failure logs and compare exact inventory failures to the source test names.
- [ ] Add the omitted pending-intent and typed-proposal tests to the existing exact inventories.
- [ ] Pin every executable Kani consumer to 0.68.0, validate the installed version, and update the mutation tool version assertions.
- [ ] Run the existing proof-runner and mutation-control tests; prove stale/mismatched versions and empty harness selection still fail.
- [ ] Run both real Kani PR sweeps with the released compiler on a supported host, retaining proof outcomes rather than only successful compilation.
- [ ] Rerun the affected crypto workflow commands and confirm exact test counts. Commit the independently verified changes.

### Task 2: Remediate dependency advisories

**Files:** `crates/guards/chio-wasm-guards/Cargo.toml`, `Cargo.lock`, affected standalone locks, `package.json`, `bun.lock`, `sdks/guard/chio-guard-ts/package-lock.json`, `sdks/typescript/package*.json`, affected package locks beneath `sdks/typescript/packages/`.

**Interfaces:** Preserve the guard backend API and TypeScript package peer contracts. Consume the original scanner JSON retained from run 37184775249; produce locks with no newly suppressed advisory.

- [ ] Enumerate affected versions and primary upstream fixes; select a supported Wasmtime/WASI pair containing both fixes.
- [ ] Update each affected dependency through its package manager, reviewing unrelated lock changes. For unpatched transitive packages, identify the owning feature and specify a bounded removal or source repair before editing it.
- [ ] Run the full affected guard backend suite, component examples and Clippy. Exercise the affected TypeScript SDK and conformance package suites.
- [ ] Run the same Cargo Audit and OSV selections as CI. Require no non-ignored vulnerabilities and no additions to the ignore policy.
- [ ] Commit validated dependency and compatibility changes with retained scanner outputs.

### Task 3: Complete source-backed supply-chain review

**Files:** `supply-chain/{audits.toml,imports.lock}`, new `supply-chain/reviews/aws-lc-rs-1.18.1.md`, any narrowly necessary new review records, `third_party/aws-lc-rs-chio/CHIO-PATCH.md` if the review finds a defect.

**Interfaces:** Registry review covers exactly aws-lc-rs 1.18.1; fork review covers `CHIO-PATCH.patch` and `CHIO-RESTORED-FIXTURES.sha256`. Cargo Vet's `safe-to-deploy` criterion remains unchanged.

- [ ] Verify archive hash, upstream origin and the complete local fork delta, including restored test fixtures.
- [ ] Review FFI ownership/lengths, key generation/parsing, AEAD and nonce behavior, zeroization, thread safety, build scripts and ambient authority. Record file/function findings and any limits.
- [ ] Exercise meaningful boundary regressions and default/FIPS suites, fixing demonstrated defects before certification.
- [ ] Reconcile new dependency audit obligations from Task 2 using trusted imports or documented source review, without exemptions.
- [ ] Add certifications only for completed reviews; run `cargo vet --locked` and retain its successful result. Commit the review evidence and records.

### Task 4: Qualify confined PostgreSQL work and crash recovery

**Files:** `examples/postgres-job-swarm/`, `crates/platform/chio-finding-market-store-postgres/examples/agent_jobs/`, `.github/workflows/postgres-job-swarm.yml`, existing native broker interfaces selected by the subordinate design, `scripts/check-native-protocol-ci.py` and its tests.

**Interfaces:** Preserve public worker lease API, tenant/owner/fence inputs, `qualify.py` and `qualify_claim_loss.py` evidence contracts, and signed receipt verification. Reuse the original admission authority.

- [ ] Write and self-review a focused design/plan after tracing the existing prepared broker and resource adapter implementation; pin exact modules and custody interfaces before transport implementation.
- [ ] Add failing boundary tests for credential isolation, forged caller, wrong tenant/lease fence, denied direct networking and lost committed replies.
- [ ] Implement the smallest mediated composition preserving these properties and the real TLS PostgreSQL resource.
- [ ] Run the public worker API suite and both native qualification trajectories on Linux x86_64, including actual host termination and recovery without redispatch.
- [ ] Verify receipts and nonsecret artifact contents, update operator documentation, run relevant Clippy and workflow contract tests, then commit.

### Task 5: Qualify and review the exact production candidate

**Files:** Source-bound records under `docs/research/dynamic-delegation/evidence/`, review evidence under `docs/papers/verifiable-work/evidence/pr1173-review/`, paper artifact manifests, this plan's execution ledger.

**Interfaces:** Consume all completed tasks; produce a clean committed candidate matching the PR head and terminal hosted results.

- [ ] Perform a separate final review of every change against the spec and Review Focus; resolve P0/P1/P2 findings with regression evidence.
- [ ] Freeze source and run the existing 21-command native qualification, format and artifact checks. Preserve superseded evidence through the existing history mechanism.
- [ ] Push the authorized branch and refresh all exact-SHA CI checks; diagnose and fix any remaining failed or cancelled required gate, then requalify changed boundaries.
- [ ] Confirm local/remote/PR identity, clean worktree, exact terminal checks and draft state. Report production acceptance separately from research publication gates, merge and deployment.
