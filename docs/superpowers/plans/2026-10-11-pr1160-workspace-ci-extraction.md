# PR 1160 Workspace CI Extraction Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans for Root integration. Root implements, integrates, qualifies and pushes; Claude independently reviews the source and sweeps exact test inventories.

**Goal:** Run the unchanged workspace test suite in parallel with build, lint and the existing feature suites, while preserving the required-check acceptance contract.

**Architecture:** Keep `check` and its reported name `Build, lint, test` as a small fail-closed aggregate. Move the original job's other steps to `build-lint` and the unchanged workspace test command to `workspace-tests`, with its own complete fixture preparation. MSRV remains unchanged.

**Tech Stack:** GitHub Actions YAML, existing Python workflow contracts and refusal regressions, Cargo/libtest.

**Spec:** The owner's CI-feedback and merge-bar instructions, the existing [landing ledger](../../security/landing-ledger.md), and the approved v2 design in `coord/pr1160` at October 11 17:51 UTC. This replaces the earlier target-kind and filter-partition proposals.

## Global constraints

- Preserve `cargo test --workspace --no-fail-fast --exclude chio-wasm-guards` exactly, including default target selection and doctests.
- Preserve `RUST_TEST_THREADS=1`, `CARGO_BUILD_JOBS=1`, the Rust toolchain, Rust flags and the existing 360-minute ceiling.
- Preserve all other original checks and standalone feature suites. No selected tests are removed or reclassified.
- Prepare runner-bound authority fixtures independently on each runner. Do not transfer another runner's authority, ownership or `/dev/shm` bindings.
- No production Rust, proof model, authorization, repository-variable, retry or acceptance changes.
- Preserve cancelled predecessor logs as incomplete evidence. The observed slow native control was CPU-bound; no hang or inevitable timeout is established.

## Review focus

- A failed, cancelled, timed-out, skipped or missing child must never produce a successful required aggregate.
- A new conditional or `continue-on-error` on a child must be rejected by the workflow contract.
- Workspace tests must retain setup and generated artifacts they previously consumed, including native fixture preparation.
- Moving checks must not leave contract validation pointed at the now-empty aggregate instead of the producing job.
- Required context identity, downstream security dependencies and trusted definition comparisons must stay bound to the actual child jobs.

## Task 1: Extract the workspace suite and preserve its acceptance contract

**Files:**

- Modify `.github/workflows/ci.yml`.
- Modify `scripts/check-security-ci-contract.py`.
- Test `scripts/tests/check-security-ci-contract.test.py`.
- Renew `scripts/tests/check-native-protocol-ci.test.py` if its owning job references change.

**Interfaces:** `check` reports the original required name and accepts only successful `build-lint` and `workspace-tests` results. The workspace job executes the exact original test command with its own setup; MSRV and all other suites retain their commands.

- [x] Trace the workspace step's environment and artifact producers; record which setup steps the new job requires.
- [x] Add contract assertions for the exact aggregate dependencies, unconditional final evaluation and explicit successful child results. Observe the old single-job workflow failing the new shape assertion.
- [x] Move the unchanged steps into their owning jobs. Copy required setup without copying runner-bound output from a different runner.
- [x] Reject missing dependencies, altered result predicates, conditional children, tolerated child failures, changed workspace flags and missing native preparation through focused mutations.
- [x] Run `python3 scripts/check-security-ci-contract.py`, `python3 scripts/tests/check-security-ci-contract.test.py` and `python3 scripts/tests/check-native-protocol-ci.test.py`; retain complete exit status and logs.
- [x] Verify the moved original steps are equal after YAML parsing, except for the reviewed owning-job placement and aggregate. Run the relevant workflow syntax and trusted-definition regressions.
- [x] Commit the isolated repair and obtain independent source review before Root integration.

## Task 2: Qualify and publish the composed workflow repair

**Files:** Existing landing ledger and a source-scoped audit under `docs/security/audits/`; update this plan's completed steps.

**Interfaces:** Consume the reviewed Task 1 commit and exact positive/negative logs. Produce a single published candidate with unchanged source test scope and an honest hosted status.

- [x] Root composes the isolated commit without concurrent integration writers and renews only affected shared metadata.
- [x] Run the affected static checks on the exact composed source. Retain the prior full-suite cancellation and the successful local native timing control separately.
- [ ] Publish the complete repair once qualified; record the exact local, remote and PR head equality and update the PR body.
- [ ] Require successful `build-lint`, `workspace-tests`, the `check` aggregate and the other three required contexts on that head. Classify other failures and address review before reporting landing readiness.
- [ ] Report the exact head, required results and remaining operational/proof obligations to the owner and Claude. Wait for the owner's explicit merge go-ahead.


## Qualification checkpoint (October 11 UTC)

Root source `98a0e77ed3` passed all thirteen affected Python check and regression
commands. Independent preservation verified all 49 original nonworkspace steps,
all ten unrelated jobs, the original workspace command and 36 aggregate result
combinations. Claude approved that exact source. The syntax wrapper's six tests
passed; targeted actionlint retained the same pre-existing unsupported
`artifact-metadata` permission diagnostic on baseline and candidate, so no global
actionlint pass is claimed.

The subsequent two-line FIPS repair `021a5b8b0d` enrolls the existing unreadable-key
forwarding control and renews only its owning job hash. The actual PQ exact gate
reproduced two passing tests followed by the Original inventory failure, then
passed with both identities enrolled. The composed contract and nine FIPS mutation
tests passed; Claude approved the exact delta. The thirteen-command campaign is
source-scoped to `98a0e77ed3`, with focused delta verification on `021a5b8b0d`.

The [batch audit](../../security/audits/workspace-ci-extraction-20261011.json)
retains logs, hashes, failure boundaries and the independent review. Publication,
exact-head hosted checks and the owner's merge go-ahead remain pending.
