# PR 1160 Cognition CI Extraction Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans for Root integration and superpowers:test-driven-development for the isolated workflow repair. Claude prepares and reviews the producer; Root alone integrates, qualifies and pushes.

**Goal:** Remove the long promoted-default suite from the serial Build and lint path without weakening the required check.

**Architecture:** Move the existing cognition-market step unchanged into an unconditional `cognition-market` job with complete independent prerequisites. The existing `check` job requires explicit success from `build-lint`, `workspace-tests` and `cognition-market`. Preserve all other jobs and the existing four required context names.

**Tech Stack:** GitHub Actions YAML, existing Python workflow contracts, Bash refusal controls.

**Spec:** The owner's efficient CI repair instructions, the [workspace extraction plan](2026-10-11-pr1160-workspace-ci-extraction.md), and the bounded extraction ruling in `coord/pr1160` commit `f31edaa666`.

## Global constraints

- Base source is `66dc1bf22df3ff6d06557fa028c8e46c59c4a934`.
- Preserve the complete promoted-default step dictionary, including commands, feature selection, `umask 022`, `RUST_TEST_THREADS=1`, `CARGO_BUILD_JOBS=1` and Rust flags.
- Preserve the 360-minute job ceilings, toolchain and dependency pins. No retries, test exclusions, proof changes, authorization rotation or production Rust edits.
- Prepare each runner's native authority fixture independently. Do not copy another runner's authority, ownership or `/dev/shm` bindings.
- Keep the cheap default-market dependency assertion in Build and lint. Move only the expensive promoted-default step.
- Keep the published candidate running while preparing the replacement. Retain cancelled results as incomplete evidence.

## Review focus

- Missing, skipped, cancelled, timed-out or failed children must fail the required aggregate.
- A cold runner must have every tool and generated input the moved suite consumes.
- Standalone Cargo commands must retain their original feature graph and serial fixture profile.
- Conditions, tolerated failures, foreign-runner fixtures or an extra early exit must not bypass qualification.
- All unrelated jobs and the other 48 Build and lint steps must remain unchanged after YAML decoding.

## Task 1: Isolated producer and refusal controls

**Files:** `.github/workflows/ci.yml`, `scripts/check-security-ci-contract.py`, `scripts/tests/check-security-ci-contract.test.py`, and `scripts/tests/check-workspace-ci-extraction.test.py`. Change native-protocol contracts only if their prerequisite ownership requires it.

**Interfaces:** `validate_build_lint_test(ci)` consumes the workflow and rejects any aggregate or producer weakening. The new job is `cognition-market`, reported as `Cognition market promoted default`.

- [ ] Add the three-child shape, exact moved-step and prerequisite assertions. Run them against unchanged `66dc1bf22d`; expect refusal because the new required child is absent.
- [ ] Extract the exact step and copy the necessary pinned setup with native fixture preparation immediately before it.
- [ ] Require all three successful results in the unconditional aggregate. Preserve the existing context name.
- [ ] Reject removed dependencies, conditional or tolerated children, modified commands/environment, omitted setup and misplaced fixture preparation.
- [ ] Execute the real aggregate Bash for all 216 triples of success, failure, cancelled, skipped, missing and timed-out results; only three successes may pass.
- [ ] Run owning checker/regressions and review the isolated commit before handoff.

## Task 2: Root composition and publication

**Files:** This plan, existing landing ledger, and a source-scoped audit under `docs/security/audits/`.

**Interfaces:** Consume the reviewed producer and its Original/green evidence. Produce one qualified workflow candidate with unchanged runtime scope.

- [ ] Independently trace prerequisite inputs, compare the moved step and every unaffected job/step against `66dc1bf22d`, and run aggregate/refusal controls.
- [ ] Compose the producer and run the affected security, native, FIPS, trusted-definition, evidence-binding and patch-hygiene contracts on the exact composed source.
- [ ] Record logs, source hashes, independent review and timing limitations. The estimate is a reason to reduce risk, not a successful hosted run or a guaranteed deadline.
- [ ] Publish the reviewed batch, verify local/remote/PR/archive equality, then stop superseded runs and preserve their incomplete logs.
- [ ] Obtain exact-head green results for the three aggregate children, the aggregate, MSRV, Vet and Deny; qualify the repaired enforcing MCP HTTP job and address new review/failures.
- [ ] Report readiness to the owner and Claude for the agreed exact-head merge handshake.

## Ruling

The retained timing analysis places Build and lint near its existing ceiling,
with a material upper-tail risk. Separating unchanged work reduces that risk
without changing what must pass. Workspace and MSRV still have long execution
times; this extraction does not establish a sub-hour pipeline. Parallel test
profiles, cache changes, lane retirement and contract redesign remain separate.
