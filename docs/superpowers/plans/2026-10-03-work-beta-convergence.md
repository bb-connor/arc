# Chio Beta Convergence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax. This is the integration boundary for the three existing lanes, not authorization to repeat their roadmaps or publish.

**Goal:** Produce one reviewable, installable beta candidate whose supported claims match security, recovery and reusable-work evidence.
**Architecture:** Join accepted lane commits, reuse the established release checks, and qualify the resulting package and actual application boundary.
**Tech Stack:** Existing Rust/SDK packaging, native Linux qualification, hosted CI, signed artifact/evidence pipeline.
**Spec:** [beta target and stopping rule](../specs/2026-10-03-agentic-work-kernel-design.md#beta-target-and-stopping-rule).

## Global Constraints

- Existing requirements are not silently waived by the word beta.
- A devnet result cannot authorize public-money operation.
- Run focused checks at each changed boundary. Run the inherited full release qualification once at the integrated candidate boundary, and rerun only what subsequent changes invalidate.
- No em dashes. Do not invent observed results, outside participants, shipped surfaces or release acceptance.
- Apply all [parent constraints](../specs/2026-10-03-agentic-work-kernel-design.md#global-constraints).

## Review Focus

- Each lane passes on a different SHA, but their joined candidate fails: require one source/artifact identity (W4.1/W4.2).
- Hosted success comes from an old run attempt or different workflow definition: bind candidate, workflow and terminal evidence (W4.2).
- Installation falls back to Disabled confinement or an old released binary: fail the advertised profile (W4.3).
- New schema/features strand old work or drop retained obligations during upgrade/rollback: migration/reopen controls (W4.2).
- Documentation calls the beta a complete security roadmap or public economic deployment: claim/support reconciliation (W4.3).

## W4.1: Consolidate source and scope

**Files:**

- Update: docs/research/work-abstraction/INTEGRATION.md and SOURCES.json.
- Update: docs/release/RELEASE_CANDIDATE.md, RELEASE_AUDIT.md, QUALIFICATION.md.
- Create: docs/release/WORK_BETA_ACCEPTANCE.json.

**Interfaces:** The acceptance record maps supported surfaces to exact security milestones, recovery phase requirements, AW01-AW31, LC01-LC06, source commits, required commands and evidence artifacts. Each lifecycle case has its own status and evidence; none is accepted solely because its component unit tests passed.

- [ ] Read each lane's latest accepted checkpoint and unresolved findings. The Mac recovery lane supplies its actual commit and requirements record; a proposed spec is not implementation evidence.
- [ ] Integrate semantic changes on an isolated release branch. Review overlaps in worker negotiation, native capture, result release, runtime stores, payment and evidence export.
- [ ] List the proposed beta surfaces and enable only their closed dependencies. Preserve all inherited required gates; exclusions require a specific scope/claim decision.
- [ ] Resolve version terminology: current release plan uses 0.2.0-alpha.N developer previews. Decide and record how the beta name relates to the actual package version before selecting a release tag; do not silently rename an alpha artifact as beta.
- [ ] Commit the integrated candidate and acceptance matrix. Record unresolved dependencies as pending, not waived.

Acceptance: AW16 has an auditable candidate and a complete gate inventory.

## W4.2: Qualify the combined candidate

**Files:**

- Extend only where missing: scripts/qualify-release.sh and its established manifest/report inputs.
- Reuse: scripts/ci-workspace.sh, check-formal-proofs.sh, check-portable-kernel.sh, check-sdk-parity.sh, qualify-process-packages.py and qualify-cross-protocol-runtime.sh.
- Reuse: .github/workflows/release-qualification.yml and existing required security/native workflows.
- Extend: WORK_BETA_ACCEPTANCE.json with evidence, terminal statuses and hashes.

**Interfaces:** Existing release aggregation must include W1/W2/W3 profiles and the recovery lane's required conformance results. Source, platform, profile, toolchain, command and terminal exit are mandatory evidence fields.

- [ ] Run changed-boundary migration tests: explicitly import/quiesce legacy D1 once, retire its writer and preserve namespace/allocation/permit bytes. Reject stale fence, missing catalog/table and unqualified restored state. Include new delegation/financial records in serving integrity, projection/global-commit and relocation checks.
- [ ] Reopen original native requests and recover admitted work across upgrade. Test rollback only to a schema-compatible version; an unsupported old binary must refuse serving rather than discard new obligations. Retain payable claims and authority tombstones independently of coordinator cache retention.
- [ ] Run the three-lane application suite on the designated enforced native platform with an independent effect observer. Missing platform or optional artifacts required by an advertised feature is unavailable, not a pass.
- [ ] Include LC01-LC06 in that existing suite: installed catalog/profile/acceptance/join behavior, scoped recovery progress, policy-generation cutpoints, bounded substitution and unpaid/funded/harness adoption. Reuse native vectors and prior artifacts when source-valid; run the missing integrated compositions rather than restarting historical campaigns.
- [ ] Run the existing full required release schedule once on the integrated candidate, including supply-chain/source audits and packaging. Never add audit exemptions just to close the gate.
- [ ] Obtain terminal hosted CI and Release Qualification results for the exact candidate and required workflow definitions. Reconcile remote/local/PR SHA, run attempt, review threads, failed/cancelled/skipped checks and generated package hashes.
- [ ] Fix a failure at its owning boundary, record the new candidate, and rerun invalidated checks. Preserve the failed campaign instead of overwriting it.
- [ ] Review the complete candidate against AW21 through AW31 as well as the original contract: checked/opaque types, owner-local idempotency, exhaustive request projection, feature graph, bounded executor behavior, private diagnostics, accepted-result evidence, current release and generation changes. Close blocking security, recovery, work-contract and packaging findings; do not relax engineering ratchets.

Acceptance: required qualification passes on one candidate. If any requirement remains unavailable, report a candidate with that specific blocker; do not infer readiness from the fraction of green checks.

## W4.3: Clean installation, final claims and release handoff

**Files:**

- Update: docs/release/RELEASE_AUDIT.md, RELEASE_CANDIDATE.md and GA_CHECKLIST.md with the beta's bounded posture.
- Update: docs/reference/WORK_PROGRAMMING.md, WORK_OWNERS.md and installed-package examples.
- Update: the architecture paper profile after P.5, preserving its actual evidence.
- Produce: existing signed release bundle with beta acceptance and work support matrix.

- [ ] Install the exact built artifacts in a clean environment without repository source imports. Run both work applications and inspect signed evidence, effects and ownership.
- [ ] Run LC06's installed LangGraph entrypoint and adoption profiles. Verify source/package identities, no unpaid funding requirement, no local fallback and the same public semantics after checkpoint resume. Verify LC05's unchanged consumer logic evidence against the actual release artifacts.
- [ ] Verify the installer selects that candidate and does not fall back to an older package. Confirm supported feature/platform/rail dimensions match documentation.
- [ ] Distinguish architecture completeness, implemented source, local qualification, hosted qualification, release readiness and publication. Automatic-defense promotion still follows Security M11's observed cohort requirements.
- [ ] Complete the concrete release bundle, operator instructions and remaining-scope record before any publication decision.
- [ ] Record final acceptance and hand off for the existing release authorization/publication process. This planning request does not authorize external publication.

Acceptance: AW17 and a beta-ready candidate if every required source, review, native, hosted and packaging gate passes. Publication is a subsequent explicit action.

Stop condition: no invented fourth feature roadmap. Remaining hypotheses about economic advantage, outside adoption and historical impact stay separately tracked and do not become fake passed gates.
