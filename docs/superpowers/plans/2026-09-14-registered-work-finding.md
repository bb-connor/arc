# Registered work and Finding acceptance implementation plan

> **For agentic workers:** Use superpowers:subagent-driven-development for the independent verifier bridge and schema work, with inline integration and independent final review. Continue through local qualification and commit under the user's execution instruction.

**Goal:** Register the funded work artifacts and enforce original Finding-facet requirements in their acceptance decisions.

**Architecture:** Existing funded native identities and custody remain authoritative. A pre-funded pinned Finding context drives the existing thirteen-facet verifier. Registered v2 agreement/decision artifacts bind its exact assessment; v1 submission/dependency encodings remain stable.

**Tech Stack:** Rust, existing Chio canonical JSON/Ed25519 and Finding verifier, JSON Schema, independent Python parser, owned Ganache mock-token witnesses.

**Spec:** [Registered work design](../specs/2026-09-14-registered-work-finding-design.md)

## Global constraints

- Fail closed; no production unwrap/expect; no em dashes; conventional local commit.
- Preserve the original operation, hold, allocation and transaction identities.
- No fabricated verified facets or broader market admission/reimbursement claims.
- Signed raw artifacts are canonical and at most 256 KiB; integer maximum is 9007199254740991.
- No push, PR, merge, hosted activation, real funds or other worktree changes.

## Task 1: Existing verifier bridge

Files: new `examples/federated-work/src/funded_work/finding_acceptance.rs` and focused submodules/tests; standalone manifest/lock only as needed.

- [x] Write and observe failing tests for required missing receipt/bond evidence, unsupported issuer/intent trust, changed profile/context and unbacked Finding claim upgrades.
- [x] Implement persisted `AcceptanceContext`, `fixture_context`, `evaluate` and `validate_assessment`. Use the actual immutable verifier draft and existing claim-derived facet floor.
- [x] Return all thirteen facets plus accepted/rejected/unavailable/unsupported outcome. Any failed facet rejects; every required facet must be verified.
- [x] Run targeted Rust tests and obtain independent review of the authority boundary.

## Task 2: Original authority integration and signed wire parsing

Files: funded `agreement.rs`, `native.rs`, `smoke.rs`, `evidence.rs`, `verification.rs`, `child.rs`, focused wire/integration tests.

- [x] Write failing tests showing changed facet requirements/context or v1 decision cannot authorize new work/payment.
- [x] Provision the context before policy/agreement, bind its digest and required facets in v2 agreement, and reject mismatched policy before funding admission.
- [x] Bind derived assessment in signed v2 decision, preserve independent custody/checker requirements, and deny unavailable/unsupported assessments without financial decision mutation.
- [x] Apply strict typed raw decoding and explicit structural validation to all four signed artifact families. Preserve existing valid v1 submission/dependency bytes.
- [x] Run focused admission, verification and decision substitution tests.

## Task 3: Registry, schemas and independent vectors

Files: core signed-artifact constants/registry; `spec/schemas/chio-work/`; funded Python wire checker and shared positive/malformed fixtures.

- [x] Register agreement v2, submission v1, dependency v1 and decision v2 with closed bounded schemas and existing Finding references.
- [x] Check identical shared vectors in Rust and Python, including duplicates, unknown fields/schema, null, integer/hex bounds and valid signatures with changed context.
- [x] Regenerate deterministic schema manifest and affected generated SDK inventories; run schema registration and code-generation checks.
- [x] Document bid/ask, verified-fix, purchase/reimbursement and challenge mappings without introducing parallel commerce authority.

## Task 4: Qualification and closeout

- [x] Run affected Rust suites and strict Clippy, independent parser and contract regressions, and the 43 funding/lifecycle/waiver/child scenarios on the final executable.
- [x] Obtain independent integrated review, resolve findings and rerun covering checks.
- [x] Retain source-bound evidence and exact command results, update broad roadmap with bounded completion and remaining gates.
- [x] Verify original checkout preservation, commit locally and confirm clean worktree and committed source/evidence hashes.
