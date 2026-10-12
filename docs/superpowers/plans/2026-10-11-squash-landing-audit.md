# Squash landing audit implementation plan

> **For agentic workers:** Use superpowers:executing-plans in Root's native thread. Claude independently reviews the design and source.

**Goal:** Accept strictly bound squash landings without relaxing qualification.

**Architecture:** Select a closed landing shape from the protected commit's
parent count. Bind a squash to the existing qualified base, source and tree;
reuse every existing authority and CI check.

**Tech stack:** Python, GitHub's supported REST contract, offline API fixtures.

**Spec:** [Squash landing audit](../specs/2026-10-11-squash-landing-audit-design.md)

## Constraints and review focus

Preserve all-attempts-success, exact PR attribution, final revalidation,
definition hashes and failure reporting. Mutable PR base, same-tree sibling
PRs, changing heads, incomplete qualification and malformed parent inventories
must never establish authority. No settings or workflow dispatch changes.

## Task 1: Qualify both commit shapes

**Files:** `scripts/audit-security-merge-qualification.py`,
`scripts/tests/trusted-ci-landing-regressions.test.py`,
`scripts/check-security-ci-contract.py` (auditor digest only),
`docs/security/committed-linux-evidence.md` (operator contract).

**Interface:** `audit_qualification` keeps its arguments and existing report
fields. `protected_parents` becomes the actual verified vector; add
`landing_method` as `merge` or `squash`. No caller gains an override parameter.

- [x] Obtain independent review of the concrete design (Claude 2026-10-11T23:48:24Z).
- [x] Add a healthy one-parent fixture with exact E commit and B-to-E ancestry;
  run it against the original shape check and retain the expected refusal.
- [x] Implement strict parent-count selection, squash identity/tree/ancestry
  checks and truthful parent/shape reporting. Preserve all other validation.
- [x] Add the specification's refusal cases using the real auditor and offline
  transport. Assert the intended refusal, not an absent fixture or API error.
- [x] Renew the auditor digest; run the complete owning audit suite and security
  contract controls, then inspect exact results.
- [x] Obtain independent source and operator-document review.
- [ ] Commit the qualified repair and publish with the API repair, separately
  from CI speed. Hosted qualification remains a separate acceptance step.
