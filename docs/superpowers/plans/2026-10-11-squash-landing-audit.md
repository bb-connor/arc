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
- [x] Commit the qualified repair and publish with the API repair, separately
  from CI speed. Hosted qualification remains a separate acceptance step.

Publication checkpoint: source and local qualification are complete in PR #1202.
The PR is draft while #1201 establishes the next base. The cancelled `61b28ca217`
run remains cancelled acceptance evidence. Integrating the actual new main and
qualifying a fresh head are still required; implementation completion does not
mean hosted qualification or trusted-definition activation.

## Task 2: Compose the reviewed CI repair batch

Scope extension: Root and Claude agreed to include the three-file release and
nightly Drogon provisioning repair in #1202. It is independent of the auditor
logic and avoids a third PR and a known stale-base qualification round.

**Files:** `.github/workflows/release-qualification.yml`,
`.github/workflows/nightly.yml`,
`scripts/tests/check-drogon-consumer-gate.test.sh`, and the landing evidence.

- [x] Retain the genuine Original failures for both omitted callers.
- [x] Review exact source `de664c85ee`, bound to the passing full local smoke.
- [x] Test the prospective composition with #1201 and the auditor changes.
- [x] Record failed, aborted and passing campaigns separately in the ledger.
- [ ] Integrate #1201's actual main landing, then the released repair, into
  the auditor branch. Verify the final composition and update #1202's scope.
- [ ] Publish the replacement and obtain fresh exact-head hosted qualification
  and review. Preserve the four-check landing bar and separate operational
  prerequisites; do not activate trusted definitions or alter proof policy.
