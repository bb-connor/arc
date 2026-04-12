# Phase 166: Security Audit Remediation, Gas/Latency Budgets, and Deployment Promotion - Context

**Gathered:** 2026-04-02
**Status:** Complete locally

<domain>
## Phase Boundary

Turn the shipped web3-runtime stack into a reproducible promotion candidate
with explicit readiness, gas, latency, and deployment-gate evidence.

</domain>

<decisions>
## Implementation Decisions

### Qualification Entry Point
- Add one focused `./scripts/qualify-web3-runtime.sh` entrypoint instead of
  forcing operators to reassemble the web3 lane manually from milestone notes.

### Budget Tracking
- Freeze gas thresholds from the measured local-devnet report.
- Freeze latency and drift thresholds from the shipped runtime policy defaults.

### Promotion Posture
- Keep live deployment automation explicitly out of scope; promotion stops at
  reviewed templates until a real deployment runner exists.

</decisions>

<code_context>
## Existing Code Insights

- `contracts/reports/local-devnet-qualification.json` already held measured
  gas data for the official contract family.
- `contracts/reports/ARC_WEB3_CONTRACT_SECURITY_REVIEW.md` already closed the
  contract-invariant review but not the broader runtime-readiness story.
- runtime policy defaults in `arc-link`, `arc-anchor`, and `arc-settle`
  already implied latency or drift budgets that needed an explicit public home.

</code_context>

<deferred>
## Deferred Ideas

- unattended live deployment automation
- mainnet secret management and wallet operations
- external hosted promotion from repo-local evidence alone

</deferred>
