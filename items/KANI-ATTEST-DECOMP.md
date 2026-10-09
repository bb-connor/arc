---
id: "KANI-ATTEST-DECOMP"
title: "Decompose the attestation-encoding non-collision Kani proof so it completes (residual from #1160)"
severity: "P1"
wave: 1
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: []
paths: ["crates/**/kani/**", "docs/security/landing-ledger.json", "docs/security/landing-ledger.md"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 16
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

#1160 landed with KANI-PROOF-QUAL recorded as an open residual (decision pr1160-kani-proof-residual, 2026-10-09). The full-domain Kani proof that the attestation encoding is non-colliding exhausted solver memory (Z3 at 26 GiB, CVC5 at 10 GiB kernel RAM) and a partial-domain probe timed out; diagnostics are in docs/security/audits/attestation-proof-resource-diagnostics-20261009.json and the #1160 final qualification review. Find a decomposition that completes within normal CI resources (for example per-field or per-length-class lemmas composed by an argument recorded in the proof notes, or a bounded domain plus a structural injectivity argument), without weakening the property.

## Acceptance

- The proof (or composed proofs) passes within the repository's Kani resource limits, and the composition argument is written down and reviewed.
- The landing ledger moves KANI-PROOF-QUAL from residual to passed, citing the run.
- A deliberately colliding encoding variant makes the proof fail (mutation control).

## Log
- 2026-10-09T19:16:55Z connor: created
- 2026-10-09T21:54:20Z connor: design input from the #1160 Claude lead: ws2 coord lane claude-pr1160-evidence/hammer/kani-attest-decomp-design.md (908 lines, sha256 prefix 8e101e5ca477cb3e, read-only, code-cited at 8f3dfac6b6; no proof run). Start from it.
