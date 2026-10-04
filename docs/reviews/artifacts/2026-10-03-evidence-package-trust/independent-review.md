# Independent integrated review

Reviewer: fresh gpt-6-astra, high reasoning, read-only, no delegated reviewers.
Candidate: staged diff against 0a455ac2c0fb9641b96d36bb2289bcd8047c325b, pinned
by review-candidate.diff and review-source-hashes.json. Production sources matched
those hashes. Native/control-plane fixture corrections postdate the snapshot.

## Original verdict

**With fixes.** No new consequential production defect found. The two known
fixture corrections need terminal owner results; strict workspace Clippy was
pending when the review finished.

Strengths: manifest and decoded-payload commitments protect disk and structured
remote inputs; every signer is externally pinned; receipt and checkpoint keys
match; the full external anchor descriptor is checked; unpinned claims remain
preview. Unix descriptor-relative bounded readers and signed JSON HTTP ingress
preserve input rejection. CLI and product signing custody are integrated.

Critical: none found.

Important:

1. Native remote fixture at tests/evidence_export/package_trust.rs encoded
   consistencyProofs instead of the existing consistency_proofs field, preventing
   the test from reaching authentication or verification. The working correction
   and typed-request precheck address it; confirm the native rerun.
2. Control-plane package_trust.rs duplicate-field assertion expected CliError::Chio
   rather than the retained CliError::SignedJson variant. The working exact-code
   assertion addresses it; confirm the owner rerun.

Minor: none warranting action.

Observed evidence at review: core 435, kernel 76, Mercury 41, Wall units 25/native
3 passed. Control-plane 38/39 and native CLI 13/14 remained failed campaigns.
The reviewer ran no Cargo commands and changed nothing.

## Declined to judge

- Empty/incomplete certificates, assigned to the next certificate batch.
- Independent child inclusion proofs, excluded from this package format change.
- Persistent receiver trust rosters; accepted admin contract selects per-import pins.
- Online PKI/DID/transparency discovery; configured descriptor trust is the boundary.
- Upstream remote collection authenticity beyond supplied evidence and transport;
  local export custody does not constitute remote attestation.
- Windows race resistance equivalent to Unix descriptor-relative opens; no equivalent
  platform qualification was supplied or claimed.
- The separate Mercury proof-package format still derives requested anchors from
  embedded publication profiles at chio-mercury-core/src/proof_package.rs:1680,1728
  and does not retain the authenticated Chio envelope. This change pins Chio
  ingestion and emits preview profiles; it does not close downstream format trust.
- Hosted CI, merge, release and operational acceptance.

## Author disposition

Adopt both Important labels: terminal tests must reach the trust boundary. The
original failing runs precede the fixture fixes and remain archived. Terminal
reruns and final acceptance are recorded in the execution record and command
index. All declined boundaries are explicitly ruled on in progress.md; downstream
Mercury trust is added to the next queue. No second review or deferred Minor.
