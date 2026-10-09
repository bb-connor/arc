# Checkpoint coordination repair

Reviewed October 9, 2026. Confidence: high for the bounded source changes and
reported local controls. The selected runtime candidate remains uninstalled and
unqualified. These results do not close the outstanding runtime findings.

The checkpoint path now completes through the production Process and Store
library identities. Two independent defects were repaired: its Native writer
needed an exclusive, temporary no-spill connection profile, and its confirmation
reservation still described a v1 receipt although Process persisted v2.

The connection scope retains the actual writer lock through commits and readback,
restores the previous configuration after success, errors and unwinding, and
fences the connection if restoration fails. The confirmation calculation now
reserves the producer's existing 8,192-byte canonical receipt ceiling, including
the complete nested receipt, while retaining the original outer fields. The
consumer enforces that same ceiling. Existing caps and original reservations
are unchanged; an already underpriced original is refused.

The integration tests use genuine production providers. Their fixture resolves
the existing journal's canonical path without removing identity checks. The
fixed test-only receipt fault owns a fresh connection. Test error context retains
the original error and source chain. Separate private context refactors preserve
public signatures, validation order and borrowing. Two existing test-hook calls
now propagate installation and removal errors.

## Verification and review

| Check | Result and scope |
| --- | --- |
| Connection profile controls | 10 passed, zero failed or ignored on macOS; setup, rollback, restoration, unwind and permanent fencing. |
| Receipt envelope controls | 3 passed, zero failed or ignored; complete v2 framing, oversized refusal and immutable underpriced-original refusal. |
| Checkpoint integration | 2 passed, zero failed or ignored; one publication, unchanged exact replay, reopen stability and rollback at the actual receipt INSERT. |
| Process unit-test caller compilation | Passed after private API and test-hook changes; no unit tests executed by this compile check. |
| Independent review | Spec and quality approval for the connection scope, receipt envelope, test migration and private context cleanup; separate source approval for the two test-hook error propagations. |
| Strict Store library Clippy | Still fails in its Process dependency: 12 unused-code diagnostics and one preserved public argument-count diagnostic. Seven targeted diagnostics were removed. Downstream Store linting is incomplete. |

The fault case verifies Process rollback and absent receipt. It does not assert
the retained Native Prepared reservation. Broader capture, historical settlement,
release, Linux, live-provider, formal and hosted qualification remain open.

## Exact local records

Records below are relative to
`target/recovery-pr/current-review-followup/runtime-integration-successor-20261009/`.
Earlier failures, snapshots and reviews remain retained.

- `checkpoint-confirmation-source.json` pins 8,314 source files for the successful
  receipt and integration runs, SHA-256
  `3321342a894a0b41d180e20374bff47272653abf60909570e5f8e17dca09a87b`.
- `checkpoint-confirmation-test-support-successor.json` records only the later
  two-line test-hook correction; production sources and the integration cases
  are unchanged from that snapshot.
- `checkpoint-write-profile/scoped-verification.json` links its four source
  hashes, both reviews and ten actual controls. These controls ran before the
  later receipt repair and retain that narrower source scope.
- `receipt-envelope-controls-first.json` and
  `checkpoint-profile-integrated-fourth.json` retain the successful commands and
  exit codes. Their corresponding logs retain registered names and counts.
- `checkpoint-receipt-envelope/`, `checkpoint-integration/` and
  `process-context-cleanup/` retain preimages, changes and independent reviews.
- `process-unit-caller-compilation-second.json` and
  `strict-store-clippy-second-result.json` distinguish compilation from execution
  and preserve the outstanding lint failure.
- `enrollment-hook-results/` retains the test-only error propagation and its
  independent review.

The next foundation work is the complete capture reservation and its consuming
writer, followed by the required reference and receipt producers. The local
`capture-tail-plan.md` maps the actual transactions, budget ownership and
acceptance controls. Funding for preparation-claim renewals must be bounded, and
preparation must preserve the debt still owed by final capture. Those invariants
remain requirements, not demonstrated outcomes.
