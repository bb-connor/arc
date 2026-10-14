# Fresh review and correction record

One fresh-context automated reviewer assessed
`230ed5418df2f1838a15457b97a335f88c774eb9..e52936f28cdd1fe5a61d9ccf7add3495b367fc21`.
The reviewer found no Critical issue or production-code regression, reproduced
two Important evidence-integrity defects and identified two narrower test/input
issues. This was an automated code/research review, not an independent operator
or human scientific review. No second review substitutes for the regression
tests below.

## Findings and one correction pass

1. **Incident accounting (Important).** The old collector counted attempts as
   incidents and checked repair only on the successful attempt. It could
   penalize a clean retry or hide repair in an earlier attempt. The corrected
   package freezes scheduled incident IDs, associates every recovery attempt
   and repair with its incident, checks coverage and counts each incident once.
   Failed attempts still contribute effort and failure counts. Earlier repairs
   disqualify unassisted recovery even when the final attempt is clean.
   Regressions cover clean retries, repaired retries, missing IDs, hidden prior
   repairs and omission from the frozen schedule.
2. **Fresh trajectory provenance (Important).** The old writer could qualify
   eight preexisting JSON files after a successful command producing none.
   A temporary mocked-command reproducer confirmed this; it does not establish
   that the actual earlier run's files were stale. The writer now archives the
   old native directory and starts an empty one before executing commands. All
   eight files must be produced afresh. The regression preserves a healthy
   record companion and rejects the stale-only run. Earlier evidence stays in
   `native-history/` and Git history.
3. **Signature control (reviewer Minor, executor Important).** The old mutation
   changed request ID, so native request-binding rejection hid whether signature
   verification ran. The new assertion initially failed with exactly that
   reason. The corrected mutation preserves all binding fields and corrupts
   only the signature; its assertion requires the cryptographic-verification
   denial. Regrading is justified because the advertised negative control is
   evidence for a signed-authority boundary, not merely test naming.
4. **Numeric handling (reviewer Minor, executor Important).** Extreme finite
   exponents could raise an uncaught decimal arithmetic exception. During
   correction an additional regression demonstrated that rounding could also
   turn a median slightly above 0.5 into a passing threshold. Inputs now have
   explicit supported precision and exponent bounds; exact rational arithmetic
   reconciles effort and decides ratio/recovery thresholds. Rounded display
   values carry exact numerators/denominators. Both regressions failed before
   correction. The demonstrated wrong endpoint justifies the higher grade.

All four findings enter the same correction pass; none is deferred as polish.
The new Python regression run initially had five failures and two errors across
23 tests, followed by a separate failing schedule-coverage test. The corrected
Python suite has 24 tests. The native signature assertion initially failed
before the signature-only mutation. Final native tests, clippy, formatting and
all source/output bindings are recorded by `verify.py` in
`results/verification.json`; that record determines terminal qualification.

`review-signature-before-assertion` records an exploratory run that passed
before the new assertion was successfully added. It is not a failing regression.
The actual failing regression is `review-signature-red`. All streams are
retained byte-for-byte, including terminal blank lines.

## Scope rulings

- Full PR #1172 mediation and authorized recovery-owner continuation remain
  open. This local profile cannot establish them; the cost is remaining native
  integration and channel-closure risk.
- Independent administration, external payment services and empirical advantage
  remain unmeasured. Mechanical intake cannot authenticate those facts; the
  cost is that no economic or independent-operation claim is accepted yet.
- Universal confinement, arbitrary exactly-once effects and untested concurrency
  or fault schedules are outside this evidence. The cost is explicit limits on
  generalizing the native result.
- Literature-wide novelty and general formal refinement remain unestablished.
  The targeted capital candidate is rejected, without claiming to have searched
  every possible mechanism. The cost is that a different contribution still
  needs its own evidence.
- Hosted qualification, whole-branch integration and publication acceptance are
  not inferred from local checks. The cost is leaving those acceptance gates open.
- The manuscript's substance was not reopened. Its preserved tree is checked;
  the cost is that this batch cannot declare that old text newly publish-ready.

The branch and worktree are retained for continuation. Historical qualification
records remain bound to their original revisions; readers auditing the old
results must use those revisions. The new record covers this continuation.
