# Receipt health sampling CI repair

Execute with superpowers:systematic-debugging and verification-before-completion.
Root owns integration; Claude reviews the isolated change.

Baseline: #1201 a2734def20, MSRV job 114610685186. The cached health
watermark observed timestamp was 1791783212918; live metadata was
1791783212932. All other fields matched. Workspace passed the same test.

The API promises a coherent cached sample without database-lock waits.
The test incorrectly required equality with newer live metadata. The existing
pause flag is not an acknowledgement of completion of an in-flight iteration.

1. Add a test-only parked acknowledgement, and await it in the health fixture.
2. Advance live observation metadata under the held lock to reproduce the
   incorrect assertion deterministically. Preserve that failing Original.
3. Assert equality with the cached sample, including all resource fields, and
   retain the real held-lock timeout, stopped state and contention controls.
4. Run focused health tests, strict owning Clippy and static owning contracts.
   Review the complete patch before one replacement push. Preserve the hosted
   failure; require fresh checks on the replacement. No production API change,
   skipped test, timing tolerance, authority mutation or gate waiver.

Local completion: the deterministic Original failed on the intended timestamp
mismatch. The repaired three health controls, 25 repeated held-lock controls,
strict all-target Clippy and static gates passed. Claude approved the complete
source with no P0/P1/P2 findings. Exact source and evidence are recorded in
`docs/security/audits/receipt-health-sample-20261012.json`. Replacement hosted
qualification remains required; the original hosted failure is preserved.
