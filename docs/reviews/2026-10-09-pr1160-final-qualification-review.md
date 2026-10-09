# Final foundation qualification review (October 9)

This review records three obligations discovered while qualifying the isolated
foundation composition. Source remains `3b0760cfe7c8bdd286fac137663872ab6ebc1e1d`
and the published PR remains `fd8bfdc947bbaf070b39457a9190f032a018e55a`.
The reviewed snapshot stage is `404064bb65cbf67c54ac76ec1be69359eb9adb59`.
No result here establishes hosted qualification, merge or release readiness.

## V25-ARCHIVE-LATE-LINEAGE: P1, required before landing

Adding valid capability lineage after legacy unsigned-subject receipts have
been archived makes intact retained history fail projection verification.
The failure affects global, filtered, unrelated and live-point retained reads.
An existing snapshot can refresh attribution while a fresh build or
recertification refuses the same history. Valid capability presentation can
trigger the lineage insertion; this is a supported-history availability bug.

The repair must distinguish archived source authentication from current query
attribution. Only an unsigned subject or issuer absent from both the archived
receipt columns and archived lineage may use current canonical lineage.
Signed attribution and recorded values must still match. Query attribution
must read the already-pinned live connection in bounded chunks, with disjoint
recorded and missing-attribution branches and bounded page merging. Do not
rewrite history, introduce an unbounded capability list, acquire a new live
snapshot, or refuse healthy history solely because its cardinality grows.

Claude owns the isolated repair. Acceptance requires genuine Original failure,
mixed signed/unsigned and live/archive controls, more than one lineage chunk,
cursor/count parity, real tamper refusals, build/refresh/recertification parity,
strict owning lint and an affected-capacity disposition. The original triage
source and log are in the coordinator's `vfix/v25/c20-sequence` evidence,
with hashes `7f92355b70da4e96bc4049d9a9ee26b4d5530dc61b65f90c74c22fbe7eba30de`
and `a4e81e0290e86c48dc5acee9bb47ae63b82bfcd862ca73255b87643f0321a434`.

## KANI-DOMAIN-BINDING: P2, required before landing

The crypto scope gate previously bound the research harnesses without binding
the complete mandatory harnesses and their fixtures. Twelve mutation controls
failed on the original gate: narrower or constant input domains, removed
assertions, added assumptions or stubs, and a fixture ignoring its symbolic
seed could escape the intended scope contract.

The isolated repair pins both mandatory modules including their fixtures.
All 15 test methods and seven related regression commands pass on the recorded
source. No mandatory proof body, symbolic domain or cryptographic assumption
was changed. The source hashes and Original/repaired results are preserved in
`/tmp/pr1160-kani-scope-binding-20261009/RESULT.json`.

Whole-batch composition, applicable real-SHA proofs, strict configuration
review and exact candidate acceptance remain pending. The latest full-domain
attestation run timed out after 1,803.225 seconds without a final assertion or
completion-cover verdict. Encoder correspondence and native controls are
component evidence only. Solver-free SSA analysis is diagnostic evidence.

## V25-C20-OBSERVER-CANCELLATION: P2, required before landing

The new per-generation count observer executes while the production walker
SQL progress handler is installed. Post-commit cancellation or budget
exhaustion can interrupt the observer's own count queries. The longer seeded
campaign at the reviewed stage reported one test pass but logged four caught
SQLite `OperationInterrupted` panics in its observer. Its last mismatch check
ran before joining the walker, allowing observation failures during shutdown
to escape that assertion. That reported pass is not accepted as complete C20
qualification.

Observe successful committed state after removing the production SQL handler
and before releasing the same snapshot lock. Production work must retain its
original cancellation and work limits. Check the final observation record
after joining the walker. Deterministic cancellation and low-budget controls,
the original intermediate-count corruption control, both seeded campaigns and
strict owning lint must pass on the composition. Root owns this test-only
repair. No production limits or test seed domains may be increased or waived.

The rejected long-run log is
`/tmp/pr1160-v25-final-20261009/c20-composed-4040/snapshot-long.log`, SHA-256
`e96e65d556700d8894bd534eb1c683c30d450f112e440fd8ae80930ec5e95f07`.
The evidence driver independently rejected an interleaved test-name line and
exited 2, so its strict lint command did not run. Preserve this parser refusal
separately from the substantive observer defect.
