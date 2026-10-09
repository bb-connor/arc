# Final foundation qualification review (October 9)

This review records obligations discovered while qualifying the isolated
foundation composition. Source remains `3b0760cfe7c8bdd286fac137663872ab6ebc1e1d`
and the published PR remains `fd8bfdc947bbaf070b39457a9190f032a018e55a`.
The reviewed snapshot stage is `404064bb65cbf67c54ac76ec1be69359eb9adb59`.
No result here establishes hosted qualification, merge or release readiness.

The sections retain the original findings. The later disposition below binds
the observer repair to its completed local evidence; it does not replace the
failed predecessor results.

## Current proof acceptance amendment (October 9, 19:16:57Z)

The owner permits #1160 to land with **KANI-PROOF-QUAL open and unproved**.
P1 **KANI-ATTEST-DECOMP** in the swarm store owns a feasible postmerge
decomposition. No new proof campaigns are authorized for this landing.
The original mandatory-domain and guard findings below remain historical;
the guard repair still needs composition checks, while the unfinished proof is
now an explicitly accepted landing residual, never a passed obligation.

Noncollision remains the separately approved SHA-256 assumption. The concrete
attestation harness also lacks a complete real-SHA determinism, upper-half
padding and context-binding result over all 256 seeds and 32 root positions.
Neither is relabeled proved. The complete source and completion cover remain
pinned. CI reports the one named residual as OPEN/UNPROVED and excludes it from
execution and passed totals; other proof enrollment remains enforced.

**No release claim, including D8 previews under ADR-0011, may state or rely on
this unproved obligation.** Existing tests and bounded evidence retain their
recorded scope. All failed, resource-refused and interrupted runs remain
preserved in [the source-bound residual audit](../security/audits/kani-open-residual-20261009.json).
Independent review, exact protected checks and normal protected merge remain.

The domain-guard and strict runner repairs are composed at `b830fb0f8965dfd4a961cec4cfd540dee8fe9b08`.
The residual audit binds their successful local controls and runtime/strict
checks. The attestation proof remains open independently of that guard repair.

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

### Late-lineage disposition at 77d94e11dc

Producer `fe4ef22b90` is composed as `77d94e11dc`. The final tests fail six
cases on Original while five refusal controls pass. All eleven pass with the
repair; controls also detect overlapping attribution branches and loss of the
second capability chunk. The composed source passes all 216 expected affected
tests, strict owning all-target Clippy, formatting and four static gates. Seven
default ignores remain explicit. [The qualification record](../security/audits/receipt-late-lineage-qualification-20261009.json)
binds those results, source hashes and the full covered-range measurement.

Absent unsigned attribution in an archive is accepted only when its lineage row
is absent too. Present or signed mismatches still refuse. A stripped unsigned
projection becomes answer-neutral through canonical live lineage; the tests
explicitly retain that contract. The operator/export subject fallback performs
repeated archive scans per 256 matching late capabilities. This is a disclosed
performance limitation and indexing follow-up, not bounded work independent of
history. HTTP snapshot request budgets are unaffected.

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

Later diagnostics preserve the initial SMT type-converter error and a private
same-version tool attempt that exhausted Z3's 14 GiB address-space allowance
(solver exit 101). Its structured result has 2,959 successes, 136 unreachable
checks and 26 solver errors, including determinism, context binding and the
completion cover. The earlier cover-only interpretation is incorrect. The
prepared-model mismatch from that attempt remains recorded separately. A new
bounded memory retry retained the domain, assertions and source but exhausted
its 26 GiB address-space allowance too. It finished after 1,410.09 seconds with
26 solver errors and no completed proof; source, model and tool hashes stayed
stable and all owned children exited. The exact 582,631,570-byte solver input
is preserved for supported-backend diagnostics. More memory alone has not
closed the local proof or made the configuration suitable for hosted CI.

Supported CVC5 1.3.0 passed ten positive and negative component controls,
including strict completion-cover handling and solver-error refusal. Native
CVC5 formula generation from the same prepared model succeeded. Its actual
solve refused allocation after 66.65 seconds under a 14 GiB address limit.
A follow-up with a kernel-enforced 10 GiB RAM ceiling and no swap was killed
for exhausting that budget after 96.99 seconds. The service then terminated;
source and tool hashes remained stable. These are resource refusals, not proof
results. The [diagnostic audit](../security/audits/attestation-proof-resource-diagnostics-20261009.json)
preserves commands, limits, hashes and component evidence. A separate native
root-position-zero probe, retaining every key seed, timed out at 300 seconds
without a terminal assertion or cover verdict. The current scope checker
correctly refused its reduced domain. Its intermediate solver responses prove
neither the partial obligation nor the full original domain. No partition
design, tool change or weaker acceptance was enrolled.

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

### Observer disposition at dc21b41788

The test-only repair is committed as
`dc21b41788047c36016c0f532fcf92e9aff946e3`. Two deterministic Original
failures and one positive control establish the cancellation and work-budget
defects. The repaired default module passed 94 tests with five explicit
ignores; the longer seeded campaign passed without observer interrupts.
After replacing unwraps in the new fixture with fallible error handling,
all three fixture controls and strict owning Clippy passed. The intermediate
count mutant still fails at generation two, and the source was restored
byte-for-byte. Seven static checks passed, with three affected checks renewed
after the fixture correction. No baseline or limit was changed.

[The source-bound qualification record](../security/audits/receipt-snapshot-observer-qualification-20261009.json)
preserves the source manifests, command results, original failures, initial
strict-lint failure, mutant and independent immutable-commit review. That
review found no blocker. Two optional notes concern pre-existing errors during
handler removal; they remain minor follow-ups rather than changes to production
behavior in this test-only repair. Source promotion and final qualification
remain pending.

## RECOVERY-RPC-SHUTDOWN: P2, required before landing

The complete control-plane run at `0fd8aa21ff` terminated with 1,573 passes,
one failure and one ignore. The failing
`remote_recovery_rpc_transport_retains_actual_native_source` reported that a
stopped authority listener still returned a recovery page. Aborting the axum
listener task does not establish that accepted keepalive connection tasks have
stopped. The fixture must establish completed shutdown before asserting a
native transport failure.

Claude owns the isolated fixture repair. Require a genuine established-
connection Original failure, cooperative shutdown joined to completion,
unchanged typed unavailable/native transport-source assertions, the focused
recovery RPC suite and strict owning lint. Do not add sleeps, assume an unused
port, retry away failures or increase production deadlines. The original
52-minute run remains failed even after a later focused repair passes.

Its terminal review is
`/tmp/pr1160-v25-final-20261009/full-cp-0fd8/TERMINAL-REVIEW.json`; the full log
SHA-256 is `f57941525b53b6a1ae1266e308479f8877be644519ef25c55e978b1a9e149580`.

The later repair `41545ff19c` is composed as `135801e303`. Its deterministic
established-connection test failed on Original, then passed with the fixture
signaling graceful shutdown and joining the server to completion. Integration
review found no blocking defect. The composed source passes all 14 focused
RPC tests and strict control-plane all-target Clippy. The native transport
source assertions remain intact; no production timeout, retry or sleep was
introduced. The [qualification record](../security/audits/recovery-rpc-shutdown-qualification-20261009.json)
binds the source and logs. This closes the local fixture repair obligation;
final candidate qualification and protected landing remain pending.

## Capacity acceptance boundary

The same-host 150k runs passed for contended Original, final source and quieter
Original, in that order. Their elapsed times were 276.44, 271.23 and 271.89
seconds. The initial contention and reversed comparison order remain explicit;
one run per side does not establish a performance improvement or regression.

These runs exercised tail settlement, checkpoint acceptance, rotation and
initial observation. Most rows were already published as tail before signing,
so they do not measure a large unpublished checkpoint-covered staging and
reread path. A further test must pause extension, append and sign 100k entries,
then resume and demonstrate actual staging and reread, bounded holds,
authenticated page/count parity and measured resource use. Claude owns this
test-only acceptance lane. Earlier one-million and ten-million measurements
remain predecessor evidence.

The additional measurement is now terminal on `873f1367f3`, with the final
late-lineage production repair and the capacity test: one pass in 220.63 seconds.
After a 1k prefix, 100k unpublished covered receipts were staged with at most 256
leaves per hold. Root validation preceded authenticated reread and publication,
while rotation archived all 101k receipts. Admin total 101k and tenant total
50,500 match the per-call page/count/cursor results. Ten stale refusals and zero
invalid outcomes were recorded during publication. Shutdown during a second 10k
covered range completed in 14.74 ms and reached `Stopped`. Default quotas and
work limits were retained. Proc sampling and process high-water memory readings
remain distinct measurements in the audit.

Relevant receipt source bytes match `77d94e11dc` except the test-only observer
repair; separately qualified authority/custody files also differ. This accepts
the previously missing source-family staging/reread capacity observation, without
claiming an exact whole-candidate run or renewing the earlier 1M/10M campaigns.
