# Receipt evidence lifecycle execution, October 3, 2026

Qualified source `ec6359a7d7fbcf0384dc667c50d9b51f3b4f3be4` is committed and pushed on
`packet/3-retention-accounting`, based on
`62ce6c65c3e9de306bc40d40102fe8c4a4dcf3d1`. The remote ref matched that exact source
commit after publication; the [publication record](https://github.com/bb-connor/arc/blob/ecb44791501c2aba671de2a967d2506f039ab42e/docs/reviews/artifacts/2026-10-03-receipt-evidence-lifecycle/source-publication.json)
retains the observation and qualified source-manifest hash. This documentation-only
follow-up records publication without changing qualified code.
This record owns AP9, AP10, AP11 and the API/start portion
of EV5, plus retained reads for EV6. Other EV5 launchers and EV6 package signing
remain open. Historical findings and milestone acceptance keep their own scope.

## Implemented boundaries

API-protect HTTP projections and the mediation kernel share the existing immutable
SQLite receipt writer. Conversion verifies the original HTTP signature and signer,
retains the complete signed HTTP record, and signs the content-bound core projection.
New sidecar events reject duplicate IDs atomically, including identical duplicates;
native sidecar redelivery recognizes already-authenticated retained evidence by
canonical equality, including after archival. New-event duplicates and changed
content still fail. Raw SQL mutation is rejected. Irreversible reserve/reconcile
results retain their signed recovery
evidence and explicitly report whether it was persisted.

Operator submissions are `AdvisoryEvaluation`, `AdvisoryOnly`, `Observed`, `Advisory`
and `HostExecutedUnmediated`, with HTTP `Incomplete` and no core decision. Authenticity
can verify while `authorized` remains false and the reported result is `observed`.
Mixed authority profiles, modified original fields and foreign projection signers
are rejected.

Durable API-protect and `chio start` require an existing private seed file through
the bounded owner-only custody loader before specs or stores are opened. Inline
seeds remain restricted to explicit ephemeral embedding. Production no longer
preloads receipt history or retains receipt vectors. Oversized legacy rows remain
untouched and cannot stop startup. Legacy revocations remain enforced; exports
explicitly refuse nonempty legacy receipt tables without decoding or re-signing them.

Paginated and point reads pin live and authenticated archive snapshots, limit
archived rows to the committed live watermark, preserve original sequence cursors
and enforce the authenticated tenant boundary. Native retained point reads also
reject archive-only suffix entries. Every committed archived claim must have exactly
one matching source row, identical payload and signed filter projections before a
query, count, point lookup or export can succeed. The check streams the prefix and
uses validated pinned live lineage for attribution fallback. Export uses the same
snapshot for tool and child records, lineage, retention metadata and publication
metadata. Tool proofs
reconstruct the original complete mixed claim batch and match its signed root.
Missing or corrupt retained history fails explicitly. The existing package format
still has tool inclusion proofs and signed child records; separate child inclusion
proofs and signed/externally anchored package envelopes belong to EV6.

`--receipt-retention-days`, `--receipt-archive` and
`--receipt-retention-interval-secs` are an explicit all-or-none policy on API-protect
and `chio start`. No policy means retention is disabled. Startup validates the
policy and preserves archive metadata I/O errors. One owned worker rotates the
shared store and reports persistent failures through health. Serving shutdown
stops maintenance and flushes accepted receipt/checkpoint work. The serving
lifetime also owns the reserved-hold reaper.

Operator configuration and migration are documented in the
[API-protect guide](../../crates/products/chio-api-protect/README.md).
The [design](../superpowers/specs/2026-10-03-receipt-evidence-lifecycle-design.md)
and [completed plan](../superpowers/plans/2026-10-03-receipt-evidence-lifecycle.md)
define the batch boundary.

## Qualification

Terminal commands, exact log hashes and source/binary manifests are retained in
[the command index](https://github.com/bb-connor/arc/blob/ecb44791501c2aba671de2a967d2506f039ab42e/docs/reviews/artifacts/2026-10-03-receipt-evidence-lifecycle/README.md).

| Boundary | Passing controls | Terminal command |
| --- | ---: | --- |
| API-protect complete library suite | 254 | `readiness-qualified-api-owner` |
| Shared HTTP-core complete library suite | 105 | `post-review-http-owner` |
| SQLite receipt store/query/export/lineage owners | 424 | `post-review-sqlite-owners` |
| CLI parsing and runtime configuration owners | 38 | `post-review-cli-owners` |

These are 821 owner/scoped runtime passes, not a full workspace runtime campaign.
Two explicit SQLite scale/million-receipt campaigns remain ignored. The four
owners' library/binary tests were built together with `--locked`; binary hashes
bind direct runtime commands to that build. The trust-boundary, clock, negative
assertion and Rust file-hygiene gates pass without new debt entries or raised
caps: 474 constructors, 85 tenant tables, 172 explicit SQL principal contracts,
426 clock observations, 38 clock compositions, and the unchanged 1,254 weak
assertion baseline. Formatting and strict
`cargo clippy --workspace --all-targets --locked --keep-going -- -D warnings` pass
(`readiness-qualified-clippy`). The API owner was rebuilt and rerun after both test-only repairs;
the other three owner results qualify their unchanged sources.

The first strict lint campaign failed on four integer casts; checked conversions
replace them. The next all-target campaign caught 12 direct unwraps in API test
fixtures; the repository's fixture helpers replace them without weakening assertions
or adding lint allowances. The API fixture rerun then failed one of 254 tests because
it checked steady readiness before writer initialization. All three health fixtures
now wait for the writer's flush acknowledgement before asserting steady readiness;
schema-corruption failure coverage remains intact. The rebuilt full API suite passes
254/254, and formatting passes (`readiness-qualified-format`). Those earlier failures
remain retained; neither repair changes production code.

The regression-first record preserves genuine failures for projection tampering
and omitted fields, observations reported authorized, duplicate appends, missing
durable custody, retained export omission, missing CLI policy and worker wiring,
public archived point omission, native uncommitted archive-tail disclosure, and
ignored archive metadata errors. Compile and fixture mistakes also remain failed.
The original broad SQLite campaign was interrupted after unrelated admission
deadlines under concurrency. A later combined owner wrapper exited 143 during
SQLite; its child terminal status and termination cause are unavailable. Neither
interruption is a pass. Only the completed owner results above qualify this batch.

## Review and decisions

One independent integrated review returned **With fixes**: one Important archive
projection-integrity finding, one Minor archived-redelivery finding, no Critical.
The author accepted the first and promoted the second to Important because false
persistence status violates this batch's contract. Four archive-tampering regressions
and one replay-after-rotation regression failed before the fixes and pass afterward
(`review-findings-red` / `review-findings-green`). The archive controls cover individual
tool/child deletion, valid signed payload substitution, tenant/timestamp/capability/
tool/decision/cost/subject filter drift, point reads and export. Redelivery controls
also retain strict duplicate, changed-content and missing-archive failures.

The original report, severity labels, declined boundaries and dispositions are in
[the independent review](https://github.com/bb-connor/arc/blob/ecb44791501c2aba671de2a967d2506f039ab42e/docs/reviews/artifacts/2026-10-03-receipt-evidence-lifecycle/independent-review.md).
All decisions and their costs are in the
[execution ledger](https://github.com/bb-connor/arc/blob/ecb44791501c2aba671de2a967d2506f039ab42e/docs/reviews/artifacts/2026-10-03-receipt-evidence-lifecycle/progress.md).
There is no second review and no deferred Minor after the regrade. The fresh 821-test
owner campaign passes after both fixes; two scale campaigns remain ignored.

## Limits and next work

Local Linux qualification does not establish hosted CI, native sandbox/release
qualification, deployment, operator migration, merge or full-roadmap completion.
Legacy evidence must be preserved separately when migrating to a new evidence DB.
An unavailable archive now makes retained reads unavailable; it cannot silently
shorten the evidence window. This batch does not qualify million-receipt scale.

The next coherent batch is externally verifiable evidence packages: EV6 signed
manifest envelopes and trusted signer inputs for verify/import; EV7 externally
validated anchor state; EV13 receipt/checkpoint signer binding; and EV12 strict
receipt/checkpoint signature verification. Include substitution, manifest rewrite,
omitted-record and wrong-anchor regression controls through native CLI workflows.
Remaining EV5 launchers, EV1/EV2 secret minimization/compaction, EV3/EV4 denial
receipts, certificate/SIEM defects and hosted/release gates stay open afterward.
