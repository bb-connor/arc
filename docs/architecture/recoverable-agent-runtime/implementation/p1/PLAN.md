# P1 execution plan

Phase: exact durable recovery, architecture revision 3. P0 contracts and the
phase-start source inventory are retained in `source-baseline.json`. This plan
implements the seven reviewable changes in `10-delivery-decisions.md`; completion
requires all 43 P1 requirements, native integration and retained verification.

| Task | Deliverable |
|---|---|
| P1-01 | Closed action, authorization, approval/coverage, grant v2, request-custody and admission-intent contracts; explicit version selection and cross-context/downgrade vectors |
| P1-02 | Sealed native observations and authoritative closure, including unknown effects behind denial receipts and late-admission fencing |
| P1-03 | Protected serving-authority recovery records, commands, quotas, events and immutable approval issuance under existing fences, integrity inventory and rollback anchors |
| P1-04 | Exact existing process binding extraction, stable reservations, protected envelope finalization and original nonce attachment with one logical-call charge |
| P1-05 | Scoped conjunctive owner/compartment coverage, grant v2 verification and native recovery participant/capture, with fresh basis and authority checks |
| P1-06 | One support-disclosure template, authenticated Rust-owned host driver and generated SDK protocol; audience-safe replay and current settlement authority |
| P1-07 | Full benign/refusal and fresh-process cutpoint corpus, independent external-effect counts, original operation/receipt recovery, partial settlement and no hidden resubmission |

Review every handwritten module, signed-wire boundary, schema migration and native
transaction. Resolve all discovered P0/P1 severity findings before completion.
Preserve existing request, nonce and receipt algorithms; never make a fixture pass
by bypassing native capture. Unsupported participant combinations refuse explicitly.

P0 resource ceilings remain hard limits. Review validity is capped at 15 minutes,
grant validity at 60 seconds and additionally by all initiating authority deadlines.
New workflow/command/custody intake uses durable scoped quotas with capacity retained
for settlement of existing work. No transaction or store mutex spans provider awaits.
Provider submission uses the pinned effect contract and no implicit transport retry.

Matched native p95 must be at most 220,683,049 ns (1.20 times the retained P0 p95
plus 1 ms), with zero benign errors and unchanged effect/quota semantics. Optimized
production workload qualification remains P6. Local tests, hosted checks and public
release remain distinct claims.

Retained P1 ceilings (fixed before corpus execution): 64 workflows and 4096
commands per tenant across all its process scopes, 128 workflows and 8192 commands
per authority. Intake stops at 3584 tenant commands, 7168 authority commands, 48 MiB of current protected
records and 57344 immutable events. Existing admission settlement has 64 MiB and
65536 event ceilings. Commands and closed identities are never evicted. Each
record is bounded at 256 KiB. Native transaction/disk/WAL failures retain original
identities and fail closed; a lost commit acknowledgement requires reconciliation.
