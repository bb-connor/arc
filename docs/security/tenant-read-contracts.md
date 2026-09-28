# Tenant read contracts

The current SQLite census contains 85 distinct tables declaring `tenant_id`,
including admission participant projections. The earlier review's 64-table
count described an older source set. Every declaration now points to its entry
in [the machine-readable inventory](trust-boundary-inventory.json).

| Read surface | Enforcing authority |
| --- | --- |
| Receipt list and point query | Sealed `ReceiptReadContext` chosen by an authenticated adapter; exact SQL tenant predicate and signed-body tenant check. |
| Receipt reports and service provenance reads | Explicit admin service / local operator context, or the internal kernel receipt-integrity owner. HTTP point loads remain admin-only. |
| Encrypted blobs and finding payloads | Exact tenant from typed handle/reference and tenant-bound key/AEAD. IDs do not grant access. |
| Sealed decoy registry | Tenant-scoped typed lookups and keyed artifact/marker references. |
| Security state | Typed tenant keys for tenant operations. Installed scheduler, recovery, readiness and compaction owners perform explicitly inventoried global operations. |
| Durable admission and accounting | Qualified, fenced kernel admission coordinator. These store handles are trusted composition dependencies, not tenant endpoints. |
| IOU settlement | Installed settlement worker or authenticated operator/service. A receipt ID is a lookup key only. |

There is no bearer-identifier class in this inventory. The 170 statements without
a simple static tenant predicate have individual source/function/SQL fingerprints
and named principal contracts. This includes global integrity scans, schema
probes, admin reports and dynamically constructed predicates. A new unscoped
statement or changed statement requires review. The gate is lexical; it cannot
prove callers authenticated their principals or analyze arbitrary dynamic SQL.

Tenant receipt reads always exclude unattributed rows. The mutable strictness
switch and NULL-tenant compatibility fallback were removed. Administrative
reads still have explicit access to unattributed local receipts. Read contexts
cannot be deserialized from remote JSON or modified through public fields.

The point-read regression gives a tenant the exact IDs of another tenant and an
unattributed receipt, checks both are invisible, and corrupts a tenant projection
to require the specific signed-body mismatch rejection. Existing store contract
tests cover tenant-scoped security-state operations. This is not a claim of a
new exhaustive negative runtime matrix for every internal table, or an audit of
PostgreSQL tenant tables; those have separate owning surfaces.

Run `python3 scripts/check-trust-boundaries.py` and its calibration test at
`scripts/tests/check-trust-boundaries.test.py`. CI runs both.

The September 28 continuation adds exact-identifier model/SQLite tests for flow,
correlation and event scans, response plans and effects, overlay contributions,
lineage fences and scheduler claims. Every tested read first proves the tenant A
record exists, then supplies A's unchanged identifiers with tenant B's scope.
The SQLite read checks repeat after restart. The subsequent batch below maps every table to a principal family or explicit
runtime gap; full runtime closure remains open. See the [execution record](../reviews/2026-09-28-reader-accounting-recovery-execution.md).


## Runtime evidence matrix (2026-09-28)

Every one of the 85 tables now has a `runtime_family` in
[the inventory](trust-boundary-inventory.json). Families identify production entry
points, test paths and function names, and an evidence kind. The gate rejects
missing mappings and missing test references. It does not run the tests or prove
a function exercises every statement in that family.

84 tables map to existing or extended runtime families; one is explicitly
`runtime-gap`. All 38 referenced family tests have terminal passing local runs.
The colliding-transition regression also repaired the independent model's global
ID cache: replay now binds tenant, transition kind and the exact request, as the
production SQLite store already did. Tenant cases use A's exact identifiers under B's scope, pair empty
or denied results with A's positive control, and repeat durable reads after
reopen. Coverage includes encrypted blobs and reference replay, Finding payloads
and pool debits, receipts and authorization consumption, decoys and watermark
sequences, typed response effects, flow/fences, correlation/advisories, response
cursors and dispatch recovery, scheduler retries, and signed ingress plus
attested Finding batch/outbox readback.

Internal admission tables use the actual qualified coordinator and source/lease
binding contract. Tests cover foreign authority, nested tenant identity and
output/nonce/egress substitution before writes. Native declassification has
exact tenant SQL tests in a rolled-back fixture and separate qualified-store
source/authority tests; this is not a hosted adapter qualification. The IOU store
has privileged integrity and rollback evidence; it has no tenant point-read API.
Global pending-ingress scans remain recovery-coordinator operations, while signed
ingress and acknowledgements enforce their tenant binding.

The remaining table is `admission_operation_authorization_consumptions`. Its
sealed local constructor is currently test-only inside `chio-kernel`; kernel
projection type tests do not establish durable SQLite evidence. Closure needs a
production signed-terminal projection fixture, positive durable readback and
foreign principal/projection substitution rejection. The factory was not made
public or deserializable to obtain a test fixture.

Packet 10.3's exhaustive runtime item remains open for this gap. PostgreSQL
surfaces and hosted deployment acceptance remain outside this SQLite matrix.
See the [execution record](../reviews/2026-09-28-signed-reader-tenant-execution.md).
