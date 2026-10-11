# API receipt integrity and evidence lifecycle

The user authorized AP9/AP10 and the receipt/export/retention continuation. The
outcome is durable, verifiable evidence for API-protect and truthful classification
of operator submissions, including after archival and restart.

## Boundaries

Use the existing SQLite receipt writer, immutable receipt/log projections and
kernel checkpoints. A second mutable HTTP/tool receipt database is not an evidence
authority. HTTP records are signed core projections that retain the entire signed
HTTP receipt under a reserved metadata key. Conversion verifies its input and
matching signer, binds all HTTP fields, and preserves semantic classification.
Native tool receipts enter the same log. New sidecar append rejects duplicate
IDs atomically; native sidecar redelivery recognizes canonical equality of
already-authenticated retained evidence, while new events and changed content
remain rejected.
The mediation kernel receives the shared durable sink before any request.

Operator submissions are AdvisoryEvaluation, AdvisoryOnly, Observed, Advisory and
HostExecutedUnmediated. Their HTTP compatibility verdict is Incomplete, never
Allow; the core projection has no decision. Verification accepts authentic
observations as evidence but reports authorized=false and result=observed.
Mediated profiles retain strict validation; arbitrary profile mixtures reject.

Durable API-protect and chio start require an existing private seed file loaded
through the bounded owner-only signing-custody helper before opening stores or
loading specs. Inline hex seeds remain available only for explicit ephemeral
embedding. No secret seed is copied into CLI configuration strings. Restart with
the same custody preserves the signer. Missing/unsafe custody fails startup.

The production proxy does not preload legacy history or retain unbounded receipt
vectors. Bounded test inspection mirrors may exist only in tests. Legacy mutable
HTTP/tool tables remain untouched and are never silently re-signed. Evidence
export refuses explicitly when such tables contain rows; operators retain the
old database and start a new evidence store, preserving legacy records separately.
Legacy revocations must continue to be enforced on upgrade.

## Retained history

Add bounded retained receipt queries using the existing authenticated archive
reader. Pin live and archive transactions while validating and reading. Restrict
archived reads to the authenticated watermark prefix, merge in original sequence
order, preserve pagination, tenant and other existing query filters. Before any
archive filter or count, stream the committed claims and verify exact source
membership, payload and signed filter projections. Attribution fallback uses
validated lineage in the pinned live store. Missing, replaced or corrupted archives
fail closed. No live-only success may hide missing retained evidence. Exports
include retained tool/child receipts and the original tool checkpoint inclusion
proofs over complete mixed batches, preserve scope and fail on incomplete evidence.
Independent child inclusion proofs require the EV6 package-format work.
Package signature/trust-anchor redesign (EV6) remains a separate finding.

API-protect and chio start accept explicit retention days, archive path and
interval as one configuration; absent configuration means retention disabled.
No silent 90-day policy. Validate before side effects and reject ephemeral or
invalid profiles. One owned worker rotates the shared store; checkpoints use the
stable signer. Shutdown stops maintenance and flushes the shared writer. Tests
exercise scheduled rotation, archive query/export, reopen/append, duplicate,
corruption and write failure. Other service launchers' EV5 wiring remains queued.

## Qualification

Regression-first controls through real handlers/stores, changed-owner suites,
strict workspace/all-target Clippy, format and source-contract gates. One fresh
integrated review, retain original findings and failed runs, fix Important and
Critical findings with regression evidence. Existing publication authorization
covers source commits and push; no merge, deployment or release is implied.
