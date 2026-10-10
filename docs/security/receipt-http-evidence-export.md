# Authenticated HTTP receipt evidence export

`POST /v1/evidence/export` uses the process-owned receipt query snapshot. It
captures the selected tool and child receipt metadata in one bounded snapshot
hold and returns the captured authenticated watermark in `snapshot`. Benign
appends can advance the serving generation while the export fetches payloads.
Invalidation or replacement of that snapshot lineage refuses the export.

Every returned receipt still verifies and must reproduce its authenticated leaf
hash. Archived subject attribution comes from the authenticated query index.
Checkpoint bytes must reproduce the walker-authenticated digest of the complete
canonical signed checkpoint. Inclusion proofs use authenticated tool and child
hashes, without loading unselected receipt payloads. The full relevant checkpoint
prefix from genesis and the existing transparency checks remain required.

Capability lineage is sampled during the export in bounded live read
transactions. It is not an immutable historical lineage snapshot.
Unsigned subject attribution must agree with the captured projection; signed
receipt attribution remains authoritative. Before any capability lineage is
bounded, decoded or refused, the stored subject of every selected capability is
compared with its captured unsigned subject inside SQLite: exact text under
binary collation, never decoded or size-checked first. Each lineage row is
compared again in the read transaction that materializes it. If a captured
unsigned subject was known, deleting its current lineage invalidates the
snapshot. Originally unknown unsigned attribution retains the existing
empty-lineage behavior. Tenant exports omit child payloads that have no tenant
join path, as in the local export.

Populated legacy mutable receipt tables, or a transport-ineligible live lineage
(including a supported legacy projection, malformed stored metadata, a cycle,
excessive depth or a missing parent), refuse only that export with a HTTP 422
and code `receipt_query_export_refused`. No partial bundle or
`Retry-After` is returned; changing the unsupported metadata requires operator
action. Unauthenticated publication enrichment has the same request-only
boundary. These refusals do not invalidate the shared authenticated snapshot or
interrupt another tenant's receipt reads. In contrast, missing or altered owned
checkpoint data, incomplete proof hashes, changed selected payloads, and a
mismatch or deletion of captured unsigned attribution invalidate that served
snapshot, even when that or another selected lineage would otherwise be refused.
SQLite busy and resource errors keep their operational status. The service must
rebuild authenticated state before serving it again.

Publication enrichment remains outside the owned receipt query projection.
A malformed mutable trust-anchor binding, missing publication metadata, or a
publication-core row that disagrees with the verified checkpoint therefore
refuses the export while leaving authenticated receipt reads available. This is
an explicit request boundary, including out-of-band corruption of that metadata;
no inconsistent publication is returned. Checkpoint bytes themselves must still
match the authenticated digest, and the next complete snapshot authentication
continues to reject corrupted immutable publication metadata.

The existing unpaginated HTTP response has these request ceilings:

- 4,096 selected tool and child receipts combined.
- 32 MiB of serialized response evidence, including transparency, snapshot
  metadata and federation policy.
- 4,096 records in the required checkpoint prefix.
- 131,072 authenticated leaves across checkpoint batches used for inclusion
  proofs.

Counts and stored byte lengths are checked before allocating selected payloads
or checkpoint metadata. Bounded source transactions end between chunks. A
request exceeding a ceiling receives HTTP 422 with
`receipt_query_work_budget_exhausted`; no partial bundle is returned and the
healthy snapshot stays available. Receipt reads and deliberate local operator
exports keep their existing boundaries. The existing export worker owns its
permit through response serialization even if the HTTP future is cancelled.

Snapshot exports return unavailable live retention diagnostics as `null` for
`liveDbSizeBytes` and `oldestLiveReceiptTimestamp`. Inferring a complete live
minimum from mutable source indexes would weaken the authenticated boundary.
Local complete exports retain these diagnostic values.

## Follow-up: anchored or paginated evidence exports

The current evidence format reconstructs checkpoint-chain commitments from
checkpoint 1. Once a recent export requires more than 4,096 prefix records,
narrowing that recent receipt query cannot reduce the required prefix. Its HTTP
error states this and directs the operator to local complete export. Supporting
arbitrarily long recent histories within a bounded HTTP response requires a
separate anchored-prefix or paginated evidence format and verifier contract.
This implementation does not claim that protocol qualification.
