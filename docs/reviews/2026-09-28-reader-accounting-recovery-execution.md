# Reader, accounting and recovery continuation

Local continuation of the sealed FROST batch on `packet/3-retention-accounting`
in `/tmp/arc-security-launch`, based on `60555a64da`. No subagents, push, merge,
workspace-wide build or operational activation. Preexisting `output/` is retained.

## Implemented boundaries

The signed-input inventory grows from 22 to 44 constrained constructors. This
batch covers authority profiles, issuance/revocation requests and peer pins,
portable passport envelopes, classifier and declassification inputs, and broker
audit, privileged-audit, provisioning, protocol and receipt readers. Native
signed input retains full-width integers. Canonical storage and IPC readers
require the exact original bytes before their existing signature, trust and
request binding checks. Broker and authority readers retain typed error sources.
Redundant canonical re-encoding is removed from the migrated broker readers;
authorization digests hash the already-proven canonical input bytes.

Private authority seed fields use zeroizing ownership and redacted Debug.
Custody writing and reading require canonical JSON with no pretty-JSON fallback.
Final review found that the shared canonical decoder's zeroizing output buffer
still left strings in its intermediate `serde_json::Value` tree. The new private
canonical encoder wipes every owned key and string value, including nested arrays
and objects. Escaping writes directly into the output instead of allocating a
second string. The custody API covers these owned buffers; it does not promise
that arbitrary custom serializers, caller-owned inputs or compiler temporaries
are erased.

`VerifiedWatermark` now has private fields and read-only getters. The proof
inventory also records the existing sealed flow, declassification, authority
exchange and audit-runner results. Ten result types are gated. The gate ignores
comments and string literals, and rejects a derived `Deserialize` as well as an
explicit implementation. `FileOwnershipProof` remains an untrusted persisted
descriptor whose HMAC and filesystem identity are rechecked before cleanup.

Both budget stores consume the shared fallible clock. In-memory operations sample
under the mutation lock; SQLite writes sample before the transaction, including
cached retries, and use fallible timestamps throughout mutation. Regression and
unavailability deny access. A failure after usage/sequence allocation rolls back
the entire SQLite transaction. Imported hold timestamps retain source event time.
Serving-owner budget handles install the shared `SystemClock`; standalone
`open_with_clock` supports external clock injection.

The scoped accounting operator gate reaches zero unchecked sites with all seven
debt entries removed and no expiry extension. Reaper counters, generated event
successors, time conversion, lease predecessors and capacity construction are
checked. Sixteen additional clamping sites become checked operations across nonce
minting, DPoP retention, migration successors, shared-evidence counts and claim-log
checkpoint continuity. Invalid nonce lifetimes fail before signing. The wider
638-site historical inventory now has 146 classifications, including 82 repaired
sites; 492 are still pending. This is not an inventory-wide arithmetic closure.

Exact-identifier tenant tests exercise the public store ports for flow snapshots,
correlation partitions and max-seen state, event scans, response plans and effects,
overlay contributions, lineage fences and scheduler claims. Tenant B receives A's
valid identifiers; each read has a positive A control. The same SQLite checks run
after reopening. This expands runtime evidence without claiming all 85 tenant
tables or privileged administrative composition paths have a complete matrix.

## Recovery and retention disposition

The plan's recovery checkbox was stale: 91 connection-recovery cases already
exist across 20 per-store modules. The owner run passes all 91. Externally anchored
stores test both sides of the durable commit/anchor boundary. Transaction-only
stores assert verified rollback, refused rollback and committed state, and have
no external-anchor phase to invent.

An isolated harness compiles the actual shared `store_connection.rs`. The original
passes `a_denied_rollback_fences_the_connection_and_hides_the_uncommitted_write`.
Replacing recovery verification with unconditional success makes that unchanged
regression fail. The production source was never mutated. Both logs and source
hashes are preserved in `recovery-mutation.json`.

A read-only refresh of [issue 1045](https://github.com/bb-connor/arc/issues/1045)
on September 28 found it still open with no comments. The original 1.6 MB MSRV job log was recovered and hashed. It records the
retention test running for over 60 seconds at 05:10:04 UTC, the concurrent
head-property test passing at 05:18:48, and job cancellation at 07:38:52. The
retention test has no terminal result or blocked stack. The historical checkout
`95ff6dc` used the property macro under `PROPTEST_CASES=256`; the current direct
24-case runner correction predates this batch.
The issue's quarantine description is stale: the current property is enabled.
The earlier passing local delayed-fsync diagnostic does not explain the old
hosted hang. No new reproduction or blocked stack was obtained, so the issue
remains open. The unchanged expensive property was not rerun for this batch.

## Focused evidence

Raw logs and diagnostic scripts are retained under
`/tmp/chio-boundary-followthrough-20260928/`.

| Boundary | Local evidence |
| --- | --- |
| SQLite accounting, checkpoint and recovery | `store-focused-2.log`: 239 pass, including all 91 per-store recovery cases. This run precedes the final canonical-buffer cleanup. |
| Budget clock faults and rollback | `clock-tests-3.log`: four pass, including failure after sequence allocation, regression, restart and cached replay denial. |
| Kernel budget and nonce behavior | `kernel-focused.log`: 30 pass. |
| Canonical bytes and custody | `canonical-tests-2.log`: 45 pass, including nested tree wiping and private duplicate-field refusal. |
| Authority readers and FROST library | `authority-reader-tests-final.log`: 19 pass; the explicit vector-generation fixture remains ignored in ordinary tests. |
| Passport and flow readers | `passport-tests.log`: 13 pass; `flow-tests.log`: 46 pass. |
| Watermark proof API | `watermark-tests-2.log`: ten pass; both compile-fail doctests pass in `watermark-docs.log`. |
| Exact tenant identifiers and restart | `tenant-tests.log`: model and SQLite cases both pass, with positive controls for each read. |
| Broker readers and retained behavior | `broker-tests-2.log`: 158 pass and three stale rejection expectations fail. `broker-ipc-final.log` passes all eight IPC cases, covering all three corrections. Together these establish 161 distinct passing owner cases. |
| Final checkpoint/report consumers | `store-continuity-tests.log`: 42 pass on the final canonical implementation. |
| Portable and downstream compilation | `portable-check.log`: core types and portable kernel pass without default features. `loopback-check.log`: the authority document consumer compiles. |
| Strict library lint | `clippy-final.log`: all ten changed owning libraries pass `-D warnings`. |
| Source gates | Trust inventory 44 constructors / 85 tables / 170 SQL contracts; nine calibrations pass. Arithmetic gate has zero unchecked operators. Clock inventory has 206 sites and no additions. File hygiene and the 1,282-assertion negative gate pass without cap/expiry relaxation. All 55 touched Rust files pass formatting; `git diff --check` passes. |

Initial compiler failures are retained: missing mutation timestamp arguments,
helper visibility, fixture imports, watermark getter call sites, a removed
canonical temporary still referenced by its digest, and a test fixture that
assumed the optional zeroize serde feature. The last fixture now owns its string
and explicitly wipes it on Drop, preserving the standalone crate's feature set.
Hygiene failures led to ordinary module extraction, not higher caps. The three
broker failures came from older generic-error expectations in the IPC corpus;
assertions now require the precise noncanonical-input variant or the specific
signature/binding rejection class. No production rejection was weakened.

## Remaining acceptance

The FROST ceremony implementation is locally complete in the preceding commit.
The broader signed-reader census, exhaustive tenant runtime matrix, 492 arithmetic
classifications and 206 remaining ambient-clock sites remain open. The clock
inventory includes fixtures as well as production adapters. Historical retention
liveness, privileged native x86_64 execution, sustained fuzz/scale campaigns,
hosted candidate qualification, review, integration and release are separate
acceptance boundaries. This batch does not claim them complete.
