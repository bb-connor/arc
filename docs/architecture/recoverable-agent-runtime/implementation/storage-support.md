# Recovery storage support

Recovery remains unreleased and unqualified. The maintained admission store
format is **42**. This is an explicit incoming-data boundary, not a declaration
that the runtime meets its acceptance requirements.

| Incoming admission format | Behavior |
|---|---|
| Fresh database | Create the supported catalog atomically. |
| Pre-recovery formats through 34 | Apply the existing guarded native migrations. Preserve original operation identities, signed bytes, events and global custody. An inadmissible native predecessor still refuses. |
| Experimental recovery formats 35 through 41 | Refuse before recovery migration. Preserve the database for offline inspection; no automatic reset, attribution or guessed migration. |
| Supported format 42 | Verify the exact catalog and native invariants before serving. |
| Unknown future format | Refuse. |

Formats 35 through 40 and the checkpoint/knowledge predecessor representations
were introduced within this unreleased PR. Repository history and the reviewed
specifications provide no release obligation for those intermediate formats.
No installation requiring them has been identified. Unknown external development
checkouts are not evidence of a supported migration contract. Their data is
retained on refusal, rather than silently adopted or erased.

The unreachable format-41 successor-ownership implementation is removed.
Original-call ownership uses the existing immutable origin claim: a different
workflow cannot consume an already claimed original. Failed or cancelled
originals gaining a safe successor remains an open requirement (C1-05); setup
replacement that requires this ownership transfer remains unavailable. A future
implementation must satisfy the complete current-format ownership contract and
its acceptance rather than revive the unsupported format.

Current checkpoint keys use separate length-framed latest and revision domains.
Every checkpoint read verifies its scope, identity and revision. Current
publication and restore records require their original actor identities.
Current knowledge codecs retain both the inline form emitted for small records
and the atom/chunk form emitted for large records. Unsupported old key and label
representations have no serving fallback. Pins use authenticated typed owners;
the old flat-pin reader and writer fixture are removed. ACL observations use
the full provider/account/resource/subject/query identity without an old shared
slot fallback.

Test-only switches that disabled current semantic annotation, status-audience,
input-label, workflow-quota or planning-allocation enforcement are removed.
Current public-interface tests exercise the actual enforcement path. Tests
whose sole purpose was constructing and adopting an unsupported intermediate
format are removed with that implementation. Same-format restart, key rotation,
exact replay, corruption refusal and custody retirement remain required.

Reference owners have one bounded bucket representation. The unused overflow
rebuild and complete cold-account adoption pipeline are removed. Installation
now initializes reference and publication accounts in one native transaction,
before its first profile can serve. Existing tenant profiles require the original
account records. Losing a profile, counter or readiness projection never permits
reinitialization: profile discovery and unused-key checks include immutable
recovery events and global commits. Multiple processes share the same tenant
account; each artifact index begins at its actual metadata commitment.

The old census temporary tables, cohort proofs, staged cold-writer receipts,
preexisting-publication leases and disconnected publication-domain census are
removed. Read-only publication catalog verification remains: reopening checks
current leases and object pointers against retained native ownership. Collection
still requires exact terminal and reference custody. This is a deletion of
unsupported state adoption, not removal of current-state integrity checks.

Artifact releases use only actor-scoped request keys. Confinement uses the
current scope-qualified textual index and full signed-token digest; the older
unscoped textual-index fallback is removed. Inline and compact checkpoint
restore decoding both require the supported format.

The Python recovery models export their selected generated identities without
aliases for intermediate generator names. The Python API baseline is pinned to
the pre-recovery revision and contains no recovery exports. Existing SDK model
contracts and their enforcement checks remain covered by that baseline.

Historical deployment roots remain necessary for same-format settlement after
key or policy rotation. They are not experimental database compatibility and
are retained. Process journal operating-mode versions also remain distinct from
admission-store format support. Existing pre-recovery Process history and
unlabeled-blob quarantine are preserved.

The [architecture review](reviews/architecture-and-deletion/README.md) records
the inspected source and removal decisions. Historical packages and their exact
original formats are available from the [history archive](history/README.md).
No historical verdict is promoted to current-source qualification.
