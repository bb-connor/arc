# Recovery storage support

Recovery remains unreleased and unqualified. The maintained admission store
format is **44**. This is an explicit incoming-data boundary, not a declaration
that the runtime meets its acceptance requirements.

| Incoming admission format | Behavior |
|---|---|
| Fresh database | Create the supported catalog atomically. |
| Pre-recovery formats through 34 | Apply the existing guarded native migrations. Preserve original operation identities, signed bytes, events and global custody. An inadmissible native predecessor still refuses. |
| Experimental recovery formats 35 through 43 | Refuse before recovery migration. Preserve the database for offline inspection; no automatic reset, attribution or guessed migration. |
| Supported format 44 | Verify the exact catalog and native invariants before serving. |
| Unknown future format | Refuse. |

Formats 35 through 43 and the checkpoint/knowledge predecessor representations
were introduced within this unreleased PR. Repository history and the reviewed
specifications provide no release obligation for those intermediate formats.
No installation requiring them has been identified. Unknown external development
checkouts are not evidence of a supported migration contract. Their data is
retained on refusal, rather than silently adopted or erased.

Format 44 also binds the required artifact-release purpose and the current
per-scope influence projection keys and payloads. Earlier experimental recovery databases
are refused at open, before any path can partially serve incompatible recovery
records. No payload defaults or experimental readers are added. The imported-source
index is created atomically during new hydration. Supported pre-recovery
initializations receive it once, under the new serving owner before requests
are served. Their original signed history remains unchanged. Missing or partial
index custody in a current initialization refuses; ordinary reads never rebuild it.

Admission with a selected native output retention profile uses retained-request
schema v6, including the original full semantic commitment. Its experimental v5
reader and constructor are removed. Pre-recovery v1 through v4 remain readable;
admission without that output profile still writes v4. The nested v5 hash domain
remains part of the unchanged v6 commitment, without enabling v5 record serving.

The unreachable format-41 successor-ownership implementation is removed.
Current original-call ownership retains the immutable origin claim. The first
transfer from a cancelled, never-admitted generation creates a current-owner
head and immutable transfer binding in one transaction. Later transfers advance
that head; earlier final workflow rows and exact command replay remain retained.
Admission, capture, Process reservation or unresolved effects refuse transfer.
Setup closes an unused generation through the same cancellation and allocation
retirement writer before replacing its selection. These source repairs still
require owning execution and do not close C1-05 or setup acceptance.

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

Setup uses its process-qualified selection key and requires the explicit command
binding field. The experimental tenant-wide selection decoder is removed. An
unsupported tenant-wide marker is authenticated and refused, so removing its
reader cannot silently disable setup protection. Current tenant-required
custody and same-format setup generation checks remain enforced.

Artifact releases use only actor-scoped request keys. Confinement uses the
current scope-qualified textual index and full signed-token digest; the older
unscoped textual-index fallback is removed. Inline and compact checkpoint
restore decoding both require the supported format.

Knowledge handles retain one record per authenticated principal, exact artifact
version, full recipient context and installation generation. Reissuing that
identity adds no record or event. A changed context or generation allocates a
new identity. Checkpoint restore and archive dependency reads use freshly
authorized internal reads without allocating handles; the exported archive
still receives its own public handle. These reads retain the ordinary policy,
audience, recipient, process and exact-byte checks.

A new handle identity is admitted only if the exact artifact version's total
across all principals, recipient contexts and installation generations,
including authenticated prior handles, remains at most 3,971. This ceiling is
262,144 / 66 rounded down. An already overfull supported prior census is
preserved and admits no new alias. The canonical index must also fit 262,144 bytes, so encoding overhead can refuse a
new identity earlier. Exhaustion refuses the new alias without writing; exact
existing aliases remain reusable while their current authority remains valid.

Collection ends issuance and readability for that version while preserving its
immutable aliases and history. It does not make an old identity fresh. Each
authority and tenant shares 512 live publication slots across its processes.
An independently published version can use a returned slot only after exact
physical collection acknowledgment and reference closure. New typed writes
remain subject to physical intake headroom; settlement retains its reserved
band.

The generic knowledge-record pool counts only its explicit installation owner,
profile and runtime families plus untyped confined or fixture pin rows. Its
48 MiB payload and 57,344-event authority bounds remain. Typed Knowledge intake,
release, reference and native journal history use their owning custody and
physical admission paths and cannot exhaust that installation pool. The generic
writer refuses those typed families and unknown Knowledge namespaces. Handle
indexes bound issuance per exact version; the authenticated prior-44 census and
import baseline preserve supported retained identities before serving. These
source changes still require the owning lifecycle, scale and restart acceptance.

[Command capacity and replay lifetime](../03-recovery-protocol.md#command-capacity-and-replay-lifetime)
declares the per-workflow live-custody interval and permanent principal-stable
replay. Inspect writes nothing; same-value aliases spend physical intake only.
Retirement never makes a consumed identity fresh or discards exact retained
replies. C2-02 remains open pending its original owning acceptance.

The Python recovery models export their selected generated identities without
aliases for intermediate generator names. The Python API baseline is pinned to
the pre-recovery revision and contains no recovery exports. Existing SDK model
contracts and their enforcement checks remain covered by that baseline.

Historical deployment roots remain necessary for same-format settlement after
key or policy rotation. They are not experimental database compatibility and
are retained. Process journal operating-mode versions also remain distinct from
admission-store format support. Existing pre-recovery Process history and
unlabeled-blob quarantine are preserved.

The unimplemented originless setup-retirement API and its predecessor harnesses
are removed. Their only inputs came from experimental recovery formats or a
test-only origin-erasing writer. Supported workflow creation always records its
original-call binding. Current unused-selection retirement and historical
settlement remain required; this deletion does not establish their acceptance.

The [architecture review](reviews/architecture-and-deletion/README.md) records
the inspected source and removal decisions. Historical packages and their exact
original formats are available from the [history archive](history/README.md).
No historical verdict is promoted to current-source qualification.

### Retained native Input fate within format 44

Current Input joins use `chio.native-security-flow-join.v3` and retain the actual
Eligible or Refused fate. Refused records retain their canonical original origin,
validated against the exact original input, request, authority, before-state and
real global commit. Classified replay never re-admits Refused or Unproved input.
Supported prior Input v2 records remain Unproved with their original bytes and
digests unchanged; raw v1 joins retain their existing behavior. Caller start also
requires retained Eligible fate before confirmation, so an in-flight prior-v2
caller operation cannot start by relying on an earlier ReadyToDispatch state. This is not a
promise that older unreleased binaries can read new v3 records. Experimental
admission formats 35 through 43 remain unsupported.
