# P4 durable knowledge operating contract

The enforced profile uses `NativeKnowledgeRuntime`, the existing fenced SQLite
serving authority and `ProcessArtifactBroker`. Artifact metadata, provenance,
release intents, checkpoint revisions, pins and lifecycle tombstones are
protected recovery records under the existing authority-wide rollback anchors.
Observation changes the actual native principal, lineage and session flow rows.
The same global history verifies their complete before/after row images on
reopen. There is no separate artifact authorization database.

## Installation and migration

The trusted host selects the recovery scope, actual native authority, producing
process context, receiving contexts, read clearances, policy, classifier key,
classifier implementation/configuration and archive signing key. It provisions
`knowledge.read`, `knowledge.write`, `knowledge.adopt` and `knowledge.admin`
capabilities independently. A digest, archive, certificate or handle alone grants
no capability. Workers receive mediated APIs, never the private blob port or a
host-selected delivery sink. Profile installation requires native flow state.

`ProcessRuntime::enable_durable_knowledge` activates process journal version 3.
The native serving authority also retains a permanent runtime enforcement
marker. Raw blob, checkpoint and storage-count routes refuse after activation;
process snapshots redact the legacy checkpoint value. An already-open raw state
reader checks the journal version on each read. Native runtime reads reject a
restored old journal and reapply the enforced version before producing a public
process snapshot. Journal downgrades are forbidden by a database trigger.

Preexisting blobs retain `legacy_quarantined=1`; activation never infers a public
label. Adoption needs a fresh adopt capability and an independently selected
exact-content classification certificate binding the original reservation,
bytes, scope, implementation and configuration. The serving owner separately
enforces the current policy and reservation generation. A successful adoption
creates a new provenance root while the legacy row remains quarantined. Adoption
does not reset knowledge in a receiving process.

Standalone legacy backups, direct SQLite access and private blob methods are
trusted operator facilities, not agent or model release APIs. Do not attach them
to the enforced worker interface. Keep both databases and their rollback anchors
under the existing host custody requirements.

## Supported backend and bounds

This phase qualifies the private Unix SQLite process journal. The journal uses
FULL synchronous commits, no-follow open, one filesystem link and private file
and parent-directory permissions. The broker rechecks the opened file's
device/inode, permissions and alias state before mediated operations. It accepts
opaque object identities, never caller-selected paths. It owns all blob writes;
a watcher has no authority. Equal bytes may share storage within one process,
with separate governed provenance and a random physical generation per stored
content lifetime. Cross-process and cross-tenant storage deduplication is absent.
A protected ownership record binds each physical runtime/process to its original
tenant scope; profile setup and every mediated mutation refuse foreign reuse.

| Resource | Ceiling or rule |
|---|---|
| Immutable artifact bytes | 1 MiB, including archive framing overhead |
| Direct dependencies | 16 per version |
| Full dependency traversal | 64 versions; overflow refuses |
| Archive versions | 16, complete ordered dependency DAG |
| Host-selected recipients | 16 |
| Checkpoint roots / model contexts / model side files | 8 each |
| Canonical contract / protected record | 64 KiB / 256 KiB |
| Restore frame | 1 MiB plus 64 KiB envelope and bounded length framing |
| Publication inventory | 512 retained versions across the authority |
| Native knowledge history / scanned pins | 4096 each |
| Combined native history | Existing 65536-event / 64 MiB bounds |
| Pure verification | Existing shared 4096-work-unit ceiling |
| Process storage and tree use | Existing process limits and bounded quotas |

No external filesystem/object-store backend, hard-link artifact transport,
caller mutation, unbounded fan-in, Merkle fan-in extension or chunked streaming
release is enabled. Those configurations refuse. This local backend does not
establish platform confinement or a separate-device Linux anchor qualification.

## Publication and reads

Publication advances through Reserved, Staged, MetadataCommitted and Available.
Stable publication identity binds every input; retry cannot replace a producer,
dependency, content, policy or reservation. Private staging and native metadata
are separate transactions with explicit fault cutpoints. Only Available versions
are readable. Exact digest, byte count and physical generation must agree before
finalization and release. Missing or corrupt content quarantines the version;
missing protected metadata fails native history verification. There is no raw
fallback or pathname substitution. Interrupted unreachable staging can be
aborted with admin authority; its original identity remains Retired permanently.

Opaque handles bind an authenticated audience and a host-selected recipient.
Metadata and errors obey the audience clearance. Ordinary errors disclose only
`durable knowledge unavailable`; dedup counts and internal content hashes have
no public query route. Classification may narrow immutable content restrictions;
influence and input identity remain retained. One-shot semantic endorsement
cannot classify an artifact. Native projection certificates additionally require
the exact completed native transformation, actual implementation/configuration,
complete certified input bytes and recomputed retained output. Withheld native
output cannot become an artifact through a raw-output fallback.

`PreparedArtifactRead` holds private zeroized staging and has no raw-byte getter,
deserialization or clone API. Before delivery the mediator verifies current
process/capability liveness, selected recipient, exact seal and dependencies.
The serving writer then commits the monotone native knowledge join and stable
release intent together and synchronizes its anchor. The sink receives bytes
only after acknowledgement. A lost acknowledgement withholds bytes; retry under
the same request, capability, handle and recipient resolves the original intent.
Delivery uncertainty pins content. Redelivery still checks fresh authority.

The native capture and knowledge join serialize through the existing writer.
Knowledge committed first refuses stale native preparation. Capture committed
first retains the original operation and budget ownership; a later dispatch
check may refuse changed knowledge. A post-capture error does not prove no
effect. No lock spans provider I/O, and no captured request is reconstructed from
newly observed state. Captured output and separately admitted artifact release
are distinct contract variants.

## Checkpoints, model contexts and transfer

Checkpoints use revision CAS, include every root and model side file, and retain
all revisions. Restore joins stronger current native knowledge before any frame
is delivered. Provider, account, conversation, cache, side-file identities and
contract digest must match the retained selected context. Rotation of any of
them refuses old restore authority. These are retained local model envelopes;
outbound provider prompts still need the independently selected native effect
contract. No live remote cache cleanup or provider reset is claimed.

Restore framing is a big-endian u32 canonical checkpoint length followed by
that checkpoint JSON, then a big-endian u32 length and exact bytes for each root
and each distinct model side file, in deterministic checkpoint order. The
checkpoint is protected native state, not a separately signed portable object.
Restore intents retain their original identity and checkpoint pins permanently.

Copy creates a provenance edge and conservatively joins all inputs. Move changes
only a logical location field. Export creates a classified artifact containing
an independently signed complete provenance manifest and all exact bytes; it
uses a selected archive sink and native release admission. The archive frame is
`CHIOAK1` plus NUL, a big-endian u32 canonical signed-manifest length, then that
manifest and ordered raw contents. Import validates signature, canonical frame,
all sizes/digests, complete DAG and every original native metadata record before
making any version available. Stable manifest mappings prevent resurrection.
This profile permits transfer only within the same process, tenant, authority
domain and retained native provenance inventory. Cross-domain/process import or
restore requires a future explicitly qualified transfer profile and refuses now.

## Retention and collection

Ephemeral unreferenced artifacts can be retired and collected. Checkpoint and
Evidence classes, all checkpoint revisions, permanent evidence pins, actual
captured/unknown native-operation pins, pending-approval pins, native producer
receipts, live derivation inputs and uncertain releases retain their versions.
The host attaches retained operation or pending-review pins through the native
validated pin APIs. Pins cannot be rebound. This bounded profile does not prune
checkpoint revisions, unpin evidence or recycle authority/tombstone identities.
Exhaustion refuses further work; operator capacity planning must account for
that conservative retention policy.

The serving writer retires availability and installs an exact sweep owner before
private byte removal. New matching publication refuses while that owner is
Sweeping; live dedup references preserve shared bytes. The private delete checks
the original physical generation, so a delayed collector cannot delete newly
published equal bytes. Finish acknowledgement must match the exact sweep seal;
an old collector cannot clear a newer barrier. Tombstones and provenance remain
after byte deletion. GC does not recall delivered copies or provide cryptographic
erasure of external provider state.

## Evidence and remaining qualification

The [verification record](verification.json) binds actual commands, results,
source/archive hashes and [13-obligation coverage](requirements-coverage.json).
The [source review](REVIEW.md) defines the exact severity scope. Failed diagnostic
attempts are retained separately from required passing local gates. The immutable
P3 package and its pre-P4 source archive remain intact.

Local native tests and portable contracts do not establish a full-workspace
green run, independent human review, clean Node installation, hosted CI, live
provider behavior, Linux confinement, Kani proof, scale/performance acceptance
or production deployment. Existing listener and distinct-device platform limits
remain recorded. P5 adds confined launch and complete parent-return mediation.
