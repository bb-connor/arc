# Durable artifacts, labels and process memory

## Object model

An artifact is an immutable content version plus authenticated provenance and release policy. A pathname, checksum, process-local cache entry or database row alone is insufficient. Reuse existing bounded process blobs where appropriate, but add authority-owned metadata and mediated read/restore APIs.

`ArtifactVersionV1` binds tenant/domain, opaque artifact/version IDs, content digest and size, media/schema type, producer process/native operation, complete bounded dependency references, confidentiality label, influence state, lineage/isolation context, classification/transform evidence, policy/contract versions, creation sequence and retention class. Version identity includes provenance identity: equal content with different origins must not accidentally share a weaker label.

The content digest is internal evidence, not a public bearer identifier. Externally visible handles are opaque, audience-scoped references. Guessing a digest must not reveal existence, labels, owner names or bytes. Deduplication may share immutable storage internally only while every reference retains its own provenance and authority. Cross-tenant deduplication must not create an existence oracle or shared deletion authority.

## Storage and publication

Initial backend: existing serving authority for protected metadata/release evidence; existing process blob store or an operator-selected immutable blob backend for bytes. The two stores are not assumed transactional together. Large filesystem/object-store support follows the same state contract and requires its own qualification.

Publication states are `Reserved`, `Staged`, `MetadataCommitted`, `Available`, `Quarantined`, `Retired`. Only `Available` is readable through normal mediated APIs. The protocol is:

1. Authorize producing operation and reserve an artifact/version plus bounded quota. Retain the intended provenance basis.
2. Stage bytes privately under an unpredictable object ID. Enforce size while streaming. Do not expose a public path or model-visible handle.
3. Seal content: finish writes, verify digest/size/schema, pin the immutable version and durability evidence. For files, use the existing confined broker's directory/handle discipline; reject unsafe traversal, symlinks, writable aliases and unsupported filesystems.
4. Commit metadata and producer/dependency evidence through the serving authority. Its transaction records the exact staged object identity and publication state. Unknown commit acknowledgement is resolved by exact readback.
5. Verify the sealed object's continued identity and finalize `Available` under authority CAS. Only then issue an audience-scoped reference.

On crash, staged bytes without metadata remain inaccessible and eventually collectable. Metadata without durable exact bytes becomes quarantined. A missing/corrupt object never falls back to reading the current pathname. Publication reconciliation uses the original version reservation and cannot invent a public label.

For filesystem publication, staging, fsync, rename and directory durability belong to an explicit backend protocol. Do not claim a database transaction atomically commits a filesystem rename. Native application writes outside the broker are unsupported for the enforced artifact profile; a post-hoc watcher cannot close the race.

## Mediated read and release

A host requests an artifact using authenticated process identity and read capability. Resolve metadata and exact object version, verify signatures/producer/dependencies as required, and prepare its flow/influence transition. Commit required observation and release evidence before any bytes, stream fragment or informative error reaches the agent/model.

The host may privately buffer/hash a bounded object before release. A large stream needs an authenticated immutable manifest with ordered chunk digests, bounded chunk count and total size; each chunk is verified before release. The session must already carry the full artifact's conservative label/influence, so chunk verification cannot retroactively narrow restrictions. Truncation or hash mismatch stops the stream and retains observations already made.

Use a private-field `PreparedArtifactRead`/classified sink abstraction. Public getters must not expose raw staged bytes before admission. A receiving process/model context is a sink even when physically local. Provider requests are egress to the configured provider tenant/account and must satisfy its contract. Encryption protects storage but does not authorize decryption or export.

A capability/ACL check is fresh at release. If the exact object/metadata changes between preparation and release, refuse or reprepare under the new version; do not silently substitute. For a read already in progress, define the profile's revocation cutpoint and chunk policy. No design can recall bytes already delivered.

### Observation and dispatch ordering

The knowledge join uses the same authority-scoped flow rows and generation/fence machinery as native input observation. It cannot commit only an artifact-release row while leaving native flow state unchanged. Join, exact recipient context and release intent are protected together; only their acknowledged commit enables the release gate. An unknown acknowledgement requires exact readback before exposing bytes. A sink is identified by a host-issued process/lineage/session/provider-context binding, not a caller-supplied session label; reusing a display name cannot replace that context.

A concurrent knowledge join invalidates stale preparation through the existing scoped egress fence. If native capture precedes the join, its exact frozen payload/recipient remain governed by the captured operation and cannot be reconstructed from newly observed context. Tests must cover both orders with shared principal, lineage and session state. Do not invent a second flow database, bypass the native generation check, or hold a global mutex across provider I/O. Where the backend cannot establish the ordering required by the profile, withhold the read rather than expose bytes first.

Release state is separate from effect state. Retain one `ReleaseIntentV1` binding artifact/version, source and admitted restrictions, recipient context, release policy, authorization and observation-transition identity. Consumed disclosure authority covers that exact release. A lost delivery acknowledgement retains uncertain delivery; it cannot create fresh disclosure authority or rerun the producing tool. Redelivery under the same release identity still checks current recipient/read authority and the declared release contract. Provider prompts and other effectful sinks use their native effect contract, rather than assuming repeated byte delivery is harmless.

Already captured output authority resumes through its existing native return protocol. A later approval for previously unknown output is a separately admitted release action with its own stable request/step identity, exact retained artifact and authority binding. It cannot be spliced into the frozen producing request. These two cases have distinct schema variants and cannot silently substitute for each other.

## Copies, derivatives and joins

Copy creates a new provenance edge retaining all input restrictions. Move changes a logical location reference, never content/provenance identity or label. Hard links and aliases are permitted only when the backend proves immutable shared content and independent governed references. Archive export carries a signed provenance manifest and classified bytes; import verifies both before assigning any readable status.

Derived artifacts join all observed inputs and model context unless an explicit authorized projection certificate justifies a narrower output. “The model summarized it” is not such a certificate. If provenance exceeds bounded fan-in, retain an authenticated Merkle dependency root plus conservative joined restrictions; dropping excess dependencies or replacing them with an empty set is forbidden. Verification of the root and required paths remains bounded and fail closed.

## Checkpoints, model state and restore

Add a labeled checkpoint envelope binding checkpoint revision, artifact references, process/runtime identity, model/provider context identity, confidentiality/influence state, lineage/isolation epoch and native evidence sequence. Its update remains compare-and-swap. The existing raw JSON checkpoint/read companion is insufficient for exporting protected state to an agent; an enforced profile must route those reads through the new mediator or disable that route for such processes.

Restoring a checkpoint restores or joins retained knowledge before reconstructing a model context. It never replaces stronger current knowledge with an older weaker snapshot. Restoring to another process requires an authorized transfer that checks capability, tenant, ancestry, isolation and provider sink. Provider caches, conversation IDs, resumed sessions and model-side files are included; an empty local transcript does not prove a clean remote context.

Unlabeled legacy blobs/checkpoints enter quarantine on activation of the enforced profile. The operator can request a separate exact-content classification/adoption operation under a declared authoritative classifier, producing a new provenance root. Adoption cannot erase restrictions in a process that already observed unknown or restricted bytes. Never infer public from a familiar path or missing label row.

## Retention, deletion and rollback

Pin versions referenced by live/uncertain operations, pending approvals, checkpoints and required receipts. Garbage collection is mark-and-sweep over authenticated references with a protected generation barrier; concurrent publication cannot be collected between staging and finalization. Grant/call tombstones outlive replay windows and every retained reference that can reintroduce the identity. Pruning old evidence must not make an old consumed authority appear new.

Deletion erases availability according to policy while preserving the minimum replay/ownership tombstone. It does not rewrite historical receipts or claim downstream recall. Cryptographic erasure is meaningful only where key ownership and provider copies are covered by the profile. Restore of a database/blob snapshot must join the existing store rollback-anchor mechanism and fail closed on inconsistent heads.

## Obligations

| ID | Normative obligation | Proposed acceptance test | Phase |
|---|---|---|---|
| ART-01 | Artifact identity MUST bind content version and provenance without treating hashes as bearer authority. | `artifacts::equal_bytes_different_provenance` | P4 |
| ART-02 | Publication MUST recover safely across every byte-store/metadata-store cutpoint. | `artifacts::publication_commit_cutpoints` | P4 |
| ART-03 | Missing or corrupt metadata/bytes MUST quarantine the version without public fallback. | `artifacts::restart_with_missing_label_or_blob` | P4 |
| ART-04 | Reads MUST commit required knowledge and validate exact bytes before model/agent release. | `artifacts::taint_commit_before_first_chunk` | P4 |
| ART-05 | Copy/move/export/import MUST preserve governed provenance across aliases and tenants. | `artifacts::copy_restore_archive_and_aliases` | P4 |
| ART-06 | Derivation MUST join all inputs unless exact scoped projection authority is verified. | `artifacts::summary_and_dependency_overflow` | P4 |
| ART-07 | Checkpoint/model restore MUST join retained knowledge and preserve provider context identity. | `memory::old_checkpoint_cannot_reset_context` | P4 |
| ART-08 | Legacy unlabeled state MUST require quarantine and explicit adoption. | `memory::legacy_state_activation` | P4 |
| ART-09 | GC and deletion MUST retain ownership/replay tombstones and live version pins. | `artifacts::gc_races_with_unknown_operation` | P4 |
| ART-10 | Existence, error, digest and deduplication channels MUST obey audience policy. | `artifacts::cross_tenant_existence_oracle` | P4 |
| ART-11 | Filesystem enforcement MUST mediate mutation rather than rely on observation after writes. | `artifacts::concurrent_writer_symlink_and_rename` | P4 |
| ART-12 | Artifact/return releases MUST join native scoped knowledge and retain release identity before delivery, including concurrent dispatch and uncertain acknowledgement. | `artifacts::join_egress_race_and_release_readback` | P4 |
