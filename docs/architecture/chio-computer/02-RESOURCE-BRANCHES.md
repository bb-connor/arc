# C2: Resource branching and publication

Status: proposed contract, revision 2. Parent: [Computer proposal](PROPOSAL.md).

## Purpose and owner

The current ResourceProvider list/read/template/completion interface does not
provide snapshot, branch, merge or transactional apply. This contract adds
qualified backend behavior through existing native admission and custody owners.
It does not add unrestricted mutation to the read interface.

The first backend owns a managed workspace snapshot and atomically published
revision pointer. It may use repository snapshot/review code as implementation
input, while preserving the existing security, artifact and store boundaries.

## Resource classes

| Class | Fork behavior |
| --- | --- |
| Branchable | Snapshot a declared consistent version and create an isolated writable branch. |
| Immutable | Retain an exact artifact/version reference under authorized access. |
| Live binding | Explicitly bind the external resource and disclose that reads/effects remain live; no rollback claim. |
| Excluded | Fail the requested profile or omit the resource only where the caller's explicit profile permits omission. |

Each binding declares supported operations, snapshot consistency, conflict unit,
version identity, isolation/enforcement profile, transfer policy, size limits,
publication/recovery owner and retention rules. Unsupported semantics are typed
refusals. A filesystem, mailbox, provider conversation and payment network do
not share a universal copy-on-write contract.

## Operation contracts

| Operation | Precondition and outcome |
| --- | --- |
| Snapshot | Current source access and size allowance; returns exact versioned manifest with labels/provenance. |
| Branch | Source snapshot and admitted branch/storage allocation; records parent and new resource identity without duplicating rights. |
| Stage | Admitted run/attempt writes private branch data within bounds; unpublished data stays inaccessible. |
| Freeze | Fence branch writers and bind one immutable proposed output revision before verification. |
| Seal | Retain immutable output, provenance and original producer references; acceptance is independently attached by the existing work owner. |
| Diff | Read the exact base/output pair through current metadata/content release checks. |
| Commit | Independently admit exact ChangeSet; compare expected base and publish through the supported owner protocol. |

The stage/freeze/seal description does not replace REC's artifact publication
states. New resource records reference the existing Reserved/Staged/MetadataCommitted/
Available or withheld/quarantined artifact disposition where applicable.
Blob storage and metadata publication are not implicitly one transaction.

## Laws

- **RES-01, isolated writes.** A candidate cannot modify the original resource
  through its branch grant. Parallel mutable participants use independent
  branches unless an explicit backend profile admits shared mutation.
- **RES-02, exact identity.** Snapshot, artifact, labels, producer operation,
  resource owner/tenant and revision are bound together. Content hash equality
  cannot substitute another work item's acceptance or provenance.
- **RES-03, bounded materialization.** Validate normalized paths, traversal,
  links, permissions, file types, expansion ratios and total bytes before
  exposure. Use the qualified host's actual filesystem enforcement. No ambient
  mounts or host-file writes follow from a namespace string.
- **RES-04, private staging.** Publish only after required metadata and custody
  records commit. Recover interrupted stages by original identity. Partial or
  unverifiable imports stay withheld or quarantined; error paths do not release
  raw bytes for debugging.
- **RES-05, current release.** Reads, chunks, diff metadata, filenames, logs and
  artifact transfer use governed release. Commit the required recipient knowledge
  transition before the first visible byte under the selected release contract.
- **RES-06, preserved knowledge.** Artifacts retain confidentiality/influence.
  Existing process observation history survives restore. Ordinary branching is
  not declassification, endorsement, or a new clean observation boundary.
- **RES-07, exact publication.** Apply compares the exact expected source revision
  and affected bindings at the authoritative commit point. A changed source is
  a conflict. There is no silent overwrite, rebase or reuse of old acceptance
  for changed output.
- **RES-08, retained uncertainty.** Unresolved effects, operation references and
  required evidence pin storage and tombstones. Deleting a candidate cannot
  release unknown monetary exposure or erase the record of an external effect.
- **RES-09, explicit atomicity.** The initial atomic guarantee is managed revision
  publication. Export to a user's live directory is separately admitted and
  journaled with dirty-file checks. Multiple resource owners require a qualified
  commit protocol or explicit per-resource outcomes.
- **RES-10, serving fences.** Stale worker/lease generations cannot write, seal,
  import or publish. Direct host enforcement must make a frozen revision
  immutable, or create an immutable copy, before verifying it.

## Remote realization

The execution profile selects one of two realizations:

1. Source-owned branch service. Remote operations bind the source resource
   authority and receiver-local execution identity through the admitted work.
2. Receiver-local execution overlay. Authorized immutable input is materialized
   at the receiver; writes remain in its confined overlay. A sealed labeled
   result is imported into the source-owned candidate under the original work
   and branch bindings.

The second profile does not transfer project ownership to the temporary remote
filesystem. The first does not promise a Chio receipt for every ordinary syscall
inside an admitted sandbox. Each profile names its actual mediation boundary.

## Confined computations

Use REC P5 for a separately admitted observation domain: verified isolation,
seed/control-channel provenance, provider context, bounded return contract and
recipient admission. Parent-influenced filenames, prompts, resource selection
and status channels are releases too. A public seed artifact or new process ID
alone cannot clean a tainted parent's chosen input. Integrity and confidentiality
have separate evidence requirements; valid JSON alone establishes neither.

Acceptance: **C2-01 through C2-07** in [ACCEPTANCE.md](ACCEPTANCE.md).
