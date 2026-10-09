# C2: Resource branching and publication

Status: proposed contract, revision 4. Parent: [Computer proposal](PROPOSAL.md).

## Purpose and owner

The current ResourceProvider list/read/template/completion interface does not
provide snapshot, branch, merge or transactional apply. This contract adds
qualified backend behavior through existing native admission and custody owners.
It does not add unrestricted mutation to the read interface.

## First backend: git-native

Computer-0 uses a git-native managed workspace:

- a snapshot is a tree object;
- a branch is a ref;
- the revision head is a ref the resource owner publishes;
- diff is a release-checked read of two exact trees.

Apply is a compare-and-swap of the project ref against the expected base, under
the resource owner's commit fence. A moved base is a conflict. Apply adopts
KSPEC-10 crossing records when they land after the success test.

The backend may reuse the worktree and patch-review code salvaged from #1164
(roadmap COMP-2). It keeps the existing security, artifact and store
boundaries. Content-addressed object identity is storage identity only. It
never substitutes for the resource, label, producer or acceptance bindings
that RES-02 requires.

The initial profile snapshots only the owner's admitted managed revision.
Dirty or untracked host files require a separate admitted import. The backend
uses private object storage and an owner-controlled ref namespace; a receiver
never receives the source's `.git` directory, unrelated objects or writable refs.
Materialization cannot execute repository hooks, filters or configuration, or
follow submodules, alternates or LFS fetches. Unsupported entries are refused
before exposure. Authorized ordinary file content still passes RES-03 bounds.
The owner durably binds the expected ref/object and Computer revision metadata
to the original publication intent before changing the ref. Recovery reconciles
that exact intent and publication; an uncertain outcome never permits a fresh
apply or an unbound head. A Git ref update alone is not the full custody journal.

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
- **RES-05, current release.** REC-P4's release contract governs every channel.
  Computer adds that diff metadata, filenames, logs and status are channels
  too.
- **RES-06, preserved knowledge.** REC-P4 label, influence and release rules
  apply in Computer-0. A branch or restore never creates a clean observation
  boundary. Later profiles additionally bind KSPEC-11's integrity admission;
  a request requiring that unavailable profile is refused, not downgraded.
  See the [profile crosswalk](ROADMAP-CROSSWALK.md#qualification-profiles).
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

1. **Receiver-local execution overlay.** This is the default between independent
   organizations, and the only realization Computer-0 allows there.
   - Authorized immutable input is materialized at the receiver.
   - Writes stay in the receiver's confined overlay.
   - A sealed, labeled result is imported into the source-owned candidate under
     the original work and branch bindings.
2. **Source-owned branch service.** Computer-0 offers this for same-domain
   placement only.
   - Remote operations bind the source resource authority and the
     receiver-local execution identity through the admitted work.
   - An independent-organization branch service would need its own qualified
     resource API, mutation/release fences and acceptance evidence. That later
     profile is not ruled out merely because the source owns the storage.

The receiver-local overlay does not transfer project ownership to the temporary
remote filesystem. Neither profile promises a Chio receipt for every ordinary
syscall inside an admitted sandbox. Each names its actual mediation boundary.

## Confined computations

Use REC P5 for a separately admitted observation domain: verified isolation,
seed/control-channel provenance, provider context, bounded return contract and
recipient admission. Parent-influenced filenames, prompts, resource selection
and status channels are releases too. A public seed artifact or new process ID
alone cannot clean a tainted parent's chosen input. Integrity and confidentiality
have separate evidence requirements; valid JSON alone establishes neither.

Acceptance: **C2-01 through C2-09** in [ACCEPTANCE.md](ACCEPTANCE.md).
