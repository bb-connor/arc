# C1: Versioned resource environments

Status: proposed contract, revision 3. Parent: [Computer proposal](PROPOSAL.md).
Assumes the completed predecessor contracts in [the crosswalk](ROADMAP-CROSSWALK.md).

## Purpose and owner

A Computer names a persistent logical resource environment. Its public handle
belongs in the runtime facade; its checked descriptions belong in runtime-core.
The environment service coordinates qualified records and existing owners. A
Computer is distinct from an organization principal, authority issuer, agent
subject, host machine, OS process, provider conversation, and SDK connection.

## Proposed records

These are conceptual fields, not new wire schemas or implemented Rust types.
Wire versions are allocated through the unified contract/schema process.

| Record | Required bindings |
| --- | --- |
| ComputerRecord | Stable ComputerId, owner/domain reference, parent revision if branched, current revision head, lifecycle generation, approved profile references |
| ComputerRevision | ComputerId, immutable revision identity, namespace digest, boot/input references, resource version vector, policy/profile basis, creation operation |
| ResourceBinding | Namespace entry, resource identity and owner, binding generation, provider/profile, supported operations, exact version or explicit live-binding mode |
| ComputerImage | Exact revision, boot bundle/expression, input/artifact references, resource binding manifest, execution/transfer requirements |
| ComputerHandle | Computer reference and authenticated client connection. Verified ingress supplies the session authority. A remote handle resolves through the receiver's partner card (COOP-2). |

Revision identity commits to canonical descriptors and their domain/version.
Equal bytes in two resources or tenants do not make their resource identities,
labels, provenance, or authorizations interchangeable. Friendly names resolve
through operator-configured catalogs/registries under current metadata access.

## Laws

- **ENV-01, reference is not authority.** Serializing a ComputerId, revision,
  image or handle reference conveys no rights. A decoded wire object cannot
  directly construct a live checked authority/session value.
- **ENV-02, immutable execution basis.** Every admitted run binds one exact
  revision, program, input and profile basis. Recovery cannot re-resolve a tag
  or current namespace head and silently change that basis.
- **ENV-03, namespace binding.** A grant resolves `/workspace` or
  `/models/default` to exact resource identities and binding generations before
  issuance. Renaming, remounting or changing a default route cannot redirect it.
- **ENV-04, independent ownership.** Running A's image on B neither changes A's
  environment owner nor makes A the issuer for B's local processes. Both owners
  retain their own keys, stores, current policies and refusal rights.
- **ENV-05, bounded manifests.** Decode limits cover graph nodes/depth, namespace
  entries, artifacts, lengths, total transfer size and verification work. Reject
  over-limit manifests before expensive fetch, decompression or signature work.
- **ENV-06, no ambient import.** The image excludes signer keys, provider secrets,
  unrestricted credentials, authority/replay/hold databases, sockets, arbitrary
  environment variables and live process memory. Private references require
  governed resolution and cannot direct arbitrary URL/path fetches.
- **ENV-07, current predicates.** The owner rules apply:
  - REC's HistoricalFact, CurrentPredicate and HeldReservation vocabulary;
  - the KSPEC-08 durable stop;
  - COOP-2 lifecycle status.

  Computer adds one rule. It never caches a current predicate in a revision or
  image record, and it never replays one from such a record.
- **ENV-08, one mutating family.** The initial candidate profile admits one
  mutating execution family through an atomic owner claim. Duplicate launch
  requests recover that claim; another launch cannot reuse it. An abandoned
  preparation is released only after owning operations establish its disposition.
- **ENV-09, no history rollback.** Restore or rebind cannot erase consumed
  resources, observation history, active stop/revocation, or external effects.
- **ENV-10, authenticated lookup.** Unknown/forbidden references have bounded
  audience-safe errors. Existence, names, revisions and diagnostics are governed
  metadata rather than a public enumeration API.

## Lifecycle

The environment owner distinguishes an open candidate, a candidate claimed by
an execution, a frozen result revision, and a sealed immutable result. Rejection,
cancellation and reconciliation needs remain inspectable dispositions; they do
not delete historical obligations. These are coordination observations, not a
replacement for native process or effect states.

The owning record retains original IDs for create/fork/claim/freeze/seal
operations. A client chooses its request identity before exchange so response
loss can be queried. A retry with different material under the same identity
is rejected. An absent facade row is not proof that another owner did no work.

Computer durability is distinct from OS process lifetime. Disconnecting a client
does not cancel execution. Relocation and explicit checkpoint recovery retain
their own qualified contracts; cloning a stopped authority store is not fork.

The record's revision head is changed only by the qualified resource/environment
owner with serving fences. Ordinary users or SDKs cannot write coordination
tables or move a head by uploading a replacement database.

## Existing substrate and new work

Reuse native org/domain/subject separation, manifests, authenticated sessions,
qualified SQLite serving ownership, current security checks and artifact custody.
New work is the environment/revision/namespace binding contract and its checked
facade. The existing work profile/catalog service resolves admitted capabilities;
Computer does not add open-web trust enrollment.

Acceptance: **C1-01 through C1-06** in [ACCEPTANCE.md](ACCEPTANCE.md).
