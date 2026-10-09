# Chio Computer: versioned, runnable resource environments

Status: proposed design, revision 2, 2026-10-09. All new APIs and types are
proposed. This document assumes completion of the unified roadmap and its
constituent programs, including their post-success-test scope. It does not
claim those programs or the Computer API are implemented or qualified today.

**A Computer is a versioned, runnable resource environment.**

**The kernel enforces the relationships between computers, processes, resources,
and authority.**

## 1. The proposed README example

Shown inside an async application or a REPL supporting top-level await.
`my_project` exports pinned program descriptors. The project already has an
input, resource bindings and approved work/host/acceptance profiles. `boot`
describes a program without starting it.

```python
from chio import Computer, USD
from my_project import explore, prototype, challenge, integrate, verify

project = Computer.open("my-project")
worker = Computer.connect("build-machine")

# Branch the project's managed state and give the candidate a boot program.
candidate = await project.fork(
    boot=(explore | prototype | challenge) >> integrate >> verify,
)

# Give another computer bounded access to that branch.
grant = candidate.grant(
    to=worker,
    resources={
        "/workspace": ["read", "write"],
        "/models/default": ["invoke"],
    },
    budget=USD(5),
    expires_in="15m",
    delegable=True,
)

# The receiving computer admits the work under its own authority.
run = await worker.exec(candidate, authority=grant)
await run.join_tree()

# Apply the exact accepted changes under the original project's authority.
print(candidate.diff())
await project.apply(candidate.changes)
```

The alternative below executes the same program against the candidate namespace
bound by the grant. It is a separate example, not an additional invocation to
append to the first:

```python
run = await worker.exec(
    (explore | prototype | challenge) >> integrate >> verify,
    authority=grant,
)
await run.join_tree()
```

Both forms normalize to the same checked description when revision, input,
program, profile and authority bindings match. They use the same owning services.
Distinct calls still require distinct admission unless they explicitly recover
the same original request identity.

The parentheses matter: Python shifts bind more tightly than bitwise OR.
Operators create bounded immutable syntax and have no execution side effects.
A bundle hash establishes content identity; trust and execution permission are
separately admitted.

The synchronous `open`, `connect`, `grant`, and `diff` spelling is a local
facade convenience. The hero's project has a configured local owner.
Connection names construct handles from configured peer descriptors;
authentication and receiver admission precede remote work. Local grant issuance
must durably complete through its owner before returning, and diff reads must
perform release checks. A remote owner needs an awaited client operation;
implementations must not hide a nested event loop or return pending issuance as
an issued grant. The underlying contracts are independent of language spelling.

## 2. Five new contracts

Computer adds these contracts on the completed substrate:

| Contract | Incremental responsibility |
| --- | --- |
| [C1: Environments](01-ENVIRONMENTS.md) | Identity, ownership, namespaces, revisions, images and authorized handles |
| [C2: Resource branches](02-RESOURCE-BRANCHES.md) | Snapshot, branch, stage, seal, diff, conflict and publication |
| [C3: Programs](03-PROGRAMS.md) | Portable bundles, composition and compilation into existing work contracts |
| [C4: Execution bindings](04-EXECUTION-BINDINGS.md) | Binding an image to admitted work, receiver-local execution and result custody |
| [C5: Execution and apply](05-EXECUTION-AND-APPLY.md) | Owner observations, durable joins, exact ChangeSets and independently admitted apply |

The predecessor programs supply capabilities, work allocation, graph extension,
process execution, consumption, recovery, acceptance, release and federation.
Computer references and composes those owners.

[Roadmap crosswalk](ROADMAP-CROSSWALK.md) records inherited contracts, all eleven
kernel specifications, superseded assumptions and source precedence.
[Codebase coverage](CODEBASE-COVERAGE.md) accounts for 158 distinct crate manifests
across the inspected foundation/work/recovery heads, SDKs and adjacent surfaces.
This is a branch-union inventory and focused architecture review, not a claim
that all crates form one merged/default build or were audited line by line.

## 3. Fundamental relationships

| Relationship | Required invariant |
| --- | --- |
| Computer to owner | The logical environment has an owner/domain; its name is not a principal or credential. |
| Computer to revision | A run freezes exact state, namespace, program and profile bindings. |
| Process to computer | Receiver-local process identities execute the admitted image; OS PIDs and placement attempts are separate. |
| Grant to resource | Rights bind resolved identities and generations, not mutable friendly aliases. |
| Child to parent work | Authority narrows; count/depth/consumption remain bounded; graph growth uses existing admitted continuations. |
| Result to producer | Provenance, labels, producer operation and exact acceptance survive transfer and integration. |
| ChangeSet to project | Acceptance does not grant apply authority; current checks and expected-base comparison remain necessary. |
| Fork to history | Resource state can branch; authority, knowledge history, holds and external effects cannot be reset by a snapshot. |

A source and executor may share an authority domain, or belong to independent
organizations. In the latter case each owns its local process tree and keys.
Their work commitment connects those trees without importing a delegated
foreign capability as a new local root.

```text
Source organization                         Executor organization

Project -> candidate revision               Worker computer
source resource owner                       local work admission
source apply authority                      local process tree and host
         |                                           |
         +--- agreed work, permitted inputs ----------+
         +--- sealed results, acceptance evidence ----+
```

No source grant forces the receiver to execute. Receiver consent does not grant
source data access. Spending, release, integrity, stop and revocation checks
remain at their actual owners.

## 4. Source ownership

The completed W1 design establishes the public and service boundaries:

| Proposed placement | Computer responsibility | Existing ownership retained |
| --- | --- | --- |
| `chio-runtime::computer` | Public Computer, Execution and ChangeSet clients | WorkClient and authenticated owner transport |
| `chio-runtime-core::{computer,program}` | Bounded descriptors and pure binding/compiler checks | Work, security and recovery checked contracts |
| `chio-control-plane::computer` | Explicit branch/work/import/apply composition | WorkService, authority, recovery and release owners |
| `chio-store-sqlite` | Qualified environment/revision/coordination records | Serving fences, migrations and native operation stores |
| Resource providers and host adapters | Supported branch/materialization/enforcement profiles | Native admission, broker custody and host confinement |
| `chio-process` and existing runner | Receiver-local processes and supervised execution | Native identity, worker protocol and closure |
| SDKs and CLI | Authoring, inspection and control | Shared canonical contracts and test vectors |

A new crate requires dependency/build justification. Computer does not introduce
a new authority engine, scheduler, consumption ledger, federation protocol, or
recovery reducer. Its coordination record references original owner operations;
it cannot infer their outcomes from missing rows.

Resource code that controls admitted bytes/effects remains part of the trusted
enforcement path wherever it is packaged. Pure client syntax is untrusted input
to authoritative validation.

## 5. Scope and qualification

The initial Computer profile uses a managed workspace backend, pinned boot
bundles, immutable artifact edges and all-success joins. It supports independent
receiver ownership as an architectural requirement. Same-domain remote placement
is another deployment profile.

A candidate permits one mutating execution family, freezes a result revision,
and becomes immutable once sealed. Protected verification reads that exact
revision. Further editing requires a new branch and its applicable authority.
A run starts a fresh boot program; arbitrary live-memory migration is excluded.

Inherited platform, provider, financial and confinement scope stays explicit.
Completing a roadmap does not qualify an explicitly exploratory backend,
arbitrary model billing route, public-money rail, or unknown peer. Paid work is
optional. Dollar ceilings require the selected profile to bound the relevant
exposure before dispatch.

The incremental delivery sequence and adverse-case criteria are in
[ACCEPTANCE.md](ACCEPTANCE.md). The first complete demonstration is an accepted
patch produced across two independently operated computers, including a dynamic
helper, a lost reply, and a source apply conflict. A second application must
reuse the same contracts without custom signing, retry, verifier or ledger code.

## 6. Revision 2 decisions

| Original proposal | Adopted revision |
| --- | --- |
| New Computer runtime crate as the default home | Extend the W1 facade/core/service boundaries first. |
| Source owns the first remote process tree; independent authority deferred | Both same-domain placement and receiver-owned cross-organization execution are explicit. |
| New shared spending and recovery machinery | Bind the completed SHARE/REC owners and qualify the new composition. |
| Generic graph runner | Compile through existing work allocation, acceptance and graph-extension contracts. |
| Snapshot excludes keys and live memory | Also preserve labels, observations, consumption, replay, revocation, stop and effect obligations. |
| One run-success state | Preserve six WorkView dimensions; specify exact convenience-wait conditions. |
| Passing checks followed by apply | Bind exact acceptance, then recheck current apply authority and integrity. |
| Standalone remote launch service | Reuse work/host transports; add the missing image/resource bindings. |

Confidence is high in these ownership and semantic decisions. Exact wire layouts,
backend limits and language ergonomics require implementation design and the
named acceptance evidence; no schedule estimate is inferred from this research.

## 7. Evidence and document validation

[source-evidence.json](source-evidence.json) retains the original 39-file
inspection and the added pinned roadmap/owner/manifest corpus. Each view records
its commit, file hashes and inspection purpose. Historical snapshots remain
historical; they do not determine today's hosted qualification.

[validation.json](validation.json) records reproducible documentation checks.
With Python 3.11 or later, run
`python3 docs/architecture/chio-computer/validate.py` from the repository root
to verify the document set and source objects available in the local Git object
database. It performs no runtime qualification.

The evidence includes divergent PR heads. Implementation must use their
qualified integration, follow the unified schema ledger, and resolve actual
migration/owner conflicts. The full-completion assumption determines this
design's substrate, not the status of those branches today.
