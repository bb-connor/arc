# Chio Computer: versioned, runnable resource environments

Status: proposed design, revision 4, 2026-10-09. All new APIs and types are
proposed. Computer-0 (section 5) is the profile for the unified roadmap's
success test. Its G4 substrate includes the closure prerequisite added by
revision 4 (section 5). Later profiles assume the roadmap's post-success-test
scope. Nothing in this document claims
that those programs, or the Computer API, are implemented or qualified today.

**A Computer is a versioned environment where authority, resources and work
live. The host supplies isolation.**

**The kernel enforces the relationships between computers, processes, resources,
and authority.**

A Computer is not a virtual machine or a sandbox. Process isolation always comes
from the host (ADR-0038: isolation denies, Chio grants). What a Computer adds
is the authority, resource, work and evidence relationships around it.

## 1. The proposed README example

Shown inside an async application, or in a REPL that supports top-level await.

- `my_project` exports pinned descriptors: `explore` and `challenge` are
  TaskLeaf contracts performed by receiver-admitted harnesses; `prototype`,
  `integrate` and `verify` are ProgramLeaf bundles. Descriptor loading follows
  C3's code-admission rules.
- The project already has an input, resource bindings and approved work, host
  and acceptance profiles.
- `boot` describes a program without starting it.

```python
from chio import Computer, USD
from my_project import explore, prototype, challenge, integrate, verify

project = Computer.open("my-project")
worker = Computer.connect("acme/build")

# Branch the project's managed state and give the candidate a boot program.
candidate = await project.fork(
    boot=explore & prototype & challenge | integrate | verify,
)

# Bound access to the branch and spending on its source-owned resources.
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

`USD(5)` bounds the source-owned resources used through this grant. The
receiver's independently billed compute and harness/model use have their own
limits. TaskLeaf authoring, such as `task("explore", contract=...)`, belongs in
the project's descriptor setup; the receiver selects a compatible admitted
harness rather than accepting a source-chosen executable for that task.

The alternative below runs the same program against the candidate namespace
that the grant binds. It is a separate example, not another call to append to
the first one:

```python
run = await worker.exec(
    explore & prototype & challenge | integrate | verify,
    authority=grant,
)
await run.join_tree()
```

**Equivalence.** Both forms normalize to the same checked description when
their revision, input, program, profile and authority bindings match. Both use
the same owning services. Distinct calls still need distinct admission, unless
they explicitly recover the same original request identity.

**Composition syntax (D23).**

- `&` composes in parallel.
- `|` composes in sequence.
- Python and Rust bind `&` more tightly than `|`, so the boot expression parses
  as `((explore & prototype & challenge) | integrate) | verify` with no
  parentheses.
- The canonical form, used by TypeScript and every language without operator
  overloading, is:

```typescript
const boot = parallel(explore, prototype, challenge).pipe(integrate).pipe(verify);
```

- Operators build bounded, immutable syntax and have no execution side effects.
- A bundle hash establishes content identity only. Trust and execution
  permission are admitted separately.

**Synchronous calls.** `open`, `connect`, `grant` and `diff` are synchronous
spellings of a local facade convenience. The hero's project has a configured
local owner.

- A connection name resolves through the receiver's partner card (COOP-2).
  Authentication and receiver admission come before any remote work.
- Local grant issuance must complete durably through its owner before it
  returns.
- Diff reads must perform release checks.
- A remote owner needs an awaited client operation. Implementations must not
  hide a nested event loop, or return a pending issuance as an issued grant.
- The underlying contracts do not depend on how any language spells them.

## 2. Five new contracts

Computer adds these contracts on the completed substrate:

| Contract | Incremental responsibility |
| --- | --- |
| [C1: Environments](01-ENVIRONMENTS.md) | Identity, ownership, namespaces, revisions, images and authorized handles |
| [C2: Resource branches](02-RESOURCE-BRANCHES.md) | Snapshot, branch, stage, seal, diff, conflict and publication; git-native first backend |
| [C3: Programs](03-PROGRAMS.md) | TaskLeaf and ProgramLeaf, composition, and compilation into existing work contracts |
| [C4: Execution bindings](04-EXECUTION-BINDINGS.md) | Binding an image to admitted work, receiver-local execution, door-charged resources and result custody |
| [C5: Execution and apply](05-EXECUTION-AND-APPLY.md) | Owner observations, durable joins, exact ChangeSets and independently admitted apply |

The predecessor programs supply:

- capabilities;
- work allocation and graph extension;
- process execution;
- consumption;
- recovery and acceptance;
- release and federation.

Computer references and composes those owners. Where an owner already defines
a rule, these contracts cite the owner's rule rather than restating it. They
state only the laws Computer adds.

**Supporting material:**

- The [roadmap crosswalk](ROADMAP-CROSSWALK.md) records inherited contracts,
  all eleven kernel specifications, superseded assumptions and source
  precedence.
- The [research appendix](research/CODEBASE-COVERAGE.md) holds the 158-crate
  coverage map and the pinned source evidence. It supports the design but does
  not gate it.

## 3. Fundamental relationships

| Relationship | Required invariant |
| --- | --- |
| Computer to owner | The logical environment has an owner/domain; its name is not a principal or credential. |
| Computer to revision | A run freezes exact state, namespace, program and profile bindings. |
| Process to computer | Receiver-local process identities execute the admitted image; OS PIDs and placement attempts are separate. |
| Grant to resource | Rights bind resolved identities and generations, not mutable friendly aliases. |
| Resource to its owner's door | A grant over a source-owned resource is enforced and charged by that resource's owner, at that owner's door. |
| Child to parent work | Authority narrows; count/depth/consumption remain bounded; graph growth uses existing admitted continuations. |
| Result to producer | Provenance, labels, producer operation and exact acceptance survive transfer and integration. |
| ChangeSet to project | Acceptance does not grant apply authority; current checks and expected-base comparison remain necessary. |
| Fork to history | Resource state can branch; authority, knowledge history, holds and external effects cannot be reset by a snapshot. |

**Two kinds of placement.** A source and an executor may share one authority
domain, or they may belong to independent organizations. In the second case:

- each organization owns its local process tree and keys;
- their work commitment connects those trees, without importing a delegated
  foreign capability as a new local root.

```text
Source organization                         Executor organization

Project -> candidate revision               Worker computer
source resource owner                       local work admission
source apply authority                      local process tree and host
source model route (door-charged)           receiver's own harnesses
         |                                           |
         +--- agreed work, permitted inputs ----------+
         +--- sealed results, acceptance evidence ----+
```

**Each check stays with its owner.**

- No source grant forces the receiver to execute.
- Receiver consent does not grant access to source data.
- Spending, release, integrity, stop and revocation checks all stay with their
  actual owners.

## 4. Source ownership

The completed W1 design sets the public and service boundaries:

| Proposed placement | Computer responsibility | Existing ownership retained |
| --- | --- | --- |
| `chio-runtime::computer` | Public Computer, Execution and ChangeSet clients | WorkClient and authenticated owner transport |
| `chio-runtime-core::{computer,program}` | Bounded descriptors and pure binding/compiler checks | Work, security and recovery checked contracts |
| `chio-control-plane::computer` | Explicit branch/work/import/apply composition | WorkService, authority, recovery and release owners |
| `chio-store-sqlite` | Qualified environment/revision/coordination records | Serving fences, migrations and native operation stores |
| Resource providers and host adapters | Supported branch/materialization/enforcement profiles | Native admission, broker custody and host confinement |
| `chio-process` and existing runner | Receiver-local processes and supervised execution | Native identity, worker protocol and closure |
| SDKs and CLI | Authoring, inspection and control | Shared canonical contracts and test vectors |

**No new crate or engine by default.**

- A new crate needs a dependency and build justification.
- Computer introduces no authority engine, scheduler, consumption ledger,
  federation protocol or recovery reducer.
- Its coordination record references the original owner operations. It cannot
  infer their outcomes from missing rows.

**Trust boundary.** Resource code that controls admitted bytes or effects stays
part of the trusted enforcement path, wherever it is packaged. Pure client
syntax is untrusted input to authoritative validation.

## 5. Computer-0: the success-test profile

Computer-0 is the profile the unified roadmap's success test runs (roadmap
decision D21). Its prerequisites are the amended roadmap's G4 substrate:

- COOP-1 to COOP-3
- WORK-W1 and W2
- REC
- SHARE-2
- KERN-1 to KERN-5, including KSPEC-04 phases 1 to 3 in KERN-3
- HOST-M2 on Linux

Revision 4 moves KSPEC-04 phase 3 into KERN-3 before G4 because C5 needs
graph/continuation and D1 issuance fences as well as process-tree closure.
Phase 3 lands against W1's qualified issuer and includes closure-state
migration/recovery and retained-capacity accounting. The remaining post-test
scope stays excluded. The [profile crosswalk](ROADMAP-CROSSWALK.md#qualification-profiles)
separates initial owner guarantees from later mechanisms and required refusals.

| Hero line | Computer-0 meaning |
| --- | --- |
| `Computer.open("my-project")` | The source's environment on the git-native backend. A snapshot is a tree object and a revision head is a ref. |
| `Computer.connect("acme/build")` | The receiver's computer, resolved through its partner card and authenticated over CT-CROSS. |
| `project.fork(boot=...)` | A snapshot plus a candidate ref. `boot` composes TaskLeafs and ProgramLeafs (roadmap decision D22). |
| `/workspace` read | A release-checked export of the immutable snapshot. |
| `/workspace` write | Writes go to the receiver's own overlay, never to the source's storage. They come back only as a sealed import into the candidate ref. |
| `/models/default` invoke | Resources are charged at their owner's door. Invocations reach the source's model route through the source's broker. The source's hold ledger enforces `USD(5)`. |
| `delegable=True` | Delegation stays inside the receiver. Its authenticated broker holds the source grant and preserves each helper's narrower local authority and context under C4. |
| `worker.exec(...)` | A co-signed, unpaid WORK-W2 agreement. Admission is owned by the receiver, which runs the work in its own HOST-M2 tree. |
| `run.join_tree()` | C5 closure through KERN-3's process fences and KSPEC-04 phase-3 graph/delegation fences, including outstanding sealed work. |
| A lost reply | Recovered by original identity through REC, with no second dispatch. |
| `diff()` and `apply()` | Apply is a compare-and-swap of the source's project ref against the expected base, under the resource owner's commit fence. A moved base returns a conflict. |
| Evidence | Exported and verified offline against the receiver's pinned partner card. |

**Excluded from Computer-0:**

- money that crosses organizations;
- multi-hop across independent keys;
- quorum, race and stream joins;
- branch backends other than git;
- the source-owned branch service between independent organizations;
- KSPEC-10 crossing records, which Computer adopts when they land.
- KSPEC-09's admission-machine refactor, KSPEC-11 integrity admission and
  KSPEC-08 phases 2 to 7. A request requiring an unavailable profile is refused.

**Always excluded:** live process migration.

## 6. Scope and qualification

**What the initial profile supports.**

- A managed workspace backend (git-native under Computer-0).
- Pinned boot bundles and task contracts.
- Immutable artifact edges.
- All-success joins.
- Independent receiver ownership, which is an architectural requirement.
- Same-domain remote placement, as another deployment profile.

**Candidate lifecycle.**

- A candidate permits one mutating execution family.
- It freezes a result revision, then becomes immutable once sealed.
- Protected verification reads that exact revision.
- Further editing requires a new branch and its applicable authority.
- A run starts a fresh boot program. Arbitrary live-memory migration is
  excluded.

**Scope does not widen by default.** Inherited platform, provider, financial
and confinement scope stays explicit. Completing a roadmap does not qualify:

- an explicitly exploratory backend;
- an arbitrary model billing route;
- a public-money rail;
- an unknown peer.

Paid work is optional, and Computer-0 is unpaid. A dollar ceiling requires the
selected profile to bound the relevant exposure before dispatch. Under
Computer-0, that means the source's own door.

**Delivery and acceptance.** [ACCEPTANCE.md](ACCEPTANCE.md) maps the
incremental delivery to the roadmap's COMP rungs and lists the adverse cases.

- The first complete demonstration is an accepted patch produced across two
  independently operated computers.
- It includes a dynamic helper, a lost reply and a source apply conflict.
- It exercises both leaf kinds.
- Application C (versioned data curation) is the required second application.
  It is COMP-5's reuse evidence and does not gate G5. It reuses the same
  contracts without custom signing, retry, verifier service or ledger code.
  Application B (confined work beside private data) remains optional stretch
  scope.

## 7. Claims under ADR-0011

Each claim names its actual mediation or observation boundary. Confinement
qualifies its declared isolation restrictions, not every effect inside it.
Claims carry the preview label until their COMP rung and gate pass.

| Claim | `boundary_class` | `planning_status` |
| --- | --- | --- |
| The receiver admits or refuses a Computer execution at its own door before any effect. | `prevent` | `ready_after_adr` (CT-WORK, CT-CROSS) |
| A grant over a source-owned resource is enforced and charged by the source's hold ledger at the source's door. | `prevent` | `ready_after_adr` (CT-COOP, ADR-0016, D21) |
| Apply publishes the exact accepted ChangeSet only while the source ref equals the expected base. | `prevent` | `ready_after_adr` (CT-WORK, D21) |
| A ProgramLeaf runs only under receiver code admission and a qualified KSPEC-07 confinement kind. | `prevent` | `ready_after_adr` (KSPEC-07, D22) |
| Harness activity outside Chio's mediation, including allowed activity inside a confined process. | `cannot_see` | `ready_after_adr` (ADR-0011, HOST-CONTRACT) |
| Harness hooks record activity after or outside the effect path. | `detect_only` | `ready_after_adr` (ADR-0011, HOST-CONTRACT) |
| The evaluator's acceptance of the exact sealed revision is recorded and exported. | `detect_only` | `ready_after_adr` (CT-WORK) |
| The source verifies the receiver's evidence offline against pinned partner keys, with no external witness. | `detect_only` | `ready_after_adr` (CT-COOP) |
| Money that crosses organizations for Computer work. | `detect_only` | `deferred` |

## 8. Revision history

**Revision 4** applies the review corrections:

- moves KSPEC-04 phase 3 into KERN-3/G4 and names initial versus later security
  and financial profiles, without weakening the join contract;
- specifies receiver-broker authority intersection, holder binding, context,
  per-owner fence semantics and original-operation recovery;
- separates effect mediation from confinement claims;
- names Application C as the required second consumer and retains Application B
  as optional stretch scope;
- corrects contract acceptance ranges and adds adverse cases for these paths;
- checks canonical published evidence deterministically and fails on missing
  published objects, with executable validator regression tests.

Follow-up corrections to revision 4 (same day):

- C3-02 uses `a & a` for the repeated parallel leaf; under D23, `a | a` is a
  sequence;
- Application C is COMP-5's reuse evidence and does not gate G5;
- at G5 each outside team qualifies in its roadmap role, so a requesting team
  need not execute a TaskLeaf;
- COMP-1 and COMP-2 are unblocked now and start on the explicit start.

**Revision 3** applies the owner's 2026-10-09 decisions (roadmap D21 to D23,
and Lane COMP in the unified roadmap):

| Revision 2 | Revision 3 |
| --- | --- |
| Assumed post-success-test scope throughout | Computer-0 needs only G4's substrate; later profiles use post-test scope |
| "A versioned, runnable resource environment" | Defined as where authority, resources and work live; the host supplies isolation |
| Leaves are pinned program bundles | TaskLeaf and ProgramLeaf, both from day one |
| `\|` parallel, `>>` sequence, parentheses required | `&` parallel, `\|` sequence, no parentheses; canonical `parallel().pipe()` |
| First backend unnamed | Git-native: tree objects, refs, compare-and-swap apply |
| Two remote realizations with no default | A receiver-local overlay plus sealed import between independent organizations; the branch service only within one domain |
| Designated consumption owner or bounded inter-owner suballocation | Select source-owner charging for Computer-0; no funding transfer between the organizations |
| Restated owner invariants | Citations to owner rules; only Computer's own laws are stated |
| Evidence and coverage in the design set | Moved to the research appendix |

**Revision 2** made these changes:

- extend the W1 boundaries instead of adding a new crate;
- make both authority profiles explicit;
- bind SHARE and REC rather than adding new machinery;
- compile through existing work contracts;
- preserve history through forks;
- keep the six WorkView dimensions;
- bind exact acceptance and then recheck apply;
- reuse the work and host transports.

Confidence is high in the ownership and semantic decisions. Exact wire layouts,
backend limits and language ergonomics require implementation design and the
named acceptance evidence. This research infers no schedule estimate.

## 9. Evidence and document validation

The [research appendix](research/source-evidence.json) retains two bodies of
evidence:

- the original 39-file inspection;
- the pinned roadmap, owner and manifest corpus.

Each view records its commit, file hashes and inspection purpose. Historical
snapshots remain historical; they do not determine today's hosted
qualification.

[validation.json](validation.json) records reproducible documentation checks.
With Python 3.11 or later, run
`python3 docs/architecture/chio-computer/validate.py` from the repository root.
It verifies the document set, operator precedence and every canonical pinned
source object. Required published objects must be fetched beforehand; missing
objects fail validation. A verified hosted equivalent replaces an unpublished
local head deterministically. Run validator regressions with
`python3 -m unittest discover -s docs/architecture/chio-computer -p 'test_validate.py'`.
These checks perform no runtime
qualification. Folding its generic checks into a repository-wide documents gate
is a follow-up, once the public-copy gate exists (roadmap OUT-2).

**Merge order.** The research evidence pins the unified roadmap amendment at
#1200's commit `e9b2660f6`. Merge #1200 with a merge commit before this PR, so
that commit stays reachable from main. Otherwise, re-pin that evidence view to
main once #1200 lands; the validator fails when a pinned published object is
missing.

The evidence includes divergent PR heads. Implementation must:

- use their qualified integration;
- follow the unified schema ledger;
- resolve actual migration and owner conflicts.
