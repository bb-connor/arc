# Chio Computer: executable environments and governed process graphs

Status: design proposal, 2026-10-09. All new APIs and types below are proposed.
This work inspected source and existing test definitions. It did not run the
runtime, establish current qualification, implement the API, or change the README.

The kernel enforces the relationships between computers, processes, resources,
and authority.

## 1. The proposed README example

Shown inside an async application or a REPL that supports top-level await.
`my_project` supplies the five program descriptors; these are application code,
not built-in agent roles. The project already has a task/input and resource
bindings. `boot` selects its entry program without executing it.

```python
from chio import Computer, USD
from my_project import explore, prototype, challenge, integrate, verify

project = Computer.open("my-project")
worker = Computer.connect("build-machine")

# Fork the project's managed state and give the new computer a boot program.
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

# Run the computer elsewhere. Its descendants share the grant's ceiling.
process = await worker.exec(candidate, authority=grant)
await process.join_tree()

# Apply the sealed, verified changes under the project owner's authority.
print(candidate.diff())
await project.apply(candidate.changes)
```

The direct form is an alternative execution of the same graph, not a second
execution to put after the first in the example:

```python
process = await worker.exec(
    (explore | prototype | challenge) >> integrate >> verify,
    authority=grant,
)
await process.join_tree()
```

The grant identifies the candidate namespace and permitted boot/launch policy.
The direct form binds the expression to that namespace. Both forms normalize
to the same kind of `ExecutionSpec`; a direct expression must satisfy the grant's
program restrictions, including any exact boot digest requirement.

The parenthesized parallel expression matters: Python's shift operators bind
more tightly than bitwise OR. Operators construct an immutable description and
perform no network, process, model, or filesystem effects. [E1]

`open` and `connect` can retain the accepted synchronous spelling by opening
local state or constructing handles from configured peer descriptors. Remote
authentication, compatibility negotiation and worker admission occur before
the first remote operation. A friendly name never establishes peer identity.

## 2. Assessment from the live checkout

Confidence is high that the abstraction fits the existing capability and
process direction. Confidence is moderate in the exact API and proposed module
boundaries. End-to-end implementation effort cannot be responsibly estimated
from source inspection alone, especially while the candidate runtime is under
remediation.

There are three separate source views:

| View | Local commit | Relevance |
| --- | --- | --- |
| `main` | `f5a9d2ab238448b8a85b04e9d426c507a2e09929` | Kernel, capability types, budget admission, receipts, signed task graphs, runtime admission/orchestration, federation transport. |
| `feat/process-command-experience-20260924` | `e245965435a1b912c9ae57bab81c81ba6f5391ea` | Durable processes, dependency runner, portable run plans, installed worker examples, repository snapshots and patch verification. |
| `feat/recoverable-agent-runtime-20261002` | `67cf758253944d3591174e35feefaf680bda9464` | Process lineage, authenticated child submission, joins, mailboxes, recovery, and native confinement work. Its current status document explicitly says the tree is not qualified. |

The latter two commits are not ancestors of local `main`. Their shared merge
base with `main` is `f5566d9a765c21cb36652a99c79de64968a656bf`. This is local Git
evidence, not a statement about current hosted PR checks or publication.

The inspected primary checkout contained unrelated CLI and review-tooling edits;
the recorded source files matched their pinned commits. This proposal is
published independently of those edits and of the candidate runtime branches.

### Existing ingredients and actual gaps

| Surface | What source already supplies | What the proposed API still needs |
| --- | --- | --- |
| Capability core [M1] | Concrete tool/resource grants, signed delegation, scope subset checks, time and monetary fields. | Computer/namespace bindings, program restrictions, resource-operation lowering and launch bindings. |
| Kernel [M2] | Guarded dispatch, budget admission/reconciliation, receipts and resource providers. | Admission contracts for computer creation/fork, launch, namespace mutation and applying change sets; actual resource-provider enforcement. |
| Signed graph authority [M3] | Task graph nodes/edges/joins, continuation tokens, route evidence, delegation witnesses, budget pools and revocation references. | A program compiler, executor, artifact flow and a durable bridge from graph allocations into live accounting. The verifier is not an executor. |
| Runtime facade [M4] | Admission hooks, orchestration stores, leases and evidence. | One coherent computer/run lifecycle; avoid a second scheduler/accounting system with incompatible state. |
| Process runtime [P1-P4] | Durable roots and children, parent-bound capabilities, checkpoints/blobs, bounded dynamic submissions, persistent waits and authenticated mailboxes. | Public Computer handles; richer terminal states; whole-tree closure; remote execution placement; frozen images and program graphs. |
| Process runner [C1-C3] | Dependency ordering, bounded concurrency, retries/suspensions, host-selected templates and a local Docker execution profile. | Extraction from CLI-private modules, per-run API, portable signed bundles and remote launch protocol. |
| Repository work [C5-C6] | Immutable archive segments, before/after digests, bounded workspace storage, patch export and source/key-bound review. | General native snapshot resource, independent branch overlays, conflicts, durable apply and safe source materialization. |
| Relocation [C4] | Stopped-host export/import with a retired source authority and re-anchoring at the destination. | Forking while the source remains live. Relocation must not be reused to copy authority. |
| Federation / transport [M7] | Pinned identities and authenticated lanes for existing federation protocols. | A versioned launch/control/artifact protocol. Authenticated transport alone does not grant execution rights. |
| Agent-web interop [M8] | Offline proof verification. | This is not a remote execution service or discovery runtime. |

No `Computer` API or Python program-operator implementation was located in the
searched main `crates/` and `sdks/` sources. `ComputerUseGuard` is a different
feature.

## 3. What a Computer is

A Computer is an identity and a managed execution environment. Its durable
record holds a resource namespace, a managed-state revision, a boot program,
policy references, and run history. A client handle carries a particular
view of and authority over that computer. Holding its name is not authorization.

Keep these concepts distinct:

| Concept | Meaning |
| --- | --- |
| `ComputerId` | Stable logical identity of the environment. |
| `ComputerRevision` | Version of its managed configuration/state. |
| `ComputerImage` | Frozen, portable launch description for a revision. |
| `ProgramExpr` | Immutable executable graph, independent of a particular run. |
| `ProgramBundle` | Pinned executable payload, dependencies, ABI and I/O metadata. |
| `Grant` | Authority to use named resources and launch within a bound envelope. |
| `ExecutionId` | One accepted launch; retries of that launch retain its identity. |
| `ProcessId` | Logical participant in that execution, distinct from an OS PID. |
| `Placement` | Worker computer and fenced attempt where a process executes. |
| `ChangeSet` | Immutable, revision-bound proposed managed-state changes. |

A candidate receives a new ComputerId and records its parent revision. Executing
it on a worker creates an ExecutionId and placement; it does not change the
candidate into the worker or transfer ownership of the project.

The first image format should include configuration, artifact and workspace
snapshot references, a pinned boot graph and resource binding descriptions.
It should exclude owner signing keys, provider secrets, unrestricted capability
material, ambient environment variables, raw sockets, and arbitrary live memory.

Initial `exec(candidate)` means starting a fresh run of its boot graph against a
frozen environment. It does not mean cloning live Python stacks or migrating
arbitrary OS memory. Explicit checkpoint recovery belongs to an existing run.

`fork()` and `resume()` have different identities: a fork creates new work;
resuming retains the original operation identities and effect records.

For the first profile, a candidate admits one active mutating run and seals
when that run closes. Its grant binds to that execution family on first launch;
the same launch key reconnects to it, while a different launch cannot reuse the
completed single-run authorization. Further experimentation starts from a new
fork. This keeps `candidate.diff()` and `candidate.changes` stable and prevents
two concurrent runs from competing to define the candidate's final result.

## 4. Program algebra

Suggested internal representation, abbreviated Rust design rather than current
compiling source:

```rust
enum ProgramExpr {
    Leaf(ProgramRef),
    Parallel(Vec<ProgramExpr>),
    Sequence(Vec<ProgramExpr>),
}

struct ProgramRef {
    bundle_digest: Digest,
    entrypoint: EntrypointId,
    input_schema: SchemaRef,
    output_schema: SchemaRef,
    requirements: ResourceRequirements,
}

struct ComputerImage {
    computer: ComputerId,
    revision: Revision,
    namespace: NamespaceSnapshot,
    workspace: SnapshotRef,
    boot: ProgramExpr,
    policy: PolicyRef,
}

struct ExecutionSpec {
    image: ComputerImageRef,
    program: ProgramExpr,
    input: ArtifactRef,
    authority: GrantRef,
    placement: ComputerId,
    idempotency_key: LaunchKey,
}
```

The Python operators return this language-neutral structure. Rust can use
`parallel([..]).then(..)` without copying Python's exact operator spelling.
The server revalidates and canonicalizes the graph; Python is not the authority.

The essential client implementation is small. For example, this authoring-only
sketch builds immutable syntax nodes; the actual compiler performs flattening,
schema validation and per-occurrence identity assignment later:

```python
from dataclasses import dataclass

@dataclass(frozen=True)
class Program:
    node: object

    def __or__(self, other):
        if not isinstance(other, Program):
            return NotImplemented
        return Program(Parallel((self.node, other.node)))

    def __rshift__(self, other):
        if not isinstance(other, Program):
            return NotImplemented
        return Program(Sequence((self.node, other.node)))
```

`Parallel` and `Sequence` here denote immutable AST types. This is not a local
`asyncio.gather` implementation, and creating the graph starts no work.
Transport accepts the canonical descriptor, not this Python object in memory.

The Rust execution boundary then accepts two inputs:

```rust
enum Executable {
    Computer(ComputerImageRef),
    Program(ProgramExpr),
}
```

The first form resolves the frozen image's boot graph. The second resolves the
candidate namespace from the grant, verifies the requested program against its
launch policy, and creates an equivalent execution image/spec. Both call the
same admission, persistence, scheduling and dispatch path. There should be no
separate interpreter with weaker checks for the convenience form.

`explore`, `prototype`, `challenge`, `integrate` and `verify` are program
descriptors exported by the application's package. Their implementations can
use different languages or agent frameworks. Generated descriptors should be
loadable without executing untrusted package initialization on the owner host.

Bundle code and dependencies are pinned before launch. Package references must
not resolve through mutable tags during recovery. An OCI descriptor can carry
the content identity of a supported container payload; Chio must still bind its
program ABI, entrypoint, I/O schemas and allowed resource requirements. [E2]
Do not serialize arbitrary Python closures with pickle/cloudpickle as the wire
execution contract.

### Exact operator semantics

| Expression | Proposed meaning |
| --- | --- |
| `a \| b` | Both receive the same immutable input and workspace base. Independent writable overlays and process identities. Output is a stable ordered/named product of their results. |
| `a >> b` | `b` receives the sealed output of successful `a`, after I/O compatibility and authority checks. |
| `(a \| b) >> c` | `c` receives both branch outputs after both succeed. No automatic interleaving of writable files. |
| `a \| a` | Two distinct process occurrences. A compiler must not deduplicate effectful nodes because their code hashes match. |
| Failed required node | Descendants dependent on its success do not start. Default policy requests cancellation of remaining siblings, drains admitted effects, and records terminal/incomplete outcomes. |

The accepted example has a precise interpretation:

```text
                    shared immutable input/base
                      /          |          \
                  explore    prototype    challenge
                      \          |          /
                       labeled result bundle
                                |
                            integrate
                                |
                             verify
                                |
                       sealed candidate changes
```

`challenge` runs in parallel with `prototype`, so it challenges the original
task/design assumptions. To review the actual prototype, write a different
dependency expression, for example `prototype >> challenge`. The spelling must
not imply knowledge that the graph does not supply.

`integrate` explicitly combines reports and proposed patches in a fresh overlay.
It owns conflict resolution as application work. The kernel preserves isolation
and prevents an unresolved/conflicting output from being silently applied.

Initial dataflow should use immutable artifact references and bounded typed
records. Streaming and reactive edges require separate cancellation,
backpressure and retention semantics and can follow later.

### Compilation and admission

Compilation resolves bundle digests, normalizes the expression, assigns stable
per-occurrence IDs, checks input/output schemas, expands static dependencies,
derives resource requirements, and produces a canonical plan digest.

Graph admission checks resource subsets, worker eligibility, depth/process
limits, budget backing, verifier policy and artifact sizes. It lowers eligible
nodes/joins to existing graph-authority evidence. Existing signed graphs do not
thereby become executable manifests; the new program/bundle binding is explicit.

Dynamic children can reuse the existing host-selected template mechanism.
Version one should admit only pinned child programs listed by the parent
program policy. Each submission becomes a governed operation with a retained
identity and a narrowed grant. Unbounded discovery is not required for the hero.

The static boot graph and dynamic process lineage are different structures.
Do not append nodes to an already signed graph. A dynamic expansion must have a
new immutable, parent-bound subplan or a versioned extension contract, retained
with its admission evidence. Reuse existing evidence only where its actual
schema and verifier semantics match.

## 5. What crosses from project to worker

Suggested initial protocol flow:

1. Resolve the worker's configured identity and authenticate it. Negotiate
   supported process/program ABI and containment profile; the worker separately
   decides whether to accept the code and resource request.
2. Freeze the candidate's launch revision, boot graph, input and resource
   bindings. Bind them to an owner-issued launch request and idempotency key.
3. Validate the grant against the image and worker identity. A grant is not an
   unrestricted bearer invitation; owner identity and process delegation remain
   independently bound.
4. Reserve bounded execution capacity and priced exposure. Retain a launch
   intent before any remote process is started.
5. Send the manifest and missing content-addressed data. Transfer scoped
   execution credentials through an authenticated control channel, separately
   from the image and ordinary artifacts.
6. The worker verifies content digests and its local launch policy, persists a
   fenced lease, starts confined processes, and acknowledges the same launch ID.
7. Resource operations return through owner-controlled endpoints. The owner's
   authority remains canonical for workspace revisions, model credentials,
   budgets, revocation and retained operation outcomes.
8. Seal process results and candidate changes only after required descendants
   and admitted operations have resolved. The owner validates evidence and
   performs any subsequent apply under its own authority.

The existing local worker protocol is explicitly Unix-domain-socket only [P5].
Putting it behind a TCP listener would not supply this protocol. A remote
control layer needs authenticated identity, bounded framing, replay binding,
artifact custody, lease/fence handling and compatibility negotiation.

### Recommended first ownership model

Use one project-side authority for the canonical process tree and shared
budget, with workers as remote execution placements. Keep remote process
credentials scoped to that authority. The worker has independent local
authority to start the sandbox, which cannot enlarge the project's resource
grant.

This is significant because the current `ProcessRuntime::create_root` rejects
a capability with a delegation chain [P1]. Do not make a received delegated
grant into a new root by stripping its chain, copying an issuer key, or minting
a replacement unlimited root on the worker.

For the first version, attach logical participants under the owner's existing
root and run their code remotely through an authenticated gateway. Their
process-scoped gateway endpoints can relay into the existing local worker
service. Worker claims about process identity are checked against the owner's
retained mapping and channel identity. Later independent-authority execution
needs a specific foreign-lineage admission contract.

A Computer image transfers data and code requirements; it never copies an
authority database. Existing export/import retires the old owner precisely to
avoid two live authoritative copies [C4]. It is a recovery/move mechanism, not
the implementation of `fork()`.

Pinned, operator-controlled workers are the initial trust profile. A worker
signature identifies the signer; it does not prove arbitrary computation was
correct. Broader worker trust, independent reruns or attested execution need
their own explicitly supported profiles.

## 6. Resource namespace and real isolation

`/workspace` is a friendly name that resolves to a typed resource identity,
owner, revision/binding generation, implementation and operation set. Grants
bind those resolved identities. Renaming or remounting a path must not redirect
an existing grant to a more powerful resource.

The current `ResourceProvider` is a list/read interface [M5]. It is not a
transactional filesystem or generic snapshot/commit API. Resource descriptors
need explicit support flags and operations for snapshot, branch, read/write,
diff, seal and apply. Unsupported resources reject the operation instead of
pretending to participate.

Overlay authority needs an explicit derivation rule. An existing capability
for one exact resource ID cannot simply become a capability for another ID by
calling it a child workspace. The owner records a candidate resource family
and its allowed branch operations, creates the overlays, and issues each node
an exact scoped handle through a checked projection of that family. Sibling
overlays and the parent project remain outside that node's rights. This may
require a typed scope/constraint extension and conformance tests; it must not
be implemented as an unchecked Python path rewrite or caller-selected prefix.

`fork()` should classify resources:

| Resource kind | Fork behavior |
| --- | --- |
| Managed workspace/artifact state | Share immutable blobs; create a new writable overlay and revision lineage. |
| Read-only remote resource | Preserve an explicitly permitted reference and its identity; state may remain live unless version-pinned. |
| Model endpoint | Preserve a mediated service reference; retain credentials and spending authority at the owner. |
| External mutable service | Do not clone or silently enable effects. Require explicit effect authority; completed effects are not rollbackable. |
| Budget/key/authority store | Never duplicate as spendable authority or export private signing material. |

For the initial execution profile, workers receive confined scratch and only
their own scoped service channel. Model calls go through the owner broker.
Avoid raw API keys, general outbound network and unrestricted host mounts.
The existing Docker runner is useful implementation precedent [C3], but it is
currently local and profile-specific; it does not qualify a new remote setup.

Treat an admitted workspace execution operation as an operation over one
snapshot/overlay. Ordinary filesystem syscalls within a sandbox are not
automatically individual Chio receipts. The implementation must state the
granularity it mediates and records.

## 7. Shared money, limits and revocation

`USD(5)` must resolve to one durable account/envelope shared across the grant's
descendants, resource operations and participating placements. The code already
represents USD in integer cents [M1], so this example is 500 currency units.
Provider pricing may need finer internal precision; reserve conservatively and
reconcile without repeated rounding that creates spendable value.

For a hard ceiling, admission enforces:

```text
realized spend + outstanding reserved exposure + proposed exposure <= ceiling
```

Do not simply put a $5 `max_total_cost` on every delegated token. That would
allow multiplication across sibling capability IDs. Existing aggregate-family
tests establish invocation-count behavior in their test definitions [P6]; they
are not proof of the proposed cross-host monetary account. Existing signed pool
verification validates a presented accounting state [M3]; it is not an atomic
distributed reservation service.

Version one should use a single owner-side monetary ledger/coordinator for the
grant, reusing the kernel's durable hold/reconcile machinery. Do not use
eventually merged per-worker balances for the strict README ceiling. Some
legacy budget-store paths explicitly discuss split-brain overrun bounds [M6],
so the supported strict profile needs to select the correct fenced store path.

Every paid adapter needs a pre-dispatch upper bound or enforceable quota. Unknown
outcomes retain their exposure until reconciled. If a provider cannot bound
spend, it cannot participate under a claimed hard cap. The documented ceiling
must say which metered costs it covers; unmetered infrastructure invoices do
not become bounded merely because execution happened inside Chio.

Process count, depth, calls, memory, concurrency, artifact storage and time
need independent finite ceilings. `delegable=True` permits admissible child
creation; it does not remove those limits. Existing per-attempt resource limits
are not automatically aggregate limits for an entire remote process tree [C1].

Revocation and expiry deny subsequent mediated operations and prevent new
descendants; admitted in-flight operations follow the selected cancellation
and recovery contract. Under a partition, an owner-authorized endpoint cannot
silently keep granting fresh paid/mutating work. Do not promise immediate
remote CPU termination or undo completed effects.

## 8. join_tree, failures and continuity

The current process type has Running and Cancelled states; completion and
attempt outcomes also live in the runner journal [P2, C1]. A public Process
needs a coherent terminal view across these stores.

Suggested run states are preparing, admitted, running, draining, succeeded,
failed, cancelled and needs_reconciliation. These are proposal states, not
current protocol enums.

`join_tree()` succeeds only after:

1. Required graph nodes and dynamically admitted descendants have completed.
2. An atomic tree-closure operation prevents further child admission.
3. Required result artifacts and receipts are durably recorded.
4. Outstanding effects/exposure are terminal under the selected contract.
5. Required verification has passed for the exact sealed output revision.

Completion cannot be implemented by reading a list of children once and waiting
on that list. A child can otherwise spawn another child during the race. The
tree needs a durable closing state/generation and transactional spawn checks.

The client disconnecting does not cancel the run. Reconnecting identifies the
same ExecutionId. Launch retry, child submission retry and resource invocation
retry each preserve their original idempotency bindings. Worker attempts use
lease generations so a stale worker cannot publish after reassignment.

Reuse the existing distinction between a retained completed result and an
unknown effect outcome. The process source includes tests for recovery after
worker death and unknown-effect non-redispatch [P7]. It does not justify
arbitrarily rerunning a paid model call, external write or nondeterministic
program because the client timed out.

The final receipt should commit to image/plan digests, grant and process lineage,
sealed output, verification identity/results and budget closure. Existing tool
receipts remain original evidence. A higher-level run receipt references them;
it must not rewrite them or imply that a signature proves business correctness.

## 9. Verification and apply

The `verify` stage is a pinned program and protected check bundle selected by
the owner. Its inputs are a sealed candidate revision and the expected check
digest. Upstream programs cannot replace the verifier or edit the acceptance
bundle and then claim success.

Run verification in an isolated context with read-only access to the output
being checked. The trusted runner records the executed program/check digests,
input snapshot, exit/result data and signer identity. An application's returned
`passed: true` is not sufficient acceptance evidence. The owner may require a
rerun on an independently selected host.

`candidate.changes` after successful `join_tree()` is an immutable ChangeSet,
including its expected base revision, candidate/output digest, affected
resource identities, provenance and verification references. Reading
`candidate.diff()` and applying `candidate.changes` must resolve to the same
sealed revision, not a moving head.

`project.apply(...)` checks owner authorization, base/revision consistency,
resource bounds, evidence and verification policy. It records an idempotent
apply intent and commits through a compare-and-swap on managed state. A base
conflict is explicit. It must not silently rerun the program, overwrite current
work or accept a different diff.

The first backend should commit a managed snapshot pointer atomically. Exporting
that state to an arbitrary user's live directory is a separate, explicit
materialization step requiring dirty-file checks and a recovery journal. Do not
claim a multi-file host-filesystem transaction from a sequence of file writes.

The hero's final line is explicit programmatic authorization to apply. It does
not mean printing the diff caused a human to review or approve it.

For more than one mutable resource, either define a genuine supported commit
protocol or return per-resource outcomes. A universal atomic apply across a
filesystem, email service and payment network is outside this proposal.

## 10. Proposed source ownership

Keep the existing pure verification and effect-enforcement boundaries. The
new computer manager supplies supported resource services and calls into those
boundaries. Model planning and application-specific integration remain program
code.

```text
Python / TypeScript / Rust authoring
             |
     canonical ProgramExpr
             |
     Computer manager + plan compiler
       |          |              |
  namespace   snapshots       run admission
       |          |              |
       +----------+---- process supervisor / remote host
                              |
                Chio capability, guard, budget,
                effect and receipt enforcement
                              |
              workspace / model / mailbox / artifact services
```

Suggested implementation placement:

| Area | Proposed work |
| --- | --- |
| `crates/core/chio-core-types` | Minimal stable Computer/Execution/Program/ChangeSet reference and wire-binding types where shared verification requires them. Avoid importing host or SDK behavior. |
| `crates/kernel/chio-process` on the selected integration baseline | Preserve durable process identity/admission. Extract runner supervision from CLI, add run terminal projection, whole-tree closure and remote placement. |
| New `crates/kernel/chio-computer` | Computer registry, namespaces, image/graph normalization, compiler, fork/diff/apply coordination and public Rust facade. Internal modules first; do not create a crate for every noun. |
| `chio-kernel` / `chio-kernel-core` | Necessary pure binding/authority validation and authoritative enforcement hooks. Do not move graph authoring or model planning into the kernel. |
| Existing durable store/coordinator | Add required tables and mutation protocols for computer/run metadata, launch bindings, budget family mapping and change-set commits. Reuse the authoritative accounting ledger. |
| Existing control-plane/transport seams | A versioned authenticated launch gateway and worker host adapter, with per-profile containment and lease custody. |
| Python and TypeScript SDKs | Thin immutable graph authoring and Computer/Process/Grant handles. No independent SDK ledger, scheduler or security policy. |
| CLI | A shell over the shared runtime APIs. Extract existing useful runner code rather than leaving a second private implementation. |

Candidate modules inside the new crate: `model`, `namespace`, `image`, `program`,
`compile`, `computer`, `grant`, `execution`, `changes`, and `store`.
The process crate owns scheduling mechanisms; the computer crate supplies
compiled plans and coordinates resources. Existing `chio-runtime` admission
hooks remain reusable. Its report-oriented orchestration must not become a
competing owner of the same process lifecycle.

The concrete high-level operations need authoritative entry points:

| Public operation | Governed operation or authority action |
| --- | --- |
| `fork` | Admit snapshot/branch creation against owner state and storage limits; record parent and new resource-family identity. |
| `grant` | Issue a signed delegation/launch envelope from the actual owner authority; record its budget account and restrictions. |
| `exec` | Admit a frozen image/plan against both project grant and worker launch policy, then retain the launch intent. |
| Child `exec` | Use authenticated process context to admit an allowed child program, narrowed resources and shared accounting. |
| Resource operation | Dispatch through the kernel and selected resource implementation under the bound process capability. |
| `apply` | Invoke owner-authorized managed-state commit with exact change-set, verification and base-revision bindings. |

These can reuse native tool/context and authority-service seams where their
contracts fit. SDK methods must not bypass them by directly updating databases
or running a sidecar script with owner credentials.

Mutations that span existing process, authority and runner databases need an
explicit retained operation/outbox and recovery state machine, or a deliberately
reviewed common transaction boundary. Calling three independent SQLite writes
does not make fork/grant/launch atomic.

## 11. Recommended implementation order and acceptance

### A. Contract and compiler

Deliver stable proposed wire schemas, descriptor packaging and operator
normalization. Prove that the two accepted `exec` forms produce equivalent
execution plans in the same candidate environment.

First select and stabilize the process/security integration baseline. The
process and recovery work inspected here is absent from local main, and the
current recovery branch records open qualification/remediation work. Reuse its
appropriate mechanisms after the required integration and review; do not build
a replacement process runtime on main or call the existing candidate qualified.

Acceptance: deterministic canonical graphs; explicit occurrence IDs; no effects
during composition; wrong I/O schemas, cycles in lowered graphs, unavailable
bundles and widened resource requirements fail before execution.

### B. One local computer and real managed branches

Deliver a native computer registry, immutable snapshot storage, forked overlays,
typed resource bindings and conflict-aware sealed apply. Reuse repository
snapshot/review evidence as a reference, while moving generic responsibilities
into the runtime.

Acceptance: edits remain isolated; parent mutation produces an apply conflict;
forks do not duplicate keys or spend; symlink/archive traversal and missing
snapshot data fail; an interrupted apply recovers its original intent.

### C. Composed execution on the process runtime

Extract and reuse the existing runner, lower parallel/sequential nodes, bind
per-stage resources, integrate protected verification and implement join-tree
closure. Use non-LLM programs first to verify semantics, then one actual agent
program using the same boundary.

Acceptance: parallel branches cannot overwrite each other; ordered stages see
only committed inputs; denied child scope never dispatches; failures stop
required successors; late children cannot escape completion; protected checks
cannot be replaced by candidate edits.

### D. Two real computers with one owner authority

Deliver remote launch admission, artifact transfer, peer pins, scoped gateway
credentials, fenced leases and remote result custody. Use two separately
isolated hosts with the supported runtime profile.

Acceptance: disconnect the submitting client; the run remains inspectable.
Kill a worker around launch and result acknowledgement; retry retains identity.
Wrong-worker grants, changed image digests and stale lease writes fail.
Partition/revoke while children are active; no new unauthorized effects occur.

### E. Exact shared spending and bounded adaptive descendants

Deliver live family monetary reservations across all participating resource
adapters and placements, child-template policy and retained expansion evidence.
These can be developed alongside C/D, but the README's money claim is gated on
their qualification.

Acceptance: concurrent siblings race for the last funds; reservations plus spend
never exceed the funded ceiling. Restart, fork, new tokens and worker changes
do not reset usage. Unknown effects retain exposure. Root revocation affects
grandchildren. Resource and process limits hold under recursive submissions.

### F. Run the exact hero from an installed package

Deliver the SDK surface only when it calls the same governed runtime. Run the
hero outside the source checkout with separately configured owner and worker,
pinned program packages and a real metered model endpoint. Inspect the diff,
verify the resulting evidence and demonstrate the defined apply behavior.

The acceptance measure is application infrastructure removed: namespace wiring,
fork bookkeeping, process/child supervision, budget sharing, authenticated result
transfer and conflict recovery should belong to Chio. Count retained application
responsibilities as well as lines removed. A facade that moves the existing
manual host setup into hidden scripts has not achieved this objective.

## 12. Decisions to settle before implementation

Recommended defaults, subject to design review:

- `boot=` on `fork()` supplies the explicit entry graph. A missing boot program
  is an error for `exec(computer)`; no secret planner is selected.
- Parallel branches have isolated writable overlays and stable labeled outputs.
- One project-side authority owns the first cross-computer process tree and
  spending account. Broader federation is a later contract.
- Supported Linux containers and pinned packages are the initial execution
  profile; arbitrary process migration is not required.
- Canonical graph/artifact descriptors are the cross-language ABI. Executable
  code is packaged separately; neither Python syntax nor closures cross as trust.
- `join_tree()` means durable successful closure and raises a structured result
  on failure or reconciliation needs. Inspection APIs retain all outcomes.
- `apply()` initially updates one managed workspace and honors protected
  acceptance policy. Materialization and external actions have separate contracts.

## 13. Source map

The adjacent [source-evidence.json](source-evidence.json) records exact inspected
file hashes and line counts so these observations can be checked against later
drift. [validation.json](validation.json) records the documentation checks.
Sources were inspected, not executed as qualification in this task.

Paths below start at the repository root at the linked commit; adjacent paths
are abbreviated within the same crate or package. The inspected local main
commit includes unpublished review tooling; all recorded main source
files also match its hosted parent, linked below. The original inspection commit
is retained in the evidence. Candidate-branch links record inspected source, not
merged or qualified functionality.

### Main checkout (M)

Source: [main source snapshot](https://github.com/bb-connor/arc/tree/f5566d9a765c21cb36652a99c79de64968a656bf).

- M1: `crates/core/chio-core-types/src/capability/scope.rs:15,86,95` and
  `capability/attenuation.rs:224,748,998`: scopes, money and attenuation.
- M2: `crates/kernel/chio-kernel/ARCHITECTURE.md:3`,
  `src/kernel/dispatch.rs:1716`, `src/kernel/validation.rs:1460`: enforcement.
- M3: `crates/kernel/chio-swarm-authority/src/types.rs:29,44,91,247`,
  `src/verifier.rs:374`, `src/verifier/budget_accounting.rs:12`: graph and
  accounting evidence. Existing internal/schema names are retained here as
  source identifiers; the proposed README does not expose them.
- M4: `crates/kernel/chio-runtime/ARCHITECTURE.md:3` and
  `crates/kernel/chio-runtime-core/src/admission_hook.rs`: runtime hooks and
  continuation checks.
- M5: `crates/kernel/chio-kernel/src/kernel/mod.rs:653`: ResourceProvider.
- M6: `crates/kernel/chio-kernel/src/budget_store.rs:616` and
  `src/budget_store/model.rs:31`: budget-store and quota models.
- M7: `crates/trust/chio-federation-transport-iroh/ARCHITECTURE.md:3`:
  transport identity and existing lanes.
- M8: `crates/platform/chio-agent-web-interop/ARCHITECTURE.md:3`: offline
  verification boundary.
- M9: `crates/platform/chio-workflow/ARCHITECTURE.md:3`: in-process ordered
  skill ledger, not the required durable distributed executor.
- M10: `crates/platform/chio-manifest/src/lib.rs:26`: signed tool manifest,
  not a portable application/program image manifest.

### Process/recovery checkout (P)

Source: [process/recovery snapshot](https://github.com/bb-connor/arc/tree/67cf758253944d3591174e35feefaf680bda9464).

- P1: `crates/kernel/chio-process/src/lib.rs:75,217,240,411`: process runtime,
  root restriction, child attachment and dispatch.
- P2: `crates/kernel/chio-process/src/types.rs:48,141`: shared tree limits and
  process states.
- P3: `crates/kernel/chio-process/src/registry.rs:20` and
  `src/store/children.rs:61,193`: host-selected child work and durable joins.
- P4: `crates/kernel/chio-process/MAILBOXES.md:1`: governed local channels.
- P5: `crates/kernel/chio-process/WORKER_PROTOCOL.md:1`: local socket transport
  and containment boundary.
- P6: `crates/kernel/chio-process/tests/aggregate_family.rs:38`: shared
  invocation family contention/restart test; `tests/processes.rs:320` tests
  tree calls and child scope.
- P7: `crates/kernel/chio-process/tests/crash_recovery.rs:96,108` and
  `tests/child_submission.rs:72,337,436`: recovery/child test definitions.
- P8: `docs/architecture/recoverable-agent-runtime/implementation/STATUS.md:1`:
  current unqualified/remediation status.

### Command/project checkout (C)

Source: [command/project snapshot](https://github.com/bb-connor/arc/tree/e245965435a1b912c9ae57bab81c81ba6f5391ea).

- C1: `crates/products/chio-cli/PROCESS_RUNNER.md:1` and
  `src/cli/process_host/runner/plan.rs:12`: dependency runner and limits.
- C2: `crates/products/chio-cli/src/cli/process_host/runner/portable.rs:1`:
  retained portable authoring resolution.
- C3: `crates/products/chio-cli/src/cli/process_host/runner/container.rs:1`:
  local container ownership/profile.
- C4: `crates/products/chio-cli/src/cli/process_host/relocation.rs:1`:
  stopped-owner relocation and authority retirement.
- C5: `sdks/python/chio-mini-swe/src/chio_mini_swe/repository_snapshots.py:75`
  and `repository_store.py:100,295`: workspace/snapshot mechanisms.
- C6: `sdks/python/chio-mini-swe/src/chio_mini_swe/repository_review.py:75`:
  source-bound exported patch review.
- C7: `sdks/python/chio-process/README.md:1` and
  `src/chio_process/__init__.py:32`: experimental synchronous local SDK.

### External primary references

- E1: [Python expression precedence](https://docs.python.org/3/reference/expressions.html#operator-precedence).
  This supports only the syntax/precedence observation, not Chio's proposed semantics.
- E2: [OCI content descriptors](https://github.com/opencontainers/image-spec/blob/main/descriptor.md).
  This supports using digest/size/media-type descriptors for packaged content;
  it does not supply Chio authority or remote execution semantics.
