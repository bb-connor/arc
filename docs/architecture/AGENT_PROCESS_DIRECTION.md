# Agent processes as the next Chio adoption hypothesis

Chio's category ambition is a reusable Rust kernel underneath agentic
operating systems. The outcome requires independent systems to depend on its
interfaces in routine workloads. Crate count, a workbench, a successful demo,
or stronger wording do not establish that outcome.

## Evidence and decision

At the `f5566d9a76` main baseline, Chio already has capability delegation,
swarm-authority verification, tool mediation, durable admission and outcome
recovery. `chio-runtime-core` contains extensive orchestration evidence and
admission machinery. The process runtime, authenticated worker protocol and
CLI host expose those guarantees to ordinary agent applications. Their
installation effort and value in independently maintained workloads remain
to be established.

Durability alone is established functionality elsewhere:

- [LangGraph persistence](https://docs.langchain.com/oss/python/langgraph/persistence)
  provides graph checkpoints for continuity and fault tolerance.
- [Temporal activities](https://docs.temporal.io/activities) execute units of
  work and persist their results through workflow history; applications still
  need to consider idempotency and external effects.
- [Restate's architecture](https://docs.restate.dev/foundations/key-concepts)
  provides durable execution through a Rust server and language SDKs.

Sources inspected on 2026-09-05. These are overlapping capabilities, not a
complete competitive survey. The inference guiding this implementation is
that Chio should combine execution recovery with its existing authority model
in a framework-independent interface that developers can adopt incrementally.

The concrete promise to test is: give workers constrained authority, run them
concurrently, stop a subtree, and recover interrupted work without losing its
identity, limits or side-effect history. A host should use that contract for
Python, JavaScript and Rust agents, without moving its planning logic into a
new framework.

## Execution sequence

| Capability | Required evidence | Candidate state |
| --- | --- | --- |
| Durable process identity and logical tool operations | Fresh OS process recovers known results; unknown effects cannot silently dispatch again | Implemented in `chio-process`; local behavioral tests and crash laboratory |
| Recursive process lifecycle | Actual child and grandchild execution, persistent limits, safe cancellation and checkpoint conflicts | Signed ancestor verification, child and grandchild invocation, admission cancellation and checkpoints implemented. The Linux runner supervises direct workers in a fixed dependency plan with persistent attempt ceilings |
| Authenticated worker protocol | Two real worker languages operate the same kernel; one worker cannot select another process or call administrative methods | Experimental Unix socket service and dependency-free Python/Node clients implemented; OS-process crash test preserves credentials, four original receipts and two publications |
| Host setup without Rust embedding | An application supplies policy and existing MCP tools, then recovers through a fresh CLI host | `chio process` provisions a declared process tree, serves MCP tools and exports private connection descriptors. CLI tests cover original receipt recovery, authority narrowing, offline administration and shared call limits |
| Framework adoption | An existing application adds Chio with small, measured integration effort and retains its framework's planning behavior | LangGraph process tool node and AI SDK 6/7 process tools implemented. Installed AI SDK packages qualify worker/host recovery and failure propagation through both generation APIs using saved scripted model responses. External application adoption remains unverified |
| Capability-scoped IPC | Send, receive and join across workers with durable message identity, backpressure and no authority expansion | Native mailbox tools implement separate send, receive and acknowledgement rights, persistent key deduplication and bounded capacity. Repository readers hand off through the kernel; LangGraph owns the join. The CLI host records the kernel-selected sending process on every message and binds each message key to that process. No delivery leases or kernel scheduler |
| Scheduling and quotas | Bounded queues, worker leases, fairness, restart fencing, shared spend and resource ceilings under contention | Linux `chio process run` launches fixed dependencies and adaptive children from host-selected templates, with bounded concurrent workers, persistent attempt ceilings and rotated credentials. Waiting parents can release their worker slot. Kernel budgets and mailbox capacity remain enforced. Each worker attempt can carry hard CPU-time, open-file, file-size and address-space ceilings applied before exec. Distributed worker leases, resident-memory accounting and multi-tenant fairness remain unimplemented |
| Portable recovery | Versioned process/checkpoint ABI, code identity, export/import, same-operation recovery across a supported host change | `chio process export` retires a stopped host and seals its authority commit chains; `import` verifies a copy against the manifest and seal, re-anchors the authority at the new path and inode identity, and the same run plan resumes interrupted operations with their original receipts. Cross-build migration is bounded by existing schema version checks; a process ABI version, code identity and live migration remain unimplemented |
| A workload worth adopting | A real multi-agent task completes more reliably or with less integration/operation work than its baseline | Repository review application uses the public CLI with concurrent readers, durable mailbox handoffs and a separate publisher. The AI SDK research swarm benchmark measures the same four-researcher loop with native processes and with local callbacks under induced failures: Chio completes every recovery scenario with one valid report and no duplicate effect and stops on cancellation, budget exhaustion and an unauthorized publication, while the baseline repeats reads and handoffs, publishes twice, ignores cancellation and produces invalid reports. A mediated call costs roughly 200-350 ms on the release build depending on machine load, about 80 durable writes; live model value and independent adoption remain unverified |
| Distribution and compatibility | Reproducible packages, a short installation path, maintained SDKs and conformance against a stable public contract | Process SDKs participate in the existing PyPI/npm release paths. A native starter installs local wheel/tarball artifacts offline and qualifies Python-to-Node recovery outside the checkout, including a rebuilt Python source distribution. Public publication, signed starter releases, reproducible native builds and a stable process ABI remain unqualified |
| Independent adoption | External maintainers run it repeatedly and choose to retain the dependency | No evidence gathered in this work |

The Rust foundation now has an [experimental worker contract](../../crates/kernel/chio-process/WORKER_PROTOCOL.md)
with persistent authentication and stable operation keys. The immediate next
deliverable is independent application adoption and a useful multi-worker
workload measured against that application's current behavior. The LangGraph
adapter and report comparison qualify one integration boundary: worker death
after successful publication but before a graph checkpoint. Both backends
finish the graph; Chio recovers the original receipt without the duplicate
publication observed in the native non-idempotent tool. This deterministic
trace does not establish live model workload value or adoption. IPC and
scheduling should grow from observed needs. Keep the public operation vocabulary small:
spawn, invoke, checkpoint, inspect, cancel, then send/receive/join with explicit
authority and durability semantics.

The [packaged starter](../../examples/process-starter/README.md) removes Rust
embedding and checkout imports from one small application's installation path.
Its copied host, built packages and receipt evidence form a development preview
for the producer's Linux architecture. The qualification demonstrates package
consumption and recovery under controlled faults; it does not count as an
independently maintained application adopting Chio.

The [AI SDK bridge](../../sdks/typescript/packages/ai-sdk-process/README.md)
connects existing Node model loops to native tool execution. Its installed-package
comparison uses the same saved provider response and publication effect: the
local callback repeats the effect after restart, while Chio replays a known
result. Unknown output and conflicting saved arguments fail without redispatch.
The higher-level `ChioProcessAgent` now journals provider responses in the native
checkpoint before releasing tool calls. Immutable process-owned response chunks
keep longer runs within the checkpoint bound, with root-wide byte/record quotas
and no missing-data regeneration. Installed HTTP-provider qualification
uses generated call IDs without an application-owned plan file and recovers
worker/host death without an extra provider planning request. Incomplete model
responses remain unknown and stop on replay. This qualifies the execution
boundary for AI SDK 6 and 7, with live hosted inference still unverified.
The [cooperative AI SDK integration](../../sdks/typescript/packages/ai-sdk-process/COOPERATIVE_SWARMS.md)
lets model-selected native child work release a waiting parent's OS slot.
Checkpointed poll ordinals observe child completion while preserving original
spawn identities and model responses. Installed fork/join qualification includes
one-slot scheduling, concurrent children, narrowed grants, mailbox handoffs,
host interruption and recovery after publication. It removes a custom workflow
state-machine requirement for this SDK integration; it does not establish
independent adoption.

## Experiments that can change the direction

Measure time to first mediated call and the application code changed when
adding Chio to an existing agent. Measure completed useful work after induced
worker and host failures, duplicate external effects, operator interventions,
and end-to-end latency. Benchmark the kernel contribution separately from
model and network time. Compare against the application's existing framework
configuration before claiming improvement.

Use a demanding initial workload, such as several research workers collecting
sources and producing one checked report, or isolated repair workers handing
tested patches to a reviewer. Require real handoffs, conflicting actions,
cancellation, a shared budget and induced failures. Keep artifact provenance
and recovered tool effects observable. A deterministic local crash laboratory
qualifies one primitive; it does not establish workload value or adoption.

The [research swarm benchmark](../../sdks/typescript/packages/ai-sdk-process/BENCHMARK.md)
runs that first workload with a scripted planner. It records the structural
outcomes above, worker attempts, wall time and the kernel's per-call cost with
its durable-write attribution: the serving lock's rollback anchor is synced on
every authority commit and accounts for most of the roughly 80 fsync calls per
mediated invocation. It also recorded two kernel limits: a call in flight when
the host dies was terminalized as unknown and denied on recovery even when its
tool is declared read-only, and every relaunch, including a cooperative
resumption, consumes an attempt. The process runtime now answers the first:
an unknown outcome for a tool its server declares free of side effects earns a
bounded fresh dispatch under an attempt-derived request id, while every
side-effecting tool stays fail-closed. Reducing per-call durable cost is the
next kernel change this measurement motivates. Live model quality is still
unmeasured.

If users can get the same operational behavior more easily from their current
stack, revise the interface and integration approach. Continue the category
goal without treating the existence of this crate as the breakthrough itself.
