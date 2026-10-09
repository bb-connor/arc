# FTL lessons: brainstorm on the shipped baseline

- Date: 2026-10-04
- Status: research notes. Nothing here is approved. Each candidate says whether it should become its own spec, fold into an existing one, or be dropped.
- Baseline: treat these as shipped:
  - `M:` = `origin/integration/process-security-m4` at `19df31ad9` (#1160: security foundation and agent processes)
  - `V:` = `origin/work/verifiable-work-session-20261003` at `14477aaac` (#1173: verifiable work, D1, S1, F1, verifiers, iroh lanes)
  - `R:` = `origin/research/openappa-recovery-20261001` at `de84fc306` (#1172: recovery lane, a hard dependency of V's work kernel)
  - `W:` = the uncommitted working tree at `standalone/arc-worktrees/recoverable-agent-runtime-20261002`, where recovery P0-P5 is implemented. Line references reflect the working tree on 2026-10-04 and may drift.

  W1-W4 have no code and are cited as contract anchors. Several R: names, such as a signed `RemedyOfferV1`, a `recovery_deliveries` outbox, and an `ExplainIntent` command, appear only in docs. W: implements different names.
- Related: `docs/superpowers/specs/2026-10-04-ftl-lessons-program-design.md` and its seven child specs.

## Why a second pass

Agent processes make the FTL analogy literal rather than metaphorical:

| FTL | Chio |
|---|---|
| Thread | Process |
| Six-op syscall table | `chio.process.v1` worker protocol (`M:crates/kernel/chio-process/WORKER_PROTOCOL.md:50-57`) |
| Handle space | Process capability and subtree |
| `HandleSpace::close` | Subtree cancel |
| Poll with one-shot re-arm | Mailbox `wait_ms` with a new operation key |
| Reaper | `wait_children` and `settle_children` |

Verifiable work then adds the multi-owner dimension FTL never has: independent kernels, sealed allocations, and escrow.

The first pass asked what Chio could borrow from FTL's kernel. This pass asks which FTL lessons apply to the agent OS Chio has now built, and which of FTL's flaws Chio has reproduced.

## Candidates, ranked

### 1. Split-domain workers (FTL's `lx` flaw, reproduced). Status: folded into spec 7 section 6 (PROPOSED)

**Problem.**
- In FTL, the Linux app and its library OS share one address space and handle space. Any app code can issue kernel calls with the container's handles (FTL `kernel/src/arch/x64/syscall.rs:65`, `lx/src/thread.rs:58`).
- Chio's worker protocol has the same shape. The 256-bit bearer credential sits inside the worker OS process, next to whatever untrusted code the agent runs. Any code that can read it can call all six ops with the process's full authority: invoke, spawn through native tools, checkpoint, cancel.
- The protocol says isolation is the host's job, and that "Unix permissions alone do not isolate mutually hostile processes with the same UID" (`M:crates/kernel/chio-process/WORKER_PROTOCOL.md:22-28`).
- The Docker profile isolates the worker from the host (`M:crates/products/chio-cli/PROCESS_CONTAINERS.md:44-57`). It does not isolate the credential from the workload inside the container.

**Precedent.** The mini-SWE adapter already splits the two domains. Model commands run through a host-selected Chio tool, and the worker never gets a shell callback (`M:sdks/python/chio-mini-swe/README.md:4-6`).

**Proposal.**
- A qualified `split_domain` worker profile:
  - the credential and the six-op client live in a small personality process (the FTL `lx` role done right: separate address space, gVisor Sentry style);
  - workload code reaches it only through a narrower channel that exposes framework actions, not raw ops;
  - the personality enforces operation-key discipline and checkpoint-before-release, which are advisory in-SDK today.
- Receipts gain caller-confinement attribution next to the existing tool-launch attribution (`native_launch`). An auditor can then tell "the tool was caged" apart from "the agent that asked was confined".

**Interactions.**
- Spec 7 (isolation): this is the caller-side dimension it now names.
- Spec 1 (ABI): the personality is an L1 client and adds no ops.
- V: confinement is a stated premise of every verifiable-work claim (`V:crates/kernel/chio-kernel/src/delegated_work.rs:4-5`). This turns part of that premise into evidence.

**Value: high. Cost: medium.** The SDK work already exists in mini-SWE form. The new work is qualification and receipt attribution.

### 2. A durable stop epoch. Status: specced as `docs/superpowers/specs/2026-10-04-durable-stop-epoch-design.md`

**Problem.**
- The emergency stop is a process-local `AtomicBool` that resets on restart, and `issue_capability` and governed active-response admission never check it. Both gaps are ledgered as open:
  - EV11: "There is no operator-reachable emergency stop" (`M:docs/security/landing-ledger.json:5066`);
  - AC6: "the emergency stop is process-local" (`M:.../landing-ledger.json:5118`).
- Neither has a design.

**FTL analog.** A boot-time flag read before any thread is scheduled.

**Precedent already built (W:).** The recovery implementation has a durable, scoped stop.
- `set_semantic_emergency_stop(scope, bool)` persists the stop as a recovery command record (`W:crates/platform/chio-store-sqlite/src/admission_operation_store/semantic.rs:355-372`).
- It is checked at plan acceptance and inside the capture and submission transactions (`W:.../semantic/capture.rs:47`, `:294`, `:336`).
- The kernel-wide stop should reuse that shape: one durable record, checked in the same writer as every capture.

**Proposal.**
- Persist the stop as a signed, fenced record in the serving-epoch state that restart safety already reconciles before readiness (`M:docs/security/native-restart-safety.md`). A restarted kernel comes up stopped.
- Expose it through the authenticated control plane.
- Make every `KernelOp` declare a stop disposition (spec 1 rule R5), so the two unchecked admit paths become a recorded decision rather than an accident.
- Optionally publish a stop epoch to federated peers, so they refuse continuations from a stopped owner. The default cross-org transport is HTTPS with mTLS or signed bodies, and iroh lane b is an optional lane (owner decision UR-D4, 2026-10-09).

**Value: high (operational safety, ledgered). Cost: low to medium.**

### 3. Process exit as an authority transition. Recommend: a small PROPOSED spec

**Problem.**
- `ProcessState` is only `Running | Cancelled` (`M:crates/kernel/chio-process/src/types.rs:126-129`). Completion lives in the runner's `runner.db`, not in the process authority.
- The runner revokes worker credentials after completion (`M:crates/products/chio-cli/PROCESS_RUNNER.md:288-289`), so the worker protocol can no longer drive an exited process. The exposure is therefore narrow. The gap is that exit is not an authority fact:
  - there is no signed terminal state;
  - closure (spec 4) and hints (spec 5) have no event to key off;
  - host-side code that calls `ProcessRuntime` directly is not refused for an exited process (inference: admission checks only `ProcessState`, `M:crates/kernel/chio-process/src/store.rs:395`).
- FTL's `Thread::close` marks the thread exited, emits `ThreadExited` to subscribers, and the reaper collects it. Exit is a kernel state, not a host note.

**Proposal.**
- Add a terminal `Exited { outcome_digest }` state, written by an authenticated runner report under the same serialization as cancel.
- Admission refuses calls for an exited process.
- Define orphan policy explicitly. The recommended default: live children of an exited parent keep running under their own capabilities, and `wait_children` already surfaces them.
- Exit-75 suspension stays `Running`.

**Interactions.**
- Spec 4: exit becomes a closure trigger.
- Spec 5: exit is a hint subject.

**Value: medium. Cost: low.**

### 4. Closure lemma and stranded-capacity accounting. Recommend: fold into spec 4, then a paper section

**Problem.**
- The verifiable-work paper puts closure, fencing, and reclamation out of scope (`V:docs/papers/verifiable-work/sections/08-limits.tex:3-9`).
- D1 forbids releasing sealed allocations, S1 forbids reclamation, and the beta excludes it (`V:docs/superpowers/specs/2026-10-02-dynamic-delegation-design.md:86-89`). Long-running programs accumulate permanently stranded capacity with no terminal accounting.

**Proposal.**
- Spec 4 revision 2 defines closure for delegation roots and swarm graphs.
- State as a composition lemma: closure preserves bounds conservation, sealed-invocation identity, and earned-child survival, and it makes stranded capacity an explicit, signed quantity in the closure artifact.
- That is a paper contribution in its own right: the first non-additive operation in a system whose composition results are all additive.

**Value: high for the paper, medium for the product.**

### 5. A constraint-enforcer registry. Recommend: fold into spec 1, or write a small spec

**Problem.**
- KG4 made `ensure_capability_issuance_supported` exhaustive over `Constraint` (`M:crates/kernel/chio-kernel/src/authority.rs:102`).
- The portable core fails closed on constraints it cannot evaluate.
- Nothing states, per constraint, who enforces it and where: kernel core, full kernel, guard, adapter, or verifier.

**FTL analog.** Every syscall number maps to exactly one handler in one exhaustive match.

**Proposal.** A closed table in which each `Constraint` variant names its enforcer and its evaluation point. Issuance rejects any constraint whose enforcer is not installed on the receiving kernel, and the portable-core deny list is generated from the table.

**Value: medium. Cost: low.**

### 6. Revocation confirmation as an evidence token. Recommend: fold into spec 4

AP8's session-wide revocation reports success only after every capability's write and readback (`M:crates/protocol/chio-mcp-remote/src/remote_mcp/admin.rs:579`). Make that readback a `RevocationConfirmed` value (unrepresentable-defects Mechanism A) that spec 4's drain and spec 2's sibling-revocation check consume. Neither can then proceed on an unconfirmed fence.

### 7. Verifiers as reference monitors. Recommend: fold into spec 1

Verifiers choose their own observers and checkers, refuse observations supplied in requests, and replay decisions at their original time (`V:docs/superpowers/specs/2026-09-15-authority-verifier-design.md`). Register them as spec 1 components with a closed operation set. The checker and the observer are `fact_source` seams, so a lying checker widens what is accepted.

### 8. Cross-owner hints. Recommend: defer (recorded in spec 5)

- Cross-owner state is poll-only today, through the W2 query.
- The only push lanes over P2P are revocation (lane b) and an experimental, pheromone-only gossip (lane c).
- A hint-only lane, with recovery-outbox semantics and payloads that grant nothing, would give liveness across owners. It should wait until independent operation is established, because every multi-owner result so far is single-host (`V:docs/papers/verifiable-work/PUBLICATION.json`).

### 9. Name every crossing point. Recommend: a cross-spec rule (specs 1 and 4)

**Problem.** FTL admits an SMP gap: a thread running on another CPU while its space closes (FTL `kernel/src/thread.rs:279-280`). Chio has several crossings where an effect or a byte leaves custody, and each has its own ordering rule, written in a different document:
- durable dispatch commit;
- the recovery cancellation tombstone, checked in the same writer as begin and capture (`W:.../recovery/native.rs:286-293`);
- P4 artifact release, where the knowledge join and release intent commit before sink I/O;
- P5 confined return, where the final serialized process-activity read is the cancellation ordering point (`W:crates/platform/chio-control-plane/src/confinement.rs:234-239`);
- mailbox send;
- provider lowering under enforced knowledge.

**Proposal.** A closed registry of crossing points. Each entry names:
- the linearization point (which transaction, which writer);
- what cancel or closure does before it and after it;
- the release authority, if any.

Spec 4's closure and spec 1's registry both consume it. A new crossing without an entry fails the escape-hatch gate.

**Value: medium. Cost: low** (mostly documentation plus one gate row).

### Already present, so no action

| FTL idea | Chio equivalent |
|---|---|
| Handles as space-local indices rather than global bearer tokens | Process guests carry no capability. Tool requests are rebuilt from the persisted capability (`M:crates/kernel/chio-process/ARCHITECTURE.md:117-122`). MCP sessions hold `issued_capabilities` |
| fork/exec with attenuation | `spawn` requires one signed delegation hop with narrower scope and share; operators pin templates |
| One-shot re-armed poll | Mailbox `wait_ms`, then a new operation key after an empty poll (`M:crates/kernel/chio-process/MAILBOXES.md:97-105`) |
| Interceptors | Guards, including output guards on mailbox payloads |
| Lazy page-in tier | Root-first lineage restoration before invoke (`M:crates/kernel/chio-process/ARCHITECTURE.md:29-38`) |
| A container with no network or console handle, the anti-`lx` | Recovery P5 confined readers. The observing child holds no credential, socket, tool or model, and talks over one framed stdin channel with an 8-byte mediated return (`W:crates/security/chio-security-types/src/confinement.rs:85-155`) |
| Memory objects with mapping attributes, and lazy mapping only when authorized | P4 labeled artifact versions. A mediated read releases bytes only after the knowledge join commits, and a copy is a provenance edge with a conservative label join, never a shared mapping |
| `ENOSYS` default-deny | P3 semantic coverage. Every exposed connector operation is covered, dynamically resolved by an operator, or refused |
| Kernel-tier fault resolution whose absence is terminal | The recovery planner maps an unsatisfied capability fact to `BlockedByCapability` (`W:crates/security/chio-recovery/src/evaluation.rs:195-206`). Spec 2's `authority` remedy is the missing upcall tier |

### Rejected

| Idea | Why |
|---|---|
| Live patching of running agents | Conflicts with `PROCESS_ABI` pinning, plans that cannot change, and determinism. Checkpoint handoff is custody, not migration (`V:docs/superpowers/specs/2026-09-15-checkpoint-handoff-design.md:3-11`) |
| A distributed scheduler borrowed from FTL | Fairness is local today, and distributed leases are acknowledged as missing. Nothing in FTL helps there |

## Suggested next steps

1. Review candidate 1 where it now lives: `2026-10-04-microkernel-isolation-backend-design.md` section 6 (worker profiles `direct`, `container`, `split_domain`; requirements S1-S5; host-sourced `worker_profile` attribution). Candidate 2 (durable stop epoch) is now specced in `2026-10-04-durable-stop-epoch-design.md`.
2. Write candidate 3 (process exit) as a short spec, or as an amendment to `M:crates/kernel/chio-process/ARCHITECTURE.md`.
3. Fold candidates 4, 6, and 7 into specs 4 and 1 during their next revision. Adopt candidate 9 (crossing-point registry) as a shared rule in specs 1 and 4.
4. Keep candidate 8 recorded in spec 5 until independent operation exists.
