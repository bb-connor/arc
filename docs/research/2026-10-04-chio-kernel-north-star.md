# Chio kernel north star: research and brainstorm

> **Historical research (2026-10-04).** This document predates the north star the owner approved on 2026-10-08, which is recorded in the unified roadmap (`docs/operations/UNIFIED_ROADMAP.md`, PR #1196):
>
> **Chio is a Rust kernel for agentic operating systems that coordinate work, share resources, and cooperate across organizational boundaries.**
>
> *Authority that only narrows. Work that survives. Evidence that travels.*
>
> The statement in section 2 is not a north star. It is kept as a technical target for the kernel, one level below the approved north star: what the kernel must become for that sentence to hold. The tagline this document once quoted in section 1 is retired. The diagnosis, measurements and bets are unchanged research. The keystone specs they produced are KSPEC-09 to KSPEC-11 in the program index (`docs/superpowers/specs/2026-10-04-ftl-lessons-program-design.md`).

- Date: 2026-10-04
- Status: historical research notes (see the banner). Nothing here is approved. Each bet ends with a proposed first step and asks whether it should become a spec.
- Inputs:
  - the nine specs of the FTL lessons program (`docs/superpowers/specs/2026-10-04-*`, PR #1174);
  - its brainstorm (`docs/research/2026-10-04-ftl-lessons-brainstorm.md`);
  - three research briefs: external OS and capability kernels, external agent security and authorization (2024-2026), and an internal assessment of the Chio kernel.
- Baseline: the same as the program umbrella, revision 3.
  - `M:` = #1160 at `19df31ad9`.
  - `V:` = #1173 at `14477aaac`.
  - `R:` = #1172.
  - `W:` = the uncommitted recovery P0-P5 worktree.
  - `B:` = `origin/wip/bench-results-2026-09-13` (#1163).
- External claims cite their sources. Mappings to Chio are this document's inference unless they cite code.

## 1. Diagnosis

The nine specs kept finding one pattern: **one concept implemented N times**.

| Concept | Copies |
|---|---|
| Classifiers of in-flight operations | Three |
| Durable operation models | Two |
| Evaluator entry points | Sixteen |
| Approval mechanisms | Five |
| Budget ledgers | Seven |
| Stop and fence mechanisms | Nine |
| Hash-chained logs | Five |
| Event streams | Five |
| `PROCESS_ABI` "version 3" definitions (security branch versus recovery worktree) | Two, incompatible |

The internal assessment measured what that costs.

- **Proof sits where the code is smallest.** `chio-kernel-core` is about 11K lines. The formal inventory is 20 Aeneas-extracted functions, 55 Kani harnesses and 149 Lean declarations (`M:docs/formal/CURRENT_STATE.md:15-31`). Most of it targets the core, but not all: the 55 harnesses are 14 internal, 25 core-public and 16 other-public, so some lie outside `chio-kernel-core`. The code that decides real effects is different:
  - an orchestration shell of roughly 125K-147K non-test lines. `chio-kernel/src` on M: has 208,300 Rust physical lines; excluding paths that contain "test" gives 124,798, and excluding only `/tests/` directories gives 146,978. Neither strips `cfg(test)` blocks. Earlier drafts said 133K without a recipe, so treat that figure as approximate;
  - over a 299K-line SQLite store behind one writer (it was 188K lines when ADR-0022 was written; `M:docs/adr/ADR-0022-store-and-kernel-decomposition.md:9-13`).

  That code is tested, not proven.
- **Mediation costs more than the work it mediates.** Every figure below is a historical measurement with its own harness. None is a current-source qualification, and spec 10 section 2.8 keeps the same distinctions.
  - **Latency.** Historical process-host tables show mediated-call medians such as 220-357 ms against handler times of 0.54-0.60 ms. Those are selected examples: the same table also has `send_findings` at 409 ms and `spawn` at 728 and 817 ms. A later historical run puts the optimized `read` median at 130 ms. The benchmark itself labels these tables historical and not qualification of the current source (`M:sdks/typescript/packages/ai-sdk-process/BENCHMARK.md:76-77`, `:143-149`, `:175-191`).
  - **Fsyncs.** In the historical trace (33 mediated invocations), authority, anchor, receipt and `process.db` fsyncs average about 26.5 per call, excluding setup. Including setup and unattributed calls it is about 40, and before the anchor fix about 85 (`BENCHMARK.md:79-115`). The trace recorded eleven authority commits; the current M: code inventory for a side-effecting call is ten (spec 10 section 2.1).
  - **Throughput and receipts.** A sustained-load harness ran 59 calls per second, with receipts growing about 11.9 KB per call (`B:docs/papers/programmable-sovereignty/bench/results/bilateral-admission-sustained-load.json`). That harness gives every worker its own kernel and SQLite receipt store, and its admission store is in memory (`B:crates/kernel/chio-runtime-core/examples/treaty_sustained_load.rs:17-23`). It is not a one-writer or shared-writer baseline. Spec 10 phase 0 measures that baseline before any throughput target is judged.
- **Evidence trails ambition.**
  - 986 of 1,583 security requirements are open-acceptance (recomputed from `M:docs/security/landing-ledger.json` at `19df31ad9`).
  - As of the 2026-10-01 execution review, no commit after `f25cd61f49` had run in hosted CI (`M:docs/reviews/2026-10-01-execution-review.md`). That records acceptance debt at that review, not a claim about every later run.
  - The quickstart begins with a release build of a 636-package CLI (`M:README.md:257-265`).

An earlier draft quoted a tagline here. That tagline is retired and no longer describes Chio (see the banner). Today the kernel is too large, too slow and too unproven for the guarantees Chio asks it to carry. **Its shape is right; its size, uniformity and proof are not.**

## 2. Kernel technical target (under the approved north star)

This section was written as this document's north star. It is now a technical target for the kernel that sits under the approved north star in the banner, and does not replace it. The approved north star says what Chio is for; this target says what its kernel has to become to carry that.

> A small, proven, fast kernel that enforces information-flow-safe authority for any agent framework, and produces evidence that anyone can verify without trusting the operator.

Five properties, each measurable:

| Property | Target | Today |
|---|---|---|
| **Small** | Trusted orchestration under about 30K lines behind a closed, layered ABI (spec 1). Everything else is a component behind a polarity-classified seam | A shell of roughly 125K-147K non-test lines; a 407-package kernel closure (an archived measurement on main `f5a9d2ab2` for one target, not an integrated M:/V:/W: count) |
| **Proven** | The code that decides effects is generated from, or refinement-checked against, one machine-checked model | Proofs cover the pure core only |
| **Fast** | Three durable commits per side-effecting call and two for eligible reads (spec 10); group commit; a shared-writer throughput target measured against a phase-0 baseline | Historical: about 26.5 attributed fsyncs per call (about 40 with setup); `read` median 130 ms; no shared-writer throughput baseline yet |
| **Agent-safe** | Unbounded or unknown external influence cannot authorize a consequential tool call except through an exact endorsement, enforced by the kernel for any framework. Bounded quarantine returns are an explicit allowance (spec 11 section 11). Bootstrap input counts as influence too: it is joined before a context is ready, and trusting it takes an operator-signed assertion, not a pinned hash (spec 11 I7a). An action contract survives attenuation independently of the integrity level | Labels exist (P4); admission ignores them |
| **Verifiable by others** | Receipts in publicly witnessed logs; confinement and execution evidence in standard formats; optionally, proof-carrying verdicts | Signed receipts, local checkpoints |

## 3. The bets

The bets are ranked by leverage. The first two are the keystone: almost every other bet becomes cheaper or provable once they exist.

### Bet 1: one pure admission machine (keystone)

**What.** Replace the three classifiers, two operation models and sixteen evaluators with one sans-IO transition function over one operation model:

```rust
fn transition(state: &AdmissionState, event: AdmissionEvent) -> (AdmissionState, EffectList)
```

- Every evaluator, recovery's original-operation closure, the spec 4 drain, spec 8's stop and startup reconciliation become drivers of it. A driver performs `Effect`s (commit, sign, dispatch) against ports.
- The machine is extracted to Lean (Aeneas already does this for kernel-core) and checked against a new Apalache admission model. No TLA+ model of the admission saga exists today, so `AdmissionMachine.tla` is new (spec `2026-10-04-pure-admission-machine-design.md`).
- It is the substrate for deterministic simulation (bet 9).

**Why.**
- This is the internal brief's top single lever.
- It is Cedar's verification-guided development applied to the part that actually decides effects: a Lean model, proofs, then differential random testing of Rust against the model. The proofs found 4 bugs and differential and property testing found 21 more ([How We Built Cedar](https://arxiv.org/pdf/2407.01688)).
- It is feasible at this size. Atmosphere is a full microkernel proven correct with Verus (SOSP 2025 best paper; [Atmosphere](https://mars-research.github.io/projects/atmo/)).

**From the specs.**
- Spec 4 rule 5.6 (one classifier) and spec 3 (one post-effect obligation) are partial versions of this.
- Spec 1's L0 registry is the machine's signature, and its R-rules become theorems.

**First step.** Write the `AdmissionState`/`AdmissionEvent` vocabulary as the union of the two operation models. Prove that the three classifier tables are each a projection of it. Port the startup classifier first.

**Cost.** High. It is a contract refactor. Do it in the model first, then one driver at a time.

### Bet 2: one crossing primitive on a minimal-commit hot path (keystone)

**What.** Every place an effect or a byte leaves custody becomes one kernel primitive with one transaction shape:
- dispatch commit;
- native capture;
- recovery and semantic capture;
- output release;
- P4 artifact release;
- P5 return;
- issuance.

**The transaction.** Inside the serving writer:
1. check the stop epoch heads (spec 8);
2. check the closure fences (spec 4);
3. check revocation and the capability tree (bet 4);
4. commit reservations (spec 3);
5. write the crossing record.

**The hot path.** Specced in `2026-10-04-crossing-primitive-design.md`. There are three path classes:
- **Side-effecting calls** take three commits:
  - the **intent commit**: begin, the admission transitions and the budget hold, up to `DispatchCommitted`;
  - the **return record**: keeps the returned bytes durable before post-return work. It is progress-only, so it needs no synchronous anchor, though a lag anchor can fire when the outcome is delayed past the lag bound;
  - the **outcome commit**: the post-return stages and the terminal projection.
- **Durable reads** take two commits (intent and outcome, no return record) only when they are eligible: covered by the durable mode, with a driver that permits bounded redispatch. Other durable or tracked reads take three commits, including reads that integrity tracking forces into durability and `invoke_known_only` reads (spec 10 section 6.2).
- **Eligible check-only reads**, outside durable coverage, redispatch-safe and untracked, take a check-only dispatch (no write) plus a release write that carries the receipt.

Fusing the return record into the outcome commit for a true two-commit side-effecting path is that spec's open decision 1.

Commits stay separate only for participants in other stores (remote budget, payment rails).

**Around it:**
- a group-commit WAL writer that batches many operations' crossings into one fsync, sharded per tenant or authority domain;
- a Merkle-batch-signed, slim receipt log, as Certificate Transparency does, with inclusion proofs returned asynchronously;
- D1's closure for non-durable calls stays with spec 3 phase 1.

**Why.**
- Signatures are not the bottleneck: 0.23 ms against a 13.9 ms kernel-only allow (`B:.../bilateral-admission-components.csv`). Commits and the single writer are.
- **The expected gain, from the arithmetic.** Narrowly scoped fsyncs fall from about 22.7 to 5 per side-effecting call (about 4.5x fewer). Counting `process.db`, they fall from about 26.5 to about 8.8 (about 3x). Latency gains are smaller, because non-fsync time stays. Spec 10's `read` target of 95 ms or less against the historical 130 ms median is about 1.37x, and its model predicts about 87 ms (about 1.5x). Earlier drafts claimed 3-5x lower latency; these inputs do not support that. Throughput under concurrency has no baseline yet and must be measured on spec 10's shared-writer fixture.
- One primitive also means one place for the specs' safety predicates. Brainstorm candidate 9 (name every crossing) becomes code.

**From the specs.**
- Spec 3's discharge token, spec 4's dispatch-commit fence and spec 8's tier-2 check all live inside the crossing transactions.
- Spec 4's crossing table is the primitive's inventory.

**First step.**
1. Write the new Apalache admission model (`AdmissionCrossing.tla`) for intent, return and outcome, and show that the existing safety predicates hold. The benchmark notes say lower commit counts require changing "contracts, which the formal models cover".
2. Prototype group commit behind the existing store port.

**Cost.** High for the contract change; medium for group commit.

### Bet 3: prompt-injection resistance enforced by the kernel

**What.** Grants declare a required **integrity**. Admission checks it against the integrity component of the calling process's P4 knowledge join. Once untrusted content has entered a context, consequential grants deny until the content is quarantined or explicitly endorsed:
- quarantine through a P5 confined reader with a typed return;
- endorsement through P3 `ScopedEndorsementV1`.

The refusal is a classified fault with a recovery remedy (spec 2), not a dead end.

**Why.**
- The field has converged on enforcement outside the model. In-model defenses fall to adaptive attacks above 50% success ([arXiv 2503.00061](https://arxiv.org/abs/2503.00061)).
- CaMeL enforces this guarantee in a custom Python interpreter ([arXiv 2503.18813](https://arxiv.org/abs/2503.18813)), and FIDES in one planner ([arXiv 2505.23643](https://arxiv.org/abs/2505.23643)).
- Chio already has the primitives at the OS layer:
  - P5 plays the role of CaMeL's quarantined LLM, enforced by a cage with `FullyEnforced` evidence;
  - P4's monotone join plays the role of FIDES's context label;
  - P3 `Withhold` and endorsement play the roles of FIDES's hide and endorse.

  The missing piece is admission consulting the label.
- **The result is spec 11's property for any framework, in any language, enforced outside the agent.** Unbounded or unknown external influence cannot authorize a gated call except through an exact endorsement. A quarantine return under a bounded requirement is an explicit allowance: its bits can still select the action, unless an action-selection contract limits the selectable set (spec 11 I22a).
- The analogies to CaMeL and FIDES describe where enforcement happens. They do not import those systems' guarantees, which come from their own dataflow models and evaluations. Chio's property needs its own composition argument, given in spec 11 section 11.

**Honesty.**
- Taint at process granularity is sound but coarse. Finer taint is heuristic (NeuroTaint, [arXiv 2604.23374](https://arxiv.org/abs/2604.23374)).
- Utility costs are real: CaMeL solves 77% of tasks against 84% undefended.
- Publish adaptive evaluations (AgentDojo, AgentDyn), not static benchmarks.

**First step.** Add `Constraint::RequiredIntegrity` (spec 11) and a deny-only `IntegrityGuard` that reads the P4 join. Ship a typed-quarantine library of enum, number and bounded-string return contracts for P5.

**Cost.** Medium.

### Bet 4: authority as a tree the kernel owns

**What.** Every capability the kernel issues, observes in a presented chain, or mints for a process becomes a node in a kernel-maintained derivation tree with generations, in seL4's style ([seL4 CDT](https://os.inf.tu-dresden.de/Studium/MkK//SS2026/sel4.pdf)).
- Closure and revocation become an eager subtree cut inside the writer.
- The check-time chain walk remains for offline links the kernel has never seen.
- Stale presentations get a typed result: "revoked at generation N", or Hubris's dead code that names the new generation ([Hubris reference](https://hubris.oxide.computer/reference/)).

On the same tree:
- **Inherited tree policy** that children cannot relax, in the style of Zircon's `ZX_POL_NEW_ANY` and `OVERRIDE_DENY`: no spawn, no egress, no knowledge export below a node ([job_set_policy](https://fuchsia.googlesource.com/fuchsia/+/56d12a94d3840e4c3a5c6d2e3fcedebca4cb77fb/docs/reference/syscalls/job_set_policy.md)).
- **Resources as capabilities**: budgets become passable objects with budget and period, like seL4 MCS scheduling contexts ([seL4 MCS](https://docs.sel4.systems/Tutorials/mcs.html)). They cover LLM tokens, wall time, tool calls and money.

**Why.**
- It fills D12, the missing production `CausalLineageStore`.
- It closes spec 4's "Incomplete" enumeration, and makes spec 2's step 3a a lookup.
- It closes FTL's ambient-creation lesson at every subtree.
- It collapses seven budget ledgers into one model.
- External validation: PORTICO shows epoch-bound handles with closure predicates reject 10 of 10 post-closure reuses, against 10 of 10 accepted by a non-revoking baseline ([arXiv 2606.22504](https://arxiv.org/abs/2606.22504)).

**First step.** A production `CausalLineageStore` over `chio-store-sqlite` capability lineage, with a downward walk. This is already a spec 4 prerequisite. Then tree policy for process subtrees.

**Cost.** Medium for the tree and policy; high for resource capabilities.

### Bet 5: five primitives instead of forty concepts

**What.** Collapse the duplicates into one primitive each:

| Primitive | Replaces | Shape |
|---|---|---|
| Exact approval | `ApprovalGuard`, governed tokens, threshold, AP2/AP3, recovery grant | One `BoundToolInvocation`-style approval. Threshold is k-of-n of it. Grant v2 remains disclosure |
| Sealed hierarchical ledger | Grant invocations, monetary caps, aggregate families, process shares, D1 slots, S1 pools, finding pool | One never-refunded ledger with `Commitment` entries (spec 3) and named release authorities |
| Fence | Emergency and semantic stop, overlays, suspension, freeze, process, workflow and work cancel | A fence row checked by bet 2's crossing primitive. Reversible (stop, overlay) or terminal (closure) |
| Hash-chained log | Receipt log, global commit chain, recovery events, keyring log, stop chain | One append-only log type with C2SP checkpoints (bet 6) |
| Hint | Session late events, mailbox waits, recovery events, plus pheromone and SIEM for observability | Spec 5's `HintSubject` with rules H1-H10 |

**Why.**
- The user-visible concept count drops from about 40 to about 15 (internal brief section 5).
- Seams between duplicates are where the specs found bugs: D1, N2, N7, and the three classifiers.

**First step.** Write the five primitive definitions as one design note. Map each existing mechanism to its primitive, or mark it as a justified exception.

**Cost.** Medium. Mostly design, plus migration.

### Bet 6: evidence anyone can verify

**What.**
- **Witnessed receipt logs.** Make receipt and stop and closure checkpoints C2SP-compatible: checkpoint note, `tlog-tiles`, and `tlog-cosignature`. Existing public witnesses can then cosign Chio logs, and split views become detectable ([C2SP tlog-cosignature](https://github.com/C2SP/C2SP/blob/tlog-cosignature/v1.0.0/tlog-cosignature.md)).
- **Standard confinement evidence.** Encode spec 7's confinement records as EAT claims in a RATS envelope ([RFC 9711](https://www.rfc-editor.org/rfc/rfc9711.html)).
- **Proof-carrying verdicts.**
  - `chio-kernel-core::evaluate` is small, deterministic and `no_std`. Run it in a zkVM, or attest it in a TEE.
  - A peer then checks that an admission verdict follows from the capability, request and revocation snapshot without trusting the receiving kernel.
  - zkVMs are production-grade for small programs ([SP1 Hypercube](https://blog.succinct.xyz/sp1-hypercube/)). zkML for LLM inference is not, and is attackable ([arXiv 2607.28884](https://arxiv.org/abs/2607.28884)). **Prove the verdict, not the inference.**
- **Notarized provider outcomes.** Upgrade `HostExecutedProviderReported` effects with web-proof notarized transcripts ([VET, arXiv 2512.15892](https://arxiv.org/abs/2512.15892)).

**Why.** This answers the verifiable-work paper's open "independent operation" gate directly (`V:docs/papers/verifiable-work/PUBLICATION.json`). Today every multi-owner result comes from one host.

**First step.** C2SP checkpoint compatibility for the receipt log. It is low cost and unlocks public witnesses.

**Cost.** Low to medium for the logs; high and research-grade for zk verdicts.

### Bet 7: durable, restartable agent processes

**What.**
- **Orthogonal persistence.** An agent process (journal, P4 knowledge, model context, optionally a VM snapshot) becomes a checkpointable object at a consistent epoch, in the style of KeyKOS and EROS ([KeyKOS](https://css.csail.mit.edu/6.566/2009/readings/keykos.pdf)).
- **Reseed on restore.** Restore bumps a generation that reseeds credentials, operation keys and nonces, as VMGenID does for Firecracker snapshots ([Lambda snapshots](https://docs.aws.amazon.com/lambda/latest/dg/microvms-images-snapshots.html)).
- **New kernel operations.** Suspend, resume, migrate within an owner, and fork-for-exploration (counterfactual branches whose knowledge joins back conservatively).
- **Confinement theorem.** P5's confined-reader launch is stated and proved on a model as an EROS-style confinement theorem: static checks on the initial capability set imply no leak except through the return contract ([EROS confinement](https://www.cs.yale.edu/flint/cs428/doc/eros-verify.pdf)).
- **Crash-only components.** Kernel components (receipt writer, signer, store adapters, recovery runtime, hint router, connector transports) are supervisor-restartable, with generation-tagged handles ([microreboot](https://static.usenix.org/events/osdi04/tech/full_papers/candea/candea_html/index.html)). Startup reconciliation becomes each component's restart routine. Spec 8's host latch becomes supervisor policy.

**Limits.** Provider-side state, such as LLM caches and remote effects, is never restorable. It is recorded as spec 3 `Commitment` entries.

**First step.** Define the process checkpoint cut over the existing journal plus P4 checkpoints, with a mandatory generation bump on restore.

**Cost.** High.

### Bet 8: the enforcement kernel for everyone's tokens

**What.** Do not fight a format war. Chio's algebra (offline attenuation, subject binding, DPoP, receipts, D1 permits, threshold approvals) is more mature than most of the field. Instead:
- **Inbound evidence profiles.** Accept these and convert them into Chio capabilities:
  - UCAN delegations and invocations ([UCAN](https://github.com/ucan-wg/spec));
  - RFC 9396 `authorization_details`, and attenuating agent tokens;
  - AP2 mandates;
  - A2A signed cards.
- **Outbound context.** Mint OAuth Transaction Tokens at the kernel boundary for downstream services ([Txn-Tokens](https://www.ietf.org/archive/id/draft-ietf-oauth-transaction-tokens-10.html)). That is also MCP's no-passthrough discipline.
- **UCAN-compatible receipts.** Project Chio receipts with `cause` chaining.
- **Under durable execution engines.** Position Chio as the authority and effect-truth runtime under Temporal, Restate and DBOS. Each activity becomes a Chio invocation with an operation key. "Unknown stays unknown" is the honest form of their "exactly-once".
- **MCP audit.** Audit the MCP edges against MCP authorization 2026-07-28: audience validation, no token passthrough, per-client consent ([MCP authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)).

**Why.** Chio becomes the place where everyone's authorization artifacts are enforced and receipted. This aligns with its IETF draft (PR #1171).

**First step.** The MCP edge audit (low cost, compliance). Then a UCAN inbound profile.

**Cost.** Medium.

### Bet 9: a proving ground of simulation, deterministic testing and real gates

**What.**
- **Whole-stack deterministic simulation.** Kernel, store, process runtime, recovery, closure and stop run under one seeded scheduler, with every source of nondeterminism injected: authority clock, RNG, fsync, network, provider responses and crashes. TigerBeetle's VOPR is the model ([VOPR](https://docs.tigerbeetle.com/about/vopr)).
- **Checked properties.** The specs' predicates: no dispatch after a fence or stop, no release outside release authorities, one terminal per session, no silent hint loss.
- **Production validation.** Validate production receipt and event logs against the same predicates, as AWS PObserve does ([Systems Correctness Practices at AWS](https://dl.acm.org/doi/abs/10.1145/3815784)).
- **Real gates.** No new campaign lands until hosted CI is green. Build the Mechanism D escape-hatch gate (spec 3). Move the reader census outside the TCB so its metric cannot be edited to zero.

**Why.**
- Four of the five Highs in the October 1 review were introduced by the campaign itself (`M:docs/reviews/2026-10-01-execution-review.md`).
- Crash and race interleavings (D1, N14, the restart class) are exactly what simulation finds.

**First step.** Restore hosted CI. Then drive the existing DST seeds through bet 1's machine.

**Cost.** Medium.

### Bet 10: a verified extension plane and a validated deployment

**What.**
- **Polarity in the type.** Guards and interceptors (FTL's planned feature) are WASM components whose WIT world encodes polarity. A `deny_only` guard's interface cannot express Allow-with-effects. It is fuel-bounded, has no I/O imports, and runs async on WASI 0.3 streams ([WASI 0.3](https://bytecodealliance.org/articles/WASI-0.3)).
- **Admitted by proof, not review.** Guards are admitted by type and proof checks, as BeePL does for eBPF ([BeePL](https://arxiv.org/abs/2507.09883v1)).
- **One validated deployment description.**
  - It lists components, seams with polarity, routes, budgets, tree policy, crossing points, stop scopes and confinement profiles.
  - It is validated before serving: complete routes, no ambient creation, budgets that sum.
  - It generates `tcb.toml`, configuration and conformance fixtures.
  - The models are seL4 capDL, Hubris `app.toml` and Fuchsia capability routing.

**Why.** Third-party policy becomes safe to load. Auditors get one auditable authority distribution. "You can't write a fork-bomb without fork" (Hubris).

**First step.** Encode guard polarity in the existing WASM guard WIT, and make `#![forbid(unsafe_code)]` a gate for in-process plug-ins.

**Cost.** Medium to high.

### Bet 11: sixty seconds to the first receipt

**What.**
- **A prebuilt single binary:** `curl | sh`, `npx` and `uvx`.
- **`chio dev`:** an embedded store, preset policy and a live receipt viewer.
- **An FTL-style end-to-end harness.** A TypeScript test boots the real Chio, makes a mediated call and asserts the signed receipt. It runs in CI *as* the quickstart, like FTL's `tests/network.test.ts`, which boots QEMU and fetches a page.
- **Error messages.** They name the concept that failed, for example the `server-id fs` footgun (`M:README.md:307-309`), and its fix.

**Why.** Time to first receipt drops from a cold release build of a 636-package CLI to under a minute. Performance and approachability are adoption blockers that no paper fixes.

**First step.** Publish one prebuilt binary, and add the end-to-end quickstart test to CI.

**Cost.** Medium.

## 4. How the nine specs fold in

| Spec | Becomes part of |
|---|---|
| 1. Closed kernel ABI | Bet 1 (machine signature), bet 10 (deployment description), "Small" |
| 2. Authority faults | Bet 3 (integrity faults as one class), bet 4 (step 3a as a tree lookup) |
| 3. Typed reservations | Bet 2 (inside the two commits), bet 5 (sealed ledger) |
| 4. Authority-space teardown | Bet 2 (fence in the crossing primitive), bet 4 (eager subtree cut), bet 1 (one classifier) |
| 5. Unified event queue | Bet 5 (hint primitive) |
| 6. Opaque adapter context | Bet 8 (fabric correlation under interop profiles) |
| 7. Isolation and confinement evidence | Bet 3 (P5 quarantine), bet 6 (EAT/RATS), bet 7 (EROS theorem) |
| 8. Durable stop epoch | Bet 2 (tier-2 check in the crossing primitive), bet 5 (fence), bet 7 (supervisor policy) |
| Brainstorm candidates | Candidate 3 (process exit) feeds bet 7. Candidate 5 (constraint-enforcer registry) feeds bet 10. Candidate 9 (crossing registry) is bet 2 |

## 5. Sequencing

```text
now (foundations; each is independently valuable):
  hosted CI green; Mechanism D gate                         (bet 9)
  live defect fixes: D1, N14, D3, D4, D6, D8, N22, N23       (umbrella section 3)
  new admission model (intent, return, outcome); anchor-before-crossing; group-commit prototype (bet 2)
  AdmissionState vocabulary; port the startup classifier     (bet 1)
  prebuilt binary + e2e quickstart in CI                     (bet 11)
  C2SP checkpoint compatibility                              (bet 6)
  MCP edge authorization audit                               (bet 8)

next (needs the keystones):
  crossing primitive carrying stop, fence and reservations  (bet 2, specs 3/4/8)
  integrity-gated admission + typed quarantine library      (bet 3)
  production CausalLineageStore, then capability tree + tree policy (bet 4)
  five primitives migration                                 (bet 5)
  whole-stack DST over the machine                          (bet 9)

later (research-grade or large):
  resource capabilities (budget and period)                 (bet 4)
  orthogonally persistent processes; EROS confinement theorem (bet 7)
  proof-carrying verdicts (zkVM/TEE); web-proof outcomes    (bet 6)
  verified extension plane; deployment description          (bet 10)
  UCAN, Txn-Token and AP2 interop profiles                  (bet 8)
```

## 6. What not to do

| Idea | Why not |
|---|---|
| Prove the whole 150K-line kernel | Infeasible (seL4 took more than 20 person-years for about 10K lines). Shrink the trusted part (bet 1 plus "Small") and prove that |
| Another token format | Interop profiles win; a format war isolates Chio (bet 8) |
| zk proofs of LLM inference | Impractical, and attackable. Prove verdicts instead |
| Fine-grained taint inside model reasoning | Heuristic. Process-level labels plus quarantine and endorsement are sound (bet 3) |
| LLM scheduling or context management inside the TCB (AIOS-style) | Efficiency logic widens the TCB. Keep it in personalities |
| Static task tables (Hubris) for agents | Agents are dynamic. Keep static templates and routes, with dynamic instances (bet 10) |
| Edge-triggered notifications | Lost transitions (Zircon documents this). Keep spec 5 H4 level-triggered: subscribe, then check the level. `Resource` is the documented edge-triggered exception |
| More campaign scope before gates are real | Four of the five October 1 Highs were self-inflicted (bet 9) |

## 7. Proposed next specs

The top three are now specced as PROPOSED drafts: `2026-10-04-pure-admission-machine-design.md`, `2026-10-04-crossing-primitive-design.md` and `2026-10-04-integrity-gated-admission-design.md`. They were the three that would unlock the most:

1. **Pure admission machine** (bet 1). The keystone for proof, simplification and simulation.
2. **Crossing primitive, minimal-commit hot path and group commit** (bet 2). The keystone for performance. It also gives specs 3, 4 and 8 their single enforcement point.
3. **Integrity-gated admission** (bet 3). The most differentiated agent guarantee, built mostly from shipped P3, P4 and P5 parts.

Bets 6 (C2SP witnessing) and 11 (60-second first receipt) are small enough to go straight to implementation plans.

## Review disposition

### Independent review (PR #1174, Codex agent)

| Finding | Title | Disposition | Where |
|---|---|---|---|
| R-0-01 | The north-star diagnosis mislabels the benchmark topology and mixes historical baselines | Fixed. Each figure now names its harness and historical status. 59 calls/s is labelled a per-worker private-kernel harness with an in-memory admission store, not a shared-writer baseline. Latency figures are labelled selected historical examples, with the 130 ms `read` median. The fsync figures are re-derived (about 26.5 attributed per call). The 3-5x latency claim is replaced by the derived ratios (95 ms target about 1.37x; model about 1.5x). The "Fast" target is now three commits per side-effecting call and two for eligible reads. Also corrected: the ledger count (986 of 1,583), the formal inventory (some harnesses are non-core), the shell size (a range with its recipe), the archived 407-package closure, and the hosted-CI statement's date | section 1; section 2 table; bet 2 |
| R-11-02 (north-star part) | A bounded return does not establish the claimed zero-injection guarantee | Fixed. The "Agent-safe" target and bet 3 state spec 11's property: unbounded or unknown influence needs an exact endorsement, and bounded returns are an explicit allowance. The CaMeL and FIDES analogies no longer import their guarantees | section 2 table; bet 3 |

### Independent review pass 2 (PR #1174, Codex agent)

| Finding | Title | Disposition | Where |
|---|---|---|---|
| R-0-02 | The research hot-path summary still describes the superseded read and return paths | Fixed. The hot-path summary now lists the three path classes: three-commit side-effecting calls with a separate return record whose anchor is lag-triggered only; two-commit durable reads; eligible check-only reads. | "The hot path" |

### Independent review pass 3 (PR #1174, Codex agent)

| Finding | Title | Disposition | Where |
|---|---|---|---|
| R-0-02 (residual) | The revised overview still makes every durable read a two-commit read | Fixed. Only eligible durable reads (covered by the mode, with bounded redispatch permitted) take two commits. Tracked or otherwise ineligible reads take three, per spec 10 section 6.2 | "The hot path" |

### Landing preparation (2026-10-09)

| Item | Disposition | Where |
|---|---|---|
| Roadmap section 7: the document still carries a superseded north star and a retired tagline | Fixed. A historical banner states the approved north star and its supporting line. The tagline in section 1 is removed and noted as retired. Section 2 is retitled as a kernel technical target under the approved north star; its content is unchanged | banner; section 1; section 2 |
