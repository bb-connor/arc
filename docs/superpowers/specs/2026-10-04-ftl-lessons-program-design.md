# Design: FTL lessons program

- Status: PROPOSED (program index, revision 3, re-baselined 2026-10-04 on #1160 + #1173 + #1172 + uncommitted recovery P0-P5). Each child spec is reviewed and approved on its own.
- Date: 2026-10-04
- Scope:
  - index, cross-spec decisions and sequencing for eleven designs: seven from the FTL review, the durable stop epoch from the follow-on brainstorm, and the three keystone specs from the kernel north star;
  - the defects found while researching them, several of which need owners whether or not any child spec is approved;
  - a pointer to the follow-on brainstorm.
- Origin: review of FTL v0.1.0 (`nuta/ftl` at `b73801a`). FTL is a small Rust OS (about 23K lines, two external crates). Its kernel answers a closed set of 31 system calls and passes everything else, including Linux system calls and CPU faults, back to a per-container library OS running in user space.
- Baseline (treated as shipped):
  - `M:` = `origin/integration/process-security-m4` at `19df31ad9` (#1160): security foundation and agent processes.
  - `V:` = `origin/work/verifiable-work-session-20261003` at `14477aaac` (#1173): verifiable work (D1 dynamic delegation, S1 swarm evolution, F1 funded work), verifiers, iroh lanes, and the W1-W4 designs. W1-W4 have no code and are cited as contract anchors.
  - `R:` = `origin/research/openappa-recovery-20261001` at `de84fc306` (#1172): the recovery design docs.
  - `W:` = the **uncommitted** working tree at `standalone/arc-worktrees/recoverable-agent-runtime-20261002`. It implements recovery P0-P5 and is built on the #1160 checkpoint `f25cd61f4`. Line references reflect the working tree on 2026-10-04 and may drift. Several R: doc names (a signed `RemedyOfferV1`, the `recovery_deliveries` outbox and its cursors, an `ExplainIntent` command, emergency revocation that withdraws approvals) are not implemented in W:. The child specs use W:'s implemented names.
  - `P:` = `feat/process-command-experience-20260924` at `e24596543`: a portable CLI runner with no kernel change.
- Follow-on:
  - `docs/research/2026-10-04-ftl-lessons-brainstorm.md`: candidates on the shipped baseline.
  - `docs/research/2026-10-04-chio-kernel-north-star.md`: the kernel north star, eleven bets that fold these specs into a small, proven, fast and agent-safe kernel.

## Revision history

**Revision 3, recovery implementation.** Recovery P0-P5 exists as code in W:, and much of it was assumed rather than read in revision 2.
- **Spec 2 (faults)** now plugs in as a recovery planner fact. W: maps an unsatisfied capability fact to the terminal `BlockedByCapability`, and the new `Authority` remedy kind is the upcall tier for exactly that case. W: pins one capability per workflow, so a resolution runs as a linked `AuthorityContinuation` workflow. Because recovery refuses delegated control tokens, an operator-assigned actor drives it.
- **Spec 7 (isolation)** recognizes that P5 already cage-confines a zero-authority `confined_reader` child. It adds that profile, an exporter requirement (P5 emits no receipt), and an `output_channels` surface.
- **Spec 6 (adapter context)** moves state homes to P4 labeled model contexts. It makes lowering into a model a knowledge-joined release.
- **Spec 5 (events)** projects recovery hints from the implemented hash-chained recovery event log, adds the audience rule H9, and records the process ABI union as v4.
- **Spec 4 (teardown)** closes recovery workflows through `CancelWorkflow`, cites recovery's same-writer tombstone as the shipped fence, unifies three classifier copies, closes confined children, and adds a table of named release crossings.
- **Spec 1 (ABI)** pins L3 to the implemented recovery surface and grows L0 from 27 to 29 ops. It classifies the recovery, knowledge, semantic and confinement seams.
- **Spec 3 (reservations)** re-cites the implemented recovery reservations and adds two `Commitment` kinds.
- **This overview** reclassifies N7 and N8 and adds nine findings.
- **Spec 8 (durable stop epoch)** is added from brainstorm candidate 2, closing D2 (EV11/AC6). It yields findings N22-N24 and cross-spec edits: R5b in spec 1, open decision 5 resolved in spec 4, and `HintSubject::Stop` in spec 5.

**Revision 2, security, processes and verifiable work.** Every child spec was re-based on M:, V:, R: and P:.
- Spec 2 became a classification layer for the recovery lane.
- Spec 5 gained a single hint vocabulary.
- Spec 3 became an application of the unrepresentable-defects design.
- Spec 4 became the paper's missing closure rule.
- Spec 1 became a layered registry.
- Spec 7 reused `native_launch` and added worker confinement.

## 1. Summary

FTL and Chio share a thesis: a small trusted mediator, with everything dialect-specific running as tenant code outside it.

The shipped baseline makes the analogy literal:

| FTL | Chio |
|---|---|
| System-call table | Six-op worker protocol |
| Handle space and its close | Capability subtree and terminal cancel |
| Poll with one-shot re-arm | Mailbox waits with one-shot re-arm |
| Reaper | `wait_children` |

The recovery implementation adds three more, each done more carefully than FTL does:

| FTL | Chio recovery |
|---|---|
| Container with no network handle | Zero-authority confined readers (P5) |
| Memory objects with mapping attributes | Labeled artifact versions with release after a knowledge join (P4) |
| Default-deny `ENOSYS` | Semantic coverage at the connector layer (P3) |

The most useful FTL lesson is a flaw: policy enforced in the same domain as the code it polices is advisory. Chio reproduces that flaw where a worker's credential sits next to untrusted workload code. P5 shows the remedy, and spec 7 generalizes it.

Across three revisions, each child spec narrowed to the gap that shipped and implemented work leaves open. The research also surfaced defects in that work itself (section 3).

## 2. Child specs (revision 3)

| # | Spec | Revision 3 scope | Status |
|---|---|---|---|
| 1 | `2026-10-04-closed-kernel-abi-design.md`: layered kernel ABI registry and TCB budget | L0 `KernelOp` has 29 ops, adding `RecoveryControl` and `RecoveryDisclosureIssuance`, over 254 classified methods. The other layers are L1 `chio.process.abi.v4` (the union of two incompatible v3s), L2 `chio.work.v1`, and L3 recovery (7 `RecoveryCommandBodyV1` variants, 3 endpoints, 15 `RecoveryPermission`s), plus component op enums. Rules R11-R13 and R5a (per-command stop dispositions). Recovery, knowledge, semantic and confinement seams are classified by polarity. Gates extend H11 and the trust-boundary census | PROPOSED |
| 2 | `2026-10-04-authority-faults-design.md`: authority fault classification for the recovery lane | A closed fault class and anti-oracle rules on the deny receipt, kept as audit evidence. The planner fact feeds a new `ExplanationRemedyKind::Authority` and assessment `RequiresAuthority`. Resolution runs as a linked `AuthorityContinuation` workflow (step 3a checks the predecessor's capability), with an operator-assigned actor and out-of-band delegators. `RecoveryContinuationBinding` is kept. It depends on generalizing the recovery profile | PROPOSED |
| 3 | `2026-10-04-typed-reservations-design.md`: post-effect discharge and typed reservations | Unrepresentable-defects Mechanisms A, C and D for the non-durable post-effect region. `Commitment` entries include implemented recovery reservations, provider lookups and grant issuance. The escape-hatch gate allowlists the W: `Drop` quarantines | PROPOSED |
| 4 | `2026-10-04-authority-space-teardown-design.md`: closing authority spaces | Uses the dispatch-commit fence (recovery's tombstone is the shipped instance) and one classifier unifying three copies. Closure covers five kinds plus recovery workflows (through `CancelWorkflow`) and confined children (through `NativeConfinedRuntime::cancel`). Adds a table of named release crossings, funded-work and knowledge invariants, stranded capacity, and the paper lemma | PROPOSED |
| 5 | `2026-10-04-unified-event-queue-design.md`: session event log and shared hint vocabulary | `HintSubject` with rules H1-H9. Recovery hints come from the recovery event chain and are re-read through `InspectWorkflow`. Processes use a long-poll `inspect` (with a fix for W:'s enforced-knowledge failure, rule P6), riding process ABI v4. Includes the hosted SSE fixes | PROPOSED |
| 6 | `2026-10-04-opaque-adapter-context-design.md`: lift-bound adapter correlation | The kernel cookie stays rejected. Under P4, the state home is the labeled `ModelContextV1` checkpoint, and lowering into a model is a knowledge-joined release. The verdict binding (`binding.v2`) carries the model-context digest. Semantic connectors are a non-goal | PROPOSED (narrowed) |
| 7 | `2026-10-04-microkernel-isolation-backend-design.md`: confinement evidence for tool servers and workers | Tool confinement uses `native_launch`, and worker profiles are `direct`, `container`, `split_domain` and `confined_reader` (P5). Adds the `chio.confined-reader.evidence.v1` exporter, `output_channels` (reported, not gating), and `RuntimeAssuranceBacking` at the `Basic` tier. The microkernel backend stays EXPLORATORY, and FTL is NO-GO | Sections 5-7 PROPOSED, sections 8-9 EXPLORATORY |
| 8 | `2026-10-04-durable-stop-epoch-design.md`: durable stop epoch | Replaces the process-local kill switch with a hash-chained `StopEpochV1` in the admission serving writer, scoped by kernel, tenant or recovery. It generalizes W:'s `set_semantic_emergency_stop`. Two tiers: an in-memory early deny, and an authoritative check inside every crossing transaction. A restarted kernel comes up stopped. Stop and resume are asymmetric: one operator to stop, a different principal or a threshold to resume. Every L0-L3 op has a disposition, and governed containment stays allowed. Evidence is a signed `chio.stop-epoch.v1`. Lane b publication is informational | PROPOSED (revision 1) |
| 9 | `2026-10-04-pure-admission-machine-design.md`: pure admission machine (north-star bet 1) | One sans-IO `transition(&AdmissionState, AdmissionEvent) -> (AdmissionState, Vec<Effect>)` in `chio-kernel-core` over one operation model, the union of the 19-state tool-dispatch and 15-state security models. The three classifiers become one cut function, and the 16 evaluators become one `evaluate` plus a blocking adapter. Proof: Aeneas extraction to Lean with ten theorems, a new `AdmissionMachine.tla`, differential tests against the legacy predicates, and DST. Migration starts with the startup classifier | PROPOSED (revision 1) |
| 10 | `2026-10-04-crossing-primitive-design.md`: crossing primitive and minimal-commit hot path (north-star bet 2) | One `CrossingTx` with ordered checks (stop epoch, closure fence, revocation, knowledge integrity, reservations, record) for every crossing. Anchor sync only before a crossing. Side-effecting calls take three commits (intent, anchor-free return record, outcome). Read-only calls take a check-only dispatch plus one release commit with the receipt (retires D1). Group commit with savepoints, per-authority-domain sharding, and staged receipts deduplicated at rest. Targets: at most 3 commits and 2 anchor syncs per call, `read` median 60 ms or less, at least 300 calls/s | PROPOSED (revision 1) |
| 11 | `2026-10-04-integrity-gated-admission-design.md`: integrity-gated admission (north-star bet 3) | `Constraint::RequiredIntegrity` over W:'s `ArtifactInfluenceV1` lattice, refined with origin classes and `ExternalBounded` for typed confined returns. A deny-only `IntegrityGuard` checks early, and the authoritative check runs inside spec 10's intent commit and check-only dispatch, using a new `knowledge_influence_heads` row. Every delivery records an output influence join. `InsufficientIntegrity` joins spec 2's fault classes, with remedies through endorsement or a quarantined continuation. MCP edges start at unknown, so integrity-gated grants deny there | PROPOSED (revision 1) |

## 3. Defects and findings

Items were verified on the M:/V: heads, or in W:'s working tree where marked.

### 3.1 Live defects

| ID | Defect | Status | Evidence | Where addressed |
|---|---|---|---|---|
| D1 | Non-durable calls can execute a tool and leave no receipt. The guard is disarmed before the receipt is built, signed and appended | Open | M:/V: `async_evaluation_core.rs:1740`; `nested_flow_evaluation.rs:1495` | Spec 3, phase 1 |
| D2 | The emergency stop is process-local and resets on restart, and it is unchecked by `issue_capability` and governed active response | Open, ledgered as EV11 and AC6 | M: `kernel/construction.rs:369` Spec 8 (`durable-stop-epoch`), which closes EV11/AC6. Spec 1 R5/R5a/R5b |
| D3 | When a hosted SSE consumer lags, the server warns and keeps going | Open | M:/V: `http_service.rs:517`, `:608`, `:702`, `:817`, `:860` | Spec 5 section 6.2 |
| D4 | Restore reseeds event ids at 0 | Open | M:/V: `session_core/factory.rs:468`, `:684` | Spec 5 section 6.2 |
| D5 | The issuance freeze is never consulted with `Delegate` | Open | M:/V: `issuance_freeze.rs:1290` | Active defense. Spec 2 covers remedies only |
| D6 | Overlay guards do not revalidate at dispatch | Open | M: `kernel/mod.rs:882` | Spec 4 section 4.2 |
| D7 | `ApprovalGuard` is unwired, with a stale doc reference | Open | M: `approval.rs:15` | HITL owners |
| D8 | Gemini adapter request ids collide | Open | M:/V: `chio-gemini-tools-adapter/src/adapter.rs:263` | Spec 6 rule 1 |
| D11 | Network and chain stacks sit in the kernel closure: `reqwest`, `hyper` and sigstore, alloy through `chio-settle` and `chio-core`, and in-crate `ureq` | Open | M: `chio-kernel/Cargo.toml:109` | Spec 1 R13 |
| D12 | There is no production `CausalLineageStore` | Open | M: `chio-security-types/src/ports/lineage.rs:294` | Spec 4 phase 4 |
| N1 | V:'s `chio-process/src/worker.rs` reverts M's authority-clock fix (`dcae5d7ba`) | Open (merge) | M:/V: `worker.rs` | Merge owners |
| N2 | The security recorder records `Released` before finalization | Open | M: `async_evaluation_core.rs:1727` | Spec 3 |
| N3 | Caged long-lived `AdaptedMcpServer` receipts carry no `native_launch` | Open | M: `chio-mcp-adapter/src/server.rs:141` | Spec 7 section 5.1 |
| N4 | The Mechanism D escape-hatch gate was never built | Open | M: `unrepresentable-defects-design.md:503-518` | Spec 3 builds it |
| N5 | GT1: the hardening gates do not run in hosted CI | Open | M: `hardening-toolchain-spec.md:506-521` | Rollout blocker |
| N6 | The default sidecar threshold collector lacks its production request-context source | Open | M: `threshold-approval-collection.md:282-283` | Approval owners |
| N9 | Container launch evidence is unsigned | Open | Spec 7 section 5.3 | Spec 7 |
| N10 | W2 plans HTTPS co-signing, while V: ships `IrohBilateralCoSigner` | Open | V: `lanes/bilateral.rs:795` | Work owners |
| N13 | Two incompatible `chio.process.abi.v3` definitions: M: `2a4c2fbe4` (broker routes) and W: (knowledge and recovery). A union must be v4 | Open (merge) | M: `chio-process/src/lib.rs:65`; W: `chio-process/src/lib.rs:54` | Spec 1 L1; spec 5 open decision 1 |
| N14 | With durable knowledge enforced, the worker `inspect` op always calls `storage()`, which refuses, so `inspect` fails for every enforced process | Open (W:) | W: `chio-process/src/worker.rs:156-162`; `lib.rs:282-288` | Spec 5 rule P6 (return the redacted snapshot) |
| N15 | New W: control-plane code samples `SystemTime::now()` instead of the authority clock. Same class as N1 | Open (W:) | W: `chio-control-plane/src/confinement.rs:53`, `semantic.rs:128`, `knowledge.rs:53` | Recovery owners |
| N16 | W:'s P5 edits `chio-cage` internals that M: moved into `chio-cage-plan` and `chio-cage-init`, and adds cage APIs that must be ported | Open (merge) | W: `chio-cage` diff (`launch.rs` +81) | Spec 7 open decisions |
| N17 | P5 confined-reader evidence lives only in review custody, with no receipt or attribution | Open (W:) | W: `docs/.../implementation/p5/OPERATIONS.md:46` | Spec 7 section 6.4 exporter |
| N18 | Doc-to-code drift in recovery: `RemedyOfferV1`, `recovery_deliveries`, cursors, `ExplainIntent`, adapter states and approval-withdrawing emergency revocation exist only in docs. V:'s W1 `WorkRecoveryLinkV1` routes to these names | Open | R:/W: `03-recovery-protocol.md:55`, `:114`; `08-protocol-operations.md:19`, `:57` | Recovery and work owners |
| N19 | The recovery profile is narrow: one template (`SupportTicketPublicIssue`) and one server, tool and purpose per process scope. V:'s work kernel assumes general recovery links | Design gap | W: `chio-security-types/src/recovery/commands.rs:12-14` | Spec 2 section 6.9 dependency |
| N20 | The drain classifier exists in three copies: startup reconciliation, recovery's original-operation closure, and the proposed drain | Design gap | W: `kernel/admission_coordinator/recovery_runtime.rs:205-240` | Spec 4 (rule 5.6) |
| N21 | About 117K lines of recovery P0-P5 implementation exist only as uncommitted changes in one worktree | Risk | `git status` in W: | Repository owner |
| N22 | The kernel stop's HTTP handlers (`/emergency-stop`, `/emergency-resume`, `/emergency-status`) exist in `chio-http-core`, but no server mounts them. This is the concrete cause of EV11 | Open | M: `chio-http-core/src/routes.rs:33`; no non-test consumer of `handle_emergency_*` | Spec 8 S18 |
| N23 | The emergency handlers compare `X-Admin-Token` with `==`, not in constant time. This contradicts the sidecar control-credential precedent | Open | M: `chio-http-core/src/emergency.rs:193`; `docs/security/sidecar-control-authority.md:8-24` | Spec 8 S18 |
| N24 | W:'s `set_semantic_emergency_stop(scope, bool)` takes no actor, records no reason, authorizer or time, and has only a test caller | Open (W:) | W: `chio-store-sqlite/src/admission_operation_store/semantic.rs:369-386`; `chio-control-plane/src/recovery/tests/semantic.rs:443` | Spec 8 S5 (unify as the recovery scope behind an authenticated wrapper) |
| N25 | P4 records no influence join when tool output is delivered to a worker: `CapturedOutput` is defined but never constructed. A worker can absorb external data without its knowledge label rising, which defeats integrity gating. Separately, product reports and proposals are published with `externally_influenced: true, unknown: true` unconditionally, which over-taints (safe) | Open (W:) | W: `chio-security-types/src/knowledge/release.rs:59` (no construction outside definitions); `chio-store-sqlite/src/admission_operation_store/product/reports.rs:110-114`, `proposals.rs:86-90` | Spec 11 (output influence join on every delivery) |

### 3.2 Resolved or reclassified

| ID | Finding | Resolution |
|---|---|---|
| D9 | Resume tag keyed with the signing seed | Fixed on the baseline (V: `session_resume.rs:802-824`) |
| D10 | A2A mapped `PendingApproval` to `Failed` | Fixed (M: `conversion.rs:99`) |
| N7 | Recovery capture does not recheck the denied capability | **Not a defect in W:.** The continuation must reuse the seed capability (W: `.../recovery/issuance.rs:76-81`), so ordinary revocation checks cover it. It applies only to spec 2's new `Authority` kind, where step 3a closes it |
| N8 | No constraint binds a capability to exact arguments | **Not a defect in W:,** because recovery never mints capabilities. It is a requirement for spec 2's `Authority` kind (`RecoveryContinuationBinding`) |
| N11 | Stranded capacity has no closure path | Design gap, addressed by spec 4 section 8 (accounting, not reclamation) |
| N12 | Stale documents | Open: chio-process `ARCHITECTURE.md` mailbox list, `approval.rs` doc, the work kernel's stale #1160 checkpoint, and W0-W2 naming |
| | Confined-child status leak through `wait_children` or `inspect` (suspected) | **Verified not leaking** in worker-facing surfaces. `wait_children` refuses `confined_` ids, and `inspect` reports only the caller. Hosts other than the CLI runner must hold rule H9 (spec 5) |
| | `observe_recovery_source` has no actor check | Host-trusted query. Current control-plane callers authenticate the actor first (W: `chio-control-plane/src/recovery/runtime.rs:322-337`, `explanation/native.rs:80-93`). Spec 1 should classify it as a host-only query so a future caller cannot skip the check |

## 4. Corrections across revisions

1. FTL network access is not fully capability-gated: `NetCreate` and `ConsoleOpen` take no handle (spec 7 requirement Q1).
2. Chio's single-approver resume is library code that nothing in evaluation drives (D7).
3. Revision 1 duplicated designed work: a fault replay participant, a session-wide bus, a `confinement` receipt key, a closure-gate tool, and a governed closure effect.
4. Revision 2 relied on R: doc names that W: never implemented (N18), and asserted N7 and N8 as recovery defects. Revision 3 corrects both.

## 5. Cross-spec decisions

1. **One hint vocabulary, never authority.**
   - Spec 5's `HintSubject` and rules H1-H9 are the only notification semantics.
   - Recovery hints come from the recovery event chain.
   - Hints are audience-scoped (H9).
   - Spec 4 projects onto `Capability`, `Operation` and `Lifecycle`/`Terminal`.
2. **One remedy path.**
   - Every authority resolution flows through implemented recovery.
   - Spec 2 adds one planner fact, one remedy kind, one assessment and one linked-workflow template, and nothing parallel.
3. **A remedy dies with the denied capability.**
   - Spec 2 step 3a checks the predecessor seed's capability.
   - Spec 4 relies on it, and closes recovery workflows through `CancelWorkflow`.
4. **Reservation classes.**
   - Recovery call slots, provider lookups, grant issuance, D1 seals, F1 backing and process slots are `Commitment` entries with no compensator.
   - The drain releases only under `PreDispatchNoEffect` or `TransportNotAccepted`.
   - After an unknown outcome, only `MutuallyAgreedUnknown` or `ContractualCaptureWaiver` releases a hold.
5. **Durability for work.** Every work profile requires durable admission.
6. **One escape-hatch gate.** It is the Mechanism D gate, and it includes W:'s `Drop`-quarantine sites.
7. **Reuse shipped gates.** H11 budgets and the trust-boundary census. GT1 blocks any claim.
8. **Confinement bindings.**
   - Tool confinement uses `native_launch`.
   - Worker confinement uses `worker_profile`, including `confined_reader` evidence exported from P5.
   - Verifiable work requires confinement through `RuntimeAssuranceBacking`.
9. **Correlation stays out of the kernel.** `invocation_digest` (`binding.v2`) binds the D1 permit and the P4 model context. Under P4, lowering into a model is a release.
10. **Closure is manual and economically inert.** It never touches earned claims, sealed allocations, escrow deadlines, pins or knowledge, and it records stranded capacity.
11. **Name every crossing.** Dispatch commit, the recovery tombstone, P4 release and P5 return each declare their linearization point (spec 4's crossing table; brainstorm candidate 9).
12. **Process ABI v4.** The union of M:'s and W:'s v3 definitions is v4. Spec 5's `inspect` fields ride it.
13. **Signed surface is additive.** The program adds only metadata, artifacts and closed-enum variants:
    - spec 2: the `authority_fault` block, `RecoveryContinuationBinding`, the `Authority` remedy kind, and the `AuthorityContinuation` template;
    - spec 3: `chio_runtime.post_effect_fault`;
    - spec 4: closure artifacts;
    - spec 7: `worker_profile` and the confined-reader evidence export.

    No receipt kind, verdict variant or native wire message changes.

## 6. Sequencing

```text
protect the work first:
  N21      -> commit and push the W: recovery implementation to a branch (owner's decision)

bug-fix lane (needs no approval of the larger designs):
  N14      -> W: inspect returns the redacted snapshot under enforced knowledge (spec 5 P6)
  N15, N1  -> authority clock in W: control plane and in V:'s worker.rs
  D1, N2   -> spec 3 phase 1
  D3, D4   -> spec 5 transport hardening
  D6       -> spec 4 phase 1 overlay revalidation
  D8       -> spec 6 phase 1
  N3       -> spec 7 native_launch for adapted servers
  D2, N22, N23 -> spec 8 phase 1 (durable chain, boot load, mounted routes, constant-time credential)

merge planning (M: + V: + W:):
  N13 process ABI v4; N16 cage crate port; N20 classifier unification; N18 doc-to-code names

gates (blocked on GT1 for any claim):
  spec 1 registry, census and budgets; Mechanism D gate (with spec 3)

after recovery generalizes beyond one template (N19):
  spec 2 Authority remedy; spec 5 recovery projections at scale; spec 4 workflow closure at scale

after W1/W2 land:
  spec 2 AllocationHolder and Payer templates; spec 4 work trigger; spec 5 work hints
```

Suggested review order:
1. Spec 5 and spec 3, which carry live defects, including N14.
2. Spec 7, where P5 and the exporter apply.
3. Spec 4.
4. Spec 2.
5. Spec 1.
6. Spec 6.

## 7. Considered and rejected

| Idea | Rejected in | Reason |
|---|---|---|
| Kernel-carried opaque adapter cookie | Spec 6 | Edges are in-process, and P4 model contexts and operation keys already hold this state |
| Adopting FTL as an isolation backend now | Spec 7 section 8 | Ambient object creation, `lx` shares a domain with the workload, and there are no IPC, filesystem or quotas |
| Pre-reserving a receipt-log slot | Spec 3 | Moves the failure instead of removing it |
| A parallel fault replay participant or remedy path | Spec 2 | Recovery owns single use and continuations |
| Swapping capability inside one recovery workflow | Spec 2 revision 3 | W: pins one capability per workflow. A linked workflow keeps that invariant |
| A new authority obligation type in grant v2 | Spec 2 revision 3 | Keeps issuers separate from approvers. Authority evidence stays in the prerequisite step |
| Kernel-minted or standing fault resolutions | Spec 2 | The kernel is a verifier, not an issuer |
| A reserved mailbox channel for process control hints | Spec 5 | It is charged to the call budget, so a process with no budget left could never learn it was cancelled |
| A new `confinement` receipt key | Spec 7 | `native_launch` already binds tool launches |
| `output_channels` as a gating surface | Spec 7 revision 3 | No tool-lane cage could then be fully enforced. It is reported instead |
| `GovernedResponseEffect::CloseAuthoritySpace` | Spec 4 | Permanent revocation remains manual |
| Line-count TCB gates and a new closure-gate tool | Spec 1 | H11 budgets and op census measure attack surface; line counts don't |
| Live patching of running agents | Brainstorm | Conflicts with `PROCESS_ABI` pinning and determinism |

## 8. Follow-on brainstorm

`docs/research/2026-10-04-ftl-lessons-brainstorm.md`:

| Candidate | Status |
|---|---|
| 1. Split-domain workers | Folded into spec 7 section 6, alongside P5's `confined_reader` |
| 2. Durable stop epoch | Specced as spec 8 (`2026-10-04-durable-stop-epoch-design.md`) |
| 3. Process exit as an authority transition | Recommended as a small spec |
| 4. Closure lemma | Folded into spec 4 section 11 |
| 5. Constraint-enforcer registry | Fold into spec 1, or a small spec |
| 6. Revocation confirmation token | Fold into spec 4 |
| 7. Verifiers as reference monitors | Fold into spec 1 |
| 8. Cross-owner hints | Deferred |
| 9. Crossing-point registry | Shared rule for specs 1 and 4. Spec 4 already has the crossing table |
