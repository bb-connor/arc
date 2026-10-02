# Chio Kernel Breakthrough Research Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans to execute this research
> plan task by task. Read the research design and pinned recovery baseline first.
> Checkboxes track evidence-producing work, not confidence or aspiration.

**Goal:** Establish or reject a consequential kernel contribution for secure,
recoverable agent work across independent owners before rewriting the flagship
whitepaper.

**Architecture:** Assume PR #1172 revision 3 is shipped, as the user instructed.
Investigate the composition of its native authority, knowledge, recovery and
effect contracts with delegated work obligations. Challenge the complete system
against strong conventional and OpenAPPA/Agoric constructions before adding code.

**Tech Stack:** Repository research/spec documents; pinned primary literature and
source; existing recovery trajectories and native Rust boundaries; a bounded
Rust experiment and Lean only where needed for the selected result.

**Spec:** [Research design](../specs/2026-10-02-kernel-breakthrough-research-design.md).
**Evidence baseline:** [Recovery manifest](../../research/kernel-work/recovery-baseline.json),
[prior art](../../research/kernel-work/2026-10-02-prior-art.md), and frozen paper
checkpoint `5e1715636f2b66295ec3022d6161b91cb77a658d`.

## Global constraints

- Keep the approved title, Chio: A Peer-to-Peer Economy of Verifiable Work.
- Freeze `docs/papers/verifiable-work/` until G4. Preserve its negative results.
- Treat all revision-3 P0-P6 recovery contracts in PR #1172 as the assumed shipped
  baseline. Do not duplicate its feature implementation plan or block conceptual
  work on its present implementation status.
- The complete kernel/recovery design can be the contribution. No unrelated new
  feature is required merely to make the research look novel.
- Use one native admission/execution authority. Keep workflow, step,
  continuation, process request and native operation identities distinct.
- Preserve exact signed custody, operation-owned nonce recovery, one unresolved
  effectful continuation per workflow, and scoped historical settlement.
- Preserve confidentiality/influence history and exact multi-owner release
  authority. A financial resolution does not establish effect truth.
- Give baselines ordinary extensions, protected state, recovery, strong host
  mediation, the same provider semantics and equivalent settlement/checker trust.
- No em dashes; signed payloads use the repository's canonical JSON rules;
  malformed or unsupported authority/evidence fails closed.
- Do not modify the user's original checkout, active security worktree or
  recovery implementation branch while executing research tasks here.
- No publication, deployment, real-funds transaction or outside contact follows
  from this plan. Existing external trial and release gates remain separate.
- Assumed semantics, model results, measured implementation results and outside
  reproduction must be distinct fields in every contribution decision.

## Review focus

1. **Unknown effects disguised as failed calls:** no replacement identity,
   released execution exposure or success claim from timeout, denial or refund.
   Covered by F05-F07 and F14 in Tasks 2, 4 and 5.
2. **Local recovery mistaken for cross-owner composition:** keep exact owner,
   authority, label, obligation and backing references across each edge.
   Covered by F02-F03, F08 and F12-F13.
3. **Revocation blocking settlement or authorizing new work:** original-operation
   settlement may continue under its narrow recovery owner; current release and
   provider-observation authority remain separate. Covered by F04 and F07.
4. **Safety obtained by stopping all work:** include allowed exact remedies,
   authoritative reconciliation and separately authorized independent branches.
   Covered by F01, F06 and F09, plus the deny-all control in Task 4.
5. **Comparison that manufactures an advantage:** permit baseline improvements,
   match observations/trust/resources, and count assistance and adapter code.
   Covered by Task 1 counterdesigns and Task 6 preregistration.

## Execution order and decision gates

Tasks 1-3 are the immediate research work. Their outputs determine whether a
prototype is justified. Tasks 4-6 are conditional experiments, with fixed
questions and deliverables; the selected mechanism's implementation interfaces
are specified at G1, not invented in advance of the research answer. Task 7 is
the only path back to the paper.

| Order | Output | Decision |
| --- | --- | --- |
| 0 | This preserved brief, source pass and recovery baseline | Planning package, not a breakthrough result |
| 1 | Strongest counterdesign and claim register | G0: a precise consequential question |
| 2 | Common model, proof obligations and adversarial scenarios | A comparison both sides can satisfy or fail |
| 3 | Minimal witness, algorithm/tradeoff proposal and written novelty judgment | G1: pursue, narrow or reject |
| 4 | Proof/counterexample analysis and bounded executable comparison | G2: mechanism evidence and useful progress |
| 5 | Native cross-owner trace correspondence and fault experiment | Evidence for the implemented composition |
| 6 | Independent critique, second-family comparison and applicable trial results | G3: generality and external claims |
| 7 | Contribution decision and exact paper claim budget | G4: justified manuscript re-entry |

No calendar deadline can guarantee a discovery. Bound the first pass to one
serious counterdesign for each of B1-B3 and one worked witness for each surviving
R1/R2 claim. A second pass must be motivated by a new source, counterexample or
concrete model change. Do not keep adding signatures or subsystems to postpone
an equivalence finding.

## Task 0: Preserve the corrected brief

**Files created by this planning pass:**

- `docs/research/kernel-work/README.md`: entry point and resume state.
- `docs/research/kernel-work/2026-10-02-prior-art.md`: source observations and
  competing constructions, with reading depth.
- `docs/research/kernel-work/recovery-baseline.json`: PR/source pins, user-supplied
  shipped assumption, document hashes and all 111 requirement IDs.
- `docs/superpowers/specs/2026-10-02-kernel-breakthrough-research-design.md`:
  preserved intent, hypotheses, proposed model and research decisions.
- This plan: ordered tasks and acceptance boundaries.

- [x] Preserve the title, larger kernel/economy ambition and manuscript critique.
- [x] Preserve the receiver-owned baseline and ERC-8183 negative results.
- [x] Inspect the current paper checkpoint and relevant native source boundaries.
- [x] Conduct a primary-source first pass, including current agent-kernel work.
- [x] Incorporate the user's PR #1172 clarification and pin revision 3.
- [x] Define candidate contributions, falsifiers, dependencies and paper gates.
- [x] Validate links, source hashes, requirement coverage and unchanged paper tree.
- [x] Commit the research package with a conventional documentation message.

## Task 1: Build the strongest counterdesign before choosing the claim

**Read:** the design, all S01-S24 entries relevant to R1/R2, and the pinned
PR #1172 architecture and preceding OpenAPPA research. The baseline manifest
gives immutable remote links; the PR need not be merged into this worktree.

**Create:** `docs/research/kernel-work/counterdesigns.md`,
`docs/research/kernel-work/recovery-crosswalk.md`, and
`docs/research/kernel-work/claim-register.json`.

**Consumes:** the recovery semantics under the explicit shipped assumption, the
historical evidence pins and the dated source comparison.
**Produces:** one common problem statement, B1/B2/B3 constructions and claim
records usable by every later experiment.

- [x] Read the full claim-relevant protocols and assumptions for OpenAPPA,
  Agoric, Beldi/RIFL, knowledge-based action and coordination avoidance. Record
  exact section/source revisions; retain remaining unknowns instead of inferring
  absence from an abstract. Inspect recent agent systems for the chosen property.
- [x] Map each used recovery capability to its PR #1172 requirement IDs and
  future experiment seam. Keep existing P0-P6 implementation/qualification
  ownership with that effort. Record any genuinely new cross-owner contract
  separately from supplied baseline behavior.
- [x] Write B1 conventional services, B2 capability contracts and B3 recoverable
  enforcement with the same trust, observation, effect and resource assumptions
  as Chio. Specify independent local engines and any shared settlement authority.
- [x] Walk the support-to-public-issue example through each construction,
  including a paid specialist, exact multiple-owner approval, lost acknowledgement
  and parent cancellation. Identify the actual missing rule or extra machinery.
- [x] Create R1/R2/R3 claim records with fields `id`, `statement`, `status`,
  `assumptions`, `recovery_requirements`, `closest_prior_art`, `counterdesign`,
  `observable_difference`, `falsifier`, `evidence`, and `next_test`. Initial
  `status` is `hypothesis`; use `not_examined` for an uninspected behavior.
- [x] Write a G0 decision. Reject unsupported exclusivity claims immediately.
  Retain an algorithm, trust/coordination tradeoff or meaningful systems question
  only if its observable difference and importance can be stated precisely.

**Acceptance:** a reviewer can build a strong conventional solution from the
description, and can say exactly what would defeat the proposed Chio claim.
Adding one ordinary field or using a competent local authority must not invalidate
the comparison setup. No implementation is required to reach G0.

**Completion record:** [Task 1 acceptance and verification](../../research/kernel-work/task1-validation.md). G0 proceeds to one shared model; no novelty, implementation or paper-readiness promotion.

## Task 2: Define one common model and the decisive scenarios

**Create:** `docs/research/kernel-work/MODEL.md` and
`docs/research/kernel-work/fixtures.json`.
**Consumes:** the G0 claim records, the baseline crosswalk and B1-B3.
**Produces:** exact state/event definitions, trust parameters, expected outcomes,
and a finite profile shared by Chio and the selected executable baseline.

- [x] Define `Owner`, `WorkEdge`, `LocalWorkflow`, `LocalOperation`,
  `ResourceAllocation`, `Observation`, `ReleaseAuthority`, `Obligation`,
  `EffectContract` and `EvidenceRef`. Map them to existing recovery types rather
  than introducing competing production authority. State which owner controls
  each field and which facts require external evidence.
- [x] Define separate execution, knowledge/release and financial state. Include
  unknown execution, completed-but-withheld output, and historical settlement
  after initiating authority expires. Preserve immutable historical records.
- [x] Define the supported finite DAG and initial bounds. Respect the recovery
  profile's 16 offers, 8 top-level remedy steps, 32 expanded nodes, depth 8,
  64 evidence references, 16 approval attestations, 64 KiB envelopes, nesting
  32 and aggregate 4,096 entries where applicable. Smaller exploration bounds
  must be named and must not redefine production limits.
- [x] Define E1 authoritative lookup and E2 opaque external effects. State
  idempotency scope, retention, transport submission cardinality, closure/fencing,
  partial effects, and what observations an honest receiver actually has. Use
  one submission unless an explicitly supported extension authorizes more.
- [x] State K1-K7, the honest-owner quantification and the intended progress
  property. Separate scope attenuation from additive resource accounting.
  Formulate information-flow/release claims independently of monetary safety.
- [x] Encode the following scenarios as symbolic commands and assertions. Every
  refusal has a relevant authorized positive counterpart. Each fixture records
  `id`, `profile`, `initial_state`, `commands`, `faults`, `observations`,
  `expected_effects`, `expected_authority`, `expected_knowledge`,
  `expected_resources`, `expected_obligations` and `expected_progress`.

| Case | Required observation |
| --- | --- |
| F01: Exact approved remedy | Materialized public issue is sent once after all required owners approve; originals and knowledge restrictions persist |
| F02: Owner/authority substitution | Partial coverage, duplicated signer aliases, wrong endorsement power or cross-owner grant deny without an effect |
| F03: Changed basis | Changed bytes, recipient, provider account, policy or ACL invalidate the affected approval; unrelated owner activity does not invalidate everything |
| F04: Nonce/custody acknowledgement loss | Original request and original issuance recover; no fresh grant, nonce, quota charge or execution identity |
| F05: Ambiguous opaque effect | Two externally different histories yield the same local observation; neither refund nor denial authorizes a blind replacement |
| F06: Authoritative reconciliation | Exact E1 evidence recovers the original outcome; incomplete lookup and unfenced not-found cannot establish no effect |
| F07: Revoked initiator | Narrow internal settlement still works for the original operation; revoked result audience remains unable to read it |
| F08: Confined paid child | Seed, result, errors and metadata preserve declared restrictions; a bounded authorized return can still enable useful parent work |
| F09: Independent branch and shared resource | A separately authorized workflow can continue where its allocation and prerequisites suffice; parent/child restart does not reset shared consumption |
| F10: Forked backing | Two 60-unit obligations cannot consume the same 100-unit reserve; retained child entitlement survives parent refund |
| F11: Authentic malicious evidence | Re-signed wrong context, substituted acceptance or conflicting transcript fails binding rather than only signature verification |
| F12: Owner-policy translation | Combining owner/compartment identities preserves every required restriction; an unsupported mapping refuses rather than dropping one owner |
| F13: Dependency lifetime | Historical review, current predicate and held reservation remain distinct at capture; an expired lock is not a valid prerequisite |
| F14: Immutable outcome | Repairing a projection does not rewrite terminal unknown history, erase partial effects or manufacture work success |
| F15: Retention and stale owner | GC, restart, snapshot rollback and old coordinator activity cannot revive consumed authority or delete unresolved ownership |
| F16: Advisory and bounded search | Exhausted or infeasible planning yields explicit advice status; no report, explanation digest or offer becomes a live execution permit |

**Acceptance:** each side receives the same visible facts. Hidden effect counters
are available only to the experiment oracle. All fixture identifiers are unique;
all expected states derive from the common model. A table of denials alone fails
this task. Existing PR #1172 trajectories supply baseline cases; add cross-owner
assertions instead of rewriting their entire suite.

**Completion record:** [KW1 model](../../research/kernel-work/MODEL.md) and [fixture families and variants](../../research/kernel-work/fixtures.json); structural checks passed. Execution assertions are qualified in Task 4, not presumed here.

## Task 3: Find a nontrivial witness and choose the smallest contribution

**Create:** `docs/research/kernel-work/WITNESS.md` and
`docs/research/kernel-work/G1-DECISION.md`.
**Consumes:** common model, fixtures and counterdesigns.
**Produces:** a selected mechanism and exact experimental specification, or a
preserved negative result with no premature implementation.

- [x] Work through at least one identical-observation pair and one useful
  cross-owner remedy by hand. Name the fact, authority or dependency that
  determines whether the next action is legal.
- [x] Try to reproduce the same result in B1-B3. Repair those constructions
  wherever ordinary engineering permits. Record the minimal additional state,
  trust, coordination or application logic on both sides.
- [x] State the candidate composition theorem and its premises, or the proposed
  algorithm and its complexity/progress claim. Explain the consequence beyond
  K1-K4 holding individually. A definition equivalent to its own checker is not
  an adequate theorem contribution.
- [x] If the contribution is a systems tradeoff, preregister the primary metric,
  important effect size and workload boundary before measuring it. Keep the
  original H2-H4 thresholds where those claims are used; do not invent favorable
  targets after seeing results.
- [x] Choose `pursue`, `narrow` or `reject` for each claim with the strongest
  objection attached. A new implementation of an old rule may be valuable; say
  exactly whether that leaves a scientific contribution to investigate.
- [x] For `pursue`, write the small experiment design: selected transitions,
  algorithm inputs/outputs, baseline ports, proof statements, named scenario
  assertions, resource bounds, run commands and source files. This completes
  the mechanism-specific design before Task 4 writes code.

**G1 acceptance:** the proposed result is consequential, falsifiable, and not
already settled by the counterdesign. It can come from the shipped-assumed
recovery architecture itself. A negative decision is a completed research result,
not permission to relabel the existing escrow paper a breakthrough.

**Completion record:** [witness and counterdesign repairs](../../research/kernel-work/WITNESS.md), [G1 decision and preregistration](../../research/kernel-work/G1-DECISION.md). R1 narrowed, R2 algorithm novelty rejected, R3 pursued conditionally; no foundational result established.

## Task 4: Establish the mechanism with proofs and executable controls

**Conditional on G1. Create:** an isolated `labs/kernel-work-composition/` with
its own `Cargo.toml`/`Cargo.lock`, `src/model.rs`, `src/continuation.rs`,
`src/baseline.rs`, `src/bin/explore.rs`, `tests/scenarios.rs` and `README.md`.
Create `docs/research/kernel-work/results/G2.md` and retained evidence under
`docs/research/kernel-work/results/model/`. No root workspace dependency change.
If a theorem is central, put its Lean definitions/proofs in the lab's `proof/`
directory with an explicit pinned toolchain and one documented build command.

**Consumes:** the mechanism-specific G1 design and shared fixtures.
**Produces:** a checked argument/counterexample corpus with an honest proof scope,
an executable conventional baseline, and evidence for safety plus useful progress.

- [x] Add the named F01-F16 scenario assertions for the selected profile before
  implementing the candidate reducer. Observe their expected initial failures.
  Encode known-good baseline behavior without disabling any permitted mechanism.
- [x] Implement the smallest pure state transition and continuation procedure
  described by G1. Use existing pure recovery semantics as specified inputs;
  never label a spec adapter a production implementation.
- [x] Enumerate bounded schedules including duplicate delivery, concurrent
  admission, crash/reopen, stale epochs and contradictory evidence. Preserve
  concrete counterexamples and the bounds/source hashes in machine-readable output.
- [x] Compare the candidate against the strongest selected baseline and explicit
  deny-all/retry-all controls. The former must lose useful progress; the latter
  must violate safety in the ambiguous effect case.
- [x] Run removal experiments only on the candidate mechanism. Attribute each
  lost property to the intended missing rule, with a positive matched case.
- [x] Prove the selected statements if the claim requires them. Do not replace
  an arbitrary-trace theorem with finite exploration or present generic conserved
  arithmetic as the cross-owner composition theorem. Record assumptions and any
  unproved implementation correspondence beside each result.
- [x] Record G2 as passed, narrowed or failed. Report safe progress, uncertainty
  and algorithm/state cost together; reject a win purchased by hidden knowledge,
  extra trusted authority, weaker policy or reduced workload semantics.

**Checks:** `cargo test --locked --manifest-path labs/kernel-work-composition/Cargo.toml`
and the documented deterministic explorer/proof commands. Every process must
finish and retain its exit code. A proof of protocol semantics is distinct from
proof of production Rust correctness.

**Completion record:** [G2 result and acceptance](../../research/kernel-work/results/G2.md), [fresh review and one correction pass](../../research/kernel-work/results/REVIEW.md), and [source-bound verification](../../research/kernel-work/results/model/verification.json). All 36 tests, 66 variants per arm, 126,893 bounded transitions, controls and removals pass their declared expectations. Scientific result remains narrowed; no native, arbitrary-trace or breakthrough claim is promoted.

## Task 5: Connect the result to actual kernel behavior

**Conditional on G2. Create:**
`docs/research/kernel-work/results/native-crosswalk.md`,
`docs/research/kernel-work/results/native/`, and an owning integration-test
design for the smallest new composition boundary.
**Consumes:** G2 transitions plus implementation/evidence delivered by PR #1172's
owners. **Produces:** source-bound correspondence and end-to-end fault traces.

The paper's conceptual baseline remains the instructed shipped specification.
Native measurements require an actual pinned implementation; import those when
available rather than inventing results or taking over the recovery roadmap.
Proof and baseline analysis can continue independently of that evidence handoff.

**Existing source anchors to inspect on the selected candidate:**

| Boundary | Existing anchor or recovery owner |
| --- | --- |
| Immutable operation state and bindings | `crates/kernel/chio-kernel/src/admission_operation.part1.inc`, `.part2.inc`, `.part3.inc` |
| Durable ownership and capture | `crates/platform/chio-store-sqlite/src/admission_operation_store/` and PR #1172's kernel recovery participant |
| Process recovery and aggregate resources | `crates/kernel/chio-process/ARCHITECTURE.md`, `tests/crash_recovery.rs`, `tests/aggregate_family.rs`, `tests/nonce_recovery.rs` |
| Cross-owner permits and funded evidence | `examples/federated-work/src/subcontract/permit.rs`, `src/funded_work/wire.rs`, `src/funded_work/execution_evidence.rs` |
| Existing abstract admission proof | `formal/lean4/Chio/Chio/Treaty/AdmissionBinding.lean`; preserve its declared model-only boundary |
| New recovery implementation | Resolve actual paths from PR #1172's source/requirement crosswalk; proposed names are not assumed existing files |

- [ ] Pin the combined source and supported profile. Map each G2 transition to
  its real native function, commit/dispatch boundary and inherited recovery test.
  Preserve separate process/native digests and original-operation nonce custody.
- [ ] Specify only the remaining cross-owner adapter or test changes. Review
  that concrete implementation design before editing production code. Reuse the
  PR's complete mediation and remedy machinery.
- [ ] Run the two-owner/three-owner trajectory with real process death and
  independent endpoint counters. Include loss before/after admission intent,
  capture, effect, outcome persistence and authorized release.
- [ ] Verify that hidden transport retries, forged context and withheld outputs
  cannot create an extra effect; verify that the authorized positive trajectory
  still completes with the expected budgets and obligations.
- [ ] Reconcile model and native traces. Any mismatch changes the implementation
  or narrows the model claim; an explanatory paragraph cannot count as a passing
  correspondence check.

**Verification scope:** run owning changed-boundary tests first. The existing
`chio-process` crash, aggregate-family and nonce suites and
`cargo test --locked -p chio-kernel --test durable_admission_sqlite` are relevant
anchors. Run them at
the selected source; historical logs do not constitute fresh results. Broaden
only for an actual integration boundary or unresolved risk. Preserve all failed
or interrupted runs and the exact reason for any unsupported feature combination.

## Task 6: Test generality, significance and external claims

**Create:** `docs/research/kernel-work/results/comparison-preregistration.md` and
`docs/research/kernel-work/results/independent-review.md`. Append measured
results only after the corresponding experiments occur.
**Consumes:** G2/native evidence, the recovery benchmark contract and existing
external-trial package. **Produces:** a bounded scientific-significance decision
and evidence for exactly the empirical claims tested.

- [ ] Reuse the support-to-public-issue and confined-research/bounded-return
  families in PR #1172. Run the same core composition rules on both. Record every
  added adapter, policy exception and host-side repair rule.
- [ ] Preregister matched actors/models, task corpus, provider semantics, trust,
  budget, failures, assistance and measurement boundaries. Count actual effects,
  quality, safe completions, approvals, blocked time, state/latency cost and
  operator interventions. Separate human wait, model cost and kernel overhead.
- [ ] Obtain adversarial critique of the mechanism and strongest counterdesign.
  Give reviewers the failed hypotheses and source pins. Automated review can
  supplement this but must not be labeled independent human expert review.
- [ ] Use the existing trial kit when independently operated participants become
  available. Preserve Q1-Q10, H1-H5, matched C0-C3 controls, pilot/power design,
  six paired integration exercises, and full failed-attempt/capital accounting.
- [ ] For quantitative integration claims, measure hands-on implementation/setup
  and recovery effort with independent teams. Code-line counts alone cannot
  establish reduced engineering cost; report initial and repeated integration
  separately. A single newcomer exercise is a demonstration, not a population
  estimate.
- [ ] Decide G3 separately for mechanism generality, independent operation,
  integration advantage and useful economics. No partner means the latter
  external evidence remains open; it does not erase completed theoretical work.

**Acceptance:** contribution importance follows from a defended result and
measured consequence, not from a score, feature count or anticipated applause.
An external pilot cannot turn already known escrow behavior into a new mechanism.

## Task 7: Decide what the paper has earned

**Create:** `docs/research/kernel-work/CONTRIBUTION-DECISION.md`.
**Consumes:** claim register, G0-G3 decisions, original H1-H5 evidence and reviews.
**Produces:** the precise scope and evidence budget for a later manuscript change.

- [ ] Write one paragraph each for the obstacle, mechanism, established result
  and consequence. State essential assumptions within the result, and show how
  the closest prior art differs under comparable conditions.
- [ ] List every contemplated abstract claim with its proof, implementation,
  baseline and empirical support. Explicitly identify use of the user's assumed
  shipped recovery specification and the actual provenance of measured results.
- [ ] Choose one disposition: foundational candidate supported; strong but
  narrower systems result; useful implementation without established research
  advance; or rejected hypothesis. Attach the strongest objection and what
  would change the decision. Do not assign a breakthrough score.
- [ ] For a supported flagship result, mark G4 and write a paper revision plan
  around the actual kernel contribution. The old funded-work artifact becomes
  supporting evaluation. Keep the title unless the user changes it.
- [ ] If only a narrower claim survives, report that outcome and resolve the
  publication scope with the user before rewriting. Preserve the current paper
  and all negative research evidence.

The new abstract should then make one consequential result unmistakable. It
should neither hide essential assumptions nor end by leaving its central
technical promise unestablished. Editing the abstract is the output of this
decision process, not its first experiment.

## Planning verification record

This section records checks of this documentation package only. New protocol
proofs, experiments, native test results and external trials are not claimed by
this planning pass.

On 2026-10-02, the documentation check verified all 28 relative file links and
section anchors, the
no-em-dash rule, exact equality of all 111 recovery requirement IDs, and SHA-256
agreement for the 16 pinned recovery/research source documents. It also verified
that the tracked paper/artifact directory matches checkpoint
`5e1715636f2b66295ec3022d6161b91cb77a658d`, with no added untracked paper files.
The preserved paper Git tree is `b8c5b771ca04903e219f9b42a50a050d326ba0ac`.
The package contains 24 prior-art entries, 16 scenario definitions, seven proof
obligations and five research gates. These counts describe the plan's coverage,
not completed research results.

Inline review checked intent coverage, supplied recovery semantics, baseline
fairness, scenario-to-obligation mapping and the distinction between assumptions
and measured results. It corrected the composition obligation to include the
cross-owner release property and made provider-deduplicated resubmission remain
conditional on its separately supported recovery profile. The initial lookup of
the PR commit was absent locally; fetching that exact PR made the source available
without changing the worktree's branch. No runtime or full-workspace test run was
needed for this documentation-only change.
