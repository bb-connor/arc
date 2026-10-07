# Chio kernel breakthrough research design

Date: 2026-10-02. Status: proposed research direction and preserved decision brief.
Companion: [execution plan](../plans/2026-10-02-kernel-breakthrough-research.md).
Sources: [prior-art comparison](../../research/kernel-work/2026-10-02-prior-art.md).

## 1. The outcome the user wants

Chio is intended to be the kernel for agentic operating systems and the agentic
economy. The approved title remains **Chio: A Peer-to-Peer Economy of Verifiable
Work**. The user wants a foundational technical contribution supporting that
vision, with the clarity and consequence associated with the Bitcoin whitepaper.
They explicitly asked for this research and planning stage before another paper
edit so the ambition, critique and candidate ideas survive changes of context.

The research question is:

> Can untrusted agents delegate consequential work across independently owned
> systems while each participant retains enforceable bounds on authority,
> resource use, knowledge and obligations through delegation, failure and recovery?

An affirmative answer alone is insufficient: existing systems can already do
parts of this, and a competent composition may do all of it. The result must
identify a consequential new capability, a materially better trust/coordination
tradeoff, or a substantial and general reduction in the machinery needed to
obtain the same guarantees. A systems breakthrough can combine familiar ideas.
It does not require inventing every component or proving competitors incapable
of expressing its wire format.

Community reaction cannot be an acceptance test. A compact, important result
that survives strong counterexamples can be. Nor does a foundational paper need
to demonstrate an already flourishing economy. It must resolve the specific
technical obstacle that makes its vision credible. Operational adoption and
economics need their own evidence when the paper claims them.

### The user's recovery baseline instruction

During this planning pass the user clarified that the recent recovery research
and specifications should be assumed shipped for the paper. Apply that instruction
to [PR #1172](https://github.com/bb-connor/arc/pull/1172), revision 3 at
`de84fc306efbb4c8dd6de748d0ad2a8d695fd30e`, including all P0-P6 capabilities and
111 acceptance requirements. The [baseline manifest](../../research/kernel-work/recovery-baseline.json)
records the exact source hashes and requirement IDs.

The research baseline therefore includes exact recovery offers and grant v2,
conjunctive multi-owner approval, bounded counterfactual planning, semantic
connectors and transformations, durable labeled artifacts/checkpoints, confined
children and mediated returns, and scoped historical settlement. Assume those
contracts hold; implementation scheduling remains with the recovery effort.

This changes the question from building recovery to establishing what the full
kernel-plus-recovery design enables. That design may itself contain the needed
contribution when composed and explained precisely. We do not require an extra
invention just because its implementation is already planned. The PR's finite
models and local semantics are inputs; a theorem about composition across
independent owners and the comparative scientific result are still to establish.

For provenance only: the inspected PR describes proposed architecture. The user's
instruction supplies the shipped assumption for research and future manuscript
architecture, not fabricated performance numbers or a claim that an external
trial occurred. Keep this distinction in the evidence register, without using
unfinished implementation as a reason to postpone conceptual research.

## 2. Preserve the diagnosis and previous negative results

The source checkpoint is `5e1715636f2b66295ec3022d6161b91cb77a658d`. The
[funded-work manuscript](../../papers/verifiable-work/paper.tex) and
[review](../../papers/verifiable-work/REVIEW.md) are complete bounded artifacts.
Their central monetary results concern conservation of funded allocations and
survival of an earned child claim when a parent fails. Our own
[ERC-8183 comparison](../../papers/verifiable-work/evidence/erc8183/REPORT.json)
reproduces those economic outcomes with unchanged upstream code. Its retained
record also includes partial settlement supported by the alternative.

The abstract opens with a real problem, then leaves the main added value of its
composition insufficiently established. Its final qualifications are evidence
of that gap. Removing them would inflate the claim. The editorial correction
comes after a stronger result: state the obstacle, mechanism, established
consequence and essential assumptions clearly; put peripheral implementation
limitations in the body. Do not draft another abstract during this program's
discovery stages.

The earlier [breakthrough judgment](../../papers/review-2026-09/15-breakthrough-judgment.md)
also defeated the claim that existing protocol compositions inherently cannot
implement receiver-owned authority. Receiver-issued tokens, protected local
records and ordinary extensions are legitimate alternatives. Preserve both
negative results as mandatory controls, not historical inconveniences.

| Observation to retain | Consequence for this program |
| --- | --- |
| Receiver ownership fits an ordinary token/profile construction | Never restrict the baseline to selected base-schema fields |
| Separate funded escrows reproduce child independence | Do not make escrow bookkeeping the new flagship theorem |
| Local durable recovery and signed unknown outcomes already exist | A new name for uncertainty is insufficient novelty |
| Existing Lean models do not prove Rust-hook equivalence | State the exact proof boundary and implementation evidence separately |
| Correctness review found no major defect in a bounded artifact | That is not independent scientific endorsement of significance |
| No outside partner is available | Prepare external work, but continue theoretical and local comparative research |
| Security hardening remains separately qualified | Neither a theorem nor a paper artifact closes production release gates |

The [uncertain-work report](../../papers/review-2026-09/33-verifiable-uncertain-work.md)
and [bounded subcontract report](../../papers/review-2026-09/35-bounded-intercompany-subcontracts.md)
are useful starting points. They explicitly identify the familiar-composition
objection. This program must confront it before extending those examples.

## 3. Three candidate contributions

All three candidates are hypotheses. R1 is the recommended organizing question;
R2 is its first demanding probe. R3 is a distinct systems route if the evidence
supports it, not an automatic substitute for the requested foundational result.

| Candidate | Proposed result | Why investigate | Strongest objection and stop condition |
| --- | --- | --- | --- |
| R1: Compositional work semantics | A small composition contract for the assumed shipped kernel and recovery system preserves each honest owner's authority, knowledge restrictions, resource bounds and obligations across work edges | Directly connects the operating-system and economy ambitions | A capability system, durable workflow, recoverable IFC runtime and escrow obtain the same result with comparable assumptions and machinery; a conjunction of existing invariants is not enough |
| R2: Cross-owner safe progress | Composing local recovery offers, exact approvals and effect contracts enables useful continuations across owners without weakening their restrictions or resetting uncertain work | Tests the consequence of PR #1172 under independent administration | OpenAPPA plus ordinary recovery mechanisms reproduces it; local remedy enumeration or a restatement of safe action is insufficient |
| R3: Reusable independent work execution | One public kernel contract achieves the same guarantees with substantially less repeated integration, recovery code or central trust across task families | Could establish a strong systems contribution even without a new impossibility result | Advantage comes from a weak baseline, undocumented expert assistance, reduced functionality, shared administration or moving costs into adapters |

Do not pursue all three as independent product initiatives. Start with the
smallest R1/R2 model and the strongest counterdesign. Use R3 measurements to
test whether the mechanism generalizes; if only R3 survives, explicitly revise
the proposed scientific claim and present that judgment to the user.

Deprioritize new settlement rails, additional agent SDKs, broad marketplaces,
reputation tokens, a new blockchain, universal work verification and branding.
Each would expand implementation without resolving the current novelty question.

## 4. Proposed model and the mechanism to investigate

The following vocabulary is a research model over the assumed shipped recovery
contracts, not a proposed replacement wire
protocol. Reuse existing identifiers and authority stores wherever they already
represent the required fact. Do not introduce a second dispatch coordinator.

**Work edge.** A delegation from one owner to another binds the input and result
predicate, authorized actor and receiver, applicable policy, resource allocation,
effect profile, funding reference when needed, and parent dependency. A remote
signature supplies evidence under an explicit trust rule; it does not activate
a local issuer root or establish that the remote host enforced its policy.

**Local operation.** Reuse PR #1172's distinct workflow, step, continuation,
process-request and native-operation identities, including its distinct intent,
process and native-material digests. The receiver durably binds its authorization decision,
resource reservation and dispatch identity before an effect can escape. Recovery
uses that original identity. Cross-domain work edges reference local operations;
they do not require every organization to share one database or global sequence.

**Three separate records.** Preserve execution knowledge, permission to act next,
and financial disposition as separate but bound state. A refund can settle a
contract without proving that an external write did not happen. A signed receipt
can establish who asserted an outcome without proving arbitrary output quality.
A verifier can check an agreed predicate without establishing that the predicate
captures everything a buyer values.

**Evidence-dependent continuation.** Use PR #1172's bounded local planner,
`PlanDecision`/`WorkflowDirective` separation, exact materialization, and native
capture. Investigate the cross-owner composition rule relating those decisions
to resource commitments, disclosure authority and outstanding work obligations.
The potential contribution is the resulting compositional algorithm and its
demonstrated tradeoff. The generic
principle that one must know an action's preconditions is established prior art
(S12 in the source comparison).

### 4.1 A concrete failure that the model must explain

A buyer commissions a public issue derived from a private support ticket. Its
provider hires a specialist through a confined, bounded-return contract. The
specialist earns its payment. Required data owners approve the exact publication
after the result is materialized. The issue receiver may have applied the write
when the provider crashes,
but the provider has no durable acknowledgement. A sibling task is independent.

This extends PR #1172's first vertical slice with independent owners and funded
specialist work. The proposed model must determine all of the following without treating a
timeout as proof of failure:

- Which owner authorized each step, and which resource remains committed.
- Whether publication can be reconciled or retried under its original key.
- Whether the sibling may continue under already partitioned authority/budget.
- Which new actions require additional authorization or outcome evidence.
- How a denied disclosure can obtain an exact remedy without clearing retained
  knowledge, disclosing the private approval basis, or bypassing an owner.
- Why a parent failure cannot consume an independently earned child allocation.
- What the buyer can independently verify and what still depends on the selected
  receiver, verifier, settlement authority or local host being honest.

Use two publication interfaces in the first model. E1 provides durable
idempotency and authenticated outcome lookup with explicit retention semantics.
E2 is an opaque, non-idempotent external effect with no authoritative outcome
lookup. Their different recovery possibilities must remain visible. Grant both
interfaces, and all relevant metadata, to the conventional baseline too.

The E2 case is a necessary negative control. No kernel can reconstruct an
unobserved effect merely by signing its uncertainty. Safe progress may require
waiting, a new authorized exposure allowance, or stopping that dependent branch.
Independent safe work may still proceed. Do not promise universal exactly-once
effects, universal completion, or free recovery of every reservation.

PR #1172 permits one unresolved effectful continuation per workflow. Independent
branches in this experiment must have their own authorized workflows and shared
budget attribution; they must not create a second continuation in a blocked
workflow. Its initial effect contract permits one outbound submission. Provider-
deduplicated resubmission is a separately qualified extension in that spec, so E1
must first use authoritative lookup. Do not assume that extension shipped unless
the recovery profile explicitly includes it.

### 4.2 Candidate proof obligations

These are propositions to formulate and attack, not established theorems.

| ID | Required statement | Premises and boundary |
| --- | --- | --- |
| K1 | Every mediated effect at an honest owner has a preceding, matching durable local authorization | Qualified host mediation, correct binding/serialization, authentic keys, durable state and declared revocation semantics |
| K2 | Delegation and recovery do not exceed the owner's authorized quantitative exposure or widen its granted scope | Authority attenuation and quantitative allocation are distinct relations; count in-flight and unresolved exposure as well as completed consumption |
| K3 | A retry or restart cannot forget an earlier possible effect or recreate a consumed right | Original identities, fencing/retention rules, effect-specific reconciliation; no refund-to-no-effect inference |
| K4 | Earned child obligations remain supported by their own allocation despite parent outcomes | Actual non-equivocating backing and the selected acceptance authority; ordinary escrow already provides this subproperty |
| K5 | Composing admissible edges preserves K1-K4 and the K7 release property for each honest resource owner | Explicit assume/guarantee interface and adversarial peer behavior; cannot assume all peers' kernels honest and then advertise protection against malicious peers |
| K6 | The selected continuation procedure permits a nontrivial class of useful progress and has a stated computation bound | Separate safety from liveness; state dependency availability, scheduling fairness and the finite profile on which completeness, if any, is claimed |
| K7 | Composition preserves the modeled knowledge restrictions and exact release authority across artifacts, confined children and owner boundaries | Reuse PR #1172's confidentiality/influence separation, admitted seed/return paths and complete declared channel coverage; this is not a universal covert-channel theorem |

For a quantitative resource, a useful starting accounting obligation is
`spent + reserved + worst_case_unresolved + delegated_remaining <= authorized`.
These must be disjoint categories for that resource. Delegated usage must have
one attribution path; never count a child's reservation both as local and as
delegated. A monetary refund follows the funding contract and does not, by
itself, remove unresolved execution exposure from another resource's accounting.
Non-additive authority, such as permitted paths or recipients, needs scope
inclusion rather than an arithmetic conservation equation.

For R2, let the receiver's evidence identify a set of compatible histories. A
proposed next action must respect the selected invariant in every compatible
history. Writing that universal condition is a specification, not an algorithm
or novelty result. The actual research questions are whether the relevant state
can be represented compactly, what information must be shared, which actions can
be admitted efficiently, and whether the resulting progress exceeds a strong
existing construction at comparable cost and trust.

Formal work must compare this construction with knowledge-based action,
security automata, partial-observation control and coordination avoidance.
Restrict the initial profile to a finite acyclic work graph. Explicitly analyze
what is lost at that boundary; do not extrapolate a depth-two experiment to
arbitrary recursive delegation. Cycles and shared obligations require a later,
separate result if they are needed for the selected claim.

### 4.3 Trust, adversary and irreducible uncertainty

The adversary controls agents, tool outputs, message delivery/order, and any
counterparty not named as trusted for the relevant property. It can replay,
equivocate, request sibling work concurrently, withhold acknowledgements, and
crash or restart processes. Test valid signatures over malicious content as
well as malformed messages. Model partitions and stale evidence explicitly.

The honest owner's host, selected mediation boundary, keys and durable store
remain assumptions. A malicious administrator can bypass its own kernel; remote
signatures cannot establish complete mediation. Backing needs an honest or
otherwise qualified non-equivocating settlement domain. Correct acceptance needs
an agreed checker or verifier assumption. Local authority cannot force a remote
organization to deliver, disclose private state, or remain online.

PR #1172's input, artifact, explanation and return mediation belong in the
assumed baseline. Prove the selected cross-owner information-flow property
explicitly; a resource-bound proof alone does not establish it. Map owner and
compartment identities without dropping restrictions, and keep confidentiality
approval distinct from integrity endorsement.
Revocation must state its effective boundary: new admission, committed dispatch,
or output release. Do not silently redefine already committed work as reversible.
Evidence expiry and retention must be specified together with retry eligibility.

## 5. What the literature changes about the approach

The [source comparison](../../research/kernel-work/2026-10-02-prior-art.md)
contains the evidence and reading limits. The important research consequences
are:

1. Agoric's older computation-market work and current capability/contract
   machinery make the combined security-and-economy vision a serious prior-art
   obligation. Compare actual guarantees, not only the agent terminology.
2. Beldi includes federated stateful execution; do not assume every durable
   workflow requires one application owner. RIFL makes atomic effect/result
   coupling explicit. Temporal permits non-retryable activities. The baseline
   must receive those options.
3. Distributed bounded counters and invariant confluence already address parts
   of resource allocation and coordination avoidance. A partitioned budget or
   monotone state is not, by itself, the missing result.
4. Agent Contracts, AgentBound, TACIT, CaMeL, AgentKernel and ContractWarden overlap
   with contracts, authority, receipts, effects or kernel enforcement. The
   preliminary reading does not establish their full limitations, nor Chio's
   superiority. Full claim-relevant reading is a first execution task.
5. Knowledge-based action and enforcement theory already explain why evidence
   constrains action. The proposed R2 contribution must survive comparison at
   the level of algorithm, expressiveness under explicit assumptions, or cost.
6. OpenAPPA already supplies policy-derived remedies, durable operation claims
   and unknown-outcome reservations. PR #1172's source research is mandatory
   input, not another investigation to repeat. Its completed recovery feature
   set is the Chio baseline; compare its composed consequence fairly with a
   strengthened OpenAPPA integration.

## 6. Fair comparison and decisive experiments

Build a conventional construction with receiver-owned capabilities or OAuth,
protected operation records, a durable workflow, authenticated receipts,
idempotency/reconciliation, recoverable information-flow enforcement, escrow
and the same output checker. It may add
ordinary fields, hooks, custom policies and a shared commitment service wherever
Chio uses an equivalent service. It may host independent local workflow engines.
If it implements the same abstract contract, that is evidence about the contract,
not grounds for disqualifying it as having become Chio.

Compare the best relevant Agoric construction and Beldi/RIFL-style mechanisms
on their supported domains. Classify unsupported cases precisely. A shared
settlement rail is compatible with independently owned application kernels;
neither side may hide the rail's trust assumption behind peer-to-peer wording.

| Experiment | Decisive observation | Interpretation |
| --- | --- | --- |
| X1: Concurrent fork, reused backing, and restart | Resource and authority bounds over all admitted children, including unknown outcomes | Any violation blocks K2/K5; ordinary allocation equivalence defeats a novelty claim about conservation alone |
| X2: Lost acknowledgement across E1/E2 | Correct outcome uncertainty and safe continuation set under identical observations | Blind retry fails safety; permanent global freeze fails the nontrivial-progress requirement |
| X3: Parent failure after child acceptance | Preserved earned child claim and explicit parent exposure | Regression control, not a claimed new economic mechanism |
| X4: Remove one proposed mechanism at a time | A specific permitted bad trace, extra required coordination, or lost safe progress | Attributes the gain; an unfairly disabled baseline proves nothing |
| X5: A second task family and independent implementer | Same core rules, declared adapter changes, equivalent safety and recovery | Tests generality and integration cost; local dual-language code is not operator independence |

Count physical effects with an observer outside the tested recovery state.
Retain both executions that look identical to the recovering participant but
have different external outcomes. Never give the production decision procedure
the observer's hidden ground truth. Record grants, policy versions, backing,
effect counts, reservations, obligations, outputs and interventions for both arms.

Measure useful completions, safely available continuations, blocked duration,
authoritative recovery time, operator interventions, retained-state size,
decision latency and capital-time. Always report the safety and quality boundary
beside performance. A trivial deny-all monitor is a negative control; a buggy
retry-all monitor is another. Both must fail the evaluation for different reasons.

Reuse PR #1172's support-to-public-issue trajectory for the first composed
experiment. Its second family, confined research with a bounded returned
decision or protected artifact reuse, tests different release and recovery
boundaries. Retain the existing funded checked-work example as the monetary
regression and original W1 economics workload. Do not create a new workload
merely to avoid a hard case. Start with fixtures, then held-out useful work only
after the mechanism merits that cost.

## 7. Evidence that unlocks the paper

The research gates are distinct from existing publication and release gates.

| Gate | Required evidence | Failure response |
| --- | --- | --- |
| G0: Precise question | One claim, explicit assumptions, observable consequence, strongest known counterdesign | Refine the question; do not add features to conceal ambiguity |
| G1: Surviving difference | A nontrivial theorem/algorithm candidate or a preregistered consequential systems tradeoff that survives the counterdesign | Record equivalence or defeat; narrow or abandon the candidate |
| G2: Mechanism evidence | Proof/counterexample analysis, useful-progress cases, fair executable controls, and clearly bounded implementation correspondence | Repair the mechanism or reject it; more prose is not remediation |
| G3: Generality and validation | Second-family evidence, independent critique, and independent operation for claims that require it | Narrow the claim or keep the affected gate open |
| G4: Paper re-entry | A written contribution decision states exactly what is established, why it matters, its strongest alternative, and its essential assumptions | Keep the flagship manuscript frozen |

A theorem about a model can support an algorithm paper without proving every
Rust crate correct. It cannot support the claim that the whole implementation
is formally verified. Finite exploration, differential testing, refinement proof
and external reproduction each support different statements. Choose the needed
evidence from the actual claim; do not equate a large test count with significance.

G4 permits a justified rewrite; publication still requires the applicable
existing gates and a fresh artifact/scientific review. If the contribution is
only a narrower systems result, explicitly discuss that scope with the user
before replacing the flagship thesis. No automatic rewrite follows a failed
foundational hypothesis.

## 8. Preserve the original program

The earlier [H1-H5 hypotheses](../../market/open-agent-work/01-thesis.md#3-research-hypotheses)
remain in force. This program changes research order, not past evidence or
acceptance thresholds.

| Existing hypothesis | Relationship to this work |
| --- | --- |
| H1: Bounded funded composition | Necessary regression property within R1; already overlaps conventional mechanisms |
| H2: Cheap verification of useful work | Independent empirical requirement; a receipt or proof of a narrow predicate cannot substitute |
| H3: Reduced repeated integration | R3, evaluated against the strongest equally provisioned construction |
| H4: Useful autonomous purchasing | Separate comparison with direct and fixed-supplier controls; no guarantee from kernel safety alone |
| H5: Compact general rule | Primary R1/R2 target, tested through abstraction, removal experiments and a second family |
| Broader foundational ambition | Requires an importance/novelty judgment after the above evidence, not a count of passed gates |

Preserve the [external trial](../../papers/verifiable-work/trial/README.md),
[qualification vocabulary](../../market/open-agent-work/05-qualification.md),
and [preregistered evaluation design](../../market/open-agent-work/06-independent-trial.md).
The existing thresholds include verification/production cost ratios of median
0.10 and p90 0.25, a lower 95% success-difference bound of -5 percentage points,
median repeated-integration time at most half the matched alternative, and at
least 95% of scheduled recoverable incidents resolved without database edits or
bespoke repair code. These are proposed acceptance thresholds, not results.
The six paired integration exercises, controls and accounting requirements remain
part of that program; do not substitute a single newcomer anecdote.

The user has no external partner yet. That delays independent-operation evidence,
not Tasks 1-5 of the research plan. No outreach, real payment, deployment or
publication is authorized by this document. Existing production security gates
remain separate. Do not modify the active security worktree for research planning.

## 9. Decisions to carry into every continuation

- Keep the title and ambition; let evidence select the actual scientific claim.
- Freeze the current manuscript and retain its artifact as supporting work.
- Investigate one small R1/R2 mechanism before expanding implementation.
- Assume PR #1172 revision 3 shipped as instructed; consume its contracts and
  trajectories rather than duplicate its implementation roadmap.
- Preserve the strongest negative results and improve the baseline when possible.
- Require both safety and useful progress; explicitly retain irreducible unknowns.
- Obtain the missing economic and external evidence only for the claims that need
  it; a successful trial alone does not establish novelty.
- Stop an unsupported candidate without describing a narrower deliverable as the
  requested breakthrough. Save the counterexample and the next justified choice.
