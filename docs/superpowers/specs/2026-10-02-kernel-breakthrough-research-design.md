# Chio kernel breakthrough research design

Status: research design. Companion: [execution plan](https://github.com/bb-connor/arc/blob/archive/pr1173-head-20261014/docs/superpowers/plans/2026-10-02-kernel-breakthrough-research.md).
Sources: [prior-art comparison](../../research/kernel-work/2026-10-02-prior-art.md).

## 1. Research question

Chio is the kernel for agentic operating systems and the agentic economy. Its
flagship paper is **Chio: A Peer-to-Peer Economy of Verifiable Work**. This
program looks for the foundational technical contribution behind that title.

> Can untrusted agents delegate consequential work across independently owned
> systems while each participant retains enforceable bounds on authority,
> resource use, knowledge and obligations through delegation, failure and recovery?

An affirmative answer is necessary but not sufficient. Existing systems already
provide parts of it, and a competent composition may provide all of it. A
result qualifies when it establishes one of:

- a consequential new capability;
- a materially better trust or coordination tradeoff;
- a substantial, general reduction in the machinery needed for the same guarantees.

A systems breakthrough may combine familiar ideas. Acceptance rests on a compact,
important result that survives strong counterexamples, not on community reaction.
The paper must resolve the technical obstacle that makes its vision credible;
operational adoption and economics need their own evidence when the paper claims them.

### Recovery baseline

The research baseline assumes the recovery design of
[PR #1172](https://github.com/bb-connor/arc/pull/1172), revision 3 at
`de84fc306efbb4c8dd6de748d0ad2a8d695fd30e`, including its P0-P6 capabilities and
111 acceptance requirements. The [baseline manifest](../../research/kernel-work/recovery-baseline.json)
records the exact source hashes and requirement IDs. The baseline includes:

- exact recovery offers and grants;
- conjunctive multi-owner approval;
- bounded counterfactual planning;
- semantic connectors and transformations;
- durable labeled artifacts and checkpoints;
- confined children with mediated returns;
- scoped historical settlement.

The question is therefore what the full kernel-plus-recovery design enables, not
how to build recovery. The composed design may itself carry the contribution.
PR #1172's finite models and local semantics are inputs; a theorem about
composition across independent owners and the comparative scientific result
remain to be established. The evidence register keeps the assumed baseline
separate from measured performance or external trials, which it does not supply.

## 2. Mandatory negative controls

The source checkpoint is `5e1715636f2b66295ec3022d6161b91cb77a658d`. The
[funded-work manuscript](../../papers/verifiable-work/paper.tex) and
[review](../../papers/verifiable-work/REVIEW.md) are complete bounded artifacts.
Their monetary results concern conservation of funded allocations and survival
of an earned child claim when a parent fails. The ERC-8183 comparison report
(`docs/papers/verifiable-work/evidence/erc8183/REPORT.json` in the
[research evidence archive](../../papers/README.md#evidence)) reproduces those
economic outcomes with unchanged upstream code, including partial settlement.

The manuscript's abstract states a real problem but does not establish the main
added value of its composition; its final qualifications record that gap. The
manuscript stays frozen until a stronger result exists, and its abstract is not
redrafted during discovery.

The [breakthrough judgment](../../papers/review-2026-09/15-breakthrough-judgment.md)
also defeated the claim that existing protocol compositions cannot implement
receiver-owned authority: receiver-issued tokens, protected local records and
ordinary extensions are legitimate alternatives. Both negative results are
mandatory controls.

| Observation | Consequence |
| --- | --- |
| Receiver ownership fits an ordinary token/profile construction | The baseline is never restricted to selected base-schema fields |
| Separate funded escrows reproduce child independence | Escrow bookkeeping is not the flagship theorem |
| Local durable recovery and signed unknown outcomes already exist | A new name for uncertainty is not novelty |
| Lean models do not prove Rust-hook equivalence | The proof boundary and implementation evidence are stated separately |
| A bounded artifact review found no major defect | That is not independent endorsement of significance |
| No outside partner is available | External work is prepared; theoretical and local comparative research proceeds |
| Security hardening is qualified separately | No theorem or paper artifact closes production release gates |

The [uncertain-work report](../../papers/review-2026-09/33-verifiable-uncertain-work.md)
and [bounded subcontract report](../../papers/review-2026-09/35-bounded-intercompany-subcontracts.md)
name the familiar-composition objection that this program must confront before
extending those examples.

## 3. Candidate contributions

R1 is the organizing question and R2 its first demanding probe. R3 is a distinct
systems route if the evidence supports it, not an automatic substitute.

| Candidate | Proposed result | Strongest objection and stop condition |
| --- | --- | --- |
| R1: Compositional work semantics | A small composition contract over the kernel and recovery system preserves each honest owner's authority, knowledge restrictions, resource bounds and obligations across work edges | A capability system, durable workflow, recoverable IFC runtime and escrow obtain the same result with comparable assumptions and machinery; a conjunction of existing invariants is not enough |
| R2: Cross-owner safe progress | Composing local recovery offers, exact approvals and effect contracts enables useful continuations across owners without weakening their restrictions or resetting uncertain work | OpenAPPA plus ordinary recovery mechanisms reproduces it; local remedy enumeration or a restatement of safe action is insufficient |
| R3: Reusable independent work execution | One public kernel contract achieves the same guarantees with substantially less repeated integration, recovery code or central trust across task families | The advantage comes from a weak baseline, undocumented expert help, reduced functionality, shared administration or costs moved into adapters |

The three are not independent product initiatives. Work starts with the smallest
R1/R2 model and the strongest counterdesign; R3 measurements test whether the
mechanism generalizes. If only R3 survives, the scientific claim is revised
explicitly. New settlement rails, agent SDKs, broad marketplaces, reputation
tokens, a new blockchain, universal work verification and branding are out of
scope: each expands implementation without resolving the novelty question.

## 4. Model

The vocabulary below is a research model over the recovery contracts, not a
replacement wire protocol. Existing identifiers and authority stores carry every
fact they already represent, and there is no second dispatch coordinator.

- **Work edge.** A delegation from one owner to another binds the input and
  result predicate, authorized actor and receiver, applicable policy, resource
  allocation, effect profile, funding reference when needed, and parent
  dependency. A remote signature is evidence under an explicit trust rule; it
  neither activates a local issuer root nor shows that the remote host enforced
  its policy.
- **Local operation.** PR #1172's distinct workflow, step, continuation,
  process-request and native-operation identities, with their intent, process
  and native-material digests. The receiver durably binds its authorization
  decision, resource reservation and dispatch identity before an effect can
  escape, and recovery uses that original identity. Cross-domain edges reference
  local operations; organizations share no database or global sequence.
- **Three separate records.** Execution knowledge, permission to act next and
  financial disposition are separate, bound state. A refund can settle a contract
  without proving that an external write did not happen. A signed receipt shows
  who asserted an outcome, not its quality. A verifier checks an agreed predicate,
  not everything a buyer values.
- **Evidence-dependent continuation.** PR #1172's bounded local planner,
  `PlanDecision`/`WorkflowDirective` separation, exact materialization and native
  capture. The open question is the cross-owner composition rule relating those
  decisions to resource commitments, disclosure authority and outstanding
  obligations. That knowing an action's preconditions constrains it is
  established prior art (S12 in the source comparison).

### 4.1 Reference failure

A buyer commissions a public issue derived from a private support ticket. Its
provider hires a specialist through a confined, bounded-return contract. The
specialist earns its payment, and the required data owners approve the exact
publication after the result is materialized. The issue receiver may have applied
the write when the provider crashes, and the provider holds no durable
acknowledgement. A sibling task is independent.

Without treating a timeout as proof of failure, the model determines:

- which owner authorized each step, and which resource remains committed;
- whether publication can be reconciled or retried under its original key;
- whether the sibling may continue under already partitioned authority and budget;
- which new actions require additional authorization or outcome evidence;
- how a denied disclosure obtains an exact remedy without clearing retained
  knowledge, disclosing the private approval basis or bypassing an owner;
- why a parent failure cannot consume an independently earned child allocation;
- what the buyer can verify, and what still depends on the selected receiver,
  verifier, settlement authority or local host being honest.

The model uses two publication interfaces, both also granted to the conventional
baseline with all relevant metadata. E1 provides durable idempotency and
authenticated outcome lookup with explicit retention. E2 is an opaque,
non-idempotent external effect with no authoritative lookup. E2 is a necessary
negative control: no kernel reconstructs an unobserved effect by signing its
uncertainty. Safe progress may require waiting, a new authorized exposure
allowance or stopping the dependent branch, while independent safe work proceeds.
There is no promise of universal exactly-once effects, universal completion or
free recovery of every reservation.

PR #1172 permits one unresolved effectful continuation per workflow, so
independent branches run in their own authorized workflows with shared budget
attribution. Its initial effect contract permits one outbound submission;
provider-deduplicated resubmission is a separately qualified extension, so E1
uses authoritative lookup first.

### 4.2 Candidate proof obligations

These are propositions to formulate and attack, not established theorems.

| ID | Statement | Premises and boundary |
| --- | --- | --- |
| K1 | Every mediated effect at an honest owner has a preceding, matching durable local authorization | Qualified host mediation, correct binding and serialization, authentic keys, durable state and declared revocation semantics |
| K2 | Delegation and recovery do not exceed the owner's authorized quantitative exposure or widen its granted scope | Attenuation and quantitative allocation are distinct relations; in-flight and unresolved exposure count alongside completed consumption |
| K3 | A retry or restart cannot forget an earlier possible effect or recreate a consumed right | Original identities, fencing and retention rules, effect-specific reconciliation; a refund never implies no effect |
| K4 | Earned child obligations remain supported by their own allocation despite parent outcomes | Actual non-equivocating backing and the selected acceptance authority; ordinary escrow already provides this subproperty |
| K5 | Composing admissible edges preserves K1-K4 and K7 for each honest resource owner | An explicit assume/guarantee interface and adversarial peers; honesty of every peer's kernel is never assumed |
| K6 | The continuation procedure permits a nontrivial class of useful progress within a stated computation bound | Safety and liveness are separate; dependency availability, scheduling fairness and the finite profile of any completeness claim are stated |
| K7 | Composition preserves the modeled knowledge restrictions and exact release authority across artifacts, confined children and owner boundaries | PR #1172's confidentiality/influence separation, admitted seed and return paths and complete declared channel coverage; not a universal covert-channel theorem |

For a quantitative resource the accounting obligation is
`spent + reserved + worst_case_unresolved + delegated_remaining <= authorized`,
over disjoint categories. Delegated usage has one attribution path: a child's
reservation is never counted both locally and as delegated. A monetary refund
follows the funding contract and does not remove unresolved execution exposure
from another resource's accounting. Non-additive authority, such as permitted
paths or recipients, uses scope inclusion, not arithmetic conservation.

For R2, the receiver's evidence identifies a set of compatible histories, and a
next action must respect the invariant in every one of them. That condition is a
specification, not an algorithm or a novelty result. The research questions are
whether the relevant state has a compact representation, what information must
be shared, which actions can be admitted efficiently, and whether the resulting
progress exceeds a strong existing construction at comparable cost and trust.

The formal work compares the construction with knowledge-based action, security
automata, partial-observation control and coordination avoidance. The initial
profile is a finite acyclic work graph, and the analysis states what is lost at
that boundary. A depth-two experiment does not extend to arbitrary recursive
delegation; cycles and shared obligations need a separate result.

### 4.3 Trust, adversary and irreducible uncertainty

The adversary controls agents, tool outputs, message delivery and order, and any
counterparty not named as trusted for the relevant property. It can replay,
equivocate, request sibling work concurrently, withhold acknowledgements, and
crash or restart processes. Tests cover valid signatures over malicious content
as well as malformed messages, with partitions and stale evidence modeled explicitly.

The honest owner's host, mediation boundary, keys and durable store are
assumptions. A malicious administrator can bypass its own kernel, and remote
signatures cannot establish complete mediation. Backing needs an honest or
otherwise qualified non-equivocating settlement domain; correct acceptance needs
an agreed checker or verifier. Local authority cannot force a remote
organization to deliver, disclose private state or stay online.

PR #1172's input, artifact, explanation and return mediation are part of the
baseline; the cross-owner information-flow property is proved explicitly, because
a resource-bound proof does not establish it. Owner and compartment identities
map without dropping restrictions, and confidentiality approval stays distinct
from integrity endorsement. Revocation states its effective boundary (new
admission, committed dispatch or output release); committed work is never
redefined as reversible. Evidence expiry and retention are specified together
with retry eligibility.

## 5. Prior-art consequences

The [source comparison](../../research/kernel-work/2026-10-02-prior-art.md)
holds the evidence and reading limits.

1. Agoric's computation-market work and capability/contract machinery make the
   combined security-and-economy vision a serious prior-art obligation; the
   comparison is of guarantees, not terminology.
2. Beldi includes federated stateful execution, so a durable workflow does not
   require one application owner. RIFL makes atomic effect/result coupling
   explicit, and Temporal permits non-retryable activities. The baseline receives
   all three options.
3. Distributed bounded counters and invariant confluence address parts of
   resource allocation and coordination avoidance; a partitioned budget or
   monotone state is not the missing result.
4. Agent Contracts, AgentBound, TACIT, CaMeL, AgentKernel and ContractWarden
   overlap with contracts, authority, receipts, effects or kernel enforcement.
   Their full limitations, and any Chio advantage, require claim-relevant reading.
5. Knowledge-based action and enforcement theory already explain why evidence
   constrains action. R2 must survive comparison at the level of algorithm,
   expressiveness under explicit assumptions, or cost.
6. OpenAPPA supplies policy-derived remedies, durable operation claims and
   unknown-outcome reservations. PR #1172's source research is input. The
   comparison is with a strengthened OpenAPPA integration.

## 6. Fair comparison and decisive experiments

The conventional construction uses receiver-owned capabilities or OAuth,
protected operation records, a durable workflow, authenticated receipts,
idempotency and reconciliation, recoverable information-flow enforcement, escrow
and the same output checker. It may add ordinary fields, hooks, custom policies
and a shared commitment service wherever Chio uses an equivalent service, and it
may host independent local workflow engines. A baseline that implements the same
abstract contract is evidence about the contract, not a disqualification.

The best relevant Agoric construction and Beldi/RIFL-style mechanisms are
compared on their supported domains, with unsupported cases classified precisely.
A shared settlement rail is compatible with independently owned application
kernels, and neither side hides the rail's trust assumption.

| Experiment | Decisive observation | Interpretation |
| --- | --- | --- |
| X1: Concurrent fork, reused backing and restart | Resource and authority bounds over all admitted children, including unknown outcomes | Any violation blocks K2/K5; allocation equivalence defeats a novelty claim about conservation alone |
| X2: Lost acknowledgement across E1/E2 | Correct outcome uncertainty and safe continuation set under identical observations | Blind retry fails safety; a permanent global freeze fails nontrivial progress |
| X3: Parent failure after child acceptance | Preserved earned child claim and explicit parent exposure | Regression control, not a new economic mechanism |
| X4: Remove one mechanism at a time | A specific bad trace, extra coordination or lost safe progress | Attributes the gain; an unfairly disabled baseline proves nothing |
| X5: A second task family and an independent implementer | The same core rules, declared adapter changes, equivalent safety and recovery | Tests generality and integration cost; local dual-language code is not operator independence |

An observer outside the tested recovery state counts physical effects. Executions
that look identical to the recovering participant but differ externally are both
retained, and the production decision procedure never sees the observer's
ground truth. Both arms record grants, policy versions, backing, effect counts,
reservations, obligations, outputs and interventions.

The measures are useful completions, safely available continuations, blocked
duration, authoritative recovery time, operator interventions, retained-state
size, decision latency and capital-time, each reported beside its safety and
quality boundary. A deny-all monitor and a retry-all monitor are negative
controls that must fail for different reasons.

The first composed experiment reuses PR #1172's support-to-public-issue
trajectory. The second family, confined research with a bounded returned decision
or protected artifact reuse, tests different release and recovery boundaries. The
funded checked-work example remains the monetary regression and the W1 economics
workload. Fixtures come first; held-out useful work follows only when the
mechanism merits the cost.

## 7. Research gates

These gates are distinct from publication and release gates.

| Gate | Required evidence | On failure |
| --- | --- | --- |
| G0: Precise question | One claim, explicit assumptions, an observable consequence and the strongest known counterdesign | Refine the question; features do not conceal ambiguity |
| G1: Surviving difference | A nontrivial theorem or algorithm candidate, or a preregistered consequential systems tradeoff, that survives the counterdesign | Record equivalence or defeat; narrow or abandon the candidate |
| G2: Mechanism evidence | Proof or counterexample analysis, useful-progress cases, fair executable controls and bounded implementation correspondence | Repair or reject the mechanism |
| G3: Generality and validation | Second-family evidence, independent critique and independent operation for claims that require it | Narrow the claim or keep the gate open |
| G4: Paper re-entry | A written contribution decision: what is established, why it matters, its strongest alternative and its essential assumptions | The flagship manuscript stays frozen |

A theorem about a model can support an algorithm paper without proving every
Rust crate correct; it does not make the whole implementation formally verified.
Finite exploration, differential testing, refinement proof and external
reproduction support different statements, and the evidence follows the claim.
G4 permits a justified rewrite; publication still requires the existing gates
and a fresh artifact and scientific review. A narrower systems result replaces
the flagship thesis only by an explicit decision.

## 8. Relation to the open agent work program

The [H1-H5 hypotheses](../../market/open-agent-work/01-thesis.md#3-research-hypotheses)
stay in force; this program changes research order, not past evidence or
acceptance thresholds.

| Hypothesis | Relationship |
| --- | --- |
| H1: Bounded funded composition | A regression property within R1; overlaps conventional mechanisms |
| H2: Cheap verification of useful work | An independent empirical requirement; a receipt or narrow-predicate proof cannot substitute |
| H3: Reduced repeated integration | R3, against the strongest equally provisioned construction |
| H4: Useful autonomous purchasing | A separate comparison with direct and fixed-supplier controls |
| H5: Compact general rule | The primary R1/R2 target, tested through abstraction, removal experiments and a second family |
| Foundational ambition | An importance and novelty judgment after the above evidence |

The [external trial](../../papers/verifiable-work/trial/README.md),
[qualification vocabulary](../../market/open-agent-work/05-qualification.md) and
[preregistered evaluation design](../../market/open-agent-work/06-independent-trial.md)
keep their thresholds:

- verification/production cost ratios of median 0.10 and p90 0.25;
- a lower 95% success-difference bound of -5 percentage points;
- median repeated-integration time at most half the matched alternative;
- at least 95% of scheduled recoverable incidents resolved without database
  edits or bespoke repair code.

These are acceptance thresholds, not results. The six paired integration
exercises, controls and accounting requirements remain part of that program.

Independent-operation evidence waits for an external partner; the theoretical
and local comparative research does not. This design authorizes no outreach,
real payment, deployment or publication, and production security gates remain separate.

## 9. Standing decisions

- The title and ambition stay; evidence selects the scientific claim.
- The current manuscript is frozen, and its artifact remains supporting work.
- One small R1/R2 mechanism is investigated before implementation expands.
- The recovery design of PR #1172 revision 3 is the baseline; its contracts and
  trajectories are consumed, not reimplemented.
- The strongest negative results are preserved, and the baseline improves when possible.
- Safety and useful progress are both required; irreducible unknowns are retained.
- Economic and external evidence is gathered only for the claims that need it; a
  successful trial alone does not establish novelty.
- An unsupported candidate stops with its counterexample and the next justified
  choice recorded; a narrower deliverable is never presented as the breakthrough.
