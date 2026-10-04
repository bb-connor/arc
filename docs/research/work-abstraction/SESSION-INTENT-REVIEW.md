# Session intent, missing connections and next design questions

Reviewed against planning commit cc11cd5636 and its pinned work/security/recovery sources.
Status: brainstorming and proposed plan amendments. This document does not expand the approved beta scope, change implementation plans or report new runtime evidence.

## Judgment

The current plans express secure work execution more precisely than the formation and evolution of working relationships. The session's ambition is broader: independently owned systems assemble into useful programs while each owner retains control and previously incurred commitments retain their meaning.

The Rust/authority review remains necessary. The missing emphasis is what programmers and agents can construct using that machinery. Most additions below are public-contract joins and acceptance cases over existing components, not new subsystems.

## What the session actually established

The conversation developed through these decisions:

1. The funded specialist experiment is useful supporting evidence, but surviving payment alone cannot carry the kernel thesis. Conventional financial mechanisms can reproduce that subproperty.
2. The October 2 brainstorm selected safe evolving delegation as the organizing problem: agents should assemble collaborations without engineers rebuilding authority, recovery and resource accounting for each relationship.
3. The October 3 sovereignty discussion made the rules of cooperation executable and evolvable. It distinguished enduring constraints, current permissions and obligations already incurred. The motivating lifecycle included recruitment, subcontracting, failure, policy change and settlement.
4. The architecture discussion separated an agent's changing plan from owner-controlled authority, execution history and obligations. Programmable sovereignty supplies local admission; work commitments supply composition across owners.
5. The owner's Linux analogy corrected an overly narrow novelty standard. A reusable architecture and practical ecosystem can be a substantial systems contribution using familiar mechanisms. Reproducing an individual guarantee is not enough to evaluate that contribution.
6. The accepted organizing statement became: work commitments form a reusable programming abstraction across independently governed systems. The paper must explain what can be programmed before detailing encodings and experiments.
7. Security and recovery remain existing parallel lanes. The paper assumes the completed recovery design as instructed; implementation and empirical claims still require actual evidence. The paper-first order remains in force.

The relevant session messages were the assistant discussions at 2026-10-02 23:29 UTC and 2026-10-03 01:21, 17:04 and 22:27 UTC, followed by the owner's approvals and planning requests. These are recovered conversation decisions, not a new retrospective account of experimental success.

## 1. Describe a working relationship, not only an invocation

Current coverage: W1 binds invocation, allocation, graph and optional funding; W2 configures owners and peers. Recovery P3 supplies semantic connector contracts. The plans do not explicitly require a common programmer-visible description joining these facts before choosing a collaborator.

Proposed amendment: expose a bounded resolved work profile, assembled from existing signed tool manifests, the recovery semantic package/deployment, treaty requirements, acceptance contract and optional financial terms. It identifies:

- required inputs and permitted recipients;
- allowed effects, resource ceilings and recovery behavior;
- the result schema and agreed acceptance procedure;
- whose evidence is accepted for each claim and what local/remote enforcement assumptions are required;
- approval, validity and settlement conditions relevant to this operation.

This is a resolved view of existing contracts, not another capability format or arbitrary executable contract language. A provider description proposes terms; the owner verifies applicability and authority. A manifest signature authenticates its source, not every claimed behavior of a remote host.

Reuse: chio-manifest's signed manifests; recovery PR #1172 05-semantic-contracts.md package/deployment separation; existing D1 WorkContract and F1 terms. Suggested owners: W1.1/W1.3, W2.1, W3.1 and paper P.2/P.3.

## 2. Make treaty-based relationship formation an explicit capability

Current coverage: W2 authenticates approved peers and verifies their treaty-bound evidence. The session also asked how agents establish a new collaboration during execution without a bespoke integration. Preparing a new D1 offer alone does not explain all of that transition.

Proposed amendment: require a supported path from a candidate in an owner-approved catalog to a concrete admitted relationship. Reuse existing treaty scope, governance ladder intersection and owner signing/approval. An agent proposes participant, task and terms; each owner checks the conditions it controls. Required enrollment remains owner-authorized. A discovered name cannot install a key or trust root.

For beta, distinguish selecting a previously unused approved participant from permissionless discovery/enrollment. The former fits the established scope and should be visible in an existing application; the latter remains deferred. The new provider should require ordinary deployment configuration, not edits to the application or a per-relationship graph/signature script.

Code already includes TreatyScope, compute_ladder_intersection and evaluate_cross_boundary_admission in chio-federation/src/treaty.rs. These should drive the composition rather than another policy intersection engine. Suggested owners: W1.3, W2.1/W2.2 and W3.3.

## 3. Connect refusal to safe progress through the existing recovery protocol

Current coverage: W1 returns typed refusal/pending outcomes; W2.4 exercises one approved recovery continuation. The common work API does not yet make the route from a refusal to the recovery protocol unmistakable.

Proposed amendment: an eligible caller receives an authorized recovery reference when the owning recovery authority provides one. The caller can use the existing ExplainIntent, SelectOffer, SubmitApproval and ResumeWorkflow operations. Depending on the supported contract, the next step can be supplying evidence, obtaining a scoped approval, selecting a narrower transformation or waiting for an outcome.

The explanation is advisory and audience-scoped. It reveals neither private policy internals nor live execution authority. The owning kernel still decides at commitment. Unsupported or irreducibly uncertain work remains blocked, while independent authorized workflows can progress within their own attributed budgets.

Reuse recovery PR #1172 08-protocol-operations.md and its exact offer/continuation semantics. Do not create another planner or change the one-unresolved-effectful-continuation rule. Suggested owners: W1.4, W2.4 and W3.2/W3.3.

## 4. Give policy evolution a visible work-level contract

Current coverage: expiry, revocation, historical settlement and immutable commitments are explicit. There is no named end-to-end work case for an owner changing operating policy while collaborators have outstanding work, despite its importance in the earlier sovereignty brainstorm.

Proposed amendment: bind work to the relevant original policy/treaty/semantic generations and describe which current rules govern each subsequent action. Exercise an existing approved reload/revocation path while work is outstanding. Show that new execution uses current admission, historical facts retain their original interpretation, current release can withhold data, and earned financial obligations follow their agreed backing and settlement rules.

Do not promise that an owner can never refuse future execution or that a receipt can compel an unwilling operator to pay. Do not turn finite predicate refinement from the earlier sovereignty model into a proof about every Rust policy update. The architectural point is the precise relationship between changing permissions and persistent commitments.

Reuse the recovery P3 registry-generation/reload contract and existing governance/policy deployment authority. A new constitutional interpreter is unnecessary. Suggested owners: W2.4, W3.3, W4.2 and paper P.3.

## 5. Make accepted results and joins part of the programming model

Concrete interface gaps: WorkViewV1 names execution, result-reference, settlement and bilateral-delivery observations, but no distinct acceptance observation. WorkPreparationV1 covers delegate, offer, select, extend and agreement; it does not explicitly expose the existing join operation.

Proposed amendments:

- Project the existing acceptance decision separately, naming the checked artifact/version, procedure, evaluator authority and evidence. Invocation authorization, observed execution, accepted output, permitted release and payment are distinct facts.
- Expose existing owner-authorized swarm join construction where the public surface lacks it. Preserve exact parent receipts/results and the selected predicate; applications must not mint their own join signatures.
- Carry result dependencies through the recovery contract's HistoricalFact, CurrentPredicate and HeldReservation semantics. A receipt for an old review or expired reservation cannot substitute for a current precondition.
- Keep artifacts labeled through producer, join, transformation and consumer. A reference or successful acceptance does not remove confidentiality or influence restrictions.

Existing foundations: D1 Acceptance::check has bounded Equals/IntegerRange clauses; S1 supplies SwarmGraphJoin, SwarmJoinReceipt and mint_swarm_join_receipt; recovery P3/P4 supplies prerequisite and artifact/release semantics. These are limited contracts, not universal AI correctness.

Suggested owners: W1.1/W1.3/W1.4, W2.3/W2.4, W3.3 and paper P.2/P.3. Validate one dependency/join through an existing application rather than building another demonstration system.

## 6. Make substitution and incremental adoption observable

Current coverage: two applications, Rust/Python/TypeScript clients, protocol fidelity and configurable providers. The earlier kernel/driver discussion also concerned existing agent harnesses and an adoption path beginning inside one owner.

Proposed amendment: explain and exercise the progression from a single owner with unpaid work, to approved cross-owner work, to optional funded obligations. Reuse one already integrated harness for an installed-client acceptance path. Keep the existing support-dimension matrix; don't add a broad new harness inventory or promise every adapter has the same enforcement boundary.

A useful composition criterion is that a provider can change its implementation or bounded internal decomposition while preserving its externally agreed work contract. The consumer continues to use that contract; any changed trust, effects, recipients or acceptance requirements require renewed admission. Swapping a future provider is distinct from replaying a sealed invocation against another route.

This criterion is a proposed strengthening of the abstraction claim. It is not a proved contextual-equivalence theorem or authorization to add arbitrary recursive graph replacement. Suggested owners: W3.3/W3.4 and paper P.2/P.3.

## The strongest next synthesis

The untrusted planner searches over possible collaborators and decompositions. Each owner admits a concrete participation under its own rules. Commitments preserve the identities, bounds and obligations that subsequent decisions must respect. Accepted, appropriately released results become inputs to later work. This process repeats as the program develops.

Admission therefore has a constructive role: it determines how a proposed collaboration can become executable. Calling it a linking step is an explanatory analogy, not a claim that a linker supplies distributed correctness or that Chio invented secure component composition.

The three scales should follow from the same rules: a program inside one owner, a collaboration across owners, and a service organization that accepts work and delegates portions of it. The paper can use the service organization to explain the architecture without adding a marketplace, incorporation system, voting mechanism or autonomous institution product to beta.

## A bounded way to restore the whole lifecycle

Strengthen the two existing applications with one shared lifecycle checklist:

1. Begin with an objective, authorized resources, protected inputs and an acceptance contract.
2. Select a collaborator not named in the original program from a qualified catalog; establish the permitted relationship through existing treaty/admission machinery.
3. Delegate a bounded subtask and consume its accepted, authorized result through an existing join/dependency.
4. Encounter a refusal and use a supported exact recovery offer/approval.
5. Change an owner's policy while work is outstanding; preserve original evidence and obligations.
6. Retain an unknown effect without retrying it; let independent authorized work progress in separately owned workflows.
7. Settle accepted work after intermediary failure and explain the result using public work/recovery interfaces alone.

These are proposed acceptance refinements. Map each to existing native/recovery evidence first, add only missing public composition cases, and avoid rerunning entire historical campaigns. The success criterion is that the shared contract supports the lifecycle without application-specific authority or recovery glue.

## Deliberate exclusions to preserve

The session retired exclusive financial novelty and a universal claim that competent conventional components cannot reproduce the behavior. It did not authorize inventing new cryptography, a token, consensus, arbitrary graph rewriting, automatic trust in strangers or universal exactly-once effects. Independent operation and quantitative superiority remain evidence-dependent claims, not requirements to keep experimenting indefinitely.

Open provider discovery, unrestricted replacement/migration and new governance products remain outside this beta plan. The proposed bounded catalog, policy-generation and join cases should not silently reintroduce them.

Before amending the normative plans, settle the common work-profile surface and which recovery/join operations need facade exposure. That decision should improve W1/W2/W3 and the paper brief rather than create a fourth feature roadmap.

## Source anchors

- [Current architecture and scope](../../superpowers/specs/2026-10-03-agentic-work-kernel-design.md).
- [Current work API](../../superpowers/specs/2026-10-03-work-runtime-design.md).
- [Existing treaty intersection and admission](../../../crates/trust/chio-federation/src/treaty.rs).
- [Existing D1 contract and acceptance predicates](../../../crates/platform/chio-workflow/src/delegation/types.rs).
- [Existing swarm graph, result and join types](../../../crates/kernel/chio-swarm-authority/src/types.rs).
- [Existing swarm construction exports](../../../crates/kernel/chio-swarm-authority/src/lib.rs).
- [Earlier preserved research question](../kernel-work/G0-DECISION.md), read with the later accepted systems-thesis correction.
- Recovery contract at de84fc306efbb4c8dd6de748d0ad2a8d695fd30e: 05-semantic-contracts.md and 08-protocol-operations.md in docs/architecture/recoverable-agent-runtime/.
- Sovereignty history at 90a10ee4e2: papers/programmable-sovereignty/sections/07-discussion.tex. Its political/legal analogies are historical context, not claims adopted here.
