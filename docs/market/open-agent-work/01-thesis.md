# Thesis, alternatives and falsifiable claims

Status: research hypotheses and chosen evaluation criteria, 2026-09-14.
Program entry: [README](README.md). Execution: [roadmap](04-roadmap.md).

## 1. The problem worth solving

A company should be able to give its agent a bounded commercial objective and
let it buy useful work from an unfamiliar company. That supplier should be
able to subcontract without gaining authority over the buyer's systems or
leaving its own specialists with unbacked promises. The buyer should be able
to check the delivered result and the agreed obligations without running the
supplier's internal orchestration system.

The difficult case contains independent administrative domains. A supplier
administrator may control its runtime, roll back its database, issue conflicting
signed statements, withhold an artifact or refuse to cooperate after a crash.
We should not rely on that administrator's accounting to establish whether its
payment promises are collectively funded.

The useful abstraction is a directed graph of work agreements. Every edge
has a result contract, an explicit disclosure boundary, a receiver's local
authorization decision, an acceptance procedure and an exclusively backed
payment obligation. Work can be decomposed differently by different providers.
The graph need not share a scheduler or application database.

This abstraction becomes interesting if its local rules compose into useful
properties of the whole workflow, and if a new participant implements those
rules once rather than negotiating new execution semantics for every partner.
Neither consequence follows merely from signing a contract.

## 2. The Bitcoin comparison we should earn

Bitcoin paired an explicit adversary and a shared transaction-history mechanism
with an argument for resolving conflicting spends under its assumptions. The
lesson for this program is to identify the conflicting claims, the authority
that resolves them and the economic reason the system remains useful. Chio
does not inherit Bitcoin's properties by using signed receipts or a chain.
[Bitcoin whitepaper](https://bitcoin.org/bitcoin.pdf)

Our smallest candidate mechanism is:

> An agent may create a payable subcontract only when the receiving company can
> verify both its locally acceptable procurement terms and an exclusive funded
> claim under the agreed acceptance procedure. Parent failure cannot cancel an
> independently earned child claim.

That rule needs an actual state transition at the funding authority, not just
a signature. It also needs a precise definition of what earns a claim, what
evidence is available, who may decide a dispute, and what happens when nobody
can establish whether work happened.

The repository review found an existing qualified finding-pool ledger with
authenticated allocations, store bindings and rollback defenses. Credit that
mechanism in H1's comparison. The research question concerns how locally
qualified reservations relate to independently enforced backing and acceptance
across administrative domains; it is not whether a naive copied integer
balance can overspend. See [R02](08-repository-review.md#r02-the-qualified-pool-ledger-is-a-major-reusable-foundation).

The proposed foundational result would explain how this rule, bounded local
delegation and inexpensive artifact verification make an open supply chain of
agent work practical. It must survive the observation that many of its parts
are already standard distributed-systems and contract mechanisms.

## 3. Research hypotheses

| ID | Hypothesis | Evidence required | Result that defeats or narrows it |
| --- | --- | --- | --- |
| H1 | Payable work agreements compose across dishonest counterparties while each honest participant's authorized financial exposure stays bounded | Model, implemented rail allocation, fork attacks, concurrent child admission and failure-state accounting | Any reachable admitted obligation is unbacked; safety depends on the dishonest payer's database |
| H2 | Buyers can verify useful outputs materially more cheaply than producing them | Held-out useful tasks, independently selected checkers, full cost and latency accounting | Cheap checks accept useless output, or verification consumes most of the useful-work advantage |
| H3 | One public contract substantially reduces repeated partner integration | Independent provider implementation, new-partner exercise and a matched alternative | Partners still need bespoke protocol code, or the alternative is comparably easy |
| H4 | Agents can choose and compose specialist purchases with bounded loss and useful economics | Live model decisions, real specialist alternatives, controls with the same models and budgets, all failed-attempt costs | A scripted chain performs equally well for the target work, or apparent margin excludes subsidies and losses |
| H5 | A compact general rule explains the gains beyond one application | Two task families, removal experiments, independent critique and precise mechanism description | Success requires a large collection of unrelated bespoke rules or a hidden central application operator |

H1 is conditional on the chosen funding and acceptance authorities, the honest
participant's enforcement and the settlement profile. H2 does not assert that
arbitrary natural-language truth can be cheaply verified. H3 measures protocol
integration separately from business onboarding. H4 is an empirical claim
about useful bounded autonomy, not a theorem about model intelligence.

## 4. The strongest competing explanation

An ordinary system can combine receiver-issued OAuth credentials or scoped
capabilities, signed application contracts, database uniqueness constraints,
durable workflows, an external escrow and a deterministic result checker.
It may achieve the same guarantees. The existing matched-ledger experiments
already give this explanation substantial support for local recovery behavior.

The comparison must permit all those components, application extensions and
reasonable engineering improvements. It must use the same funding rail,
verifier, network, task corpus, models and fault schedule. If Chio only wins
because the alternative was denied a field or persistence mechanism, H3 and
H5 have not been tested.

Possible defensible contributions, in decreasing ambition:

1. A composition result and mechanism enabling an independently operated work
   economy with materially different trust or cost requirements.
2. A small open interoperability contract with substantial measured reductions
   in repeated integration and recovery work at equivalent guarantees.
3. A well-qualified product implementation that makes existing mechanisms
   practical for companies.

All three may be useful businesses. Only the evidence should choose the paper's
claim. Publishing a narrower result is preferable to an unsupported grand claim.

## 5. Closest prior art to confront

| Source | Relevant overlap | Required response in this program |
| --- | --- | --- |
| [AP2 v0.2](https://ap2-protocol.org/ap2/specification/) | Signed commercial/payment mandates and deterministic verification; agent-to-agent mandate delegation is explicitly outside this version's scope | Reuse or map mandate semantics; do not treat that scope boundary as proof AP2 cannot support delegation |
| [A2A specification](https://a2a-protocol.org/latest/specification/) | Agent discovery, tasks, messages and artifacts | Carry the work profile over A2A; demonstrate independent semantics rather than invent another message bus |
| [Agent Contracts, v1](https://arxiv.org/html/2601.08815v1) | Resource-bounded contracts, recursive delegation, budget conservation and dynamic teams are already proposed | Compare monetary claim backing and adversarial administrative domains; do not claim invention of agent contracts or contract-based teams |
| [AgentBound, v1](https://arxiv.org/html/2606.30970v1) | Composed governance and verifiable receipts, assuming owner and enforcement signing keys remain uncompromised | Separate local runtime enforcement from claims enforceable against a dishonest remote operator |
| [Contingent payments for services](https://eprint.iacr.org/2017/566) | Fair exchange and payment for verifiable services have established constructions and assumptions | Specify the availability and adjudication mechanism; receipt integrity alone is insufficient |

These sources were checked on 2026-09-14. The moving protocol specifications
must be pinned to releases or content hashes before M0 closes. Their omission
of our exact profile is not evidence of a new impossibility result. Published
performance numbers are authors' claims until independently reproduced.

M0's prior-art dossier must also cover Contract Net, capability delegation,
distributed transactions and sagas, verifiable computation, optimistic
verification, existing escrow protocols and machine-service markets. For each,
identify the closest executable construction and the assumptions it would need
to implement our example. A long list of names is not a novelty argument.

## 6. Deliberate exclusions

The initial program does not require a new token, chain, universal agent
identity network, global reputation score or foundation-model training run.
It does not attempt arbitrary subjective dispute resolution, unsecured lending,
cross-chain atomicity, unrestricted recursive delegation or automatic legal
recognition of agents as businesses.

Cross-border operation means independent administration and permitted exchange
across actual locations. It does not imply that a signed artifact settles
jurisdiction, taxation, licensing or legal enforceability. Those properties
must be assessed for a concrete pilot separately from the protocol's guarantees.

## 7. Decision rule

Proceed toward the strongest claim only while the experiments strengthen it.
After G2, failure to find economically useful checkable work redirects effort
to the workload and verification research. After G3, no integration advantage
redirects effort to a focused market product. After G4, no compact explanatory
mechanism yields a systems paper with measured results, not a foundational
whitepaper framed around an unproven inevitability.

Retain the failed hypotheses, counterexamples and negative measurements. They
are part of the result and prevent the next iteration from repeating an
attractive but already disproved claim.
