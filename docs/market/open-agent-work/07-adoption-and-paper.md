# Adoption, open implementation and the whitepaper

Status: strategy and publication plan. Program entry: [README](README.md).

## 1. Start with one repeated commercial need

The initial product is a company agent buying a checked software artifact
under an explicit price, disclosure policy and recovery contract. The company
can sell specialist work through the same protocol. Build the shortest path
from a real task to a useful delivered result and a reconciled payment.

The first operator experience should let a company:

1. Select permitted task, funding and verification profiles.
2. Configure a bounded agent mandate and approved data disclosure.
3. Publish or receive offers through a registry or direct endpoint.
4. See exactly what it will pay, what counts as acceptance and what remains
   payable if a parent or specialist fails.
5. Retrieve results and resolve an incident with the documented tools.

Present business decisions clearly. A user needs to understand costs, accepted
properties, data recipients and unresolved outcomes. Schema names, Merkle
internals and implementation milestones belong in technical documentation.

## 2. Distribution through existing agent systems

Use the current A2A adapter and existing tool-access integrations. An agent
framework should expose a small set of governed procurement operations while
its local owner retains policy and credential control. Provide one reference
integration with a real agent framework, then let demand choose the next.

For payment mandates, publish a precise AP2 mapping where semantics align.
Document which Chio obligations require an additional work profile and which
remain payment-rail responsibilities. Do not rewrite shared commerce semantics
just to own the entire stack. The current AP2 delegation scope is a point for
interoperability work, not a durable competitive moat.
[AP2 specification](https://ap2-protocol.org/ap2/specification/)

Adoption artifacts, in order:

- A concise work-profile specification and executable conformance corpus.
- A minimal provider that does not require deploying the entire workspace.
- Buyer and verifier libraries with exact error and recovery semantics.
- Operator setup, key rotation, funding reconciliation and incident guides.
- A live independently operated task exchange with reproducible evidence.
- A second task profile demonstrating that the contract is reusable.

A newcomer should implement the common contract once. Adding a partner within
an existing profile should normally be a policy/configuration decision.
Introducing a new work predicate or funding trust model legitimately requires
new integration and qualification; do not count that as zero-cost onboarding.

The [repository review](08-repository-review.md) identifies existing listing,
federation, SDK, CLI, Proof Room and enterprise-export surfaces to extend.
Product SDKs may reuse the Rust verifier, but the paper's independent
implementation claim needs a separately authored verifier/provider. Pin and
test external protocol versions against the actual projection validators;
an existing offline AP2 projection does not by itself supply a live payment
client or the new work-obligation semantics.

## 3. Market formation

Recruit a small set of buyers with recurring bounded repair work and suppliers
with distinct expertise. Measure time to useful result, paid repeat use,
supplier fill rate, unsuccessful attempts, dispute rate, retained capital and
the operational cost of incidents. Publish whether early participants are
subsidized or compensated for integration.

The first market does not need a global auction. Use signed fixed-price quotes,
an explicit budget and a small set of eligible alternatives. Add more elaborate
matching only if observed task failure or unused capacity justifies it.
Limit discovery abuse with bounded queries, local admission policy and explicit
resource budgets. Identity count is not economic reputation.

Potential business models include managed operator tooling, verification and
settlement services, qualified task profiles and enterprise support. Test
willingness to pay after useful repeat exchanges exist. Keep the wire contract,
offline verification and independent implementation possible without buying
a Chio-hosted application subscription.

The desired network effect is reusable integration and a larger pool of
economically useful specialists. More participants do not automatically create
better work, trustworthy claims or profitable suppliers. Measure those effects
before presenting them as an adoption advantage.

## 4. Open protocol governance

Publish versioned profiles with independent test vectors, migration rules and
explicit trust dependencies. Separate base contract semantics from optional
workload, verification and funding profiles. New profiles do not silently
weaken accepted obligations under old versions.

Before calling the profile an open interoperability standard, require two
independently maintained implementations, a public compatibility matrix,
documented extension/review processes and a way to propose changes without
access to the Chio deployment. Use an appropriate openly usable specification
and implementation licensing arrangement after repository/license review;
do not invent an unreviewed licensing promise in the paper.

No registry listing automatically grants local authority. No Chio-operated
service is a hidden requirement for verifying historical artifacts. Mark the
dependencies that remain essential, including F1's selected verifier and
settlement domain. A token or governance organization is not required to
establish these properties.

Existing trust-market verifiers explicitly reject several unimplemented global
market and insurance claims. Preserve those old-profile rejections. A new
narrow work profile gets a deliberate claim mapping and conformance evidence;
launch language must not silently turn policy-based enrollment into a claim
that an unrestricted marketplace or funded insurance market already operates.

## 5. Whitepaper structure

Approved title, locked by the repository owner on 2026-09-14:
**Chio: A Peer-to-Peer Economy of Verifiable Work**.
The [whitepaper home](../../papers/verifiable-work/README.md) is the canonical
record. The abstract and strength of the claims follow the experiments; the
approved title does not assert that the proposed economy is already qualified.

| Section | What it must establish | Required evidence |
| --- | --- | --- |
| Problem | Why independent agent work creates a concrete authorization, verification and obligation problem | The forked-funding and failed-intermediary examples |
| Model | Parties, adversary, local enforcement and funding/verifier assumptions | Exact F1/F2 boundary and unavoidable residual losses |
| Mechanism | The smallest contract and transition rules that make the claimed composition work | Canonical objects, admission rule and claim-consumption path |
| Argument | Which invariants compose and under what assumptions | Q1-Q9 model/proof/implementation correspondence |
| Implementation | Reuse and the minimal new components | Source map, public profile and two independent implementations |
| Evaluation | Useful work, failure outcomes, integration effort and economics | The matched trial, confidence intervals and negative results |
| Related work | The closest constructions and what they can already achieve | Versioned primary sources and a fair executable baseline |
| Limits | What remains trusted, expensive, subjective or unavailable | Counterexamples, excluded profiles and unresolved evidence |

Aim for a compact main argument that can be understood through one successful
trade and one failed intermediary. Put the full schema, conformance vectors,
large attack matrix and raw data in an artifact companion. Do not hide a
load-bearing assumption only in an appendix.

The existing paper and reports remain historical evidence. Rewrite the main
claim only after the funded exchange and comparison establish it. Preserve
the earlier matched-ledger result instead of erasing it from the narrative.
It is the strongest reason to test whether the new contribution is substantive.

## 6. Claim register

Maintain a versioned register with these fields for every substantial sentence
in the abstract, introduction and conclusion:

```text
claim_id, exact_claim, profile, adversary, assumptions,
supporting_source_version, evidence_paths, counterexample,
baseline_result, status, next_decisive_test
```

Use statuses `hypothesis`, `modeled`, `locally-tested`, `independently-reproduced`,
`externally-operated`, `refuted` and `narrowed`. These are different dimensions
of evidence as well as progress labels; a local test does not imply a theorem,
and an external deployment does not imply a fair comparison. Record more than
one status where needed.

Before external publication, request independent critiques of the funding
model, acceptance oracle, comparison fairness and claimed novelty. Prepare
reviewable material first; contacting reviewers is a separate authorized action.
Record the strongest objection and the minimal experiment that could settle it.

## 7. Risk register and strategic responses

| Risk | Early signal | Response |
| --- | --- | --- |
| Familiar composition is the entire result | C1 matches guarantees and integration cost | Publish a focused systems/product result; stop claiming a new foundational mechanism |
| No valuable cheap-to-check workload | W1 cost ratios or buyer-use results fail | Two bounded workload iterations, then reconsider H2 before expanding infrastructure |
| Verifier trust dominates everything | F1 requires the same trusted service to decide all work | State the dependency; pursue F2 only for a measured useful property |
| Funding ties up too much capital | Parent failures and timeouts erase supplier margin | Shorter funded milestones or smaller task scope; no unsecured credit disguised as conservation |
| Partner setup remains bespoke | Newcomer needs custom code or continual maintainer access | Simplify the profile and improve conformance before recruitment expands |
| Live agents add cost without value | C3 matches C2 | Keep deterministic procurement useful; narrow the autonomy claim |
| Remote disclosure exceeds comfort | Buyers reject required verifier or specialist access | Select public/shareable tasks or a different profile; do not promise cryptographic deletion |
| Real-funds or jurisdictional constraints delay trial | Concrete operator review cannot approve the arrangement | Publish bounded test-environment evidence and record the missing external gate |
| Program becomes an infrastructure rewrite | New crates and frameworks multiply before G1 | Return to one funded bilateral exchange and its attack trace |
| Evidence becomes irreproducible | Results depend on dirty source, skipped tests or private resets | Stop claim promotion until source, artifacts and dependencies reconcile |

## 8. What success would mean

The strongest success is a small public mechanism that lets independently
operated agents create useful, verifiable, funded work relationships dynamically,
with measured advantages and clearly bounded trust. Companies can adopt it
without surrendering local authority or sharing a proprietary application
operator.

A narrower success is still worth shipping: a practical protocol and toolkit
for buying checked work with better recovery and less integration effort.
The program succeeds intellectually when the final judgment is determined by
the strongest evidence, including a result that the Bitcoin-level analogy
has not been earned.
