# Open agent work: the Chio breakthrough program

Status: proposed research and implementation program. Written 2026-09-14.
This package records decisions, dependencies, experiments and completion gates.
It implements no new protocol behavior and authorizes no external deployment,
fund transfer or partner communication.

Approved whitepaper title, locked 2026-09-14:
**Chio: A Peer-to-Peer Economy of Verifiable Work**.
The [whitepaper home](../../papers/verifiable-work/README.md) records the title
and the relationship to existing papers and research evidence.

## The outcome we are building toward

Chio should become a common protocol through which agents belonging to
different companies find work, hire specialists, exchange checked results and
settle their obligations. Each company retains control of its own resources,
data disclosures and financial exposure. Participants can use different agent
frameworks, models, implementations and infrastructure.

The ambitious outcome is a market in which temporary teams form around funded
work. A buyer specifies an outcome. A provider decides how to achieve it,
procures intermediate results, delivers a verifiable artifact and earns a
margin. A newly encountered specialist can participate under the receiver's
existing policy without being integrated into a shared application operator.

The candidate research contribution is a small, composable work contract that
joins local authority, independently checkable acceptance and exclusively
backed obligations across those relationships. Existing settlement systems
supply monetary scarcity. Existing agent transports carry messages. Chio must
demonstrate that its composition makes a materially better system possible.

We cannot schedule a Bitcoin-level breakthrough. We can schedule the experiments
that would distinguish a foundational result from good systems engineering.
The strongest objection remains that capabilities, escrow, signed contracts
and durable workflows can achieve the same result at comparable complexity.
The plan gives that alternative the same resources and a fair opportunity to win.

## Read and execute in this order

| Document | Decision it makes |
| --- | --- |
| [01: Thesis and claim gates](01-thesis.md) | What would constitute a breakthrough, the closest competing ideas, and what would falsify our claims |
| [02: Protocol and funded obligations](02-protocol.md) | Trust boundaries, contract objects, money conservation, terminal states and the first settlement profile |
| [03: Verifiable work](03-verifiable-work.md) | The first useful workloads, acceptance contracts, verification costs, disclosure and agent autonomy |
| [04: Implementation roadmap](04-roadmap.md) | Repository reuse, milestone dependencies, work packages, effort assumptions and the first execution sequence |
| [05: Qualification](05-qualification.md) | Formal properties, hostile-operator attacks, crash tests, conformance and evidence requirements |
| [06: Independent trial](06-independent-trial.md) | Independent operators and implementations, matched baselines, measurements and decision thresholds |
| [07: Adoption and paper](07-adoption-and-paper.md) | Distribution, interoperability, protocol governance, the whitepaper and strategic stop conditions |
| [08: Repository reconciliation](08-repository-review.md) | Source-backed reuse decisions, sixteen integration gaps and the inventory of all 163 workspace members |
| [09: Security roadmap and sync decision](09-security-roadmap-sync-review.md) | Active security/process PRs, ten additional integration findings, actual merge conflicts and the checkpoint to reuse |
| [First-slice implementation plan](../../superpowers/plans/2026-09-14-open-agent-work.md) | Exact files, model/test code, inspection commands and review checkpoints for starting M0/M1 |

The first executable milestone is **M0: freeze the comparison and expose the
funding counterexample**. Do this before a general protocol extraction, a new
marketplace UI or another large demonstration. The complete work queue and the
first ten working days are in document 04.

The repository review adds P40-P55 to the original forty work packages. In
particular, reuse the existing qualified finding-pool ledger and its rollback
defenses; the deliberately unsafe local-balance model is not evidence that
this ledger is vulnerable. The program now contains 56 work packages, with
the integration requirements attached to their owning milestones.

The second pass keeps those 56 packages and strengthens their acceptance
requirements. Use a frozen Security M4 checkpoint before native funded-work
implementation, with an isolated integration rehearsal for the current paper
changes. PR #1117 is the active foundation; the older #1029 is a historical
requirements reference. Model and contract research can continue while that
checkpoint is prepared. See document 09 for the current qualification limits.

## Decisions made by this plan

1. Start with useful software artifacts whose agreed properties can be checked
   mechanically. Use the current OpenAPI authentication review as a regression
   fixture, then qualify a bounded source-repair workload.
2. Start with a funded bilateral exchange and one subcontracting level. Earn
   deeper delegation through explicit fan-out, liability and recovery tests.
3. Protect an honest company against a malicious remote company operator,
   including database forks and contradictory signatures. Retain a separate
   assumption that the honest company's own resource enforcement works.
4. Use an existing settlement rail with an explicit trusted verifier profile
   first. Investigate proof-authorized settlement for a narrow task family as
   a separate research branch. A shared verifier is a named trust dependency.
5. Require prefunded child obligations. Expected parent revenue is not
   collateral. Reputation and underwriting decisions are not deposited funds.
6. Keep local capability issuance local. Discovery, payment and subcontract
   evidence cannot install a remote capability issuer.
7. Measure the strongest practical alternative, including its ability to add
   ordinary signed application fields, use the same escrow and run a durable
   ledger. Protocol-field omissions are not an impossibility result.
8. Require an independently written provider and independently administered
   companies before claiming open interoperability. A Python client against
   our own Rust provider is useful preparation, not sufficient evidence.
9. Freeze experiment thresholds before scored runs. Report failures, operating
   effort, locked capital and uncertainty alongside successful deliveries.

## Where we actually start

The inspected checkout is based on
`2b3b5af8cbfbc6f16ce6005de3f97cd149803b81` and contains substantial uncommitted
work. The following is a local evidence baseline, not a merged release claim.

| Foundation | Current evidence | Boundary to cross |
| --- | --- | --- |
| Finding market | [Market architecture](../ARCHITECTURE.md) describes artifacts, purchase coordination, delivery guards and durable stores | Existing cross-organization escrow remains conditional |
| Three-party work | [Report 35](../../papers/review-2026-09/35-bounded-intercompany-subcontracts.md) and [operator notes](../../../examples/federated-work/SUBCONTRACT.md) record receiver-enforced permits, bounded disclosure and child recovery | One Linux host, one administrator, synthetic local credits, a fixed specialist |
| Independent verification | Report 35 retains Python and Rust verification of nested deliveries | Independently authored provider, parser and settlement implementation still needed |
| Failure behavior | Reports [33](../../papers/review-2026-09/33-verifiable-uncertain-work.md), [34](../../papers/review-2026-09/34-mutually-agreed-unknown-release.md) and 35 preserve unknown work and separately resolve payment | No proof of aggregate company solvency or protection against a dishonest journal owner |
| Comparison discipline | [Matched ledger](../../papers/review-2026-09/18-matched-outcome-ledger.md) and subsequent reports matched important local guarantees | Extend the comparison to funded cross-company work and integration effort |

Report 35 records 54 passing process scenarios, 11 Rust tests and 30 Python
tests against its retained local source inventory. Those are historical
qualification results, not tests rerun by this planning change. Its evidence
manifest and source snapshots must remain immutable.

## Program gates

| Gate | What must be observable | What it permits us to say |
| --- | --- | --- |
| G0: honest problem | Exact adversary, fair baseline, economic failure matrix and counterexample | We have a concrete research problem |
| G1: funded exchange | Backing cannot be reused; eligible claims survive payer refusal within the selected profile | This profile supports bounded funded work |
| G2: composition | Successful children stay payable after parent failure; all reachable losses have owners and backing | This bounded delegation profile composes |
| G3: independent use | Independent providers and operators interoperate from the published contract | The contract is portable beyond our implementation |
| G4: measured advantage | Preregistered useful-work, verification and integration targets survive matched comparison | We have an evidenced systems contribution |
| G5: foundational argument | A compact mechanism explains a substantial new capability or improvement that survives expert counterexamples | A breakthrough claim is worth defending |

Passing G1 through G3 is valuable even if G5 fails. Do not rename those results
as a foundational breakthrough. If the experiments only show a better
integration product, pursue that product with the corresponding paper claim.

## Working discipline

Each milestone ends with a reviewable code change, a claim-to-evidence table
and a decision to continue, narrow or stop. Prefer a compiling vertical slice
over simultaneous changes across the workspace. Follow the existing fail-closed,
canonical serialization and receipt conventions. Reconcile current source and
required exact-commit checks before integration claims.

This program extends the cognition market's research frontier. It does not
silently change the qualified release boundary documented in the market
README, replace the existing transparency program, or declare hosted public
activation complete. Operators must separately choose and qualify any eventual
real-funds deployment.
