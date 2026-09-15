# Independent-company trial and matched evaluation

Status: experiment design. Recruitment, external deployment and real payment
are future work. Program entry: [README](README.md).

## 1. The decisive demonstration

A company publishes a funded, mechanically checkable work request. An agent
at a second company selects and hires a specialist at a third. The specialist
delivers useful intermediate work and establishes its payment claim. The
intermediary is then stopped or becomes uncooperative. The specialist still
redeems its eligible claim; the root buyer's outcome follows its separate
contract. An independent observer reconstructs both obligations and the
remaining losses from the public verification interfaces.

Repeat with successful final delivery, an invalid artifact, competing specialist
offers and an attempted double pledge from a forked payer database. Introduce
a new specialist after the software is frozen. Operators connect it through
the same profile without writing new code for that partner.

This combines the hardest economic failure, useful work, implementation
portability and genuine company independence in one understandable experiment.
A polished success video without the failure and comparison evidence is not
the result.

## 2. Participants and independence

Require three core work operators, an additional newcomer for the onboarding
test, at least two independently written provider implementations and an F1
verifier independent of the parties whose exchange it adjudicates. For the
cross-border phase, place participating companies in at least two actual
jurisdictions with each operator approving its own data and funding scope.

Each company controls its own keys, hosting account, deployment, agent/model
configuration, policies, state, funding account and incident response. The
Chio team cannot log into every participant, reset balances or sign on their
behalf. Record any shared infrastructure, libraries, consultants or custody.

The independent implementer starts from the frozen profile, vectors and public
documentation. Record specification questions and fixes. The implementation
must include a provider, not only a buyer facade around our server. Have it
verify backing and resolve an incident independently.

The production Python/TypeScript cognition-market SDKs currently delegate
proof verification to the Rust CLI. Count those integrations as SDK compatibility,
not additional independent verifiers. P50 records shared application code,
subprocesses and verifier ownership for every participant. Pin the exact
external-protocol projection versions as well as the new work profile.

Freeze each node's actual security and custody profile before the pilot. The
[security review](09-security-roadmap-sync-review.md) found a 64-operation
executor retention ceiling and unqualified enforced-swarm/process compositions.
P53 must demonstrate sufficient sustained retention, including retries and
unknown effects, without resetting budgets or discarding claim history. P52
must qualify the chosen sandbox and host; a Disabled smoke run cannot stand in
for that evidence. Independently written providers need the common wire and
decision contract, not Chio's entire Rust workspace or its local process host.

Discovery may be shared, but permit direct signed offers or another registry.
Remove the Chio-operated discovery/coordinator service during a run after
agreements are established. Existing work, artifact retrieval and eligible
claims must continue through the declared operator, verifier and rail
dependencies. This tests application-operator independence, not independence
from the chosen settlement or verification infrastructure.

P52 chooses the operator profile explicitly. Start with independently operated
qualified single-operator nodes, including the SQLite ledger's store-binding
and separate-device rollback-anchor requirements. Select the existing hosted
PostgreSQL/Firecracker profile only if tenancy or isolation needs justify it.
For that profile, reuse its authenticated domain backend, tenant spend store,
worker and network/KVM canaries and supply their actual prerequisites. The
selected profile must pass before scored external work begins. Several tenants
under one company administrator still count as one administrative operator.

P46's newcomer admission uses an already approved local policy. Record any
manual trust import required by the selected federation profile as onboarding
effort. No experiment may silently disable local activation to achieve its
setup-time target.

## 3. Staged trial

| Stage | Scope | Exit requirement |
| --- | --- | --- |
| A: compatibility | W0, test funds, all implementation pairings and malformed vectors | Q1-Q8 hold within the declared profile |
| B: unscored pilot | 30 W1 development tasks across at least three defect categories | Checkers, cost logging, task matching and operational procedures work; estimate sample size |
| C: frozen evaluation | Initially plan 150 held-out W1 task instances with three stochastic repetitions per applicable arm | Complete paired data, all failures retained and preregistered analysis applied |
| D: adversarial operation | Actual independent hosts, scheduled failures and hostile counterparties | Q2-Q5/Q9 observed at authority and beneficiaries, with full recovery records |
| E: newcomer | Previously uninvolved specialist under the frozen profile | Measured setup effort and no new pair-specific protocol code |
| F: bounded real payment | Separately authorized low-exposure useful-work canary after qualification | Final independently verified deposits, payouts, fees, refunds and residual locked funds |

Use the pilot to perform a power analysis before freezing Stage C. Increase or
reduce the proposed 150-instance design before scoring if justified by expected
variance and budget. Publish the final sample size, stopping rule and task
exclusions. If a confidence interval remains inconclusive, report that result
or preregister another independent sample. Do not extend only the favorable arm.

A full four-arm design with 150 tasks and three repetitions entails up to
1,800 task attempts before faults and onboarding runs. Build a cost estimate
from the pilot before committing compute or partner time. Test-chain balances
and team-funded subsidies are labeled explicitly.

## 4. Give the alternatives the same tools

| Arm | Purpose | Allowed resources |
| --- | --- | --- |
| C0: direct buyer agent | Test whether buying specialist work beats producing it internally | Same model family/access, task information, checker and total resource allowance |
| C1: composed cross-company baseline | Test Chio's protocol/integration contribution | Receiver-owned auth, signed application contracts, durable workflow/ledger, identical escrow/verifier, ordinary protocol extensions |
| C2: Chio with live selection | Test the proposed system | The same economic, model, network and evaluation conditions |
| C3: Chio with fixed supplier workflow | Isolate the value of agent procurement decisions | Same Chio mechanisms, models and budget, but a predetermined eligible workflow |

C1 must support the same failure guarantees being compared. Give its implementer
time to remove obvious deficiencies found in an unscored review. If a guarantee
cannot be matched within the allotted engineering budget, publish that budget,
the attempted construction and the remaining gap. Do not call the gap a
theoretical impossibility.

Use paired tasks and counterbalance execution order. Pin model versions and
record provider changes or outages. Apply the same caches or report cold/warm
runs separately. Keep held-out checker contents unavailable to all production
arms equally. Cluster analysis by task/repository to avoid counting repeated
model attempts as independent problems.

## 5. Measurements and provisional decision thresholds

These are program choices to preregister in P02, not already achieved results.
Any revision before Stage C receives a rationale and a new version.

| Measure | Definition | Initial decision threshold |
| --- | --- | --- |
| Monetary safety | Violations of Q2-Q5 in the published attack corpus | Zero observed violations; any counterexample blocks the corresponding claim |
| Verification cost | Full checker/dispute cost divided by production cost; also absolute cost and latency | Median at most 0.10, p90 at most 0.25 for accepted W1 results; all-attempt figures also published |
| Useful output | Held-out acceptance plus predeclared buyer-use criteria | C2's lower 95% interval for success-rate difference versus C1 at least -5 percentage points |
| Repeated integration | Hands-on technical time from documented prerequisite readiness to first verified paid-profile result for a new partner | Median at most half C1; no new per-pair protocol code in the frozen profile |
| Newcomer setup | Technical setup after generic infrastructure and business prerequisites are satisfied | Complete within one working day in the planned newcomer exercise; report every assistance session |
| Buyer economics | Price plus buyer verification, coordination and recovery costs per useful accepted result | C2 no higher median than C1 at the qualified quality boundary |
| Autonomous choice | C2 versus C3 useful output per unit cost, task success and specialist substitution | At least one preregistered meaningful improvement, with uncertainty reported and no safety regression |
| Recovery | Time and operator actions to an authoritative terminal after dependencies are restored | At least 95% of scheduled recoverable incidents need no database edits or bespoke repair code |
| Capital use | Integral of locked balance over time; maximum frozen amount and failed-parent loss | All exposure within declared reserves; report the cost without a fabricated universal target |

The half-time integration and cost-ratio thresholds are substantial targets
chosen to challenge the thesis. A smaller measured advantage can justify a
narrower product claim. Safety gates cannot be traded for faster onboarding.
Do not drop quality failures to improve cost per result.

One newcomer is a demonstration, not a population-level estimate of onboarding
effort. For a quantitative H3 paper claim, repeat with multiple new operators
or independent integration teams; plan at least six paired exercises and report
the small-sample uncertainty. Record the initial independent implementation
cost separately from subsequent partner setup. A protocol that costs more
initially may still win as the number of partners grows, but that crossover
must be measured rather than assumed.

## 6. Event and cost record

For each attempt retain a privacy-safe record containing task/arm/repetition,
source/profile/model versions, operator and implementation identities, quotes
seen, procurement decision, authoritative allocations, production and checking
durations, raw resource usage, fee destinations, parent/child outcomes, funding
terminal, recoveries and any human intervention.

Reconcile four views: buyer cash flows, each seller's cash flows, funding
authority balances and total resource consumption. Report seller revenue minus
compute, specialists, verification, rail fees, failed attempts and capital cost.
Publish gross margin and subsidy-adjusted margin separately. A subsidized
positive cash balance is not evidence that autonomous firms are profitable.

Technical integration includes debugging, undocumented operator assistance,
credential configuration and task-profile mapping. Business onboarding includes
commercial terms, procurement, jurisdictional review and funding arrangements.
Show both elapsed and hands-on time, separately and together. Excluding business
work from a technical protocol metric must not hide total deployment effort.

## 7. Real-funds readiness

Before Stage F, produce a concrete deployment package: exact binaries and
contracts, keys/admin/registry roles, accepted asset and finality policy,
independent verifier custody, per-company and total exposure caps, fee reserves,
data scope, incident contacts, withdrawal/recovery procedure and a canary script
with expected balances for each outcome.

The operators must authorize their own participation, data sharing and funds.
Obtain qualified review of the actual jurisdictions and commercial arrangement
where needed; this plan makes no legal conclusion. A testnet or simulated
balance cannot substitute for that external decision or for completed payment.

Begin with an amount whose complete loss fits every participant's explicit
limit, then execute a success, invalid-result rejection and intermediary-failure
case. Pause new admissions on unverified finality, unexpected monetary state,
lost custody or violated exposure. Preserve existing claim access during that
pause wherever the settlement contract allows it.

## 8. Readout

Publish a claim-by-claim verdict, not one blended benchmark score. Include the
strongest successful attack, baseline improvements, missing evidence and the
cost of the trust dependencies. Supply a minimal demonstration plus the full
reproduction package; a third party should be able to verify an earned child
payment and failed parent outcome without our narrative.

If H1-H3 pass but H4 fails, publish a useful interoperable work protocol without
claiming autonomous team formation adds economic value. If H3 fails, retain the
funded market capability and narrow the protocol claim. If the comparison
matches everything at comparable cost, record that as the answer to the
breakthrough question.
