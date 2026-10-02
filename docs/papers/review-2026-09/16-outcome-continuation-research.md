# Research continuation: work that survives the agent

2026-09-13. Continuing the breakthrough objective after the negative judgment
in [15](15-breakthrough-judgment.md). This is an experiment and implementation
record, not a declaration that the objective has been achieved.

## What the research eliminates

Receiver-owned authorization is established prior art. KeyNote roots decisions
in local policy; end-to-end authorization spans administrative and protocol
boundaries. Macaroons provide attenuated delegation with contextual conditions.
Those mechanisms must be available to a fair alternative.
[RFC 2704](https://www.rfc-editor.org/rfc/rfc2704.html),
[Howell and Kotz, 2000](https://www.usenix.org/conference/osdi-2000/end-end-authorization),
[Birgisson et al., 2014](https://research.google/pubs/macaroons-cookies-with-contextual-caveats-for-decentralized-authorization-in-the-cloud/).

State-changing authorization is also established: Becker and Nanz describe
policies that update authorization state and reason about access sequences.
Making a receipt enable a later action is not, by itself, a new security logic.
[A Logic for State-Modifying Authorization Policies](https://www.microsoft.com/en-us/research/publication/a-logic-for-state-modifying-authorization-policies/).

The August 2026 CapLease preprint is especially close to durable agent
authorization. It studies fresh issuance for the same authorization and compares
its mechanism with an equally stateful server ledger. Both obtain replay
protection under the paper's matched centralized assumptions. Its effects
guarantee depends on an idempotent sink. We have read the paper, not reproduced
its experiments. A different token representation cannot establish separation
from that alternative.
[Xu et al., arXiv:2608.01710v1](https://arxiv.org/html/2608.01710v1).

Durable execution alone is another insufficient distinction. Temporal already
documents retryable activities and the need for idempotency at external effects.
[Temporal activity definitions](https://docs.temporal.io/activity-definition).

## Candidate mechanism and its falsifier

Test whether independently administered receivers can execute a useful chain
of work in which agents only propose actions and carry evidence. No agent or
shared workflow coordinator should be trusted to remember which effects remain
authorized, reconstruct lost authority, or assert that a predecessor succeeded.

Each receiver activates a finite set of effect slots and transition rules under
its own roots. A rule binds an objective outcome verifier, the predecessor's
logical identity and accepted evidence, the permitted next action, resource,
argument binding, validity, and local effect budget. A verified outcome may
activate a successor slot only through the successor receiver's rule. Minting
a fresh agent, session, token, or request identifier cannot create a fresh slot.

The first substantial demonstration should be a real artifact workflow:
untrusted workers propose a patch, an independent receiver validates the exact
artifact under an owner-selected test contract, and another receiver authorizes
one bounded downstream effect for that artifact. Replace workers and the agent
process, duplicate and reorder deliveries, expire and revoke local records, and
crash each receiver around admission, dispatch, and outcome persistence.
Uncertain non-idempotent effects must remain uncertain, not be retried under a
fresh identity. Source checkout changes must remain reviewable.

Compare the same workload against a receiver-issued opaque handle backed by a
durable server ledger. Give it equivalent key placement, state, storage, and
sink semantics. Measure the security and recovery code the application must
supply, independently verified completion, operator intervention, and useful
work completed under faults. Do not count missing extension fields as attacks.

The candidate fails if the useful guarantees require the agent or coordinator
to remain trusted, if uncertainty is hidden by fresh identifiers, or if the
matched ledger composition achieves them with comparable integration cost.
Passing this experiment would support a stronger systems contribution. It
would still not establish Bitcoin-scale impact or remove trust in all receivers.

## Foundation implemented in this continuation

The live treaty hook now resolves receiver-provisioned lease and governance
activation records. It checks lease issuer and scope and governance issuer,
algorithm and digest. The presentation window uses treaty, continuation, lease,
and governance intervals. Missing records and revocation tombstones deny;
revalidation resolves them again before dispatch. See
[the hook](../../../crates/kernel/chio-runtime-core/src/admission_hook/dsse.rs)
and [store interface](../../../crates/kernel/chio-runtime-core/src/store/traits.rs).

The records are trusted local activations, not self-authenticating governance
receipts. The caller cannot provision them through the admission request.
This change is intentionally fail-closed for older deployments lacking those
records. A durable revocation tombstone prevents reactivation under the same
identifier; renewal requires a new identifier and a new local admission bundle.

Both substitution drivers now assert the dispatch count for both evaluations,
including pairs, combined residuals, and follow-ups. Replacing the observed
count with 999 now fails both tests that survived that mutation in review 15.
The intermittent positive-control denial was diagnosed as writer startup:
the test host submitted a request before the asynchronous SQLite writer had
verified its head. It now crosses `wait_for_writer_ready`, preserving the
production fail-closed gate.

The updated classification is 55 leaves: 27 equality-bound, 1 domain-bound,
13 statement-only, 8 uncompared, 2 refused, and 4 absent optional. This is
coverage of this implementation, not a minimality theorem or a Rust refinement
proof. The whitepaper now includes the receiver-issued-token counterexample
and the relevant prior art, and identifies the outcome-continuation composition
as a hypothesis to implement and test.

## Validation retained

[The evidence manifest](evidence/16-outcome-continuation/manifest.json)
records reproduction commands, source and log hashes, and the limits of each
run. These are local results on an uncommitted working tree based on
`2b3b5af8cbfbc6f16ce6005de3f97cd149803b81`, not remote CI or release qualification.

| Check | Result |
| --- | --- |
| Final runtime-core library and integration suite | 247 tests passed, including all 37 binding tests and 283 driven substitution cases across both corpora |
| Runtime harness | 22 tests passed |
| Verifier/hook conformance | 7 tests passed |
| Benchmark smoke | All 3 allow/deny groups passed; no latency claim |
| Runtime-core and harness Clippy, all targets | Passed with warnings denied |
| Federation pair example Clippy | Passed with warnings denied |
| Pair and combined-residual counter mutations | Both failed at the counter assertion, as required |
| Lean admission model | Passed |
| Workspace formatting and diff whitespace | Passed |
| Whitepaper build, references, macro drift and limits | Passed: 12 pages, 4,726 body words |

The final full runtime-core run includes the last malformed scope checks.
Harness, conformance and benchmark runs used fixtures without optional lease
scopes and preceded that final rejection check; final runtime/harness Clippy
compiled all targets afterward. The temporary mutation target was removed
before the final suite. The paper's retained latency measurements predate this
implementation and are labeled accordingly. Deployment provisioning requirements
are documented in the [runtime README](../../../crates/kernel/chio-runtime-core/README.md#treaty-presentation-records).

## Remaining work

Build and evaluate the successor-activation mechanism above. Existing treaty
continuations still require provisioning outside the kernel. This pass does
not establish a complete multi-hop workflow, public anti-equivocation, truth of
external effects against dishonest kernels, or an independently reproduced
cross-organization deployment. Early-denial co-signing, the previously observed
budget-release invariant, and a freshly retained concurrency sweep also remain
open. The breakthrough objective remains active.
