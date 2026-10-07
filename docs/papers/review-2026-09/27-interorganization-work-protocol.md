# Direction: a protocol for work between organizations

The primary objective is to make Chio a protocol that independently operated
agents use to agree on work and carry it out across company and national
boundaries. Each organization retains its own authority over tools, data,
spending and approvals. The cognition market infrastructure supplies discovery,
procurement, evidence and settlement to that workflow.

The first use case is a company buying a bounded security review from another
company's agent. A specialist may receive a narrower subcontract when the
agreement permits it. The buyer receives a verifiable result tied to the exact
agreement, and both parties retain evidence of their obligations and actions.

## Why this is the priority

The potential contribution is a reusable agreement and execution boundary:
organizations can collaborate without giving a shared coordinator authority
over their systems. The previous experiments established useful local
mechanisms and their limits. Continuing to optimize an isolated repair checker
would leave interoperability, operational independence and adoption untested.

This remains a hypothesis about a valuable protocol. Neither a new cryptographic
primitive nor a Bitcoin-scale breakthrough has been established. The strongest
objection is that Chio may only package existing mechanisms into a complex
integration. Evidence that would change that judgment is independent teams
connecting different implementations, completing useful work, and retaining
their local controls without bespoke security glue for each partner.

## Existing components and observed boundaries

This is a source inspection of the current dirty checkout based on
`2b3b5af8cbfbc6f16ce6005de3f97cd149803b81`, not remote release qualification.

| Surface | Existing implementation | Boundary relevant to this objective |
| --- | --- | --- |
| Discovery and messaging | `chio-a2a-adapter`, `chio-a2a-edge` | Initial method, part, response and MIME-type mismatches repaired for a bounded 1.0 profile in the local tests below. |
| Procurement | `chio-open-market::bidding` | Signed bid, ask, acceptance and verified reservation witness exist. Pure acceptance does not reserve funds. |
| Finding purchases | `finding_purchase_coordinator.rs` in `chio-control-plane` | Explicitly a single-operator coordinator with durable reservations, stable payment identities and terminal recovery. This is reusable infrastructure, not bilateral escrow already demonstrated. |
| Local authority | `chio-kernel`, `chio-runtime-core` | Capability validation, local admission, durable execution and signed receipts exist. Imported evidence must not activate trust roots. |
| Federation | `chio-federation`, `chio-federation-transport-iroh` | Handshakes, local activation controls, treaties, co-signatures and revocation lanes exist. The paper's tool-request lane is explicitly experimental. |
| Commerce evidence | `chio-commerce-order`, `chio-transaction-passport` | Offline replay and evidence verification exist. They do not execute orders or establish the truth of an arbitrary deliverable. |
| Product examples | `agent-commerce-network`, `internet-of-agents-web3-network` | Procurement and subcontracting scenarios exist. The simpler buyer stores jobs in memory; the larger local scenario centrally assembles the workflow. Separate organization labels alone do not demonstrate independent operation. |

Historical planning paths `docs/research/cognition-market/PLAN.md` and
`plans/2026-08-28-M11-hosted-production.md` are absent from this checkout.
Their remembered milestone status is not current evidence.

## Protocol boundary to implement

Use existing A2A messaging and Chio market artifacts wherever they fit. Specify
the bindings between them: partner identities, agreement digest, accepted
scope and price, approved data disclosure, result acceptance rule, deadlines,
permitted subcontracting, and selected settlement and dispute services.
Version negotiation must reject unsupported required semantics.

Each participant keeps its signing keys, activated trust roots, admission
records, budget and durable inbox/outbox locally. A received message supplies
evidence to a local decision; it cannot expand that participant's permissions.
Every accepted workflow transition is bound to the agreement and its preceding
state. Duplicate delivery must return the recorded result or preserve an
uncertain operation for reconciliation.

The agreement may select an operator or arbiter already trusted by both
parties. That trust must be explicit. A signature establishes who attested to a
result; each job still needs an acceptance rule. Payment completion needs the
selected rail's evidence. A status string or local test credit is insufficient.

Organization and country identifiers do not establish legal compliance or
physical data residency. Deployment must enforce each participant's configured
disclosure and execution restrictions. Claims about a geographic boundary need
measurements from that actual deployment.

## Acceptance sequence

1. Connect the production A2A client to the production kernel-backed edge over
   HTTP. Verify an allowed call's receipt, a denied call's zero dispatch count,
   task ownership, and repeated task retrieval without re-execution.
2. Carry existing signed market artifacts through that connection. Bind a job
   to the accepted offer, reservation authority, scope and result checker.
3. Run buyer and provider as independently configured processes with separate
   credentials and durable stores. Neither process receives the other's
   administrative credentials or database access.
4. Disconnect and kill each side at acceptance, dispatch, result publication and
   settlement. Recover using its own journal and peer messages. Record unknown
   effects without replaying them blindly.
5. Exercise a denied subcontract, unauthorized data disclosure, changed terms,
   expired authority, stale revocation state and duplicate payment request.
6. Qualify two actual administrative domains and a second implementation.
   Retain an independently verifiable evidence bundle for the complete job.

The first item is a bounded interoperability slice. It does not close the
durability, bilateral settlement, independent deployment or adoption items.

## Implemented interoperability slice

`chio-a2a-edge` now handles `SendMessage`, `GetTask` and `CancelTask` using
the standard 1.0 message and task shapes. Calls use the existing kernel
orchestrator. The source message id supplies the request id for request-bound
authorization. Results retain signed kernel metadata, output-mode negotiation
and task ownership. The Agent Card publishes MIME types and disables its
previous unsupported SSE claim. Existing slash-form methods remain available.

The regression test
`crates/tooling/chio-conformance/tests/a2a_client_edge_interop.rs` runs the
production client against the production edge over loopback HTTP. Before the
change, the structured call failed on the missing JSON input advertisement and
the text call failed with method-not-found. After the change:

- The permitted call produces one tool execution and a completed task. The
  test verifies its receipt under the separately pinned provider kernel key,
  its allow decision and the original argument binding.
- A newly constructed client reloads its file-backed task registry, discovers
  the server again and retrieves the same completed task. Execution stays at
  one.
- A capability scoped to another tool produces a failed task, a verified
  signed denial and zero tool executions.

Five edge tests also cover ambiguous or unsupported request semantics, task
ownership, cancellation, output-mode retention, truthful capability discovery
and rejection of a stale task id after replacing the edge instance. A fresh
random namespace prevents a lost task table from reusing another job's id.
Replacing an instance is not a retained process-kill recovery experiment.

The HTTP host in this test uses an explicit fixture credential resolver. The
tool returns structured fixture data. This is not a completed security review,
two organizations running independently, TLS deployment qualification, market
settlement, or an independently implemented client. The provider task table
remains in memory; repeated `SendMessage` is not deduplicated by this slice.
Multi-turn contexts, tenant routing, file parts, message extensions and history
are rejected by the bounded projection. Hosts still enforce authentication,
TLS, request sizes and version headers.

The paper's research question now names procurement, delegation, verification
and settlement under local authority. Its implementation and novelty claims
remain bounded by the measured evidence.

Validation uses the local checkout and locked offline Rust dependencies:

```sh
cargo test --locked --offline -p chio-a2a-edge -p chio-conformance \
  --lib --test a2a_client_edge_interop
cargo clippy --locked --offline -p chio-a2a-edge -p chio-conformance \
  --lib --test a2a_client_edge_interop -- -D warnings
cargo fmt -p chio-a2a-edge -- --check
make -C docs/papers/evidence-crosses build check
```

The edge suite has 98 passing tests, the conformance library has 38, and the
new HTTP integration target has two. Clippy passes with warnings denied.
Formatting of the crate and newly added source fragments passes. The paper
build passes at 12 pages and 4,986 body words. Retained logs, the changed edge
source, and source hashes are indexed in
[the evidence manifest](evidence/27-interorganization-work-protocol/manifest.json).
This is local verification of uncommitted work, not remote CI or a release.

## Research checkpoint

The Cartesi/RISC Zero experiment in `examples/repair-machine-proof` is paused.
Its build did not complete and no proof was generated. It is not on the critical
path for the selected trusted-checker work profile.

The A2A wire reference is the official
[A2A specification](https://a2a-protocol.org/latest/specification/), inspected
on 2026-09-13, especially sections 4.1 and 9.4. The initial incompatibility is
observable in repository code independently of that reference: the adapter
sends `SendMessage` with untagged parts, while the edge originally accepts
`message/send` with tagged parts and returns a different task envelope.
