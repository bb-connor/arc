# Work protocol, SDK and application surface

Status: proposed. Implements AW11 through AW15.
Parent: [architecture and constraints](2026-10-03-agentic-work-kernel-design.md).
Consumes: [runtime](2026-10-03-work-runtime-design.md), [owner services](2026-10-03-work-owner-services-design.md).

## Shared semantics

Extend existing cross-protocol lifecycle/fidelity metadata with the negotiated work profile. Protocol adapters translate envelopes and return bounded projections; they do not implement their own allocation, authorization, recovery or financial reducer.

Keep the original route and request fixed after sealing. Equivalence across protocols means separately bound invocations obey the same contract. It does not mean a sealed MCP call can be replayed through A2A with a new route.

Support is a set of dimensions: admission, owned dispatch, durable execution observation, current output-release enforcement, recovery continuation, work-command transport and funded-settlement profile. Unsupported combinations fail before dispatch. An adapter does not get every dimension by implementing an authentication callback.

MCP, A2A, ACP and governed HTTP receive positive and negative work vectors. Envoy ext_authz advertises admission only unless a particular complete deployment earns additional dimensions. Provider trace-only surfaces remain trace-only. Reuse the existing CHIO_CROSS_PROTOCOL_QUALIFICATION_MATRIX.json; add work-profile dimensions rather than a competing inventory.

## SDK and host operations

Extend the existing Python chio-process and TypeScript @chio-protocol/process packages with WorkClient wrappers using the negotiated chio.work.v1 session. Preserve old clients and their exact request derivation. Proposed client methods:

- submit(command: WorkCommandV1) -> WorkCommandResultV1
- prepare(proposal: WorkPreparationV1) -> WorkPreparedV1
- inspect(handle: WorkHandleV1) -> WorkViewV1

Python raises a bounded WorkError with stable code and original command reference. TypeScript provides matching types and errors. Neither auto-retries a side effect or generates a replacement command ID after timeout.

Higher-level delegate/select/submit/collect helpers construct these commands through the required prepare operation at each owning service. They cannot expose private signing keys or create authority from a local cache. Rust uses chio-runtime, not chio-runtime-core or example modules.

Mount the work service through an optional host-owned WorkCommandService in the existing WorkerService. To keep dependencies acyclic, chio-process only owns a bounded transport extension port, while chio-control-plane supplies the work implementation. Keep work-specific orchestration out of the generic process runtime. The recovery lane's new host operations and version negotiation must be joined before either lane changes worker.rs.

CLI work operations live under chio work with init, serve, submit, inspect, collect and export subcommands. init requires a local owner deployment profile and produces a proposed provisioning result; serving requires the existing qualified authority activation. No network caller can call init. Commands use existing process/private-directory/configuration facilities.

## Two applications

Application A is the existing API review program: a survey discovers a missing authentication declaration, the plan grows to a specialist, and the intermediary dies after the child's accepted work. Convert it to the public work/SDK contract with configurable tools and owners.

Application B is the recovery roadmap's support-ticket-to-public-issue program composed with a separately owned analysis/redaction worker. Its owner-controlled disclosure approval, exact recovery continuation, labeled artifact and authorized publication reuse recovery P1/P3/P4. A rejected disclosure may progress through one approved continuation; already uncertain publication is not retried.

The applications use different tasks, acceptance procedures and transport/host combinations. Both use the same work command contract, lifecycle projections and operator setup. Their application modules may contain domain logic, manifests and policy. They must not contain custom authority verification, native nonce ownership, recovery state machines or escrow implementations.

Reuse the security reference-swarm as the confinement/integration harness and the recovery lane's support-disclosure workload. Do not create a third independent scheduler or duplicate those campaigns.

## Evidence of reuse

Report:

- which responsibilities are provided by Chio and which remain application code;
- application glue changed when replacing a provider, protocol or host before a new commitment is sealed;
- end-to-end task outcomes, actual effects, refusal/unknown states and recovery behavior;
- setup steps, code/dependency/configuration footprint and reviewer-recorded integration effort;
- latency/resource/capital/checker costs where measured, with workload and environment.

For any claimed quantitative integration advantage, compare against a competent capabilities + durable workflow + transactional/contract escrow composition using the same authority, confinement, outputs and fault rules. Reuse prior comparator artifacts where applicable, but do not treat financial equality as the full comparison. The default beta paper claims a reusable architecture, not a measured superiority result; a new full comparator implementation is not a prerequisite for that bounded claim.

No preset speedup or code-reduction threshold is required to make results look impressive. The beta acceptance requirement is working reuse by both applications and honest cost reporting. A claim of lower integration effort requires the corresponding comparative evidence; a tie or loss is retained. Stop after this bounded evaluation. Unestablished economic/adoption hypotheses do not initiate another experiment automatically.
