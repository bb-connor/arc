# Work protocol, SDK and application surface

Status: incorporates the approved composition refinements. Implements AW11 through AW15 and public-client/lifecycle acceptance for AW26 through AW31.
Parent: [architecture and constraints](2026-10-03-agentic-work-kernel-design.md).
Consumes: [runtime](2026-10-03-work-runtime-design.md), [owner services](2026-10-03-work-owner-services-design.md).

## Shared semantics

Extend existing cross-protocol lifecycle/fidelity metadata with the negotiated work profile. Protocol adapters translate envelopes and return bounded projections; they do not implement their own allocation, authorization, recovery or financial reducer.

Keep the original route and request fixed after sealing. Equivalence across protocols means separately bound invocations obey the same contract. It does not mean a sealed MCP call can be replayed through A2A with a new route.

Support is a set of dimensions: admission, owned dispatch, durable execution observation, current output-release enforcement, recovery continuation, work-command transport and funded-settlement profile. Unsupported combinations fail before dispatch. An adapter does not get every dimension by implementing an authentication callback.

Extend that same matrix with resolved-profile queries, qualified all_success joins and acceptance-evidence projections. A transport carrying a profile description has not thereby qualified its predicates, remote confinement or result-release path. Canonical vectors include stale generations, wrong evaluator/artifact and changed dependency category as well as invocation bindings.

MCP, A2A, ACP and governed HTTP receive positive and negative work vectors. Envoy ext_authz advertises admission only unless a particular complete deployment earns additional dimensions. Provider trace-only surfaces remain trace-only. Reuse the existing CHIO_CROSS_PROTOCOL_QUALIFICATION_MATRIX.json; add work-profile dimensions rather than a competing inventory.

## SDK and host operations

Extend the existing Python chio-process and TypeScript @chio-protocol/process packages with WorkClient wrappers using the negotiated chio.work.v1 session. Preserve old clients and their exact request derivation. Proposed client methods:

- submit(command: WorkCommandV1) -> WorkCommandResultV1
- prepare(proposal: WorkPreparationV1) -> WorkPreparedV1
- query(query: WorkQueryV1) -> WorkQueryResultV1
- inspect(handle: WorkHandleV1) -> WorkViewV1 as a query convenience

Python raises a bounded WorkError with stable code and original command reference. TypeScript provides matching types and errors. Neither auto-retries a side effect or generates a replacement command ID after timeout.

Higher-level delegate/select/submit helpers construct commands through the required prepare operation at each owning service. collect means historical Reconcile; reading result bytes uses the existing recovery release operation. A lost preparation/command response is resolved by its original ID even when no work handle was returned. They cannot expose private signing keys or create authority from a local cache. Rust uses chio-runtime, not chio-runtime-core or example modules.

Use the same query method for Catalog and Profile; avoid a second discovery client. Join uses prepare(Join), then the existing prepare/apply Extend path. Inspect exposes acceptance and recovery separately from execution and payment. A returned WorkRecoveryLinkV1 is passed to the existing recovery client; explanation/offer/approval/resumption retain that protocol's own identity, scope and revision. A helper cannot auto-select an offer, grant an approval or retry an uncertain effect. Keep commands and artifact bodies lossless and bounded in all three languages.

Reuse WorkerService's credential journal, frame limits and InvocationPreparer for ordinary preparation. Add an optional host-owned WorkCommandService only for closed work operations the existing preparer cannot express. To keep dependencies acyclic, chio-process owns this bounded authenticated transport seam, while chio-control-plane supplies the concrete work service. The Rust facade exposes a typed WorkClient over transport, not a constructor for privileged caller context. Keep work-specific orchestration out of the generic process runtime. The recovery lane's new host operations and version negotiation must be joined before either lane changes worker.rs.

CLI work operations live under chio work with init, serve, submit, inspect, collect and export subcommands. inspect accepts either a handle or the original command/preparation reference; collect reconciles historical obligations and never prints protected result bytes. Existing recovery commands handle result access. init requires a local owner deployment profile and produces a proposed provisioning result; serving requires the existing qualified authority activation. No network caller can call init. Commands use existing process/private-directory/configuration facilities.

Generate schemas/types through existing codegen where supported and share canonical positive/negative vectors across Rust, Python and TypeScript. Wide native identifiers/revisions use their specified lossless wire representation; JavaScript Number coercion may not change signed bytes or digest meanings. SDK errors expose stable codes and authorized references, not nested parser strings. Test metadata canaries, maximum/one-over bounds, unsupported variants, and abandoned/stalled sessions. Keep signing, release decisions and retries in their existing Rust owners.

## Two applications

Application A is the existing API review program: a survey discovers a missing authentication declaration, the plan grows to a specialist, and the intermediary dies after the child's accepted work. Convert it to the public work/SDK contract with configurable tools and owners.

Application B is the recovery roadmap's support-ticket-to-public-issue program composed with a separately owned analysis/redaction worker. Its owner-controlled disclosure approval, exact recovery continuation, labeled artifact and authorized publication reuse recovery P1/P3/P4. A rejected disclosure may progress through one approved continuation; already uncertain publication is not retried.

The applications use different tasks, acceptance procedures and transport/host combinations. Both use the same work command contract, lifecycle projections and operator setup. Their application modules may contain domain logic, manifests and policy. They must not contain custom authority verification, native nonce ownership, recovery state machines or escrow implementations.

Reuse the security reference-swarm as the confinement/integration harness and the recovery lane's support-disclosure workload. Do not create a third independent scheduler or duplicate those campaigns.

## Required composition cases

The following cases strengthen those two applications. They are acceptance contracts shared by W1/W2/W3, with lower-level existing evidence reused where it already establishes a boundary. Record actual public-interface runs for the compositions themselves.

| Case | Application and action | Required observation and negative control | Owning tasks |
| --- | --- | --- | --- |
| LC01 | A resolves a catalog/profile and selects a participant absent from its initial task graph | Config-only provider selection; correct treaty/peer admitted; unknown peer, wrong account and stale generation refused before issuance/effects | W1.3, W1.4, W2.1, W2.2, W3.3 |
| LC02 | A evaluates a specialist artifact and extends the graph with an all_success join before dependent work | Exact artifact/procedure/evaluator evidence; join and continuation issued only with the committed successor; wrong artifact/evaluator/parent, duplicate receipt and losing head CAS issue no usable successor | W1.5, W3.3 |
| LC03 | B follows an authorized recovery link after refusal and uses one exact approved continuation | One allowed publication; unauthorized explanation/approval refused; unknown original publication is never resent; separate authorized workflow still progresses within its own budget | W1.6, W2.4, W3.2, W3.3 |
| LC04 | B changes the owner's semantic/policy generation with work outstanding; A retains an earned child claim across intermediary failure | Stale offer blocked, captured history preserved, current recipient can be withheld and backed earned claim remains collectible; historical release/review/lock receipts cannot authorize current use | W2.4, W3.3, W4.2 |
| LC05 | A uses one approved provider implemented directly, then one with bounded internal delegation, for fresh commitments under the same external requirements | Same consumer task code and agreed result predicate; configuration and new bindings may change; extra effects/readers or altered acceptance require new admission; old sealed route remains fixed | W3.3, W3.4 |
| LC06 | A runs unpaid inside one owner, across enrolled owners, and with the optional qualified funded profile; it also runs from an installed LangGraph client | Same work API and domain task logic; no mandatory funding for unpaid mode, no local callback fallback or new operation ID on resume; record actual qualified dimensions and package origins | W3.3, W3.4, W4.3 |

LC02 consumes artifacts through the existing recovery prerequisite categories HistoricalFact, CurrentPredicate and HeldReservation. Exercise exact-version review, changed current bytes, expired reservation and revoked recipient at the dependent commitment. Preserve confidentiality and influence labels through producer, input manifest and consumer; successful acceptance is not declassification.

For LC06 reuse sdks/python/chio-langgraph's existing authenticated process integration and stable persisted operation-key/checkpoint discipline. Add a small work-node adapter using the shared WorkClient, with planning/checkpoint storage still owned by LangGraph. Its envelope fixes command kind, command ID and body; changed body under a persisted identity conflicts. Bound responses stay outside model-visible content until an authorized projection/release. Qualify this one harness through actual installed packages; no live model API or new harness inventory is needed.

LC05 establishes the observed contract substitution for two configured implementations. It is not a general contextual-equivalence theorem, automatic provider migration or a license to change sealed history. LC01 is selection within approved enrollment, not permissionless discovery. Lifecycle checks can share fixtures and cutpoints; do not force unrelated facts into one giant test or start a third application.

## Evidence of reuse

Report:

- which responsibilities are provided by Chio and which remain application code;
- application glue changed when replacing a provider, protocol or host before a new commitment is sealed;
- end-to-end task outcomes, actual effects, refusal/unknown states and recovery behavior;
- setup steps, code/dependency/configuration footprint and reviewer-recorded integration effort;
- latency/resource/capital/checker costs where measured, with workload and environment.

For any claimed quantitative integration advantage, compare against a competent capabilities + durable workflow + transactional/contract escrow composition using the same authority, confinement, outputs and fault rules. Reuse prior comparator artifacts where applicable, but do not treat financial equality as the full comparison. The default beta paper claims a reusable architecture, not a measured superiority result; a new full comparator implementation is not a prerequisite for that bounded claim.

No preset speedup or code-reduction threshold is required to make results look impressive. The beta acceptance requirement is working reuse by both applications and honest cost reporting. A claim of lower integration effort requires the corresponding comparative evidence; a tie or loss is retained. Stop after this bounded evaluation. Unestablished economic/adoption hypotheses do not initiate another experiment automatically.
