# Agentic work kernel: architecture and beta convergence

Date: 2026-10-03
Status: execution specification incorporating the owner's approved session-intent refinements; grounded in the source snapshots below. Implementation remains pending.
Scope: the third workstream alongside the active security and recovery roadmaps.
Authorization: the owner approved the architectural thesis and requested the complete planning package. This package does not execute the implementation or revise the manuscript.

## Intent and contribution

Chio makes work a reusable programming abstraction across independently governed systems. An agent chooses and organizes work. Each owner's kernel enforces the authority, resource commitments, execution history and obligations governing its participation.

The contribution is a common execution contract, implemented through existing capability, treaty, guard, swarm, process, receipt and settlement machinery. Reconstructability from known components is not a veto on systems innovation. Comparisons must assess the reusable contract and application responsibilities, not merely whether another escrow reproduces a financial trace. No exclusive-expressiveness, universal result-correctness or inevitable ecosystem-impact claim follows.

Success means a developer can construct two materially different applications using the same supported work interface, without writing a custom authority verifier, retry coordinator, graph-signing script or settlement state machine. Owners can refuse admission under their own configuration. Adding supported transports does not create new execution semantics.

The full programming lifecycle is part of that criterion: resolve a working contract, select a previously unused approved collaborator, delegate, accept and compose results, recover through an authorized continuation, and change current policy without rewriting prior commitments. An agent proposes how a program develops; each owner admits its own participation. Work commitments preserve the terms and history on which subsequent work depends.

## Source and ownership snapshot

The [current-state review](../../research/work-abstraction/CURRENT-STATE.md) and [source manifest](../../research/work-abstraction/SOURCES.json) bind the inspection to exact commits. Refresh these inputs before implementation.

| Lane | Observed source | Ownership |
| --- | --- | --- |
| Existing work construction and manuscript | paper/verifiable-work-20261002, 611660eb24521a4d02020615f650dadad92eae03 | D1 allocation, S1 extension, composed F1 example, paper |
| Active security continuation | packet/3-retention-accounting, a99437b3ea8ef7ea03c7d2926049b27cb140b3c5 | Native admission, confinement, identity, clocks, readers, evidence, release assurance |
| Published security integration checkpoint | PR #1160, f25cd61f49fbf9a15a70396da82d9808ba4e1da2 | An earlier checkpoint, not the entire active continuation |
| Recovery contract | PR #1172, de84fc306efbb4c8dd6de748d0ad2a8d695fd30e | Recoverable-agent-runtime revision 3, P0 through P6 |
| Recovery implementation | PR #1172 is the pinned design contract | Implementation SHA and phase acceptance require independent qualification |

Recovery integration MUST identify its actual implementation commit and phase evidence before acceptance.

The work and security snapshots have 93 and 21 commits exclusive of their common history respectively. Counts only describe divergence. A reviewed semantic integration is required; neither entire branch is silently substituted for the other.

## Chosen approach

Three approaches were considered:

1. Editorial consolidation alone. It would clarify the idea but leave application authors assembling the reusable contract from example internals.
2. A new universal work engine with its own authority, journals and distributed transaction protocol. It would duplicate the strongest existing machinery and compete with the active roadmaps.
3. Extend the existing public runtime facade, promote reusable composition, expose owner-scoped services and qualify the resulting interface. Selected.

Use chio-runtime as the public Rust client facade and chio-runtime-core for checked work contracts, shared binding checks and existing S1 storage. Concrete host composition belongs in chio-control-plane. Keep D1 rules in chio-workflow, qualify production D1 persistence through chio-store-sqlite, and preserve S1, native capture, recovery and financial ownership. No new top-level runtime crate is required.

The [second architecture review](../../research/work-abstraction/ARCHITECTURE-REVIEW.md) records why a generic host pass-through, unrestricted request envelopes and an unfenced allocator are insufficient. Its corrections are incorporated into the specs and tasks, not deferred as optional polish.

The owner subsequently approved all six proposals in the [session intent review](../../research/work-abstraction/SESSION-INTENT-REVIEW.md). Incorporate them into these same five plans. An editorial-only amendment would omit the public API gaps; a separate collaboration engine or sixth implementation plan would split ownership of the same contracts. Add focused runtime tasks for resolved profiles and accepted-result joins, and extend existing owner, SDK, application, release and paper tasks. No new crate, policy language, trust authority or recovery coordinator is required.

## Component specifications

- [W1: reusable work runtime](2026-10-03-work-runtime-design.md)
- [W2: independently controlled owners](2026-10-03-work-owner-services-design.md)
- [W3: protocol, SDK and application surface](2026-10-03-work-developer-surface-design.md)
- W4: beta convergence and acceptance, specified below
- P: architecture whitepaper, specified below

## Global constraints

These requirements apply to every implementation plan.

- Reuse the existing capability, treaty, D1 allocation, S1 graph, native custody, process and payment authorities. No second execution or recovery authority.
- A work handle and every transported commitment are evidence or references. They never mint live authority or install trust.
- Owner provisioning selects trust roots, signers, peer identities, policies, semantic contracts and rails. Incoming work cannot select administrative configuration.
- Preserve complete request bindings and original operation identities. Unknown effect, unavailable output, unpaid work and missing bilateral receipt are distinct facts.
- Use the recovery lane's exact continuation, native observation, historical settlement and release contracts. Do not introduce generic retry, mutable sealed requests or compensation-as-no-effect.
- Preserve existing canonical signing domains and encodings. New signed families require explicit versioned domains and negative vectors; old persisted bytes retain their decoder.
- Use the selected source's Clock port and strict authoritative JSON readers. Rust workspace edition 2021 and Rust 1.94 remain unchanged; preserve the Rust 1.93 floor of proof-substrate crates such as chio-settle.
- Fail closed, retain typed rejection provenance, forbid new unsafe code, and keep unwrap_used and expect_used denied.
- Use checked value types and closed outcomes. Wire decoding is not authentication; verified authority and live ownership remain opaque. Pure code uses concrete types/static dispatch; new traits require a real dependency boundary.
- Reuse the security lane's engineering standard: one module responsibility, no new hand-maintained include!, no module-size ratchet relaxation, and no permissive security-trait defaults. Preserve inner error causes privately and redact external diagnostics.
- Keep signer intent and idempotency at the issuing authority. Coordinator indexes, copied stores and retry caches cannot mint rights. New authoritative tables join the existing serving projection, integrity, migration and continuity contracts.
- Bound parsing, verification work, queues and blocking tasks. Never hold a store transaction across remote I/O. Cancellation or dropped futures cannot erase committed obligations.
- Separate query, historical reconciliation and current result release. Protect metadata as well as payload bytes. Work commitments reference protected exact invocation custody; they do not become generic credential containers.
- Resolved profiles, acceptance observations and recovery links are audience-scoped projections of existing authorities. They do not install trust, authorize effects, declassify artifacts or certify arbitrary usefulness.
- No em dashes. Do not invent observed results, outside participants, shipped surfaces or release acceptance.
- Run focused checks at each changed boundary. Run the inherited full release qualification once at the integrated candidate boundary, and rerun only what subsequent changes invalidate.

## Programming and authority model

A work commitment links an allocation, exact selected invocation, receiving authority, original working terms and acceptance contract, graph participation and optional funded agreement. It is a programming abstraction over these records, not a replacement wire capability or a global atomic transaction.

Owner-controlled resources keep separate authoritative stores:

| Resource | Existing owner | Third-lane responsibility |
| --- | --- | --- |
| Delegation allowance | D1 rules plus qualified serving-store adapter | Preserve D1 semantics; add fenced allocation, selection, sealing and historical readback |
| Program graph | Qualified S1 issuer head/archive; existing runtime evidence lookup | Reuse extension verification; commit signed successors before publication; expose exact history |
| Permission and native effects | Receiver's configured kernel and serving authority | Bind the contract, then enter ordinary admission and capture |
| Durable process request | ProcessRuntime and recovery P1 bridge | Retain one immutable logical call and exact continuation |
| Knowledge and result release | Recovery P3/P4/P5 authorities | Project references and request authorized reads/returns |
| Funding and earned payment | PaymentAdapter plus selected financial rail | Join exact agreement/reserve/operation; report financial state separately |
| Peer evidence | Federation/treaty verification and durable receipt machinery | Deliver and reconcile exact signed evidence under pinned peer policy |
| Working terms and candidate catalog | Owner-provisioned manifests, semantic registry generations and treaty scope | Resolve bounded authorized views; revalidate at preparation and native commitment |
| Result acceptance and joins | Agreed evaluator evidence, S1 issuer and recovery artifact/dependency owners | Project exact decisions and construct qualified joins without application signing |

The runtime may retain command IDs, requested digests and references for coordination. These records cannot certify dispatch, no effect, an earned claim or output-release permission. Each mutation is idempotent at its owning authority. Lost acknowledgement means exact readback under the original command, never a new ID.

A program has one protected allocator per delegation root and one serialized graph head per declared pool. Receivers have independent execution custody. Graph versions can be transported as authenticated evidence; a copied database is not another spendable allocator. There is no global ordering requirement for unrelated programs.

## Recovery and security handoff

| Consumed contract | Owner | Workstream integration rule |
| --- | --- | --- |
| Current caller, issuer, route and transport identity | Security | Use the hardened ingress and authenticated caller context; never synthesize identity from headers |
| Native capture, fencing, nonce and budget participation | Security | No orchestration database can substitute for capture |
| ProcessRecoveryPort reserve/finalize | Recovery P1 | Use the same reservation and complete process binding through lost acknowledgement |
| KernelRecoveryPort observe/resolve_admission/settle_retained | Recovery P1 | Resolve original operations; historical settlement cannot release output or dispatch new work |
| Exact approval/remedy and grant v2 | Recovery P1/P3 | Approval creates only the specified continuation under its owning authority |
| ArtifactReleasePort / ConfinedReturnPort | Recovery P4/P5 | Result references do not release bytes; current recipient authority is checked |
| Semantic connector coverage | Recovery P3/P6 | Advertise only the intersection of work, security and recovery support |
| Receipts, audience restrictions and package verification | Security | Export through existing verified evidence paths, including refusal and partial-delivery states |

The recovery specification's proposed names are contract anchors, not proof those APIs already exist. At integration, record their actual landing paths and signatures. If the implementation changes a contract, update the relevant adapter/spec and focused tests together; do not duplicate the old proposal.

## Beta target and stopping rule

The proposed beta profile is an installable developer kernel and reference host on the platform qualified by the security lane. Linux x86_64 Enforced mode is the initial acceptance target; other platforms retain their own explicit support levels. Native Rust, Python process workers and TypeScript process workers share the same work model. MCP, A2A, ACP and HTTP are individually qualified according to their actual mediation boundaries.

Funded work is part of the architecture and the beta API. The initial qualified rail may remain an explicitly labeled local development-chain profile with mock assets. Public-money deployment needs its own rail, contract, finality and operational acceptance; a devnet result cannot authorize it. No mandatory chain or payment is introduced for unpaid work.

Envoy ext_authz remains an admission integration unless the deployment supplies and qualifies the full execution/evidence path. Observation-only provider integrations remain observation-only. A supported-surface matrix is an executable contract, not a count of adapters.

Beta source readiness is the conjunction of:
1. Security acceptance for every enabled beta surface, including inherited audit, native and hosted requirements.
2. Recovery acceptance for the phases/features advertised by beta.
3. W1 through W3 acceptance below.
4. One integrated candidate with package/install, migration, replay, cross-owner, protocol and documentation evidence.
5. Closed blocking reviews and an explicit remaining-scope record.

The release integration plan reuses the existing RELEASE_CANDIDATE, RELEASE_AUDIT and QUALIFICATION contracts. Existing requirements are not silently waived by the word beta. A scoped release decision must identify any excluded feature and its claim impact. Observed automatic-defense promotion remains governed by Security M11; publishing a developer beta does not close that operational milestone.

Stop adding features when these obligations are met. Open provider discovery, arbitrary graph edits, task migration between owners, budget reclamation, a universal marketplace, generalized semantic correctness and a new consensus layer are outside this third workstream.

Selecting a previously unused participant from an owner-approved catalog is in scope. Enrollment, key installation and deployment activation remain owner operations. Provider substitution applies to future commitments satisfying the same explicit external requirements; it does not retarget sealed work or imply unobserved equivalence between implementations.

## Acceptance requirements and plan ownership

| ID | Requirement | Plan / acceptance |
| --- | --- | --- |
| AW01 | Public facade supports the work contract without direct example/core imports | W1.1, W1.7 |
| AW02 | Existing allocation/selection/seal bindings are preserved | W1.2, W1.4 |
| AW03 | Additive growth preserves old rights and uses one protected head | W1.1, W1.4, W1.6 |
| AW04 | Command loss/reopen preserves original identities and cannot infer no effect | W1.6 |
| AW05 | Execution, acceptance, recovery, output release, settlement and bilateral-delivery observations remain separate | W1.5, W1.6, W2.3 |
| AW06 | Paid and unpaid work use the same execution contract; amounts are not hardcoded to W0 | W2.3 |
| AW07 | Each receiver selects trust and admission policy; requests cannot provision | W2.1 |
| AW08 | Separate owners exchange authenticated work without sharing private keys/stores | W2.2 |
| AW09 | Bilateral co-signing reconstructs the exact authorized statement and survives loss | W2.2 |
| AW10 | Existing recovery P1/P3/P4/P5 handles compose without a duplicate coordinator | W1.6, W2.4 |
| AW11 | Protocols preserve bindings or explicitly refuse unsupported fidelity | W3.1 |
| AW12 | Python and TypeScript clients use the same host contract and error semantics | W3.2 |
| AW13 | A clean installation runs two different applications without authority glue | W3.3 |
| AW14 | Reuse is measured at application boundaries; any comparative claim has a fair matched baseline | W3.4 |
| AW15 | Original and newly issued work obey distinct current/history/release rules | W2.4, W3.1 |
| AW16 | Three lanes converge on one auditable candidate without skipped required gates | W4.1, W4.2 |
| AW17 | Packages and support claims identify the exact tested candidate | W4.3 |
| AW18 | The paper leads with the programming model and programmable sovereignty | P.2, P.3 |
| AW19 | Completed-design prose is separate from unobserved implementation/evaluation | P.1, P.4 |
| AW20 | Publication and breakthrough claims have claim-specific, explicit acceptance | P.1, P.5 |
| AW21 | Checked data, opaque authority, closed results and dependency boundaries are enforced by Rust API and feature checks | W1.1, W1.7, W2.3 |
| AW22 | Production allocation and graph issuance participate in qualified serving ownership, integrity and explicit migration | W1.2, W1.4, W4.2 |
| AW23 | Every issuance/mutation has owner-local original-ID readback; coordinator loss cannot duplicate rights | W1.4, W1.6, W2.2 |
| AW24 | Exact invocation custody and distinct digest meanings preserve every signed binding without credential leakage | W1.0, W1.4, W2.3 |
| AW25 | Bounded concurrency/decoding, metadata release and cancellation preserve ownership under stalled peers | W1.0, W1.1, W1.6, W2.1, W3.2 |
| AW26 | Bounded resolved work profiles join existing manifests, semantic generations, treaty conditions and acceptance terms without minting authority | W1.3, W2.1, W3.1 |
| AW27 | An application selects an unused owner-approved collaborator through existing treaty/admission checks, without per-relationship code or trust installation | W1.4, W2.1, W2.2, W3.3 |
| AW28 | Exact acceptance observations and qualified S1 joins make results usable by later work while preserving dependency categories and labels | W1.5, W2.3, W2.4, W3.3 |
| AW29 | Refusal/pending observations expose only authorized existing recovery references; exact recovery enables progress without fresh retries or blocking independent workflows | W1.6, W2.4, W3.2, W3.3 |
| AW30 | Policy/semantic-generation changes during outstanding work preserve historical interpretation and earned obligations while rechecking current execution/release | W2.4, W3.3, W4.2 |
| AW31 | The same application contract supports single-owner unpaid, cross-owner and optional funded work, plus one installed harness and bounded provider substitution | W3.3, W3.4, W4.3 |

## Execution order

Paper P.1 through P.4 comes first, as requested. It yields a complete architecture manuscript describing the intended completed system. It may run while the other two agents continue their lanes.

Then W1 -> W2 -> W3 -> W4 -> P.5. W3 schema/SDK preparation can follow the frozen W1/W2 contract, but cannot claim a working host before it exists. W2.4 depends on the recovery lane's required ports. W4 joins all three lanes; it is a release integration step, not a fourth feature roadmap.

Use one implementation owner for this tightly coupled third lane and focused review at the public API, owner-boundary and final candidate boundaries. This package does not authorize spawning agents or publishing.

Within W1, execute the numbered tasks in order: source inventory, checked contracts, qualified stores, resolved profiles, owner preparation, accepted-result joins, recovery projections, public-client conversion. The two added tasks make independent review boundaries explicit. W2 and W3 then qualify these contracts remotely and through installed clients. The shared lifecycle cases in the developer specification are mandatory composition checks, not a new experimental campaign.

## Whitepaper design brief

Retain the approved title, Chio: A Peer-to-Peer Economy of Verifiable Work. Explain Chio as a modern kernel architecture for independently governed agent programs. The work commitment is the unit of composition; programmable sovereignty is the local authority rule making that composition possible.

The architecture sections describe the completed design in present tense. Introduce the programming model before detailed record encodings, theorem premises or the retained experiment. Language/runtime names belong in implementation details. Use one running application to explain the model and a second to establish that it is reusable.

Explain working terms, treaty-based collaborator selection, acceptance and joins, authorized progress after refusal, and policy evolution through that running application. Show the same rules inside one owner, between owners, and in a service that accepts work and delegates portions of it. A service organization is an explanatory composition, not a new governance or marketplace product. Admission is the constructive step that makes proposed participation executable; any linking analogy remains an analogy. Do not generalize the existing preservation proof to arbitrary substitutions or all policy changes.

Keep research history and artifact detail available, but do not make the abstract conclude with implementation language, a limitation inventory or a promise of future work. End the abstract with what the architecture enables. Assumptions belong beside the guarantees they delimit and in a concise system model.

Before implementation, the manuscript is an architecture specification, not a report that the new services have shipped. Existing evaluation retains its real source and one-administrator scope. New measured results, outside operation and shipping claims enter only after corresponding evidence exists.

The legacy PUBLICATION.json couples publication to economic advantage and a foundational-breakthrough judgment. Preserve that historical record. Introduce an explicit architecture-publication profile whose requirements match the revised thesis, with separately tracked open economic/adoption hypotheses. Do not relabel an unpassed historical gate as passed or silently weaken the old checker.
