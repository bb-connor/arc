# Agentic work kernel: architecture and beta convergence

Status: planned implementation contract. The [integration inventory](../../research/work-abstraction/INTEGRATION.md) distinguishes interfaces on main from pending work and recovery dependencies.

## Intent and contribution

Chio makes work a reusable programming abstraction across independently governed systems. An agent chooses and organizes work. Each owner's kernel enforces the authority, resource commitments, execution history and obligations governing its participation.

The contribution is a common execution contract, implemented through existing capability, treaty, guard, swarm, process, receipt and settlement machinery. Reconstructability from known components is not a veto on systems innovation. Comparisons must assess the reusable contract and application responsibilities, not merely whether another escrow reproduces a financial trace. No exclusive-expressiveness, universal result-correctness or inevitable ecosystem-impact claim follows.

Success means a developer can construct two materially different applications using the same supported work interface, without writing a custom authority verifier, retry coordinator, graph-signing script or settlement state machine. Owners can refuse admission under their own configuration. Adding supported transports does not create new execution semantics.

The full programming lifecycle is part of that criterion: resolve a working contract, select an unused approved collaborator, delegate, accept and compose results, recover through an authorized continuation, and change current policy without rewriting prior commitments. An agent proposes how a program develops; each owner admits its own participation. Work commitments preserve the terms and history on which subsequent work depends.

## Source and authority ownership

The [integration inventory](../../research/work-abstraction/INTEGRATION.md), [current-source map](../../research/work-abstraction/CURRENT-STATE.md) and [source manifest](../../research/work-abstraction/SOURCES.json) identify exact constructors, owner transactions and missing interfaces. A type in a pending branch or this specification is not a serving API.

Use chio-runtime as the public Rust client facade and chio-runtime-core for checked work contracts and pure binding checks. Concrete owner composition belongs in chio-control-plane. D1 rules belong in chio-workflow, with production persistence under chio-store-sqlite's serving authority. S1 graph issuance, native capture, recovery and financial obligations retain their separate owners. No new top-level runtime crate is required.

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
- Every Chio-owned format uses one v1 shape and strict structural rejection. Distinct live shapes use distinct v1 domain names. Remove superseded decoders and update every caller in the same change; no unshipped-format conversion path remains.
- Use the selected source's Clock port and strict authoritative JSON readers. The inspected workspace uses edition 2021 and Rust 1.95; chio-settle declares Rust 1.93. Preserve each owning package's declared floor.
- Fail closed, retain typed rejection provenance, forbid new unsafe code, and keep unwrap_used and expect_used denied.
- Use checked value types and closed outcomes. Wire decoding is not authentication; verified authority and live ownership remain opaque. Pure code uses concrete types/static dispatch; new traits require a real dependency boundary.
- Reuse the security lane's engineering standard: one module responsibility, no new hand-maintained include!, no module-size ratchet relaxation, and no permissive security-trait defaults. Preserve inner error causes privately and redact external diagnostics.
- Keep signer intent and idempotency at the issuing authority. Coordinator indexes, copied stores and retry caches cannot mint rights. New authoritative tables join the existing serving projection, integrity and continuity contracts. Each SQLite store has one v1 schema; any mismatching stamp returns exact StaleSchema. Development databases with retired shapes are wiped and reprovisioned, never converted.
- Bound parsing, verification work, queues and blocking tasks. Never hold a store transaction across remote I/O. Cancellation or dropped futures cannot erase committed obligations.
- Separate query, historical reconciliation and current result release. Protect metadata as well as payload bytes. Work commitments reference protected exact invocation custody; they do not become generic credential containers.
- Resolved profiles, acceptance observations and recovery links are audience-scoped projections of existing authorities. They do not install trust, authorize effects, declassify artifacts or certify arbitrary usefulness.
- No em dashes. Do not invent observed results, outside participants, shipped surfaces or release acceptance.
- Before each implementation merge, run full library and integration tests for every changed crate, strict all-target Clippy with -D warnings, and cargo fmt --all --check. Preserve an original failing behavioral test and its passing result. Hosted qualification remains a separate release acceptance boundary; it does not delay a locally qualified merge.

## Programming and authority model

A work commitment links an allocation, exact selected invocation, receiving authority, original working terms and acceptance contract, graph participation and optional funded agreement. It is a programming abstraction over these records, not a replacement wire capability or a global atomic transaction.

Owner-controlled resources keep separate authoritative stores:

| Resource | Required owner | Work responsibility |
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
| RecoveryProcessReservationPort and RecoveryProcessOriginPort | Pending recovery implementation | Reserve and seal the exact process request, then read the same retained origin after lost acknowledgement |
| RecoveryAuthorityPort | Pending recovery implementation | Resolve original operations; historical settlement cannot release output or dispatch new work |
| Exact approval, remedy and grant | Pending recovery implementation | Approval creates only the specified continuation under its owning authority |
| Protected artifact materialization and confined return | Pending recovery implementation | Use the concrete APIs in the integration inventory; result references never release bytes or bypass current recipient authority |
| Semantic connector coverage | Recovery P3/P6 | Advertise only the intersection of work, security and recovery support |
| Receipts, audience restrictions and package verification | Security | Export through existing verified evidence paths, including refusal and partial-delivery states |

The recovery specification's proposed names are contract anchors, not proof those APIs already exist. At integration, record their actual landing paths and signatures. If the implementation changes a contract, update the relevant adapter/spec and focused tests together; do not duplicate the old proposal.

## Beta target and stopping rule

The proposed beta profile is an installable developer kernel and reference host on the platform qualified by the security lane. Linux x86_64 Enforced mode is the initial acceptance target; other platforms retain their own explicit support levels. Native Rust, Python process workers and TypeScript process workers share the same work model. MCP, A2A, ACP-Client and HTTP are individually qualified according to their actual mediation boundaries.

Funded work is part of the architecture and the beta API. The initial qualified rail may remain an explicitly labeled local development-chain profile with mock assets. Public-money deployment needs its own rail, contract, finality and operational acceptance; a devnet result cannot authorize it. No mandatory chain or payment is introduced for unpaid work.

Envoy ext_authz remains an admission integration unless the deployment supplies and qualifies the full execution/evidence path. Observation-only provider integrations remain observation-only. A supported-surface matrix is an executable contract, not a count of adapters.

Beta source readiness is the conjunction of:
1. Security acceptance for every enabled beta surface, including inherited audit, native and hosted requirements.
2. Recovery acceptance for the phases/features advertised by beta.
3. W1 through W3 acceptance below.
4. One integrated candidate with package/install, schema-refusal, restart/replay, cross-owner, protocol and documentation evidence.
5. Closed blocking reviews and an explicit remaining-scope record.

The release integration plan reuses the existing RELEASE_CANDIDATE, RELEASE_AUDIT and QUALIFICATION contracts. Existing requirements are not silently waived by the word beta. A scoped release decision must identify any excluded feature and its claim impact. Observed automatic-defense promotion remains governed by Security M11; publishing a developer beta does not close that operational milestone.

Stop adding features when these obligations are met. Open provider discovery, arbitrary graph edits, task migration between owners, budget reclamation, a universal marketplace, generalized semantic correctness and a new consensus layer are outside this Work contract.

Selecting an unused participant from an owner-approved catalog is in scope. Enrollment, key installation and deployment activation remain owner operations. Provider substitution applies to future commitments satisfying the same explicit external requirements; it does not retarget sealed work or imply unobserved equivalence between implementations.

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
| AW22 | Production allocation and graph issuance participate in qualified serving ownership, integrity and stale-schema refusal | W1.2, W1.4, W4.2 |
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

The [runtime plan](../plans/2026-10-03-work-runtime.md) and [integration inventory](../../research/work-abstraction/INTEGRATION.md#implementation-order) define the dependency order. D1 and S1 extension work require the separately landed work substrate. Recovery-dependent halves of W1.3 through W1.6 require their actual recovery owners and retained-identity tests; non-recovery halves expose only their narrower supported profile.

W2.1 includes `/cosign`; W2.5's operator package is required for outside teams. W2.4 requires qualified original-operation recovery. W3 consumes frozen W1/W2 contracts without claiming an installed serving host before its transport is qualified. W4 joins work, security and recovery at the release boundary. The paper's publication and economic claims remain separate acceptance records.

## Whitepaper design brief

The approved title is *Chio: A Peer-to-Peer Economy of Verifiable Work*. The paper presents a kernel architecture for independently governed agent programs. Work commitments are the unit of composition; programmable sovereignty is the local authority rule governing participation. Introduce the programming model before record encodings, theorem premises and evaluation details. Use one running application to explain the model and a second to establish reuse.

Explain working terms, treaty-based collaborator selection, acceptance and joins, authorized progress after refusal, and policy evolution through those applications. Apply the same rules within one owner, between owners, and in a service that delegates portions of accepted work. Admission makes proposed participation executable. The preservation proof retains its stated premises; it does not establish arbitrary substitution or arbitrary policy evolution.

Present-tense architecture prose describes the design, not an observed deployment. Identify the manuscript as an architecture specification until implementation evidence supports stronger claims. Preserve exact source identities and the one-administrator scope of the existing evaluation. Each implementation, measurement, outside-operation and shipping claim requires its own evidence. State assumptions beside the guarantees they delimit. End the abstract with the architectural capability, without promotional claims.

Architecture publication has a distinct acceptance profile from economic advantage and adoption hypotheses. The profile requires complete design, verified implementation claims, consistent artifacts, technical review, supported empirical claims and exact source identities. Open economic or adoption gates remain open unless their own evidence satisfies them; a different publication profile cannot mark them passed or weaken their checker. Negative validation must reject unverified implementation claims, missing claim evidence and unknown profiles, and confirm that unsupported economic claims still fail.

The [pinned paper plan](https://github.com/bb-connor/arc/blob/cafdc970e4f89bddf810647e4228a605ed9f498a/docs/superpowers/plans/2026-10-03-verifiable-work-finalization.md) defines P.1 through P.5. Paper execution and artifacts remain outside this Work prerequisite import. AW18 through AW20 retain the requirements in this brief; the inventory does not claim paper publication acceptance.
