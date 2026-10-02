# Task 1 primary-source audit

Research date: 2026-10-02. This extends, rather than silently replaces, the
[first pass](2026-10-02-prior-art.md). It reads the claim-relevant protocols,
premises and selected source definitions. It does not reproduce the papers'
experiments or audit every implementation path. `not_examined` means no conclusion
about that behavior. An abstract's omission is never evidence of impossibility.

[task1-sources.json](task1-sources.json) records exact downloaded PDF hashes,
software revisions, selected source-file hashes and reading locations. Full
third-party papers and repository archives remain local research-cache material;
they are not republished in this repository. Primary links below support the
source observations. The proposed integrations are our counterdesigns, not
features attributed to upstream products.

## Core competing mechanisms

| Source and inspected locations | Finding used in Task 1 | Consequence or reading boundary |
| --- | --- | --- |
| S07 [RIFL, SOSP 2015](https://web.stanford.edu/~ouster/cgi-bin/papers/rifl.pdf), sections 3 and 4.1-4.4, APIs in figures 3-5 | RPC identity, duplicate/result tracking, migration and leases protect retry semantics. Completion data must commit atomically with the operation's mutations. Lease expiry can leave a reported ambiguous outcome while preventing unsafe retry after record reclamation | Grant B1 durable identity and result tracking. Its arbitrary external HTTP write still needs E1/E2 handling. Performance and implementation are not reproduced |
| S08 [Beldi, OSDI 2020](https://www.usenix.org/system/files/osdi20-zhang_haoran.pdf), sections 2.2-3.2, 4.3, 5 and 6.1-6.2 | Independent SSFs own their databases/runtimes. Deterministic replay and atomic operation logging support recovery; callbacks preserve invocation results. Storage is strongly consistent, fault tolerant and locally atomic. GC requires a bound on live instance lifetime. Workflow transactions use distributed locking and commit propagation | Independent ownership does not defeat this baseline. State the crash/storage/synchrony premises; do not assert Byzantine-peer or opaque-external-effect guarantees from them. Transactions need not encompass child payment or every workflow |
| S11 [Coordination Avoidance in Database Systems](https://www.vldb.org/pvldb/vol8/p185-bailis.pdf), sections 3-4, definitions 1-6 and theorem 1 | I-confluence characterizes the combination of global invariant validity, transactional availability, convergence and coordination freedom for the paper's replica/transaction/merge model. Reachable states have a common ancestor; the transaction set and invariant matter together | A budget bound alone is insufficient reason to claim new coordination savings. Map the chosen operations and merge semantics before applying the theorem to Chio. No automatic theorem about Byzantine work owners or information flow follows |
| S12 [Knowledge of Preconditions](https://arxiv.org/abs/1606.07525v1), sections 2-3, definition 2.1 and theorem 3.1 | Knowledge ranges over histories indistinguishable in the agent's local state. For a conscious action, a necessary precondition implies knowledge of that precondition. The semantics explicitly abstract from the computation needed to determine knowledge | R2 cannot claim novelty for acting safely under every compatible history. It needs a useful procedure, representation or tradeoff. This is a necessary-condition result, not a ready implementation or general liveness theorem |
| S13 [Bounded counters](https://arxiv.org/abs/1503.09052v1), system model, section II.D and section III, figure 2 | Crash/recovery processes retain persistent memory. Rights split among replicas permit local bounded updates; transfers and consumption are recorded in monotone state with specific single-writer ownership | Give all baselines rights partitioning. Do not treat a malicious signer's arbitrary counter state as authoritative backing. The old author-hosted PDF URL returned 404; the exact arXiv version was read instead |
| S04 [Zoe offer safety](https://github.com/Agoric/documentation/blob/d89bd222164c61d0ff9f0b8d3116f0687ee2770f/main/guides/zoe/offer-safety.md), offer-enforcement and proposal documents; [offerSafety.js](https://github.com/Agoric/agoric-sdk/blob/3a9096a59d398d357e4e849f1abada7b41a82a9c/packages/zoe/src/contractFacet/offerSafety.js) and [rightsConservation.js](https://github.com/Agoric/agoric-sdk/blob/3a9096a59d398d357e4e849f1abada7b41a82a9c/packages/zoe/src/contractFacet/rightsConservation.js), complete functions | Offer safety checks satisfaction of give or want amounts; rights conservation checks amount equality per brand. Assets remain under platform custody. The contract application selects valid reallocations | Independent backed child claims are a legitimate construction. A proposal's acceptance token for external work requires the same trusted predicate as Chio; Zoe does not itself judge that work |
| S05 [Durable contract details](https://github.com/Agoric/documentation/blob/d89bd222164c61d0ff9f0b8d3116f0687ee2770f/main/guides/zoe/contract-details.md), durable objects/facets; [vat transcripts](https://github.com/Agoric/agoric-sdk/blob/3a9096a59d398d357e4e849f1abada7b41a82a9c/packages/SwingSet/docs/transcript.md); [vat upgrade](https://github.com/Agoric/agoric-sdk/blob/3a9096a59d398d357e4e849f1abada7b41a82a9c/packages/SwingSet/docs/vat-upgrade.md), Upgrade Sequence, Exported Obligations, Durable State, Promises Are Broken | Deterministic transcript replay restores a worker; durable state and object identities bridge incarnations. Upgrading differs from replaying a crash, and ordinary promises do not cross upgrade. Facets partition object authority | B2 stores long-lived operation/obligation state durably and recovers it explicitly. Neither an ordinary rejected promise nor a kernel transcript establishes the outcome of an arbitrary remote write. Full chain/bridge implementation qualification is `not_examined` |

## OpenAPPA, source rather than positioning

Revision: `a96f87d1fec900caf890f14342a089a32b3bfaff`. Reused the pinned
[Chio technical investigation](https://github.com/bb-connor/arc/blob/de84fc306efbb4c8dd6de748d0ad2a8d695fd30e/docs/research/openappa-2026-10-01/technical-review.md),
then inspected the following primary contracts and definitions directly:

| Primary file / location | Finding and comparison rule |
| --- | --- |
| S24 [plan.rs](https://github.com/archestra-ai/OpenAPPA/blob/a96f87d1fec900caf890f14342a089a32b3bfaff/appa-engine/src/plan.rs#L1), module contract and declared remedy subset | Registered authority assignments and narrowing remedies are enumerated under a load-time bound. Direct prerequisite recommendations are separately checked when executed. Empty-plan completeness is relative to the supported subset and stage; local useful recovery is already supplied |
| S24 [label.rs](https://github.com/archestra-ai/OpenAPPA/blob/a96f87d1fec900caf890f14342a089a32b3bfaff/appa-engine/src/label.rs#L938), `Label`, `top`, `bottom`, `combine`; symbolic audience contract | Combination lowers trust and intersects audiences. `top()` is maximum trust/public. Keep a separate domain-qualified owner-obligation vector when this audience projection loses authority structure; a name-based Chio mapping is unsound |
| S24 [basis.rs](https://github.com/archestra-ai/OpenAPPA/blob/a96f87d1fec900caf890f14342a089a32b3bfaff/appa-engine/src/basis.rs#L1), `PolicyBasis`, family/flow/subject versions | Equality of all three versions controls validity. Do not assume a family-global invalidation is an unavoidable cost of the architecture: separate roots and sound dependency refinements are allowed baseline improvements |
| S24 [projection.rs](https://github.com/archestra-ai/OpenAPPA/blob/a96f87d1fec900caf890f14342a089a32b3bfaff/appa-engine/src/projection.rs#L476), dispatch reservation and close handling; root-fork reservation handling | Indeterminate closure retains reservations; known failure closes remove them. Root forks retain inherited unresolved reservations. B3 must classify lost ACK as indeterminate and keep the effect adapter's original identity |
| S24 [eventlog/lib.rs](https://github.com/archestra-ai/OpenAPPA/blob/a96f87d1fec900caf890f14342a089a32b3bfaff/appa-eventlog/src/lib.rs#L1), storage contract; [receipts.rs](https://github.com/archestra-ai/OpenAPPA/blob/a96f87d1fec900caf890f14342a089a32b3bfaff/appa-eventlog/src/receipts.rs#L1), key/binding/error definitions | Durable claims and compare-and-swap log basis are real mechanisms. Session-bound and caller-bound claims have different semantics. B3 uses the appropriate binding and adds the qualified external-operation bridge; local receipts are not automatically portable execution authority |

The earlier investigation's selected test results are historical evidence, not
fresh Task 1 executions. Full B3 monetary/owner-label/host integration remains
`not_examined` as an implementation; this task specifies a viable construction.

## Recent agent systems: inspect the claimed property

| Source and full-text locations inspected | Relevant overlap and explicit boundary |
| --- | --- |
| S17 [TACIT v2](https://arxiv.org/abs/2603.00991v2), sections 3.2-3.6 and guarantee discussion | Tracked capabilities, classified containers, purity and a restricted safe-language harness constrain effects and disclosure. Stateless LLM behavior is an infrastructure obligation. This is a substantial confidentiality/capability comparator. Cross-owner E1/E2 settlement/cancellation correspondence is `not_examined`; the authors' experiments were not rerun |
| S18 [CaMeL v2](https://arxiv.org/abs/2503.18813v2), sections 3-5.4 and side-channel discussion | Separates control from untrusted data, labels values, evaluates tool policies and handles tainted errors. The described implementation has engine-defined policies; more granular multiparty policy is identified as future design. That does not prevent an extended baseline from adding it. Durable cross-owner effect/obligation correspondence is `not_examined` |
| S19 [Agent Contracts v3](https://arxiv.org/abs/2601.08815v3), sections 4.1, 6.1 and 7.1-7.3 | Hierarchical resource conservation and lifecycle contracts overlap directly. The paper explicitly distinguishes inter-call hard enforcement from approximate or soft single-call limits. For our hard exposure claim, every arm must reserve a genuine provider-enforced bound or refuse the unsupported profile. Do not infer a crash-safe settlement implementation from conservation equations |
| S20 [AgentBound v2](https://arxiv.org/abs/2606.30970v2), sections 3.2, 4.1-4.3 and 6-7 | Delegated authority, owner constitution and site contract compose conservatively; obligations accumulate and review cannot expand underlying authority. Mandatory pre-dispatch mediation, signing keys and receipt storage are assumptions. This defeats uniqueness of multiple policy authorities and receipts. Exact lost-ACK/earned-child correspondence is `not_examined` |
| S21 [AgentKernel v1](https://arxiv.org/abs/2609.29647v1), sections 5.1 and 5.4-5.5, especially trust assumptions and properties 5.1-5.2 | Integrated identity, memory/flow and syscall enforcement already constitute a claimed agent-kernel architecture. The paper names registry/adapter/OS trust, segmentation risk and deferred mechanized verification. Do not inherit its comparative exclusivity claims. E1/E2 and backed obligations are `not_examined`. The PDF itself repeats the August date beside a September arXiv identifier; preserve that metadata anomaly rather than silently correcting it |
| S22 [ContractWarden v1](https://arxiv.org/abs/2609.38248v1), section III.A-D, tables I-III | Human-confirmed contracts, process-bound pre-execution gating, monotone egress state, descendant/shared-object propagation and sibling isolation are concrete overlap. Coverage and source-position reuse limits are explicit; ordinary in-task declassification is outside its stated model. Its reported tests are not Chio results. Cross-owner effect/settlement composition is `not_examined` |

## Additional close antecedents found in Task 1

| ID / primary source | Claim-relevant reading and implication |
| --- | --- |
| S25 [Protecting Privacy using the Decentralized Label Model](https://www.cs.cornell.edu/andru/papers/iflow-tosem.pdf), sections 3.1-3.7; compare the [1998 formal label treatment](https://www.cs.cornell.edu/andru/papers/sp98/paper.html) | Independent per-owner policy components and owner-scoped declassification are established. Every policy must be respected; collapsing independent reader policies loses meaning. J1 must identify a real composition obligation rather than claiming invention of all-owner approval |
| S26 [DStar, NSDI 2008](https://www.scs.stanford.edu/~dm/home/papers/zeldovich:dstar.pdf), sections 2-3, especially 3.2-3.5 | Local exporters check each half of a labeled transfer, with category-specific delegated host trust and self-certifying names. A receiving host must be trusted for the restrictions it handles. A central naming authority is not mandatory. This is direct cross-host, mutually distrustful IFC prior art, not merely a single-machine label model |
| S27 [Algorithms for Omega-Regular Games with Imperfect Information, v1](https://arxiv.org/abs/0706.2619v1), section 2, lemma 1; section 3.1 and theorem 2 | Observation-based strategies and knowledge-state subset construction already provide a general route to safe control in a finite game. The construction can grow exponentially; symbolic alternatives are studied. R2 must map the exact game/objective and distinguish a useful specialization from renaming compatible histories. No stochastic or unrestricted synthesis claim is inferred |

These additions change the shortlist: owner-specific disclosure and safe control
under partial observations must be part of the strongest baseline, not apparent
gaps obtained by comparing only newer agent frameworks.

## Background sources and unresolved work

S01 (RFC 8693's profile freedom), S02 (Macaroons' attenuation), S03 (Agoric's
computation-market vision), S06 (seL4), S09 (Temporal), S10 (Sagas), and S14-S16
(runtime enforcement, PCC and IronFleet) retain their first-pass reading limits.
Task 1 does not assert a precise implementation deficiency, proof result or
performance comparison against them. No saga rollback of an irreversible
external effect is assumed. S23's pinned ERC-8183 comparison remains an existing
negative control, not a newly executed experiment.

Before a theorem or algorithm claim, Task 3 must deepen the particular
assume/guarantee, information-flow or control-theory antecedent that the selected
statement actually depends on. Before execution, pin the chosen baseline's full
build and adapters. That additional work cannot rescue an unsupported current
exclusivity claim. The present G0 decision makes none.
