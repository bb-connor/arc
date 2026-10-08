# Capability and roadmap traceability

Status: accepted planning direction, 2026-10-08 UTC. Source existence, roadmap
intent and installed qualification are distinct. This is a design crosswalk,
not a new API, owner or claim registry.

**Chio is a Rust kernel for agentic operating systems that coordinate work,
share resources, and cooperate across organizational boundaries.**

The integration is valuable when an application can rely on these native
properties instead of rebuilding identity verification, delegation accounting,
resource fences, effect recovery and evidence inside each harness. OS adapters
make those properties real on the host; applications still choose their goals,
plans, workers, models and interfaces.

## How every decision is grounded

A proposal must identify: the consumer problem; existing primitive and source;
authoritative owner; OS port or transport it needs; supported capability/profile;
what remains application-owned; source versus qualification status; and a useful
positive plus independent failure oracle. A feature name in the catalog is not
an excuse to add a new daemon, protocol, resource ledger or task language.

Source aliases T/F/W/R/K/N/G refer to exact revisions in
[PROGRAM-MAP](../../../architecture/PROGRAM-MAP.md). Public documentation and
Megastart observations are recorded in [product grounding](research/product-grounding.md).
The table's decisions apply to selected capabilities. It does not require every
feature in every deployment, nor permit claiming unimplemented features.

| Capability and consumer value | Existing primitive and accountable source | Native integration decision | Application boundary and acceptance |
| --- | --- | --- | --- |
| Agent identity and passports: assess a previously unknown collaborator without a shared application account | T:`docs/reference/AGENT_PASSPORT_GUIDE.md`; F:`chio-credentials` passport/presentation/challenge; portable `chio-kernel-core/src/passport_verify.rs` | Bind selected authenticated workload/process to subject and holder proof; evaluate issuer, audience, challenge, expiry and selected lifecycle policy in the actual credential/admission owner. Native process identity, credential claims and present effect permission remain separate. | App may select an approved collaborator or display claims. It cannot turn reputation into a grant. Bare verification is narrower than native relying-party/current admission. Q24/C09 test valid credentials without grants, replay, stale/revoked policy and workload substitution. |
| Recursive delegation: a coordinator can delegate bounded work that children can narrow again | F:`chio-core-types/src/capability/attenuation.rs`; kernel delegation/parent custody; K:S1 registry/S4 closure | Reuse actual serving-path lineage and current authority. Bind delegator, recipient, tool/resource scope, constraints, expiry and applicable budget allocation. State supported depth and verification profile; qualify each, including ancestor revocation. | App chooses task decomposition. It does not mint missing parents, recompute authoritative remaining scope or bypass unsupported forms. Q25/C10 require useful grandchild work and independently refused widening/revoked descendants. Hosted and portable verification profiles need separate evidence. |
| Swarm authority: fan-out and fan-in carry verifiable authorization across a task graph | T:`chio-swarm-authority` verifier/types; W:`evolution.rs`, runtime SQLite `swarm_authority_bundles.rs`; W1 production custody/issuance | Bind graph, witnesses, continuations, route, budget and revocation epoch to actual runtime admission. Additive extension advances one protected head atomically. Qualify durable replay, resource conservation and exact accepted dependencies. | App plans/schedules the graph. Offline bundle verification and fixture signing do not prove production issuance or accepted parent work. Q26/C11 race extensions/replays and reject a signed join with invalid parent evidence. |
| Durable Agent Processes: useful work survives worker/client replacement | F:`chio-process` registry/runtime, WORKER_PROTOCOL and CLI PROCESS_HOST; recovery P1 | Map logical process and original operation identities to native worker custody, credentials, deadlines, checkpoints, cancellation and exact child bindings. Keep logical Agent Process distinct from OS PID/incarnation. | App owns business state and scheduling. PID, pane, checkpoint and logical invocation are not interchangeable. Q02/Q07/Q19/Q23 and C02/C05 independently check effects and descendant closure across loss/restart. |
| Shared resources: cooperating agents safely access the same queue, document or service | Public shared-resource contract; actual selected resource owner; existing kernel/store authority and W D1 allocation | At the actual mutation boundary, atomically check trusted caller, current assignment/fence, expected version, original ID and applicable grant. Qualify the real service, not only an adapter's optimistic check. | App selects jobs/assignments within authority. Mailbox lease, latest version and resource ownership remain distinct. Q27/C03 reject stale owners with fresh versions and preserve exact prior replay without new mutation. |
| Shared capacity and accounting: siblings cannot each spend the same allowance | G persistent aggregate family; native budget store; W D1 allocator/selection/seal and K resource research | Keep one qualified admission/allocator owner per declared scope; surviving reservations and consumption join its fencing, integrity, snapshot and migration rules. Expose typed units and unknown observations faithfully. Native CPU/memory limits are a separate OS resource contract. | Client progress bars and sibling shares are not a ledger. G uses direct worker grants and rejects unsupported multi-hop aggregate delegation. No distributed atomic-budget claim follows from a local SQLite owner or portable graph. Q15/Q25/Q27 and C04 observe real effects/charges under races and restart. |
| Verifiable work: another app can rely on an exact accepted result | W1 planned Prepare/Submit/Query and WorkView; existing D1/S1/native/recovery owners | Bind original working terms, producer, task, artifact, evaluator/version and evidence. Preserve execution, acceptance, result, recovery, settlement and bilateral delivery separately. Qualify actual W1 facade and accepted-result joins; names in a spec are not installed APIs. | Domain acceptance procedure belongs to the application contract; native validation/commit of the bound evidence belongs to its owner. A model answer, exit code, test-only signature or human click is not W1 acceptance. Q01/Q14/Q26/C08/C11. |
| Recovery and knowledge release: failures do not duplicate effects or leak old results | R implemented seven-command recovery candidate; W1 release-port reconciliation; K:S3/S9 M20/S10/S11 | Query original command/preparation/operation across loss; preserve retained uncertainty and owner retry dispositions. Separate historical reconciliation from new dispatch and present result release. Authenticate current audience before metadata or payload disclosure. | App decides whether to request an allowed remedy. It does not create a new ID after timeout, rewrite sealed intent or treat compensation as no effect. Q02-Q06/Q14/Q21/C02/C07/C08 qualify actual native outcomes. |
| Federation and organizational cooperation: independent operators can work together while retaining local control | Existing federation/treaty verifier and durable artifact owners; W2 owner services; W3 installed transports | Enroll peer roots/endpoints and semantic profiles administratively. Each owner keeps keys/store/policy and may refuse. Carry exact authority/evidence, recheck current recipient permission and reconcile interrupted bilateral exchange. | Discovery or work requests cannot choose administrative roots or grant themselves access. Q28/C06/C07 require real independent custody for an organizational claim; a local fixture only proves its protocol branch. Unpaid work requires no funding rail. |
| Native guards and tool mediation: the same authorization rule works through different tools/protocols | Kernel admission, native policy/guards, protocol MCP/A2A/ACP-Client/provider adapters; K:S1 R11/R12 | Lower supported operations to existing native tools. Qualify normalization, exact arguments, current grant, installed guards and actual effect port. Keep adapter-specific dialects outside L0. | Harness chooses tool calls. A hook, transport authentication or successful parser is not complete mediation. Doc 19 I01-I08 and Q11/Q12/Q22 apply to each protected host; unmapped effects stay unavailable or truthfully unmediated. |
| Credentials and model/network access: untrusted workers use allowed services without receiving reusable secrets | F secret broker, model relay/gateway, native host credential owners | Bind credentials and egress to enrolled subject/profile, intended endpoint and current authority. Use platform-qualified custody and constrained handles; record native context limitations, such as daemon versus user keychain. | App chooses permitted model/service. It does not receive grant/receipt signers or broad provider keys. Q10/Q13/Q29 plus native egress/descriptor/environment probes show actual denied access. |
| Receipts, lineage and independent evidence: an operator or counterparty can verify what a claim covers | Existing signed receipts/Merkle log/trust-control, lineage, proof/verifier and audience-safe export; K:S3/S5 | Retain signing domains, original identities, provenance and evidence class. Preserve post-dispatch uncertainty. Use non-persisting reads/bounded hints and explicit gaps. Export current-authorized bytes through the existing owner. | UI can display evidence but cannot upgrade host-reported events to mediated effects, an allow receipt to completion, or one administrator's two keys to independent organizations. Q04/Q09/Q14/Q18/Q21/C07. |
| Metering and optional financial settlement: work can earn an obligation independently of delivery | Existing payment/settlement owners and selected rails; W2/W4 | Add exact agreement/reserve/operation/finality gates only to funded profiles. Recover earned obligations under historical authority without automatically releasing protected output. | App can propose price/terms. It cannot infer settled money from accepted work or erase earned payment because delivery failed. Unpaid local/cooperative work stays useful without a market, chain or hosted billing account. |
| Kernel simplicity, performance and integrity: applications rely on a smaller, inspectable trusted core | K:S1 interface census; S9 admission machine; S10 authority crossings; S11 integrity-safe inference | Register every consumed seam, TCB role and layer descent. Retain present safety invariants while implementing owner phase deltas. Extend influence/endorsement and confinement evidence in their owners when selected. | No Chio UI, universal scheduler or arbitrary feature census enters the core. Proof/performance/injection-resistance claims require the named model, implementation and actual evaluation, never OS integration alone. Q30 and owner-specific keystone gates. |

## NVIDIA research: use the evidence, decide the product deliberately

Input N is a pinned research/strategy proposal, not an accepted replacement for
the user's product ambition. Its `06-strategy-and-roadmap.md` sections 1-3 and
F-2 explicitly recommend a narrower authority/evidence category and freezing
some native runtime/broker work on the OpenShell path. ADR-0038 overrides that
choice for this program. Its F-1 through F-17 commercial, publication, staffing
and vendor engagement decisions are not adopted by reference.

Retain these technically useful consequences:

1. Evaluate existing containment/runtime backends through narrow qualified ports.
   Avoid building a bespoke VM, endpoint sensor suite or sandbox language before
   proving a required owner gap. Native host integration remains a product path,
   and Chio still owns its authority/resource/custody obligations.
2. Treat external runtime policy as an additional enforcement boundary, not a
   portable Chio capability, caller identity or work acceptance record. Any grant
   projection must document semantic loss and reject unrepresentable required
   restrictions. Never claim whole-machine mediation from one network seam.
3. Bind evidence to the actual sandbox/process, policy, runtime version and
   original operation where the selected seam can establish them. Pre-forward
   approval, upstream effect, response withholding and unknown outcome are
   different facts. Historical prototype latency is not Rust/native performance.
4. Design foreign issuer/credential and evidence adapters through existing trust
   and canonical verification owners. An imported assertion or authenticated
   transport cannot silently install trust or bypass receiver-local admission.
5. Differentiate through demonstrated composition: accepted work under attenuated
   authority, conserved resources and failure-safe independent-owner exchange
   across applications and runtimes. Basic argument filtering, a dashboard or a
   signed log alone does not establish a durable competitive advantage.

A bounded current source recheck on 2026-10-08 UTC inspected OpenShell at
`277f922d6d3b08b16d825cbd97499fe1a50031ac`. Its [README](https://github.com/NVIDIA/OpenShell/blob/277f922d6d3b08b16d825cbd97499fe1a50031ac/README.md)
describes runtime containment, credential handling and policy verification.
The [policy schema](https://github.com/NVIDIA/OpenShell/blob/277f922d6d3b08b16d825cbd97499fe1a50031ac/docs/how-it-works/policies/schema.mdx)
still distinguishes MCP method/tool rules from argument matching and describes
middleware error behavior. The [multi-player RFC](https://github.com/NVIDIA/OpenShell/blob/277f922d6d3b08b16d825cbd97499fe1a50031ac/rfc/0011-multi-player-design/README.md)
limits its own scope to a single gateway. These facts justify testing candidate
integration seams; they do not establish that NVIDIA or another vendor cannot
build competing authority, federation or resource features. The stored
[source observation](research/openshell-source-observation.json) records hashes
and scope. No runtime was executed and no entire competitor-stack refresh is
claimed. Future adapter selection must repin and rerun its exact conformance.

The strategic thesis is therefore an inference to test: a reusable kernel that
makes multi-application, multi-owner systems substantially easier to build is
more valuable than another workbench or one runtime-specific filter. Measure it
through consumer adoption and actual application burden in CONSUMERS, without
invented speedups, exclusivity or market demand.

## Relationship to Clawdstrike and native security extensions

Clawdstrike research can inform macOS process/network observations and extension
packaging. It does not replace Chio's issuer, budget, resource or work owners.
A sensor statement has declared coverage, freshness and loss; selected policy
may use it to restrict admission. It cannot expand authority, certify an unseen
effect or turn endpoint telemetry into a work receipt. ES/NE entitlements,
consent, boot and extension lifecycle remain separate platform gates. The macOS
annex retains the precise source pins and experiments. Managed endpoint sensing
is optional to the native kernel profile, unless a selected claim requires it.

## Decisions and acceptance linkage

| Decision | Grounding | Required evidence |
| --- | --- | --- |
| Native owners and headless consumers precede UI | K layer/TCB rules; public process/SDK docs; G host/Herdr split | Q23/Q30; C01/C02/C05; installed independent app and harness; no optional projection dependency |
| Separate user-session and service principal | Actual OS identity/credential/lifecycle primitives and current native authority | Q29 and platform boot/lock/logout/expiry tests; explicit unavailable service profile until implemented |
| Reuse Rust core, native policy and owner schemas | Existing kernel/guard/SDK contracts; K R11/R12 | Source/API reconciliation and real owner conformance; no second security/ledger implementation |
| Coordinate without a universal Chio scheduler | Process, W1 and swarm contracts; application-owned plans | Q25/Q26 and W3 independent applications; exact accepted joins; external plan/checkpoint ownership |
| Shared resources are a native contract | Persistent admission budgets plus owner-atomic assignment/version/ID | Q27/C03/C04 with native state and effect observers; single-owner and distributed guarantees named separately |
| Cooperation is an independent release dimension | Federation, W2, current disclosure and bilateral evidence | Q28/C06/C07 plus actual separately administered parties for that claim |
| Optional platform shells and workbench | Same owner bindings and bounded optional OPERATOR | Full selected graphical/browser/privacy/accessibility matrix; no UI availability gate for native functions |
| Native or external containment is replaceable | Foundation/doc 19, S7, platform source experiments and N seam evidence | Actual host/tool/evaluator profile, I01-I08, no ambient bypass; runtime policy approval never grants Chio authority |
| Keep claim limits visible without shrinking ambition | ADR-0011, owner status and native case manifests | Each release advertises exact capabilities/profile; current source, installed qualification and public availability remain separate |

The shared plan's packets 1-3 ground and qualify owners, packets 4/4a prove
independent consumers, packet 5 proves the three product dimensions and packet 6
qualifies native delivery. Platform packets supply ports and lifecycle. New
capabilities enter this same traceability process; implementation convenience
or a frontend control does not set architecture.
